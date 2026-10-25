//! The relay: a Cloudflare Worker between the host (Claude's `cldp`) and
//! paired phones. Messages and devices are D1 rows; file bodies are R2
//! objects streamed straight from the request and back, so they never pass
//! through wasm memory. The API is listed in `cld_phone_proto::api`.
//!
//! Bindings: `DB` (D1), `FILES` (R2). Secrets: `HOST_TOKEN`, `TOTP_SECRET`,
//! and optionally `NTFY_URL` (+ `NTFY_TOKEN`) for push notifications.
//!
//! Uploads, downloads and stored bytes are capped (`Limits`) so the relay
//! stays inside R2's free tier whatever a client does.
//!
//! The worker creates its own tables (`schema.sql`, every statement
//! `IF NOT EXISTS`) the first time each instance touches the database, so a
//! deploy needs no separate migration step.

use cld_phone_proto::api::{
    decode_header_name, limit_from, mime_from_name, safe_file_name, safe_mime, valid_file_id,
    Device, ErrorBody, FileRef, Me, Message, NewMessage, PairRequest, PairResponse, Role, Sender,
    Status, Want, DEFAULT_DOWNLOADS_PER_DAY, DEFAULT_STORAGE_MB, DEFAULT_UPLOADS_PER_DAY,
    KEEP_DAYS, MAX_FILE_BYTES, MAX_NAME, PAGE, TOKEN_DAYS,
};
use cld_phone_proto::gate::{Gate, PairState};
use cld_phone_proto::{constant_time_eq, hex, sql_statements, token_digest, totp};
use std::sync::atomic::{AtomicBool, Ordering};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::*;

const DAY_MS: i64 = 86_400_000;
/// `last_seen` is rewritten at most this often, so polling costs reads only.
const SEEN_EVERY_MS: i64 = 3_600_000;
/// Uploaded files never attached to a message are dropped after this.
const ORPHAN_MS: i64 = DAY_MS;
const SCHEMA: &str = include_str!("../schema.sql");
/// Set once this instance has applied the schema.
static SCHEMA_READY: AtomicBool = AtomicBool::new(false);
/// Daily R2 counters are kept this long.
const USAGE_KEEP_DAYS: i64 = 40;

/// The R2 budget; defaults and variable names are in `cld_phone_proto::api`.
struct Limits {
    storage_bytes: i64,
    uploads_per_day: i64,
    downloads_per_day: i64,
}

impl Limits {
    fn from_env(env: &Env) -> Limits {
        let var = |name: &str| {
            env.var(name)
                .ok()
                .map(|v| v.to_string())
                .or_else(|| secret(env, name))
        };
        Limits {
            storage_bytes: limit_from(var("STORAGE_LIMIT_MB").as_deref(), DEFAULT_STORAGE_MB)
                .saturating_mul(1 << 20),
            uploads_per_day: limit_from(var("UPLOADS_PER_DAY").as_deref(), DEFAULT_UPLOADS_PER_DAY),
            downloads_per_day: limit_from(
                var("DOWNLOADS_PER_DAY").as_deref(),
                DEFAULT_DOWNLOADS_PER_DAY,
            ),
        }
    }
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    let res = route(&mut req, &env, &ctx).await;
    match res {
        Ok(r) => Ok(r),
        Err(e) => {
            console_error!("{} {}: {e}", req.method(), req.path());
            json_error(500, "relay error")
        }
    }
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    if let Err(e) = ensure_schema(&env).await {
        console_error!("schema: {e}");
        return;
    }
    if let Err(e) = cleanup(&env).await {
        console_error!("cleanup: {e}");
    }
}

/// Who is calling.
enum Caller {
    Host,
    Phone { hash: String, name: String },
}

impl Caller {
    fn sender(&self) -> Sender {
        match self {
            Caller::Host => Sender::Claude,
            Caller::Phone { .. } => Sender::Phone,
        }
    }
}

async fn route(req: &mut Request, env: &Env, ctx: &Context) -> Result<Response> {
    let path = req.path();
    let method = req.method();
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    if parts == [""] && method == Method::Get {
        return Response::ok("cld-phone relay\n");
    }
    if parts.first() != Some(&"api") {
        return json_error(404, "not found");
    }
    ensure_schema(env).await?;
    if parts == ["api", "pair"] && method == Method::Post {
        return pair(req, env, ctx).await;
    }

    let Some(caller) = authenticate(req, env).await? else {
        return json_error(401, "not paired or token expired");
    };
    let host = matches!(caller, Caller::Host);

    match (method, &parts[1..]) {
        (Method::Get, ["me"]) => Response::from_json(&Me {
            role: if host { Role::Host } else { Role::Phone },
            name: match &caller {
                Caller::Host => "host".into(),
                Caller::Phone { name, .. } => name.clone(),
            },
        }),
        (Method::Get, ["messages"]) => list_messages(req, env).await,
        (Method::Post, ["messages"]) => post_message(req, env, ctx, &caller).await,
        (Method::Delete, ["messages"]) => clear(env).await,
        (Method::Post, ["messages", id, "close"]) if host => close(env, id).await,
        (Method::Post, ["files"]) => upload(req, env).await,
        (Method::Get, ["files", id]) => download(env, id).await,
        (Method::Get, ["status"]) if host => Response::from_json(&status(env).await?),
        (Method::Post, ["pair", "reset"]) if host => reset_pairing(env).await,
        (Method::Post, ["logout"]) => match &caller {
            Caller::Phone { hash, .. } => {
                db(env)?
                    .prepare("DELETE FROM devices WHERE token_hash = ?1")
                    .bind(&[hash.as_str().into()])?
                    .run()
                    .await?;
                Response::from_json(&serde_json::json!({ "ok": true }))
            }
            Caller::Host => json_error(400, "the host has no device token"),
        },
        _ => json_error(404, "not found"),
    }
}

// ---------------------------------------------------------------- helpers

/// Apply `schema.sql` (all `IF NOT EXISTS` / `OR IGNORE`) once per instance.
async fn ensure_schema(env: &Env) -> Result<()> {
    if SCHEMA_READY.load(Ordering::Relaxed) {
        return Ok(());
    }
    let db = db(env)?;
    let statements = sql_statements(SCHEMA)
        .iter()
        .map(|s| db.prepare(s.as_str()))
        .collect();
    db.batch(statements).await?;
    SCHEMA_READY.store(true, Ordering::Relaxed);
    Ok(())
}

fn today() -> i64 {
    now_ms() / DAY_MS
}

/// Count one R2 operation of `kind` ('put' or 'get') against today's
/// budget, or return false once `limit` is used up. One statement, so
/// parallel requests cannot both take the last unit. It counts before the
/// operation runs, so a failed operation still counts.
async fn reserve(env: &Env, kind: &str, limit: i64) -> Result<bool> {
    #[derive(Deserialize)]
    struct Row {
        #[allow(dead_code)]
        n: i64,
    }
    let row: Option<Row> = db(env)?
        .prepare(
            "INSERT INTO usage (day, kind, n) VALUES (?1, ?2, 1) \
             ON CONFLICT (day, kind) DO UPDATE SET n = n + 1 WHERE n < ?3 RETURNING n",
        )
        .bind(&[num(today()), kind.into(), num(limit)])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

async fn used_today(env: &Env, kind: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        n: i64,
    }
    let row: Option<Row> = db(env)?
        .prepare("SELECT n FROM usage WHERE day = ?1 AND kind = ?2")
        .bind(&[num(today()), kind.into()])?
        .first(None)
        .await?;
    Ok(row.map(|r| r.n).unwrap_or(0))
}

async fn stored_bytes(env: &Env) -> Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        total: i64,
    }
    let row: Option<Row> = db(env)?
        .prepare("SELECT COALESCE(SUM(size), 0) AS total FROM files")
        .first(None)
        .await?;
    Ok(row.map(|r| r.total).unwrap_or(0))
}

fn now_ms() -> i64 {
    Date::now().as_millis() as i64
}

fn db(env: &Env) -> Result<D1Database> {
    env.d1("DB")
}

fn json_error(status: u16, msg: &str) -> Result<Response> {
    Ok(Response::from_json(&ErrorBody { error: msg.into() })?.with_status(status))
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| Error::RustError(format!("random: {e}")))?;
    Ok(hex(&buf))
}

fn secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
}

fn num(v: i64) -> JsValue {
    JsValue::from(v as f64)
}

async fn authenticate(req: &Request, env: &Env) -> Result<Option<Caller>> {
    let Some(header) = req.headers().get("Authorization")? else {
        return Ok(None);
    };
    let Some(token) = header.strip_prefix("Bearer ").map(str::trim) else {
        return Ok(None);
    };
    if token.is_empty() {
        return Ok(None);
    }
    // A short host token would be guessable; refuse to run with one.
    if let Some(host) = secret(env, "HOST_TOKEN").filter(|t| t.len() >= 32) {
        if constant_time_eq(host.trim().as_bytes(), token.as_bytes()) {
            return Ok(Some(Caller::Host));
        }
    }

    #[derive(Deserialize)]
    struct Row {
        name: String,
        last_seen: i64,
    }
    let hash = token_digest(token);
    let now = now_ms();
    let row: Option<Row> = db(env)?
        .prepare("SELECT name, last_seen FROM devices WHERE token_hash = ?1")
        .bind(&[hash.as_str().into()])?
        .first(None)
        .await?;
    let Some(row) = row else { return Ok(None) };
    if now - row.last_seen > TOKEN_DAYS * DAY_MS {
        return Ok(None);
    }
    if now - row.last_seen > SEEN_EVERY_MS {
        db(env)?
            .prepare("UPDATE devices SET last_seen = ?1 WHERE token_hash = ?2")
            .bind(&[num(now), hash.as_str().into()])?
            .run()
            .await?;
    }
    Ok(Some(Caller::Phone {
        hash,
        name: row.name,
    }))
}

// ---------------------------------------------------------------- pairing

#[derive(Deserialize)]
struct PairRow {
    ver: i64,
    last_step: i64,
    fails: i64,
    window_start: i64,
    total_fails: i64,
}

async fn load_pairing(env: &Env) -> Result<PairState> {
    let row: Option<PairRow> = db(env)?
        .prepare("SELECT ver, last_step, fails, window_start, total_fails FROM pairing WHERE id = 1")
        .first(None)
        .await?;
    let row = row.ok_or_else(|| Error::RustError("pairing row missing; apply schema.sql".into()))?;
    Ok(PairState {
        ver: row.ver,
        last_step: row.last_step,
        fails: row.fails,
        window_start: row.window_start,
        total_fails: row.total_fails,
    })
}

/// Write `next` only if the row is still at `prev_ver`.
async fn store_pairing(env: &Env, prev_ver: i64, next: &PairState) -> Result<bool> {
    let res = db(env)?
        .prepare(
            "UPDATE pairing SET ver = ?1, last_step = ?2, fails = ?3, window_start = ?4, \
             total_fails = ?5 WHERE id = 1 AND ver = ?6",
        )
        .bind(&[
            num(next.ver),
            num(next.last_step),
            num(next.fails),
            num(next.window_start),
            num(next.total_fails),
            num(prev_ver),
        ])?
        .run()
        .await?;
    Ok(res.meta()?.and_then(|m| m.changes).unwrap_or(0) == 1)
}

async fn pair(req: &mut Request, env: &Env, ctx: &Context) -> Result<Response> {
    let Some(secret) = secret(env, "TOTP_SECRET").and_then(|s| totp::decode_secret(&s)) else {
        return json_error(503, "pairing is not set up on the relay");
    };
    let Ok(body) = req.json::<PairRequest>().await else {
        return json_error(400, "expected {code, name}");
    };
    let now_s = now_ms() / 1000;

    let state = load_pairing(env).await?;
    let reserved = match state.reserve(now_s) {
        Gate::Open(s) => s,
        Gate::Locked { retry_after } => {
            let mins = (retry_after + 59) / 60;
            return json_error(429, &format!("too many tries; wait {mins} min"));
        }
        Gate::Disabled => {
            return json_error(403, "pairing is off after too many failures; run `cldp pair --reset`")
        }
    };
    if !store_pairing(env, state.ver, &reserved).await? {
        return json_error(429, "busy; try again");
    }

    let Some(step) = totp::matching_step(&secret, &body.code, now_s as u64) else {
        return json_error(401, "wrong code");
    };
    let Some(accepted) = reserved.accept(step as i64) else {
        return json_error(401, "code already used; wait for the next one");
    };
    if !store_pairing(env, reserved.ver, &accepted).await? {
        return json_error(409, "busy; try again");
    }

    let token = random_hex(32)?;
    let name = {
        let n = safe_file_name(&body.name);
        if n == "file" { "phone".to_string() } else { n.chars().take(MAX_NAME).collect() }
    };
    let now = now_ms();
    db(env)?
        .prepare("INSERT INTO devices (token_hash, name, created, last_seen) VALUES (?1, ?2, ?3, ?3)")
        .bind(&[token_digest(&token).as_str().into(), name.as_str().into(), num(now)])?
        .run()
        .await?;
    notify(env, ctx, "Phone paired", &format!("{name} can now read and answer Claude"), false);
    Response::from_json(&PairResponse {
        token,
        expires: now + TOKEN_DAYS * DAY_MS,
    })
}

async fn reset_pairing(env: &Env) -> Result<Response> {
    let state = load_pairing(env).await?;
    if !store_pairing(env, state.ver, &state.reset()).await? {
        return json_error(409, "busy; try again");
    }
    Response::from_json(&status(env).await?)
}

async fn status(env: &Env) -> Result<Status> {
    #[derive(Deserialize)]
    struct DevRow {
        name: String,
        created: i64,
        last_seen: i64,
    }
    #[derive(Deserialize)]
    struct Count {
        n: i64,
    }
    let devices: Vec<DevRow> = db(env)?
        .prepare("SELECT name, created, last_seen FROM devices ORDER BY created")
        .all()
        .await?
        .results()?;
    let count: Option<Count> = db(env)?
        .prepare("SELECT COUNT(*) AS n FROM messages")
        .first(None)
        .await?;
    let pairing = load_pairing(env).await?;
    let limits = Limits::from_env(env);
    Ok(Status {
        storage_bytes: stored_bytes(env).await?,
        storage_limit: limits.storage_bytes,
        uploads_today: used_today(env, "put").await?,
        uploads_limit: limits.uploads_per_day,
        downloads_today: used_today(env, "get").await?,
        downloads_limit: limits.downloads_per_day,
        devices: devices
            .into_iter()
            .map(|d| Device {
                name: d.name,
                created: d.created,
                last_seen: d.last_seen,
            })
            .collect(),
        pair_fails: pairing.total_fails,
        pair_disabled: pairing.disabled(),
        messages: count.map(|c| c.n).unwrap_or(0),
    })
}

// ---------------------------------------------------------------- messages

#[derive(Deserialize)]
struct MessageRow {
    id: i64,
    sender: String,
    reply_to: i64,
    body: String,
    choices: String,
    want: String,
    files: String,
    created: i64,
    answer: i64,
    closed: i64,
}

impl MessageRow {
    fn into_message(self) -> Message {
        Message {
            id: self.id,
            from: Sender::parse(&self.sender).unwrap_or(Sender::Claude),
            reply_to: self.reply_to,
            body: self.body,
            choices: serde_json::from_str(&self.choices).unwrap_or_default(),
            want: Want::parse(&self.want).unwrap_or_default(),
            files: serde_json::from_str(&self.files).unwrap_or_default(),
            created: self.created,
            answer: self.answer,
            closed: self.closed != 0,
        }
    }
}

async fn list_messages(req: &Request, env: &Env) -> Result<Response> {
    #[derive(Deserialize)]
    struct Q {
        after: Option<i64>,
    }
    let after = req.query::<Q>().ok().and_then(|q| q.after).unwrap_or(0).max(0);
    let rows: Vec<MessageRow> = db(env)?
        .prepare("SELECT * FROM messages WHERE id > ?1 ORDER BY id LIMIT ?2")
        .bind(&[num(after), num(PAGE as i64)])?
        .all()
        .await?
        .results()?;
    let list: Vec<Message> = rows.into_iter().map(MessageRow::into_message).collect();
    Response::from_json(&list)
}

async fn post_message(req: &mut Request, env: &Env, ctx: &Context, caller: &Caller) -> Result<Response> {
    let Ok(new) = req.json::<NewMessage>().await else {
        return json_error(400, "expected a message");
    };
    let from = caller.sender();
    if let Err(e) = new.check(from) {
        return json_error(400, &e);
    }
    let db = db(env)?;

    if new.reply_to != 0 {
        #[derive(Deserialize)]
        struct Target {
            sender: String,
        }
        let target: Option<Target> = db
            .prepare("SELECT sender FROM messages WHERE id = ?1")
            .bind(&[num(new.reply_to)])?
            .first(None)
            .await?;
        match target {
            None => return json_error(400, "reply_to: no such message"),
            Some(t) if t.sender == from.as_str() => {
                return json_error(400, "reply_to: cannot answer your own message")
            }
            Some(_) => {}
        }
    }

    let files = file_refs(&db, &new.files).await?;
    if files.len() != new.files.len() {
        return json_error(400, "unknown file id");
    }
    let body = new.body.trim_end().to_string();
    let choices: Vec<String> = new.choices.iter().map(|c| c.trim().to_string()).collect();
    let row: Option<MessageRow> = db
        .prepare(
            "INSERT INTO messages (sender, reply_to, body, choices, want, files, created) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) RETURNING *",
        )
        .bind(&[
            from.as_str().into(),
            num(new.reply_to),
            body.as_str().into(),
            serde_json::to_string(&choices)?.as_str().into(),
            new.want.as_str().into(),
            serde_json::to_string(&files)?.as_str().into(),
            num(now_ms()),
        ])?
        .first(None)
        .await?;
    let msg = row
        .ok_or_else(|| Error::RustError("insert returned no row".into()))?
        .into_message();
    if new.reply_to != 0 {
        db.prepare("UPDATE messages SET answer = ?1 WHERE id = ?2")
            .bind(&[num(msg.id), num(new.reply_to)])?
            .run()
            .await?;
    }
    if from == Sender::Claude {
        let title = if msg.want == Want::None { "Claude" } else { "Claude asks" };
        notify(env, ctx, title, &msg.body, msg.want != Want::None);
    }
    Response::from_json(&msg)
}

/// The stored files among `ids`, in the order asked for.
async fn file_refs(db: &D1Database, ids: &[String]) -> Result<Vec<FileRef>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    #[derive(Deserialize)]
    struct Row {
        id: String,
        name: String,
        mime: String,
        size: i64,
    }
    let marks: Vec<String> = (1..=ids.len()).map(|i| format!("?{i}")).collect();
    let args: Vec<JsValue> = ids.iter().map(|s| s.as_str().into()).collect();
    let rows: Vec<Row> = db
        .prepare(format!(
            "SELECT id, name, mime, size FROM files WHERE id IN ({})",
            marks.join(",")
        ))
        .bind(&args)?
        .all()
        .await?
        .results()?;
    Ok(ids
        .iter()
        .filter_map(|id| rows.iter().find(|r| &r.id == id))
        .map(|r| FileRef {
            id: r.id.clone(),
            name: r.name.clone(),
            mime: r.mime.clone(),
            size: r.size.max(0) as u64,
        })
        .collect())
}

async fn close(env: &Env, id: &str) -> Result<Response> {
    let Ok(id) = id.parse::<i64>() else {
        return json_error(400, "bad id");
    };
    let row: Option<MessageRow> = db(env)?
        .prepare("UPDATE messages SET closed = 1 WHERE id = ?1 AND sender = 'claude' RETURNING *")
        .bind(&[num(id)])?
        .first(None)
        .await?;
    match row {
        Some(r) => Response::from_json(&r.into_message()),
        None => json_error(404, "no such question"),
    }
}

async fn clear(env: &Env) -> Result<Response> {
    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let ids: Vec<Id> = db(env)?.prepare("SELECT id FROM files").all().await?.results()?;
    delete_files(env, ids.into_iter().map(|r| r.id).collect()).await?;
    db(env)?.prepare("DELETE FROM messages").run().await?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

// ---------------------------------------------------------------- files

fn object_key(id: &str) -> String {
    format!("f/{id}")
}

async fn upload(req: &mut Request, env: &Env) -> Result<Response> {
    let length: Option<u64> = req
        .headers()
        .get("Content-Length")?
        .and_then(|v| v.trim().parse().ok());
    let Some(length) = length else {
        return json_error(411, "Content-Length required");
    };
    if length == 0 {
        return json_error(400, "empty file");
    }
    if length > MAX_FILE_BYTES {
        return json_error(413, &format!("files are limited to {} MB", MAX_FILE_BYTES >> 20));
    }
    let raw_name = req.headers().get("X-File-Name")?.unwrap_or_default();
    let name = safe_file_name(&decode_header_name(&raw_name));
    let mime = {
        let given = safe_mime(&req.headers().get("Content-Type")?.unwrap_or_default());
        if given == "application/octet-stream" {
            safe_mime(mime_from_name(&name))
        } else {
            given
        }
    };
    let Some(stream) = req.inner().body() else {
        return json_error(400, "empty file");
    };

    let limits = Limits::from_env(env);
    if !reserve(env, "put", limits.uploads_per_day).await? {
        let msg = format!(
            "daily upload limit ({}) reached; it resets at 00:00 UTC",
            limits.uploads_per_day
        );
        return json_error(429, &msg);
    }
    // Two uploads racing past this check can overshoot by one file, which the
    // default cap leaves ample room for.
    if stored_bytes(env).await? + length as i64 > limits.storage_bytes {
        let msg = format!(
            "relay storage full ({} MB); clear old messages",
            limits.storage_bytes >> 20
        );
        return json_error(507, &msg);
    }

    // The row goes in before the object, so every stored object is counted
    // and found by the cleanup even if the put dies halfway. The runtime
    // holds the body to Content-Length, so that is its size.
    let id = random_hex(16)?;
    db(env)?
        .prepare("INSERT INTO files (id, name, mime, size, created) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&[
            id.as_str().into(),
            name.as_str().into(),
            mime.as_str().into(),
            num(length as i64),
            num(now_ms()),
        ])?
        .run()
        .await?;
    let put = env
        .bucket("FILES")?
        .put(object_key(&id), Data::ReadableStream(stream))
        .http_metadata(HttpMetadata {
            content_type: Some(mime.clone()),
            ..Default::default()
        })
        .execute()
        .await;
    if let Err(e) = put {
        db(env)?
            .prepare("DELETE FROM files WHERE id = ?1")
            .bind(&[id.as_str().into()])?
            .run()
            .await?;
        return Err(e);
    }
    Response::from_json(&FileRef {
        id,
        name,
        mime,
        size: length,
    })
}

async fn download(env: &Env, id: &str) -> Result<Response> {
    if !valid_file_id(id) {
        return json_error(404, "no such file");
    }
    let refs = file_refs(&db(env)?, &[id.to_string()]).await?;
    let Some(file) = refs.first() else {
        return json_error(404, "no such file");
    };
    let limit = Limits::from_env(env).downloads_per_day;
    if !reserve(env, "get", limit).await? {
        let msg = format!("daily download limit ({limit}) reached; it resets at 00:00 UTC");
        return json_error(429, &msg);
    }
    let Some(object) = env.bucket("FILES")?.get(object_key(id)).execute().await? else {
        return json_error(404, "file body missing");
    };
    let Some(body) = object.body() else {
        return json_error(404, "file body missing");
    };
    let headers = Headers::new();
    headers.set("Content-Type", &file.mime)?;
    headers.set("Content-Length", &object.size().to_string())?;
    headers.set(
        "Content-Disposition",
        &format!(
            "attachment; filename*=UTF-8''{}",
            rfc5987(&file.name)
        ),
    )?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("Cache-Control", "private, no-store")?;
    Ok(Response::from_body(body.response_body()?)?.with_headers(headers))
}

/// RFC 5987 percent-encoding for the download's file name.
fn rfc5987(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn delete_files(env: &Env, ids: Vec<String>) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let bucket = env.bucket("FILES")?;
    for chunk in ids.chunks(500) {
        let keys: Vec<String> = chunk.iter().map(|id| object_key(id)).collect();
        bucket.delete_multiple(keys).await?;
        let marks: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
        let args: Vec<JsValue> = chunk.iter().map(|s| s.as_str().into()).collect();
        db(env)?
            .prepare(format!("DELETE FROM files WHERE id IN ({})", marks.join(",")))
            .bind(&args)?
            .run()
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- upkeep

/// Daily: drop old messages, their files, unattached uploads and idle devices.
async fn cleanup(env: &Env) -> Result<()> {
    let now = now_ms();
    let old = now - KEEP_DAYS * DAY_MS;
    let db = db(env)?;
    db.prepare("DELETE FROM messages WHERE created < ?1")
        .bind(&[num(old)])?
        .run()
        .await?;

    // A file is kept while a surviving message names it, or while it is
    // fresh enough to still be attached.
    #[derive(Deserialize)]
    struct Id {
        id: String,
    }
    let doomed: Vec<Id> = db
        .prepare(
            "SELECT id FROM files WHERE created < ?1 AND NOT EXISTS \
             (SELECT 1 FROM messages WHERE messages.files LIKE '%' || files.id || '%')",
        )
        .bind(&[num(now - ORPHAN_MS)])?
        .all()
        .await?
        .results()?;
    delete_files(env, doomed.into_iter().map(|r| r.id).collect()).await?;

    db.prepare("DELETE FROM usage WHERE day < ?1")
        .bind(&[num(today() - USAGE_KEEP_DAYS)])?
        .run()
        .await?;

    db.prepare("DELETE FROM devices WHERE last_seen < ?1")
        .bind(&[num(now - TOKEN_DAYS * DAY_MS)])?
        .run()
        .await?;
    Ok(())
}

/// Push a notification through ntfy when `NTFY_URL` is set. The text is only
/// included with `NTFY_PREVIEW = "1"`, since a public ntfy topic is readable
/// by anyone who knows its name.
fn notify(env: &Env, ctx: &Context, title: &str, text: &str, question: bool) {
    let Some(url) = secret(env, "NTFY_URL").or_else(|| env.var("NTFY_URL").ok().map(|v| v.to_string()))
    else {
        return;
    };
    let preview = env
        .var("NTFY_PREVIEW")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false);
    let body = if preview {
        text.chars().take(300).collect::<String>()
    } else if question {
        "Open cld-phone to answer".to_string()
    } else {
        "Open cld-phone to read it".to_string()
    };
    let token = secret(env, "NTFY_TOKEN");
    let title = title.to_string();
    ctx.wait_until(async move {
        let send = async {
            let headers = Headers::new();
            headers.set("Title", &title)?;
            headers.set("Priority", if question { "high" } else { "default" })?;
            headers.set("Tags", "speech_balloon")?;
            if let Some(t) = token {
                headers.set("Authorization", &format!("Bearer {t}"))?;
            }
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(JsValue::from_str(&body)));
            Fetch::Request(Request::new_with_init(&url, &init)?).send().await?;
            Ok::<(), Error>(())
        };
        if let Err(e) = send.await {
            console_error!("ntfy: {e}");
        }
    });
}
