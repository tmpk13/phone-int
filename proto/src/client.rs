//! Blocking client for the relay API, used by `cldp` and the phone app.
//! Every call is one short request; waiting for an answer is the caller
//! polling [`Client::messages`].

use std::fmt;
use std::time::Duration;

use ureq::http::Response;
use ureq::{Agent, Body};

use crate::api::{
    ErrorBody, FileRef, Me, Message, NewMessage, PairRequest, PairResponse, Project, ProjectPatch,
    Status, MAX_FILE_BYTES,
};

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The relay answered with an error status.
    Status { code: u16, message: String },
    /// No usable answer: DNS, TLS, refused, timed out.
    Transport(String),
    /// An answer that did not parse.
    Decode(String),
}

impl Error {
    /// The token is wrong or has lapsed: the phone has to pair again.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Error::Status { code: 401, .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status { code, message } => write!(f, "{message} ({code})"),
            Error::Transport(e) => write!(f, "no connection: {e}"),
            Error::Decode(e) => write!(f, "bad answer: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Turn an error status into [`Error::Status`] with the relay's message.
fn checked(resp: std::result::Result<Response<Body>, ureq::Error>) -> Result<Response<Body>> {
    let mut resp = resp.map_err(|e| Error::Transport(e.to_string()))?;
    let code = resp.status().as_u16();
    if code < 400 {
        return Ok(resp);
    }
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    let message = serde_json::from_str::<ErrorBody>(&text)
        .map(|e| e.error)
        .unwrap_or_else(|_| {
            let t = text.trim();
            if t.is_empty() || t.len() > 200 {
                format!("HTTP {code}")
            } else {
                t.to_string()
            }
        });
    Err(Error::Status { code, message })
}

fn json<T: serde::de::DeserializeOwned>(mut resp: Response<Body>) -> Result<T> {
    resp.body_mut()
        .read_json()
        .map_err(|e| Error::Decode(e.to_string()))
}

/// Trim a base URL to `scheme://host[:port]` form without a trailing slash.
pub fn normalize_base(base: &str) -> String {
    let base = base.trim().trim_end_matches('/');
    if base.starts_with("http://") || base.starts_with("https://") {
        base.to_string()
    } else {
        format!("https://{base}")
    }
}

/// Exchange an authenticator code for a device token.
pub fn pair(base: &str, code: &str, name: &str) -> Result<PairResponse> {
    let url = format!("{}/api/pair", normalize_base(base));
    let req = PairRequest {
        code: code.trim().to_string(),
        name: name.to_string(),
    };
    json(checked(agent(Duration::from_secs(30)).post(&url).send_json(&req))?)
}

/// An authenticated connection to the relay.
#[derive(Clone)]
pub struct Client {
    base: String,
    auth: String,
    quick: Agent,
    bulk: Agent,
}

impl Client {
    pub fn new(base: &str, token: &str) -> Client {
        Client {
            base: normalize_base(base),
            auth: format!("Bearer {}", token.trim()),
            quick: agent(Duration::from_secs(30)),
            // Files can be tens of megabytes on a phone uplink.
            bulk: agent(Duration::from_secs(900)),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn get(&self, path: &str) -> Result<Response<Body>> {
        checked(
            self.quick
                .get(self.url(path))
                .header("Authorization", &self.auth)
                .call(),
        )
    }

    fn post_json(&self, path: &str, body: &impl serde::Serialize) -> Result<Response<Body>> {
        checked(
            self.quick
                .post(self.url(path))
                .header("Authorization", &self.auth)
                .send_json(body),
        )
    }

    fn post_empty(&self, path: &str) -> Result<Response<Body>> {
        checked(
            self.quick
                .post(self.url(path))
                .header("Authorization", &self.auth)
                .send_empty(),
        )
    }

    pub fn me(&self) -> Result<Me> {
        json(self.get("/api/me")?)
    }

    /// Messages with ids above `after`, oldest first, at most a page.
    pub fn messages(&self, after: i64) -> Result<Vec<Message>> {
        json(self.get(&format!("/api/messages?after={after}"))?)
    }

    /// Like [`Client::messages`], but only those in `project` (`""` for
    /// the ones without a project).
    pub fn project_messages(&self, after: i64, project: &str) -> Result<Vec<Message>> {
        json(self.get(&format!("/api/messages?after={after}&project={project}"))?)
    }

    /// Every project, latest activity first.
    pub fn projects(&self) -> Result<Vec<Project>> {
        json(self.get("/api/projects")?)
    }

    /// Change a project (made if missing). `name` must pass
    /// [`crate::api::valid_project`], which also keeps it URL safe.
    pub fn update_project(&self, name: &str, patch: &ProjectPatch) -> Result<Project> {
        json(self.post_json(&format!("/api/projects/{name}"), patch)?)
    }

    pub fn send(&self, msg: &NewMessage) -> Result<Message> {
        json(self.post_json("/api/messages", msg)?)
    }

    /// Mark a question as no longer needing an answer (host only).
    pub fn close(&self, id: i64) -> Result<Message> {
        json(self.post_empty(&format!("/api/messages/{id}/close"))?)
    }

    /// Delete every message and file.
    pub fn clear(&self) -> Result<()> {
        checked(
            self.quick
                .delete(self.url("/api/messages"))
                .header("Authorization", &self.auth)
                .call(),
        )
        .map(|_| ())
    }

    pub fn upload(&self, name: &str, mime: &str, bytes: &[u8]) -> Result<FileRef> {
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(Error::Status {
                code: 413,
                message: format!("{name} is over {} MB", MAX_FILE_BYTES >> 20),
            });
        }
        json(checked(
            self.bulk
                .post(self.url("/api/files"))
                .header("Authorization", &self.auth)
                .header("Content-Type", mime)
                .header("X-File-Name", header_name(name))
                .send(bytes),
        )?)
    }

    pub fn download(&self, id: &str) -> Result<Vec<u8>> {
        let mut resp = checked(
            self.bulk
                .get(self.url(&format!("/api/files/{id}")))
                .header("Authorization", &self.auth)
                .call(),
        )?;
        resp.body_mut()
            .with_config()
            .limit(MAX_FILE_BYTES + 1024)
            .read_to_vec()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Paired devices and pairing counters (host only).
    pub fn status(&self) -> Result<Status> {
        json(self.get("/api/status")?)
    }

    /// Turn pairing back on after too many failures (host only).
    pub fn reset_pairing(&self) -> Result<Status> {
        json(self.post_empty("/api/pair/reset")?)
    }

    /// Drop this device's token (phone only).
    pub fn logout(&self) -> Result<()> {
        self.post_empty("/api/logout").map(|_| ())
    }
}

/// Percent-encode a file name for the `X-File-Name` header, which only
/// carries visible ASCII. The worker reverses it with [`decode_header_name`].
pub fn header_name(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b" ._-()[]+,".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub use crate::api::decode_header_name;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_name_round_trips_any_name() {
        for name in ["photo 1.jpg", "r\u{e9}sum\u{e9}.pdf", "a%b\r\nc", "100%"] {
            let enc = header_name(name);
            assert!(enc.bytes().all(|b| (0x20..0x7f).contains(&b)), "{enc}");
            assert_eq!(decode_header_name(&enc), name);
        }
    }

    #[test]
    fn base_urls_get_a_scheme_and_lose_the_slash() {
        assert_eq!(normalize_base("relay.example.dev/"), "https://relay.example.dev");
        assert_eq!(normalize_base(" http://127.0.0.1:8787 "), "http://127.0.0.1:8787");
    }

    #[test]
    fn status_errors_carry_the_relay_message() {
        let e = Error::Status {
            code: 401,
            message: "bad token".into(),
        };
        assert!(e.is_unauthorized());
        assert_eq!(e.to_string(), "bad token (401)");
    }
}
