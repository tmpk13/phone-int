//! JSON bodies of the relay API, and the limits the worker enforces.
//!
//! | Method | Path | Who | Body / answer |
//! | --- | --- | --- | --- |
//! | POST | `/api/pair` | anyone | [`PairRequest`] -> [`PairResponse`] |
//! | GET | `/api/me` | host, phone | [`Me`] |
//! | GET | `/api/messages?after=N[&project=P]` | host, phone | `Vec<`[`Message`]`>` (ids above N, oldest first) |
//! | POST | `/api/messages` | host, phone | [`NewMessage`] -> [`Message`] |
//! | GET | `/api/projects` | host, phone | `Vec<`[`Project`]`>` (latest activity first) |
//! | POST | `/api/projects/<name>` | host, phone | [`ProjectPatch`] -> [`Project`] |
//! | POST | `/api/messages/<id>/close` | host | the closed [`Message`] |
//! | DELETE | `/api/messages` | host, phone | clears every message and file |
//! | POST | `/api/files` | host, phone | raw bytes, `x-file-name` header -> [`FileRef`] |
//! | GET | `/api/files/<id>` | host, phone | raw bytes |
//! | GET | `/api/status` | host | [`Status`] |
//! | POST | `/api/pair/reset` | host | [`Status`] (pairing back on) |
//! | POST | `/api/logout` | phone | drops the calling device's token |
//!
//! The host authenticates with the `HOST_TOKEN` secret, a phone with the
//! token `/api/pair` gave it, both as `Authorization: Bearer <token>`.
//! Errors answer with a status code and an [`ErrorBody`].
//!
//! Every message belongs to a project (a repo name such as `cld-phone`), or
//! to none (`""`, shown as "General"). Posting a message creates its project
//! and keeps the project's state current; see [`ProjectState`].

use serde::{Deserialize, Serialize};

/// Longest message text, in bytes.
pub const MAX_BODY: usize = 20_000;
/// Most answer buttons on one question.
pub const MAX_CHOICES: usize = 12;
/// Longest answer button label, in bytes.
pub const MAX_CHOICE: usize = 200;
/// Most files on one message.
pub const MAX_FILES: usize = 20;
/// Largest single file.
pub const MAX_FILE_BYTES: u64 = 30 * 1024 * 1024;
/// Longest file or device name, in bytes.
pub const MAX_NAME: usize = 120;
/// Longest project name, in bytes (see [`valid_project`]).
pub const MAX_PROJECT: usize = 64;
/// Longest progress update (a Claude message that asks nothing), in
/// characters: updates are read as one line in a feed on a phone. Details
/// go in an attached file.
pub const MAX_UPDATE: usize = 200;
/// Longest project description, in characters.
pub const MAX_ABOUT: usize = 200;
/// Most items on a project's todo list.
pub const MAX_TODOS: usize = 30;
/// Longest todo item, in characters.
pub const MAX_TODO: usize = 120;
/// Messages and files older than this are deleted by the daily cleanup.
pub const KEEP_DAYS: i64 = 14;
/// A device token lasts this long after its last use.
pub const TOKEN_DAYS: i64 = 180;
/// Most messages one `GET /api/messages` returns.
pub const PAGE: usize = 200;

// The relay's R2 budget. R2's free tier allows 10 GB stored, 1 million
// writes (class A) and 10 million reads (class B) a month, shared by every
// bucket on the account; these defaults keep this relay to a small part of
// it. Each can be changed with a plain variable of the same name on the
// worker. A day is a UTC day, so a month is at most 31 of them.

/// `STORAGE_LIMIT_MB`: total size of stored files.
pub const DEFAULT_STORAGE_MB: i64 = 2048;
/// `UPLOADS_PER_DAY`: file uploads (one R2 put each).
pub const DEFAULT_UPLOADS_PER_DAY: i64 = 1000;
/// `DOWNLOADS_PER_DAY`: file downloads (one R2 get each).
pub const DEFAULT_DOWNLOADS_PER_DAY: i64 = 10_000;

/// A limit from an optional variable: a positive whole number, or `default`.
pub fn limit_from(var: Option<&str>, default: i64) -> i64 {
    var.and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

/// Who sent a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sender {
    Claude,
    Phone,
}

impl Sender {
    pub fn as_str(self) -> &'static str {
        match self {
            Sender::Claude => "claude",
            Sender::Phone => "phone",
        }
    }

    pub fn parse(text: &str) -> Option<Sender> {
        match text {
            "claude" => Some(Sender::Claude),
            "phone" => Some(Sender::Phone),
            _ => None,
        }
    }
}

/// What kind of answer Claude is after. The app uses it to point at the
/// right button; any answer is accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Want {
    /// A typed answer (or a tap on one of the choices).
    #[default]
    Text,
    /// A camera photo.
    Photo,
    /// A file or a picture from the phone.
    File,
    /// Nothing: a notice, not a question.
    None,
}

impl Want {
    pub fn as_str(self) -> &'static str {
        match self {
            Want::Text => "text",
            Want::Photo => "photo",
            Want::File => "file",
            Want::None => "none",
        }
    }

    pub fn parse(text: &str) -> Option<Want> {
        match text {
            "text" => Some(Want::Text),
            "photo" => Some(Want::Photo),
            "file" => Some(Want::File),
            "none" => Some(Want::None),
            _ => None,
        }
    }
}

/// A file stored on the relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// 32 lowercase hex characters.
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
}

impl FileRef {
    pub fn is_image(&self) -> bool {
        self.mime.starts_with("image/")
    }
}

/// One message in either direction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: i64,
    /// The project it belongs to; `""` for none. A reply always takes its
    /// question's project.
    #[serde(default)]
    pub project: String,
    pub from: Sender,
    /// The message this answers, or 0.
    pub reply_to: i64,
    pub body: String,
    /// Answer buttons (Claude's questions only).
    pub choices: Vec<String>,
    pub want: Want,
    pub files: Vec<FileRef>,
    /// Unix milliseconds.
    pub created: i64,
    /// The latest reply to this message, or 0.
    pub answer: i64,
    /// Claude no longer needs an answer.
    pub closed: bool,
    /// Claude says the project's work is finished.
    #[serde(default)]
    pub done: bool,
}

impl Message {
    /// A question still waiting on the phone.
    pub fn is_open_question(&self) -> bool {
        self.from == Sender::Claude && self.want != Want::None && self.answer == 0 && !self.closed
    }

    /// Worth a notification: an open question, or the work being finished.
    /// Progress updates only land in the feed.
    pub fn is_alert(&self) -> bool {
        self.is_open_question() || (self.from == Sender::Claude && self.done)
    }
}

/// `POST /api/messages`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMessage {
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub choices: Vec<String>,
    #[serde(default)]
    pub want: Want,
    /// Ids from `POST /api/files`.
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub reply_to: i64,
    /// `""` for none; ignored on a reply, which joins its question's project.
    #[serde(default)]
    pub project: String,
    /// The project's work is finished (Claude's updates only).
    #[serde(default)]
    pub done: bool,
}

impl NewMessage {
    /// Problems the worker refuses with 400, for a message from `from`.
    pub fn check(&self, from: Sender) -> Result<(), String> {
        if self.body.trim().is_empty() && self.files.is_empty() {
            return Err("empty message".into());
        }
        if self.body.len() > MAX_BODY {
            return Err(format!("text over {MAX_BODY} bytes"));
        }
        if !self.project.is_empty() && !valid_project(&self.project) {
            return Err(format!("bad project name {:?}", self.project));
        }
        let update = from == Sender::Claude && self.want == Want::None;
        let chars = self.body.trim().chars().count();
        if update && chars > MAX_UPDATE {
            return Err(format!(
                "an update is at most {MAX_UPDATE} characters ({chars} given); \
                 keep it to one line and attach details as a file"
            ));
        }
        if self.done && !update {
            return Err("only Claude's updates mark a project done".into());
        }
        if self.files.len() > MAX_FILES {
            return Err(format!("more than {MAX_FILES} files"));
        }
        if let Some(bad) = self.files.iter().find(|id| !valid_file_id(id)) {
            return Err(format!("bad file id {bad:?}"));
        }
        if self.reply_to < 0 {
            return Err("bad reply_to".into());
        }
        if from == Sender::Phone && (!self.choices.is_empty() || self.want != Want::Text) {
            return Err("only Claude sets choices or want".into());
        }
        if self.choices.len() > MAX_CHOICES {
            return Err(format!("more than {MAX_CHOICES} choices"));
        }
        if self
            .choices
            .iter()
            .any(|c| c.trim().is_empty() || c.len() > MAX_CHOICE)
        {
            return Err(format!("choices must be 1 to {MAX_CHOICE} bytes"));
        }
        Ok(())
    }
}

/// Where a project stands. Claude's updates move it between active and
/// done; only the user archives it, and any new message brings it back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    #[default]
    Active,
    /// Claude's last update said the work is finished.
    Done,
    /// Off the main feed until something new happens in it.
    Archived,
}

impl ProjectState {
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectState::Active => "active",
            ProjectState::Done => "done",
            ProjectState::Archived => "archived",
        }
    }

    pub fn parse(text: &str) -> Option<ProjectState> {
        match text {
            "active" => Some(ProjectState::Active),
            "done" => Some(ProjectState::Done),
            "archived" => Some(ProjectState::Archived),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TodoState {
    #[default]
    Todo,
    Doing,
    Done,
}

/// One item on a project's todo list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Todo {
    pub text: String,
    #[serde(default)]
    pub state: TodoState,
}

/// A project as `GET /api/projects` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    /// One line on what the project is.
    pub about: String,
    pub todos: Vec<Todo>,
    pub state: ProjectState,
    /// Unix milliseconds.
    pub created: i64,
    /// The latest message or change, unix milliseconds.
    pub updated: i64,
}

impl Project {
    /// (done, total) todo items.
    pub fn progress(&self) -> (usize, usize) {
        let done = self.todos.iter().filter(|t| t.state == TodoState::Done).count();
        (done, self.todos.len())
    }
}

/// `POST /api/projects/<name>`: the fields to change; the project is made
/// if it does not exist. A phone may only set the state, to active or
/// archived.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Replaces the whole list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub todos: Option<Vec<Todo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ProjectState>,
}

impl ProjectPatch {
    /// Problems the worker refuses with 400, for a change from `from`.
    pub fn check(&self, from: Sender) -> Result<(), String> {
        if from == Sender::Phone {
            if self.about.is_some() || self.todos.is_some() {
                return Err("a phone only archives or restores projects".into());
            }
            if self.state == Some(ProjectState::Done) {
                return Err("only Claude marks a project done".into());
            }
        }
        if let Some(about) = &self.about {
            if about.trim().chars().count() > MAX_ABOUT {
                return Err(format!("about is at most {MAX_ABOUT} characters"));
            }
        }
        if let Some(todos) = &self.todos {
            if todos.len() > MAX_TODOS {
                return Err(format!("at most {MAX_TODOS} todo items"));
            }
            if todos
                .iter()
                .any(|t| t.text.trim().is_empty() || t.text.trim().chars().count() > MAX_TODO)
            {
                return Err(format!("todo items are 1 to {MAX_TODO} characters"));
            }
        }
        Ok(())
    }
}

/// A project name: 1 to [`MAX_PROJECT`] ASCII letters, digits, `.`, `_` or
/// `-`, starting with a letter or digit. Safe in a URL path and a file name.
pub fn valid_project(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PROJECT
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}

/// The nearest valid project name to `raw` (a directory name, say): other
/// characters become `-`, the front is trimmed to a letter or digit, and the
/// result is cut to [`MAX_PROJECT`]. `None` when nothing usable is left.
pub fn project_name(raw: &str) -> Option<String> {
    let mapped: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '-' })
        .collect();
    let trimmed = mapped.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    let cut: String = trimmed.chars().take(MAX_PROJECT).collect();
    let cut = cut.trim_end_matches('-').to_string();
    valid_project(&cut).then_some(cut)
}

/// `POST /api/pair`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// The 6 digits from the authenticator app.
    pub code: String,
    /// Shown by `cldp status`.
    pub name: String,
}

/// The device token and when it lapses if unused (unix milliseconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResponse {
    pub token: String,
    pub expires: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Host,
    Phone,
}

/// `GET /api/me`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    pub role: Role,
    pub name: String,
}

/// A paired phone, as `GET /api/status` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub created: i64,
    pub last_seen: i64,
}

/// `GET /api/status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub devices: Vec<Device>,
    /// Failed pairing attempts since the last success.
    pub pair_fails: i64,
    /// Pairing is off until `POST /api/pair/reset`.
    pub pair_disabled: bool,
    pub messages: i64,
    /// Bytes of stored files, and the cap.
    #[serde(default)]
    pub storage_bytes: i64,
    #[serde(default)]
    pub storage_limit: i64,
    /// File uploads and downloads so far this UTC day, and the caps.
    #[serde(default)]
    pub uploads_today: i64,
    #[serde(default)]
    pub uploads_limit: i64,
    #[serde(default)]
    pub downloads_today: i64,
    #[serde(default)]
    pub downloads_limit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// File ids are 16 random bytes in lowercase hex.
pub fn valid_file_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A file name that is safe to store, show and join onto a directory: the
/// last path component only, no control characters, no leading dots, at most
/// [`MAX_NAME`] bytes (cut on a character boundary, keeping the extension).
pub fn safe_file_name(raw: &str) -> String {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .map(|c| if c.is_control() || ":*?\"<>|".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim().to_string();
    if cleaned.is_empty() {
        return "file".into();
    }
    if cleaned.len() <= MAX_NAME {
        return cleaned;
    }
    let (stem, ext) = match cleaned.rfind('.') {
        Some(dot) if cleaned.len() - dot <= 10 => cleaned.split_at(dot),
        _ => (cleaned.as_str(), ""),
    };
    let mut cut = MAX_NAME - ext.len();
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{ext}", &stem[..cut])
}

/// A best guess at a MIME type from a file name, for uploads that do not
/// carry one.
pub fn mime_from_name(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" | "csv" | "toml" | "rs" | "py" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        _ => "application/octet-stream",
    }
}

/// Reverse the client's percent-encoding of the `X-File-Name` header. Bad
/// escapes are kept as they are; invalid UTF-8 is replaced.
pub fn decode_header_name(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A MIME type the relay will store: `type/subtype` from a safe alphabet,
/// otherwise `application/octet-stream`. Stops a client from making the
/// download answer with `text/html`.
pub fn safe_mime(raw: &str) -> String {
    let base = raw.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let ok = base.len() <= 100
        && base.split('/').count() == 2
        && base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/.+-_".contains(&b));
    if !ok || base.contains("html") || base.contains("javascript") || base == "image/svg+xml" {
        return "application/octet-stream".into();
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(body: &str) -> NewMessage {
        NewMessage {
            body: body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn json_shape_is_stable() {
        let m = Message {
            id: 3,
            project: "bench".into(),
            from: Sender::Claude,
            reply_to: 0,
            body: "Which rev?".into(),
            choices: vec!["A".into(), "B".into()],
            want: Want::Photo,
            files: vec![],
            created: 1,
            answer: 0,
            closed: false,
            done: false,
        };
        let text = serde_json::to_string(&m).unwrap();
        assert_eq!(
            text,
            r#"{"id":3,"project":"bench","from":"claude","reply_to":0,"body":"Which rev?","choices":["A","B"],"want":"photo","files":[],"created":1,"answer":0,"closed":false,"done":false}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&text).unwrap(), m);
        assert!(m.is_open_question());
    }

    #[test]
    fn messages_from_a_relay_without_projects_still_parse() {
        let old = r#"{"id":3,"from":"phone","reply_to":0,"body":"hi","choices":[],"want":"text","files":[],"created":1,"answer":0,"closed":false}"#;
        let m: Message = serde_json::from_str(old).unwrap();
        assert_eq!((m.project.as_str(), m.done), ("", false));
    }

    #[test]
    fn new_message_defaults_every_field() {
        let m: NewMessage = serde_json::from_str(r#"{"body":"hi"}"#).unwrap();
        assert_eq!(m, msg("hi"));
    }

    #[test]
    fn checks_refuse_what_the_worker_refuses() {
        assert!(msg("hi").check(Sender::Phone).is_ok());
        assert!(msg("  ").check(Sender::Phone).is_err());
        assert!(msg(&"x".repeat(MAX_BODY + 1)).check(Sender::Claude).is_err());

        let files_only = NewMessage {
            files: vec!["0123456789abcdef0123456789abcdef".into()],
            ..Default::default()
        };
        assert!(files_only.check(Sender::Phone).is_ok());
        let bad_file = NewMessage {
            files: vec!["../etc/passwd".into()],
            ..msg("x")
        };
        assert!(bad_file.check(Sender::Phone).is_err());

        let choices = NewMessage {
            choices: vec!["yes".into(), "no".into()],
            ..msg("ok?")
        };
        assert!(choices.check(Sender::Claude).is_ok());
        assert!(choices.check(Sender::Phone).is_err(), "phones send no choices");
        let blank_choice = NewMessage {
            choices: vec![" ".into()],
            ..msg("ok?")
        };
        assert!(blank_choice.check(Sender::Claude).is_err());
        let want = NewMessage {
            want: Want::Photo,
            ..msg("x")
        };
        assert!(want.check(Sender::Phone).is_err());
    }

    #[test]
    fn notices_and_answered_or_closed_questions_are_not_open() {
        let base = Message {
            id: 1,
            project: String::new(),
            from: Sender::Claude,
            reply_to: 0,
            body: "x".into(),
            choices: vec![],
            want: Want::Text,
            files: vec![],
            created: 0,
            answer: 0,
            closed: false,
            done: false,
        };
        assert!(base.is_open_question());
        assert!(!Message { want: Want::None, ..base.clone() }.is_open_question());
        assert!(!Message { answer: 2, ..base.clone() }.is_open_question());
        assert!(!Message { closed: true, ..base.clone() }.is_open_question());
        assert!(!Message { from: Sender::Phone, ..base.clone() }.is_open_question());

        let update = Message { want: Want::None, ..base.clone() };
        assert!(!update.is_alert(), "progress updates only go to the feed");
        assert!(Message { done: true, ..update }.is_alert());
        assert!(base.is_alert());
    }

    #[test]
    fn updates_are_one_short_line() {
        let update = |body: &str| NewMessage {
            want: Want::None,
            ..msg(body)
        };
        assert!(update(&"x".repeat(MAX_UPDATE)).check(Sender::Claude).is_ok());
        let long = update(&"x".repeat(MAX_UPDATE + 1)).check(Sender::Claude).unwrap_err();
        assert!(long.contains("attach details"), "{long}");
        // Counted in characters, so non-ASCII text gets the same room.
        assert!(update(&"\u{e9}".repeat(MAX_UPDATE)).check(Sender::Claude).is_ok());
        // Questions and the phone's messages keep the full length.
        assert!(msg(&"x".repeat(5000)).check(Sender::Claude).is_ok());
        assert!(msg(&"x".repeat(5000)).check(Sender::Phone).is_ok());
    }

    #[test]
    fn only_claude_updates_mark_done() {
        let done = NewMessage {
            want: Want::None,
            done: true,
            ..msg("Shipped")
        };
        assert!(done.check(Sender::Claude).is_ok());
        let question = NewMessage {
            want: Want::Text,
            ..done.clone()
        };
        assert!(question.check(Sender::Claude).is_err());
        let phone = NewMessage {
            want: Want::Text,
            ..done
        };
        assert!(phone.check(Sender::Phone).is_err());
    }

    #[test]
    fn project_names_are_url_and_file_safe() {
        for good in ["cld-phone", "AT86RF215", "v1.2_test", "a"] {
            assert!(valid_project(good), "{good}");
        }
        for bad in ["", ".", "..", "-x", "a/b", "a b", "\u{e9}t\u{e9}", &"x".repeat(MAX_PROJECT + 1)] {
            assert!(!valid_project(bad), "{bad:?}");
        }
        let bad = NewMessage {
            project: "../x".into(),
            ..msg("hi")
        };
        assert!(bad.check(Sender::Claude).is_err());
        assert!(msg("hi").check(Sender::Claude).is_ok(), "no project is fine");
    }

    #[test]
    fn project_names_from_directory_names() {
        assert_eq!(project_name("cld-phone").as_deref(), Some("cld-phone"));
        assert_eq!(project_name("My Project (old)").as_deref(), Some("My-Project--old"));
        assert_eq!(project_name(".hidden").as_deref(), Some("hidden"));
        assert_eq!(project_name("caf\u{e9}").as_deref(), Some("caf"));
        assert_eq!(project_name("/").as_deref(), None);
        assert_eq!(project_name(&"y".repeat(100)).map(|n| n.len()), Some(MAX_PROJECT));
    }

    #[test]
    fn project_patches_by_role() {
        let todos = ProjectPatch {
            todos: Some(vec![Todo {
                text: "Parse".into(),
                state: TodoState::Doing,
            }]),
            ..Default::default()
        };
        assert!(todos.check(Sender::Claude).is_ok());
        assert!(todos.check(Sender::Phone).is_err(), "the phone does not edit plans");
        let archive = ProjectPatch {
            state: Some(ProjectState::Archived),
            ..Default::default()
        };
        assert!(archive.check(Sender::Phone).is_ok());
        let done = ProjectPatch {
            state: Some(ProjectState::Done),
            ..Default::default()
        };
        assert!(done.check(Sender::Phone).is_err());
        let blank = ProjectPatch {
            todos: Some(vec![Todo {
                text: " ".into(),
                state: TodoState::Todo,
            }]),
            ..Default::default()
        };
        assert!(blank.check(Sender::Claude).is_err());
        let many = ProjectPatch {
            todos: Some(vec![
                Todo {
                    text: "x".into(),
                    state: TodoState::Todo
                };
                MAX_TODOS + 1
            ]),
            ..Default::default()
        };
        assert!(many.check(Sender::Claude).is_err());
        // Absent fields stay out of the JSON, so they are left alone.
        assert_eq!(serde_json::to_string(&archive).unwrap(), r#"{"state":"archived"}"#);
    }

    #[test]
    fn limits_take_positive_numbers_only() {
        assert_eq!(limit_from(None, 7), 7);
        assert_eq!(limit_from(Some(" 500 "), 7), 500);
        for bad in ["0", "-3", "lots", ""] {
            assert_eq!(limit_from(Some(bad), 7), 7, "{bad:?}");
        }
    }

    #[test]
    fn status_from_an_older_relay_still_parses() {
        let s: Status = serde_json::from_str(
            r#"{"devices":[],"pair_fails":0,"pair_disabled":false,"messages":3}"#,
        )
        .unwrap();
        assert_eq!((s.messages, s.storage_limit), (3, 0));
    }

    #[test]
    fn file_ids_are_32_lower_hex() {
        assert!(valid_file_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_file_id("0123456789ABCDEF0123456789abcdef"));
        assert!(!valid_file_id("0123456789abcdef"));
    }

    #[test]
    fn safe_file_name_keeps_one_harmless_component() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("C:\\Users\\me\\photo.jpg"), "photo.jpg");
        assert_eq!(safe_file_name(".bashrc"), "bashrc");
        assert_eq!(safe_file_name("a\nb\u{7}.txt"), "a_b_.txt");
        assert_eq!(safe_file_name(""), "file");
        assert_eq!(safe_file_name("dir/"), "file");
        assert_eq!(safe_file_name(".."), "file");
        let long = format!("{}.jpeg", "\u{e9}".repeat(200));
        let cut = safe_file_name(&long);
        assert!(cut.len() <= MAX_NAME && cut.ends_with(".jpeg"), "{cut}");
    }

    #[test]
    fn mime_guesses_and_sanitizing() {
        assert_eq!(mime_from_name("IMG_1.JPG"), "image/jpeg");
        assert_eq!(mime_from_name("noext"), "application/octet-stream");
        assert_eq!(safe_mime("image/jpeg"), "image/jpeg");
        assert_eq!(safe_mime("Image/PNG; charset=x"), "image/png");
        assert_eq!(safe_mime("text/html"), "application/octet-stream");
        assert_eq!(safe_mime("image/svg+xml"), "application/octet-stream");
        assert_eq!(safe_mime("garbage"), "application/octet-stream");
    }
}
