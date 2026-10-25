//! JSON bodies of the relay API, and the limits the worker enforces.
//!
//! | Method | Path | Who | Body / answer |
//! | --- | --- | --- | --- |
//! | POST | `/api/pair` | anyone | [`PairRequest`] -> [`PairResponse`] |
//! | GET | `/api/me` | host, phone | [`Me`] |
//! | GET | `/api/messages?after=N` | host, phone | `Vec<`[`Message`]`>` (ids above N, oldest first) |
//! | POST | `/api/messages` | host, phone | [`NewMessage`] -> [`Message`] |
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
/// Messages and files older than this are deleted by the daily cleanup.
pub const KEEP_DAYS: i64 = 14;
/// A device token lasts this long after its last use.
pub const TOKEN_DAYS: i64 = 180;
/// Most messages one `GET /api/messages` returns.
pub const PAGE: usize = 200;

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
}

impl Message {
    /// A question still waiting on the phone.
    pub fn is_open_question(&self) -> bool {
        self.from == Sender::Claude && self.want != Want::None && self.answer == 0 && !self.closed
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
            from: Sender::Claude,
            reply_to: 0,
            body: "Which rev?".into(),
            choices: vec!["A".into(), "B".into()],
            want: Want::Photo,
            files: vec![],
            created: 1,
            answer: 0,
            closed: false,
        };
        let text = serde_json::to_string(&m).unwrap();
        assert_eq!(
            text,
            r#"{"id":3,"from":"claude","reply_to":0,"body":"Which rev?","choices":["A","B"],"want":"photo","files":[],"created":1,"answer":0,"closed":false}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&text).unwrap(), m);
        assert!(m.is_open_question());
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
            from: Sender::Claude,
            reply_to: 0,
            body: "x".into(),
            choices: vec![],
            want: Want::Text,
            files: vec![],
            created: 0,
            answer: 0,
            closed: false,
        };
        assert!(base.is_open_question());
        assert!(!Message { want: Want::None, ..base.clone() }.is_open_question());
        assert!(!Message { answer: 2, ..base.clone() }.is_open_question());
        assert!(!Message { closed: true, ..base.clone() }.is_open_question());
        assert!(!Message { from: Sender::Phone, ..base }.is_open_question());
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
