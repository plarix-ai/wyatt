//! Append-only, hash-chained, signed audit log.
//!
//! Each line is one JSON record. `hash` is SHA-256 over the previous record's
//! hash and this record's canonical JSON (sorted keys, without `hash` and
//! `sig`). `sig` is an Ed25519 signature over `hash`. Editing, dropping or
//! reordering a record breaks the chain at that point, and forging a new
//! chain needs the signing key, which only the daemon's user can read.
//!
//! The chain cannot show that records were cut from the end. Ship the head
//! (`wyatt audit verify` prints it) to another system if that matters.
//!
//! Only the daemon writes the log; MCP gateways and the Claude Code hook send
//! their events to it with the `notice` op. Each append still holds an
//! exclusive `flock` while it reads the head from the end of the file and
//! writes its line, so a second daemon pointed at the same state directory
//! by mistake cannot fork the chain.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::clock;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct Audit {
    path: PathBuf,
    file: File,
    key: SigningKey,
}

struct Lock<'a>(&'a File);

impl<'a> Lock<'a> {
    fn exclusive(f: &'a File) -> io::Result<Lock<'a>> {
        // SAFETY: flock on a valid fd owned by `f`, which outlives the guard.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(f))
    }
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        // SAFETY: see `exclusive`.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn load_or_create_key(dir: &Path) -> io::Result<SigningKey> {
    let path = dir.join("audit.key");
    let key = match fs::read(&path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} is not a 32-byte key", path.display()))
            })?;
            SigningKey::from_bytes(&seed)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| io::Error::other(e.to_string()))?;
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
            f.write_all(&seed)?;
            f.sync_all()?;
            SigningKey::from_bytes(&seed)
        }
        Err(e) => return Err(e),
    };
    let public = format!("{}\n", hex::encode(key.verifying_key().to_bytes()));
    if fs::read_to_string(dir.join("audit.pub")).ok().as_deref() != Some(public.as_str()) {
        fs::write(dir.join("audit.pub"), public)?;
    }
    Ok(key)
}

/// Reads the last complete line of the file, scanning backwards in blocks.
fn last_line(f: &File) -> io::Result<Option<String>> {
    let mut f = f;
    let len = f.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    let mut end = len;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let start = end.saturating_sub(4096);
        let mut chunk = vec![0u8; (end - start) as usize];
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        if let Some(i) = body.iter().rposition(|b| *b == b'\n') {
            return Ok(Some(String::from_utf8_lossy(&body[i + 1..]).into_owned()));
        }
        if start == 0 {
            return Ok(Some(String::from_utf8_lossy(body).into_owned()));
        }
        end = start;
    }
}

pub fn chain_hash(prev: &str, rec: &Map<String, Value>) -> String {
    let mut body = rec.clone();
    body.remove("hash");
    body.remove("sig");
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(serde_json::to_string(&body).expect("JSON map serialises").as_bytes());
    hex::encode(h.finalize())
}

impl Audit {
    pub fn open(dir: &Path) -> io::Result<Audit> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let key = load_or_create_key(dir)?;
        let path = dir.join("audit.jsonl");
        let file = OpenOptions::new().create(true).append(true).read(true).mode(0o600).open(&path)?;
        Ok(Audit { path, file, key })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Appends one record of `kind` and returns its sequence number.
    pub fn append(&self, kind: &str, mut rec: Map<String, Value>) -> io::Result<u64> {
        let _lock = Lock::exclusive(&self.file)?;
        let (seq, prev) = match last_line(&self.file)? {
            None => (0, GENESIS.to_string()),
            Some(line) => {
                let head: Value = serde_json::from_str(&line).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("audit head is not valid JSON ({e}); run `wyatt audit verify`"),
                    )
                })?;
                let seq = head["seq"].as_u64().ok_or_else(|| io::Error::other("audit head has no seq"))?;
                let hash = head["hash"].as_str().ok_or_else(|| io::Error::other("audit head has no hash"))?;
                (seq + 1, hash.to_string())
            }
        };
        rec.insert("seq".into(), seq.into());
        rec.insert("ts".into(), clock::rfc3339(clock::now_ms()).into());
        rec.insert("kind".into(), kind.into());
        rec.insert("prev".into(), prev.clone().into());
        let hash = chain_hash(&prev, &rec);
        let sig = self.key.sign(hash.as_bytes());
        rec.insert("hash".into(), hash.into());
        rec.insert("sig".into(), hex::encode(sig.to_bytes()).into());
        let mut line = serde_json::to_string(&rec)?;
        line.push('\n');
        (&self.file).write_all(line.as_bytes())?;
        Ok(seq)
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub records: u64,
    pub head: Option<(u64, String)>,
    pub problems: Vec<String>,
}

pub fn read_public_key(s: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] =
        hex::decode(s.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("public key must be 64 hex characters")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())
}

/// Checks sequence numbers, links, hashes and signatures of every record.
pub fn verify(path: &Path, key: &VerifyingKey) -> io::Result<Report> {
    let mut r = Report::default();
    let mut prev = GENESIS.to_string();
    for (i, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        let n = i + 1;
        let Ok(Value::Object(rec)) = serde_json::from_str::<Value>(&line) else {
            r.problems.push(format!("line {n}: not a JSON object"));
            continue;
        };
        let seq = rec.get("seq").and_then(Value::as_u64);
        let hash = rec.get("hash").and_then(Value::as_str).unwrap_or_default().to_string();
        if seq != Some(r.records) {
            r.problems.push(format!("line {n}: seq {seq:?}, expected {} (record missing or reordered)", r.records));
        }
        if rec.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            r.problems.push(format!("line {n}: prev does not match the hash of the record before it"));
        }
        let want = chain_hash(rec.get("prev").and_then(Value::as_str).unwrap_or_default(), &rec);
        if want != hash {
            r.problems.push(format!("line {n}: content does not match its hash (record edited)"));
        }
        let sig = rec
            .get("sig")
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .map(|b| Signature::from_bytes(&b));
        match sig {
            Some(sig) if key.verify_strict(hash.as_bytes(), &sig).is_ok() => {}
            _ => r.problems.push(format!("line {n}: bad signature")),
        }
        r.records = seq.unwrap_or(r.records) + 1;
        r.head = Some((r.records - 1, hash.clone()));
        prev = hash;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wyatt-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn rec(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = tmp("chain");
        let a = Audit::open(&dir).unwrap();
        let b = Audit::open(&dir).unwrap(); // a second process on the same log
        for i in 0..5 {
            let w = if i % 2 == 0 { &a } else { &b };
            assert_eq!(w.append("call", rec(serde_json::json!({"tool": "read", "i": i}))).unwrap(), i);
        }
        let key = read_public_key(&fs::read_to_string(dir.join("audit.pub")).unwrap()).unwrap();
        let ok = verify(a.path(), &key).unwrap();
        assert!(ok.problems.is_empty(), "{:?}", ok.problems);
        assert_eq!(ok.records, 5);

        let text = fs::read_to_string(a.path()).unwrap();
        let edited = text.replacen("\"i\":2", "\"i\":9", 1);
        fs::write(a.path(), &edited).unwrap();
        let bad = verify(a.path(), &key).unwrap();
        assert!(bad.problems.iter().any(|p| p.starts_with("line 3: content")), "{:?}", bad.problems);

        let dropped: String =
            text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| format!("{l}\n")).collect();
        fs::write(a.path(), dropped).unwrap();
        let bad = verify(a.path(), &key).unwrap();
        assert!(bad.problems.iter().any(|p| p.contains("record missing")), "{:?}", bad.problems);

        fs::write(a.path(), &text).unwrap();
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert_eq!(verify(a.path(), &other).unwrap().problems.len(), 5);
        fs::remove_dir_all(dir).unwrap();
    }
}
