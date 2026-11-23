//! Lexical path normalisation.
//!
//! This is the first of two path checks. It decides what path a rule sees and
//! rejects anything that leaves the tool's root on paper. It never touches the
//! file system, so it cannot see symlinks; the fs driver closes that gap by
//! opening files with `openat2(RESOLVE_BENEATH)` relative to the root.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    Nul,
    Relative,
    Escapes { root: String },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Empty => f.write_str("path is empty"),
            PathError::Nul => f.write_str("path contains a NUL byte"),
            PathError::Relative => f.write_str("relative path and the tool has no root"),
            PathError::Escapes { root } => write!(f, "path leaves the tool root {root}"),
        }
    }
}

/// Folds `.`, `..` and repeated slashes. Relative input is joined to `root`.
/// With a root, the result must stay inside it.
pub fn normalize(root: Option<&str>, input: &str) -> Result<String, PathError> {
    if input.is_empty() {
        return Err(PathError::Empty);
    }
    if input.contains('\0') {
        return Err(PathError::Nul);
    }
    let joined = match (input.starts_with('/'), root) {
        (true, _) => input.to_string(),
        (false, Some(r)) => format!("{r}/{input}"),
        (false, None) => return Err(PathError::Relative),
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(PathError::Escapes { root: root.unwrap_or("/").to_string() });
                }
            }
            c => parts.push(c),
        }
    }
    let out = format!("/{}", parts.join("/"));
    if let Some(r) = root
        && !is_under(&out, r)
    {
        return Err(PathError::Escapes { root: r.to_string() });
    }
    Ok(out)
}

/// True when `path` is `root` or inside it. Both must be normalised.
pub fn is_under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    root.is_empty() || path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
}

/// The part of a normalised `path` below `root`, without a leading slash.
/// Returns "." for the root itself.
pub fn relative_to<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    let root = root.trim_end_matches('/');
    if path == root || (root.is_empty() && path == "/") {
        return Some(".");
    }
    path.strip_prefix(root)?.strip_prefix('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_and_confines() {
        let r = Some("/srv/app");
        assert_eq!(normalize(r, "logs/../logs/./a.log").unwrap(), "/srv/app/logs/a.log");
        assert_eq!(normalize(r, "/srv/app//x").unwrap(), "/srv/app/x");
        assert_eq!(normalize(r, ".").unwrap(), "/srv/app");
        assert!(matches!(normalize(r, "../../etc/shadow"), Err(PathError::Escapes { .. })));
        assert!(matches!(normalize(r, "/etc/passwd"), Err(PathError::Escapes { .. })));
        assert!(matches!(normalize(r, "/srv/application"), Err(PathError::Escapes { .. })));
        assert_eq!(normalize(None, "/a/b/../c").unwrap(), "/a/c");
        assert_eq!(normalize(None, "/../../x").unwrap_err(), PathError::Escapes { root: "/".into() });
        assert_eq!(normalize(None, "x").unwrap_err(), PathError::Relative);
        assert_eq!(normalize(r, "a\0b").unwrap_err(), PathError::Nul);
    }

    #[test]
    fn literal_dots_in_names_are_fine() {
        // The v0.3 prototype denied any path containing "..", including this one.
        assert_eq!(normalize(Some("/d"), "release..notes.txt").unwrap(), "/d/release..notes.txt");
        // Percent signs are ordinary bytes in a file name, not an encoding.
        assert_eq!(normalize(Some("/d"), "%2e%2e/x").unwrap(), "/d/%2e%2e/x");
    }

    #[test]
    fn relative_paths() {
        assert_eq!(relative_to("/srv/app/a/b", "/srv/app"), Some("a/b"));
        assert_eq!(relative_to("/srv/app", "/srv/app"), Some("."));
        assert_eq!(relative_to("/srv/apple", "/srv/app"), None);
    }
}
