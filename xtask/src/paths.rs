//! Path helpers shared by the checkers and their tests.

use std::io;
use std::path::{Path, PathBuf};

/// `\\?\C:\x` -> `C:\x`, `\\?\UNC\srv\share\x` -> `\\srv\share\x`; anything else is `None`.
/// Pure string logic so it is tested on every OS.
pub fn strip_verbatim(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{rest}"));
    }
    let rest = s.strip_prefix(r"\\?\")?;
    let b = rest.as_bytes();
    let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    let sep_ok = b.len() == 2 || b[2] == b'\\';
    (drive && sep_ok).then(|| rest.to_string())
}

/// `fs::canonicalize` without the Windows verbatim (`\\?\`) prefix. Git for Windows and other
/// native tools do not accept verbatim paths in environment variables or `-C` arguments.
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    let canon = path.canonicalize()?;
    if cfg!(windows)
        && let Some(plain) = canon.to_str().and_then(strip_verbatim)
    {
        return Ok(PathBuf::from(plain));
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::strip_verbatim;

    #[test]
    fn strips_drive_and_unc_forms_only() {
        assert_eq!(strip_verbatim(r"\\?\C:\a\b").as_deref(), Some(r"C:\a\b"));
        assert_eq!(strip_verbatim(r"\\?\C:").as_deref(), Some("C:"));
        assert_eq!(
            strip_verbatim(r"\\?\UNC\srv\share\x").as_deref(),
            Some(r"\\srv\share\x")
        );
        assert_eq!(strip_verbatim(r"C:\a"), None);
        assert_eq!(strip_verbatim(r"\\?\Volume{1234}\a"), None);
        assert_eq!(strip_verbatim("/tmp/a"), None);
    }
}
