//! Ed25519 signers (M3-D3, M3-D4): a PKCS#8 PEM key from bytes, a file or an environment variable;
//! key generation; and an external command that signs on the key holder's behalf.
//!
//! Secrets never leave these types. No error, `Debug` output or log line holds private-key bytes,
//! PEM text, an environment variable's value or a command's arguments: errors carry fixed reasons
//! and, as their cause, a short text that names only a path, a variable name or the program (argv[0])
//! and its exit status.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use lunepack_core::error::SignerError;
use lunepack_core::{Error, SignatureAlg, Signer, Verifier};
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::Ed25519Verifier;

/// Largest key file read, before anything is parsed.
pub const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;
/// Largest command output read.
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 4096;

const NOT_A_KEY: &str = "not a PKCS#8 Ed25519 private key";

/// The cause of a signer failure: a short text that never holds secret material.
#[derive(Debug)]
struct Detail {
    text: String,
    source: Option<io::Error>,
}

impl Detail {
    fn new(text: impl Into<String>) -> Self {
        Detail {
            text: text.into(),
            source: None,
        }
    }

    fn with_io(text: impl Into<String>, source: io::Error) -> Self {
        Detail {
            text: text.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Detail {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

fn failed(reason: &'static str, detail: Option<Detail>) -> Error {
    SignerError::Failed {
        reason,
        source: detail.map(|d| Box::new(d) as Box<dyn std::error::Error + Send + Sync>),
    }
    .into()
}

fn hex(bytes: &[u8]) -> String {
    lunepack_core::encoding::hex_encode(bytes)
}

fn key_id_hex(public: &[u8; 32]) -> String {
    hex(&sha2::Sha256::digest(public))
}

/// An Ed25519 signing key held in memory, wiped when dropped.
pub struct Ed25519Signer {
    key: SigningKey,
    public: [u8; 32],
}

impl Ed25519Signer {
    /// Parses a PKCS#8 (v1 or v2) PEM private key, `-----BEGIN PRIVATE KEY-----` (RFC 8410).
    ///
    /// Anything else (a different algorithm, a public key, garbage) is
    /// `Error::Signer(Failed { reason: "not a PKCS#8 Ed25519 private key", .. })`; neither the
    /// message nor the cause holds any of `pem`.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        match SigningKey::from_pkcs8_pem(pem) {
            Ok(key) => Ok(Self::from_key(key)),
            // The parser's error describes the structure it rejected, not the input's bytes; it is
            // still reduced to a fixed text so a future version cannot start echoing the input.
            Err(_) => Err(failed(NOT_A_KEY, None)),
        }
    }

    fn from_key(key: SigningKey) -> Self {
        let public = key.verifying_key().to_bytes();
        Ed25519Signer { key, public }
    }

    /// Reads a PKCS#8 PEM key file of at most [`MAX_KEY_FILE_BYTES`].
    ///
    /// On Unix a file readable by group or others (`mode & 0o077 != 0`) is refused, and the error
    /// names the path and `chmod 600`. The permission and size are read from the opened file, not
    /// from the path, so the file cannot be swapped between the check and the read (a directory or
    /// other non-regular file is also refused before the open, so the open cannot block or fail with
    /// an unrelated error). The text is
    /// read into a buffer that is wiped after parsing. (Windows inherits the directory's ACL; it is
    /// not checked.)
    pub fn from_key_file(path: &Path) -> Result<Self, Error> {
        let shown = path.display();
        // Classified before opening: Windows cannot open a directory with `File::open` ("Access is
        // denied"), and opening a FIFO on Unix blocks. A path that cannot be inspected falls through
        // to the open, which reports the real cause (a missing file keeps its `NotFound`). The
        // check on the opened handle below stays authoritative.
        if let Ok(before) = std::fs::metadata(path)
            && !before.is_file()
        {
            return Err(failed(
                "the signing key path is not a regular file",
                Some(Detail::new(format!("key file {shown}"))),
            ));
        }
        let mut file = File::open(path).map_err(|e| {
            failed(
                "the signing key file could not be opened",
                Some(Detail::with_io(format!("key file {shown}"), e)),
            )
        })?;
        let meta = file.metadata().map_err(|e| {
            failed(
                "the signing key file could not be inspected",
                Some(Detail::with_io(format!("key file {shown}"), e)),
            )
        })?;
        if !meta.is_file() {
            return Err(failed(
                "the signing key path is not a regular file",
                Some(Detail::new(format!("key file {shown}"))),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(failed(
                    "the signing key file is readable by group or others",
                    Some(Detail::new(format!(
                        "key file {shown}: run `chmod 600` on it"
                    ))),
                ));
            }
        }
        if meta.len() > MAX_KEY_FILE_BYTES {
            return Err(failed(
                "the signing key file is over 16 KiB",
                Some(Detail::new(format!("key file {shown}"))),
            ));
        }
        // Allocated once at its final size, so growing the buffer never leaves an unwiped copy.
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES as usize + 1));
        (&mut file)
            .take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| {
                failed(
                    "the signing key file could not be read",
                    Some(Detail::with_io(format!("key file {shown}"), e)),
                )
            })?;
        if buf.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(failed(
                "the signing key file is over 16 KiB",
                Some(Detail::new(format!("key file {shown}"))),
            ));
        }
        let text = std::str::from_utf8(&buf).map_err(|_| {
            failed(
                NOT_A_KEY,
                Some(Detail::new(format!("key file {shown} is not UTF-8 text"))),
            )
        })?;
        Self::from_pkcs8_pem(text)
            .map_err(|_| failed(NOT_A_KEY, Some(Detail::new(format!("key file {shown}")))))
    }

    /// Reads a PKCS#8 PEM key from the environment variable `var`. A missing or non-UTF-8
    /// variable is an error that names the variable, never its value.
    pub fn from_env(var: &str) -> Result<Self, Error> {
        let Some(value) = std::env::var_os(var) else {
            return Err(failed(
                "the signing key variable is not set",
                Some(Detail::new(format!("variable {var}"))),
            ));
        };
        let bytes = Zeroizing::new(value.into_encoded_bytes());
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            failed(
                "the signing key variable is not UTF-8 text",
                Some(Detail::new(format!("variable {var}"))),
            )
        })?;
        Self::from_pkcs8_pem(text)
            .map_err(|_| failed(NOT_A_KEY, Some(Detail::new(format!("variable {var}")))))
    }

    /// The public key as 64 lowercase hex characters.
    pub fn public_key_hex(&self) -> String {
        hex(&self.public)
    }

    /// The key id (SHA-256 of the public key) as 64 lowercase hex characters.
    pub fn key_id_hex(&self) -> String {
        key_id_hex(&self.public)
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signer(key id {})", self.key_id_hex())
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }

    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        Ok(self.key.sign(message).to_bytes())
    }
}

/// A freshly generated key: its public key and the file it was written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    /// The public key.
    pub public_key: [u8; 32],
    /// The key file (the given path, with `.key` appended when it had no extension).
    pub path: PathBuf,
}

/// Generates an Ed25519 key from the operating system's randomness and writes it to `path` as a
/// PKCS#8 PEM file.
///
/// `.key` is appended when `path` has no extension. The file is created with `create_new` (an
/// existing file, of any kind, is an error and is left untouched) and mode 0600 on Unix; the seed
/// and the PEM text are wiped from memory after writing. A file that was created but could not be
/// written completely is removed.
pub fn generate_key_file(path: &Path) -> Result<GeneratedKey, Error> {
    let path = if path.extension().is_none() {
        path.with_extension("key")
    } else {
        path.to_path_buf()
    };
    let shown = path.display();

    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| {
        failed(
            "the operating system gave no randomness",
            Some(Detail::new(e.to_string())),
        )
    })?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let public_key = key.verifying_key().to_bytes();
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| failed("the key could not be encoded as PKCS#8", None))?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|e| {
        let reason = if e.kind() == io::ErrorKind::AlreadyExists {
            "the key file already exists"
        } else {
            "the key file could not be created"
        };
        failed(
            reason,
            Some(Detail::with_io(format!("key file {shown}"), e)),
        )
    })?;
    let written = file
        .write_all(pem.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        // This call created the file (create_new succeeded), so removing it is removing our own.
        let _ = std::fs::remove_file(&path);
        return Err(failed(
            "the key file could not be written",
            Some(Detail::with_io(format!("key file {shown}"), e)),
        ));
    }
    Ok(GeneratedKey { public_key, path })
}

/// A signer that asks an external command (M3-D4): argv from configuration, run without a shell.
///
/// The exact bytes to sign are written to the command's stdin, which is then closed. The command
/// must exit 0 and print exactly 128 lowercase hex characters, optionally followed by one `\n`,
/// within 4 KiB. The signature is verified under the configured public key before it is used, so a
/// command holding another key (or a hostile one) fails closed. stderr is inherited and never
/// read; the environment is inherited. Errors name argv[0] and the exit status only.
pub struct CommandSigner {
    argv: Vec<String>,
    public: [u8; 32],
}

impl CommandSigner {
    /// A signer running `argv` (program, then arguments) for the key `public_key`. An empty argv
    /// or a public key that is not a valid Ed25519 key is an error.
    pub fn new(argv: Vec<String>, public_key: [u8; 32]) -> Result<Self, Error> {
        if argv.first().is_none_or(|program| program.is_empty()) {
            return Err(failed("the signing command is empty", None));
        }
        Ed25519Verifier::check_public_key(&public_key)?;
        Ok(CommandSigner {
            argv,
            public: public_key,
        })
    }

    fn program(&self) -> &str {
        &self.argv[0]
    }

    fn fail(&self, reason: &'static str, what: &str) -> Error {
        failed(
            reason,
            Some(Detail::new(format!("command {}: {what}", self.program()))),
        )
    }

    fn fail_io(&self, reason: &'static str, what: &str, source: io::Error) -> Error {
        failed(
            reason,
            Some(Detail::with_io(
                format!("command {}: {what}", self.program()),
                source,
            )),
        )
    }
}

impl fmt::Debug for CommandSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The arguments may carry configuration values, so only the key id is shown.
        write!(f, "CommandSigner(key id {})", key_id_hex(&self.public))
    }
}

impl Signer for CommandSigner {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }

    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let mut child = Command::new(self.program())
            .args(&self.argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                self.fail_io(
                    "the signing command could not be started",
                    "could not be started",
                    e,
                )
            })?;
        let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(self.fail(
                "the signing command could not be connected",
                "no pipe to the command",
            ));
        };

        // The message goes in on its own thread: the command may write before it has read all of
        // its input, and a 1 MiB message does not fit a pipe.
        let mut output = Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES + 1);
        let read = std::thread::scope(|scope| {
            scope.spawn(move || {
                // A command that stops reading early closes the pipe (or is killed below): its exit
                // status and output say what went wrong, so this error is dropped.
                let _ = stdin.write_all(message);
            });
            let read = (&mut stdout)
                .take(MAX_COMMAND_OUTPUT_BYTES as u64 + 1)
                .read_to_end(&mut output);
            if output.len() > MAX_COMMAND_OUTPUT_BYTES || read.is_err() {
                // Stop the command before the scope joins the writer: a command still producing
                // output and not reading its input would otherwise block on a full stdout pipe
                // while the writer blocks on a full stdin pipe, and neither would ever return.
                // Killing it closes its end of stdin, so the writer's `write_all` fails and ends.
                let _ = child.kill();
            }
            drop(stdout);
            read
        });
        let too_long = output.len() > MAX_COMMAND_OUTPUT_BYTES;
        let status = child.wait().map_err(|e| {
            self.fail_io(
                "waiting for the signing command failed",
                "could not be waited for",
                e,
            )
        })?;
        if let Err(e) = read {
            return Err(self.fail_io(
                "reading the signing command's output failed",
                "output could not be read",
                e,
            ));
        }
        if too_long {
            return Err(self.fail(
                "the signing command printed more than 4 KiB",
                "output over 4096 bytes",
            ));
        }
        if !status.success() {
            return Err(self.fail(
                "the signing command failed",
                &format!("did not succeed ({status})"),
            ));
        }

        let text = output.strip_suffix(b"\n").unwrap_or(&output);
        let Ok(text) = std::str::from_utf8(text) else {
            return Err(self.fail(
                "the signing command's output is not a signature",
                "output is not 128 lowercase hex characters",
            ));
        };
        let Ok(sig) = lunepack_core::encoding::hex_decode_array::<64>(text) else {
            return Err(self.fail(
                "the signing command's output is not a signature",
                "output is not 128 lowercase hex characters",
            ));
        };
        Ed25519Verifier
            .verify(SignatureAlg::Ed25519, &self.public, message, &sig)
            .map_err(|_| {
                self.fail(
                    "the signing command's signature does not verify under the configured key",
                    "signature does not verify",
                )
            })?;
        Ok(sig)
    }
}
