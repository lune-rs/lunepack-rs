# Threat model

Status: **draft**, awaiting approval together with `docs/FORMAT.md`.

What lunepack's update and install path defends against, and what it does not. The format rules
referred to here are in `docs/FORMAT.md`; the decisions in `docs/DECISIONS.md` (D7, D17, D21, D24,
D33, D34, D35, M3-D1 to M3-D13, M4-D1 to M4-D23).

## Assets

- **Code that runs on the user's machine**: the installed app tree, the runtime, the UI binary and
  the Windows stub. The main asset: an attacker who can place bytes there runs code as the user (or,
  for a per-machine install, as every user).
- **Trust state**: the compiled-in root, the persisted highest root version, key-set version and
  feed seq per channel (anti-rollback floors), and the install-state record (current, previous,
  pending and bad versions).
- **Signing keys**: the offline root keys and the online release keys. Only public keys ever reach
  clients.
- **Privacy**: the install id and the rollout bucket (D24). They are never sent.
- **Availability**: the ability to receive security updates in time.

## Trust anchors

- The trusted root compiled into the app, or a higher root version the client verified before.
- Everything else is derived: root rotations (signed by the old and the new root), the key set
  (signed by the root), the feed and manifests (signed by release keys), packs and frames (bound by
  SHA-256 in the signed manifest).
- The first download of an installer is outside the format: it is protected by OS code signing and
  the user's choice of source, not by lunepack. After that, the installer verifies its own payload
  against its compiled-in root like any update.

## Attacker classes

### 1. Network or hosting attacker

Controls the network path or the static host (a compromised bucket, CDN or mirror), but holds no
signing key.

Stopped:
- **Modified or forged documents**: every document's signature is checked over PAE(type, payload)
  before its payload is parsed; packs and frames are checked by SHA-256 before use.
- **Mix and match**: the key set is bound to the app id and root version, the feed to the app id and
  channel, the manifest by size and hash from the feed and to the app id, version and target.
- **Rollback and replay**: floors on root version, key-set version and feed seq per channel; an old
  but validly signed document below a floor is rejected. The client never downgrades.
- **Endless data**: every download is capped by a signed size (manifests by the feed, frames and
  packs by the manifest) or by a fixed cap (root and key set 64 KiB, feed 8 MiB).
- **Parser attacks before authentication**: the only code that sees unauthenticated bytes is the
  size check, the strict JSON pre-pass, the envelope parse and base64 decoding: pure safe Rust,
  fuzzed. Payload parsers, frame descriptors and decoders run only on authenticated bytes.
- **Tracking**: no identifying query parameters; the rollout bucket is computed locally.
- **Hostile responses to a Range request (M4)**: see "The download path" below. A short, long,
  mislabelled, re-encoded or mixed-version body is refused or caught by a hash before anything is
  placed.

Not stopped:
- **Freeze**: withholding new documents (feed, key set, a root rotation) keeps clients on the
  current version. Bounded by expiry: a feed past `expires` (default 90 days) or a key set past its
  `expires` gives "no update" plus a reported error, so the freeze becomes visible. Without
  `expires`, a freeze is unbounded and silent.
- **Denial of service**: refusing to serve, or serving garbage, blocks updates; it never installs
  anything.
- **Learning what a client fetches**: the attacker sees which documents and ranges are requested.

### 2. Leaked release key

The attacker holds a key listed in the current key set. With a release threshold above 1 one key
is not enough; the rest of this section assumes the attacker meets the threshold.

Stopped:
- After the root signs a new key set without the key, every client that has seen it rejects
  documents signed by that key, and the key-set floor stops the old key set from coming back. No
  app update is needed.
- The key is only accepted inside its `not_before`/`not_after` window for feeds.

Not stopped:
- Until clients fetch the revoking key set, the attacker can sign a feed and manifests and ship
  arbitrary code to clients they can serve (with hosting control, or with network control over a
  client). An attacker who also controls hosting can withhold the revoking key set; that freeze is
  bounded only by the key set's `expires` and the key's `not_after`. Short windows and an `expires`
  on the key set limit this.
- A leaked key can raise the feed `seq` floor to a huge value, so the publisher's next feeds must
  exceed it.

### 3. Leaked root key

The attacker holds root keys meeting the root threshold.

Not stopped: the attacker can sign a key set with their own release keys and a root rotation to a
root they control. A client that accepts the rotation persists the higher root version, which then
wins over the compiled-in root, so an app update with a new compiled-in root does not recover such
a client; only a reinstall does.

Mitigations, not prevention: keep root keys offline, use an m-of-n threshold above 1 so one leaked
key is not enough, and rotate promptly (a rotation the publisher signs first raises the floor for
clients that fetch it before the attacker's).

### 4. Local process running as the same user

Not stopped for a per-user install: such a process has the same rights as the app. It can modify
the installed tree, the state record (including the anti-rollback floors and the bad-version list)
and the app binary with its compiled-in root. lunepack does not try to protect a per-user install
from its own user.

Stopped: it cannot alter a per-machine install or its machine-scope state (written only by the
privileged engine in admin-only locations).

The library's own files are in the same position (M4). For a per-user install the state directory,
the download cache and the version trees are writable by that user, so such a process can:
- rewrite or delete the install-state records, including lowering the floors or emptying `bad`
  (FORMAT.md 12). The records are checksummed against a torn write, not authenticated; the checksum
  is no defence against an attacker who writes a whole record. Not stopped, like the tree itself;
- plant or edit cache files. This gains nothing beyond what it can already do: a complete cache file
  is named by its SHA-256 and is hashed again before use (and a frame again by `decode_verified`), so a
  planted file fails the hash, is refetched, and at worst costs the user a download;
- hold or release the updater lock, which only gives `Busy` or lets two operations race on files each
  of which is checked by hash. A race can fail a stage; it cannot place unverified bytes.

### 5. Local process running as another user

Stopped:
- Per-user installs live in the user's own profile, which other users cannot write.
- Per-machine installs: the privileged engine takes only an app id and payload handles the caller
  opened itself, copies the payload into an admin-only staging directory, and only then verifies
  the whole chain (copy, then verify: no time-of-check/time-of-use window). It never follows a
  caller-supplied path or URL, never runs payload code before verification, and never acts for an
  app id without a protected install record. Machine-scope floors are kept by the engine; the
  non-elevated library also keeps its own floors and enforces the higher of the two.
- The library never writes the machine install's state (M4, FORMAT.md 12.6): it reads the machine
  record and the tree through the layout, and writes only this user's `install-counters` records,
  cache and lock in the user's own directories. Another user cannot lower this user's floors, and
  this user's counters cannot lower the machine record's: a check uses the field-wise higher of the
  two. A counters record whose install id differs from the machine record's stops the load.

Not stopped: denying service to other users' updates by holding resources, within OS limits.

### 6. Malicious publisher (out of scope)

The publisher's signature is the definition of an authentic release; lunepack cannot tell an
honest release from a malicious one signed with the right keys. OS code signing and the optional
publisher-continuity check (the installed and the candidate binaries share an OS signing identity)
detect a change of publisher identity, not malicious intent.

## Decoder exposure (Revision 2)

The compression adapter uses `lzma-rust2` with its `optimization` feature, which contains unsafe
code and asm (D17, D34). That exposure is bounded by the format: the decoder sees only frames whose
SHA-256 matched the publisher-signed manifest, and only after the descriptor (codec id, dictionary
sizes at most 16 MiB, BCJ2 sub-stream lengths) passed the pure-core checks. Feeding the decoder
crafted input therefore needs a release key (class 2) or the publisher (class 6). The output is
capped at the signed size and checked against the signed file hash before placement.

The client keeps that order in memory (M4-D11). The staging engine reads exactly the signed `length`
bytes of a frame into memory and `decode_verified` hashes those bytes and decodes the same buffer, so
the decoder never reads bytes that were checked earlier and re-read from a file an attacker could
change in between. A frame that does not hash right is never decoded, whether it came from the cache,
a Range response, the full pack or the current tree.

## The UI process is untrusted (Revision 2)

The installer and update UI is a separate process (D35). The engine (runtime, installer bootstrap
or privileged engine) owns every decision and every file operation; the UI only renders the
engine's events and returns the user's choices. The engine treats those choices as untrusted
input: it validates them against what the verified manifest and the install scope allow, and no
outcome of install, apply, confirm or rollback depends on the UI being present, alive or honest.
The UI never runs elevated, so a fault in the GPU or window stack cannot act with elevated rights.

## Packager and signing keys

`lunepack` (`docs/CLI.md`) holds the signing keys' reach, not the keys' custody: it is run by the
publisher, on the publisher's machine or CI runner, and trusts that machine. What it does and does not
defend is below. Everything it writes is a document the format already authenticates, so a flaw here
is a publisher-side compromise (classes 2, 3 and 6), never something a client has to trust.

- **Key files at rest.** A key is Ed25519 as PKCS#8 PEM. `keys gen` creates it with `create_new` and
  mode 0600 on Unix; loading refuses a file readable by group or others. On Windows the file
  inherits its directory's ACL, which lunepack neither sets nor checks. Any process of the same user
  can read the file: lunepack does not protect keys from their own user (class 4). Keep root keys
  offline and out of CI; give CI only a release key with a short window.
- **An env signer.** `env:<VAR>` reads a PEM from the environment. The value is visible to every
  process of the same user that can read the process environment (on Linux, `/proc/<pid>/environ`) and
  is inherited by every child the CI job starts. Prefer a file or a command signer where that matters.
- **A command signer.** For HSM, KMS or a signing service. The message goes to the command's stdin and
  the signature comes back on stdout; lunepack never sees the key. The argv is visible to other
  processes of the same user, so it must not hold secrets: pass them in the command's environment. The
  command's stderr goes to the terminal untouched, so a noisy command can print what it likes.
- **Signatures are verified before use.** A command signer's output is checked against the configured
  public key before it is placed in a document; a wrong, malformed or oversize answer fails the
  command. A key is only accepted if it is a valid, non-small-order Ed25519 key, and only if it is in
  the root or key set it signs for, inside its window, and counted once toward the threshold.
- **Nothing secret is printed.** No command prints, logs or puts in an error a private key, a PEM line,
  an environment value or a config value. Config errors name the file and line and never the text
  of the line; a bad `SOURCE_DATE_EPOCH` is named, not echoed. An integration test scans stdout and
  stderr of every command for each generated key in raw, hex (both cases), base64 (both alphabets, with
  and without padding) and PEM-line form. It cannot see a secret that a command signer's own stderr
  prints, or one the operator passes in an argv.
- **Every output is verified before it is placed.** Each command builds its documents, then checks them
  with the verifiers a client uses (root walk, key set, feed, manifest, the pack against its signed
  size and hash, every frame through the decoder), and only then moves files into place (temporary file
  in the destination directory, then rename). `pack` places the pack before the manifest and never
  overwrites either; feeds and key sets are replaced atomically. A bug in the packager's encoder, layout
  or writer therefore surfaces as a failed command, not as a release that clients reject.
- **Input is treated as the publisher's own files.** `pack` copies the input to a private temporary
  directory first, hashes the copy, and re-checks each file's hash when it is read for encoding, so a
  file that changes during packaging is an error. It refuses special files (fifo, socket, device),
  checks symlinks against the format's rules and does not follow them. It does not defend against a
  hostile build output: a malicious binary in the input is packaged as is.
- **Revocation is guarded.** `keys set` and `keys rotate-root` refuse to leave a feed that `verify`
  would reject unless told to; no writer reads a feed it cannot verify (so a forged `seq` or release
  list in an edited feed file never enters a new feed); every release a written feed lists is
  re-verified in full. A feed's `seq` is not secret and not protected from a writer holding the
  threshold of release keys: see the leaked-key class above and the `seq` = 2^53-1 limitation in
  `docs/CLI.md`.
- **Replayed older documents (S1, M3-R2-D1).** The writers build on the previous feed and `keys.json`
  in the release directory and read them with time checks skipped, so a class 1 attacker who puts back
  a genuine older document there (the publisher fetched the directory from the host it can write to)
  would have its releases, rollouts, keys, windows or threshold re-signed with a fresh `seq` or version
  and no expiry to reveal it. The defence is the publisher state file (`docs/CLI.md`), kept with the
  config and outside the release directory: every writer refuses a previous document older than the
  recorded root version, key set version or feed `seq`, and one the file has no record of, unless the
  operator overrides (`--allow-older-previous`, `--trust-release-dir`); `keys set` never carries over a
  threshold the state does not vouch for, and prints what it changes. Deletion is treated as the
  oldest replay (F5, S2): a recorded `keys.json` or root that is missing is refused, and only
  `--allow-older-previous` builds without it, with `--threshold` required, so deleting `keys.json` can
  no longer yield a version-1 key set with a default threshold of 1 and a record lowered to match. No
  writer lowers a recorded value without that override. A removed feed is the one document that may be
  missing (the revocation fallback, M3-R1-D1); its restarted `seq` must still exceed the record. After an
  operator lowers the record with the override, genuine documents between the new and the old recorded
  values are no longer recognised as replays, so restore the release directory from the publisher's own
  storage rather than override where possible. Writers trust the release
  directory's previous documents for freshness only as far as the state file vouches: without it (a
  lost file, or a run with `--trust-release-dir`), the directory must come from the publisher's own
  storage, never from the public host. The state file is not secret but must be kept from the same
  attacker; one who can edit it and the release directory both can still roll the writer back.
- **The key set's extra minutes.** Revoking in two moves leaves the old key in the local `keys.json`
  between the moves. Nothing is uploaded between them; if the publisher uploads after the first move,
  the old key is still accepted by clients until the second.

## The download path (M4)

The client's fetch and staging code adds untrusted input beyond the signed documents. Every item
below is checked before it can influence a file placed in a version tree.

**Response headers, Range responses and redirects.** A transport reports every header (names
lowercased, values as raw bytes, duplicates kept) and core applies one set of rules to all
transports (M4-D9), failing closed:
- at most one each of `content-range`, `content-length`, `content-encoding`, `etag` and
  `last-modified`; a duplicate fails;
- a `206` needs a `Content-Range` that matches `bytes <first>-<last>/<total>` exactly (lowercase
  unit, digits only, at most 16 digits, values at most 2^53 - 1), whose range equals the one
  requested and whose total equals the signed pack size; `*`, unsatisfied-range forms and any
  mismatch are an error, so a host cannot hand over a different window of a different file;
- `content-encoding` absent or `identity`; `Accept-Encoding` is never sent and no coding is decoded,
  so a compression layer cannot change the bytes between the host and the hash;
- `If-Range` carries a strong ETag or the Last-Modified value; if the file changed (or the host
  ignores `If-Range`), the final hash catches the mixed file, the part is deleted and the download
  restarts once from byte 0;
- a transport follows at most 5 redirects and returns the final response. A redirect changes where
  bytes come from, never what they must hash to: documents are verified by signature and artifacts
  by the signed SHA-256 and size, so a redirect to a hostile host (class 1) gains what that class
  already has. The default transport sends only `User-Agent: lunepack`, `Range` and `If-Range`:
  no app id, version or install id (D24).

**Cache files.** The cache holds frames and packs under their SHA-256 and `.part` files with a small
strict-JSON sidecar (the validator and a hash of the URL). All of it is local input of class 4. A
complete file was hashed when it was finished and is hashed again when used; a `.part` longer than
its signed size is deleted; a sidecar that is missing, does not parse or names another URL is ignored, so the part is
resumed without `If-Range` and the final hash decides.
Documents are never cached, so the floors alone protect them.

**State records.** The install-state records are local input too (FORMAT.md 12). M4-D23 sets the
rule for a record that is damaged or wrong:
- a file that fails an *integrity* check (name, size cap, magic, format byte, length, checksum, or a
  payload `seq` that differs from its name) is a torn write: it is skipped and the next lower record
  is tried;
- a record that passes integrity but fails parsing or the semantic rules (or names a newer format,
  an unknown critical feature or another app id) **stops the load** and writes nothing. Its checksum
  shows a writer wrote it whole, and falling back to an older record would let one with lower floors
  win, which is a rollback.

So the load returns the newest record that was completely written, or fails; it never returns an
older one while a newer whole one exists. A commit refuses to lower any floor and reads back its own
bytes before it writes. A record from a newer build (for example after an app rollback) fails closed
with a distinct error rather than a panic.

**Absent root documents and 403 (M4-D10).** The root walk asks for `root-<k+1>.json` and treats 404,
410 and 403 as "no such root"; every other status and every transport error fails the check. The
user decided to include 403 because an S3 bucket without `s3:ListBucket` answers 403 for a missing
key, and a host that cannot say 404 would otherwise fail every check. It adds no attacker
capability: an attacker who controls responses (class 1) can already answer 404 and hide a rotation,
which is the freeze already described there, bounded by the key set's and feed's expiry.

## Denial-of-service bounds

| Resource | Bound |
|---|---|
| Document bytes | 64 KiB root and key set, 8 MiB feed, 64 MiB manifest (and the feed's signed size) |
| Signature checks per document | at most 16 signatures, each a single Ed25519 verification |
| JSON | depth 32; duplicate keys rejected; integers at most 2^53 − 1 |
| Counts | 16 root keys, 64 release keys, 10,000 releases, 200,000 entries |
| Downloads | capped by signed sizes; nothing fetched is trusted before its hash matches. A response's `Content-Length`, when present, must equal the expected byte count and is checked before the body is read; a body is read to at most that count and fails on one byte more (M4-D9) |
| Range requests | one at a time; at most 64 runs, else the full pack; a `200` to a Range request becomes the full-pack download, never a second request (M4-D8) |
| Install-state records | at most 1 MiB each; at most three kept after a commit |
| Decoder memory | the signed dictionary per LZMA2 stream, at most 16 MiB (three for BCJ2), checked before allocation; concurrent decoders limited by a memory budget |
| Decoder output | exactly the signed size; decoding stops as soon as it would exceed it |
| Root walk | each step needs signatures from both roots, so its length is bounded by real rotations; a check also stops after 1024 steps |
| Freeze | feed and key-set expiry turn a silent freeze into a reported error |

Memory budget (M4-D11, M4-D13). Staging charges each decode job `length + decoder memory + 256 KiB`
of I/O buffers against a budget (default 256 MiB) and runs at most `min(available_parallelism, 8)`
jobs at once. The decoder memory is the frame's signed dictionaries plus a constant per codec
measured for `lzma-rust2` (about 10 MiB for the LZMA2 variants, about 12 MiB for BCJ2, none for
stored), and a measurement test keeps the constants above what the decoder really allocates. A job
that alone exceeds the budget runs only when nothing else runs, so a large signed frame slows
staging and never deadlocks it. The peak is therefore bounded by the budget plus one oversized job,
and by the signed sizes, not by anything the host sends.

Cancel latency. Cancelling or dropping an operation stops its work at the next check: the transport
is polled on the caller's task, file I/O and decoding run on lunepack's worker threads and look at
the cancel token between chunks, jobs and writes. The default HTTP transport is the exception: a
worker blocked inside a socket read ends at the per-read timeout (30 s by default, a builder
option), and the updater lock stays held until that worker returns, so a new operation meanwhile gets
`Busy`. An injected async transport has no such delay, because its futures die with the operation's.
A host that stalls a connection can therefore delay a retry by up to the read timeout; it cannot
corrupt anything.

## Clock

Expiry and key windows use the local clock only. A clock set earlier than the installed release's
signed `issued` time is implausible: expiry and key-window checks are skipped and the skip is
reported, so a wrong clock cannot brick updates. The cost is that an attacker who can also set the
clock back (a local attacker, classes 4 and 5) defeats expiry; signatures, binding and floors still
hold.
