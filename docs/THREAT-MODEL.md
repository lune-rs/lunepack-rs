# Threat model

Status: **draft**, awaiting approval together with `docs/FORMAT.md`.

What lunepack's update and install path defends against, and what it does not. The format rules
referred to here are in `docs/FORMAT.md`; the decisions in `docs/DECISIONS.md` (D7, D17, D21, D24,
D33, D34, D35).

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

### 5. Local process running as another user

Stopped:
- Per-user installs live in the user's own profile, which other users cannot write.
- Per-machine installs: the privileged engine takes only an app id and payload handles the caller
  opened itself, copies the payload into an admin-only staging directory, and only then verifies
  the whole chain (copy, then verify: no time-of-check/time-of-use window). It never follows a
  caller-supplied path or URL, never runs payload code before verification, and never acts for an
  app id without a protected install record. Machine-scope floors are kept by the engine; the
  non-elevated library also keeps its own floors and enforces the higher of the two.

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

## The UI process is untrusted (Revision 2)

The installer and update UI is a separate process (D35). The engine (runtime, installer bootstrap
or privileged engine) owns every decision and every file operation; the UI only renders the
engine's events and returns the user's choices. The engine treats those choices as untrusted
input: it validates them against what the verified manifest and the install scope allow, and no
outcome of install, apply, confirm or rollback depends on the UI being present, alive or honest.
The UI never runs elevated, so a fault in the GPU or window stack cannot act with elevated rights.

## Denial-of-service bounds

| Resource | Bound |
|---|---|
| Document bytes | 64 KiB root and key set, 8 MiB feed, 64 MiB manifest (and the feed's signed size) |
| Signature checks per document | at most 16 signatures, each a single Ed25519 verification |
| JSON | depth 32; duplicate keys rejected; integers at most 2^53 − 1 |
| Counts | 16 root keys, 64 release keys, 10,000 releases, 200,000 entries |
| Downloads | capped by signed sizes; nothing fetched is trusted before its hash matches |
| Decoder memory | the signed dictionary per LZMA2 stream, at most 16 MiB (three for BCJ2), checked before allocation; concurrent decoders limited by a memory budget |
| Decoder output | exactly the signed size; decoding stops as soon as it would exceed it |
| Root walk | each step needs signatures from both roots, so its length is bounded by real rotations |
| Freeze | feed and key-set expiry turn a silent freeze into a reported error |

## Clock

Expiry and key windows use the local clock only. A clock set earlier than the installed release's
signed `issued` time is implausible: expiry and key-window checks are skipped and the skip is
reported, so a wrong clock cannot brick updates. The cost is that an attacker who can also set the
clock back (a local attacker, classes 4 and 5) defeats expiry; signatures, binding and floors still
hold.
