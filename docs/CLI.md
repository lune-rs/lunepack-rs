# lunepack CLI

`lunepack` packages an app's build output into a signed release directory that any static host can
serve, and checks such a directory the way a client does. The directory layout, the documents and
the signatures are defined in [`docs/FORMAT.md`](FORMAT.md); the decisions behind the tool are
M3-D1 to M3-D13 and M3-R1-D1 in [`docs/DECISIONS.md`](DECISIONS.md); what it defends against is in
the packager section of [`docs/THREAT-MODEL.md`](THREAT-MODEL.md).

Exit codes: 0 on success, 1 when a command fails or a check does not hold, 2 on a usage error.
Errors print as `error: <message>` on stderr. Progress and results print on stdout. No command prints
a private key, an environment variable's value or a config value.

Global option, accepted by every command: `--config <path>` (default `./lunepack.toml`).

## Packaging any app

The packaged app is an opaque build-output directory (M3-D13). `pack` is given:

- the directory (`--input`): the app's files as they should be installed, from any language or build
  system;
- the app id: from `lunepack.toml` (`--app-id`, when given, must equal it);
- the version and the target: flags, `--version` and `--target`.

Nothing reads a `Cargo.toml` or any other build file of the app, runs cargo, rustc or any toolchain,
or infers the version or the target. Files are classified by their contents, never their names
(M3-D6): PE (`.exe`, `.dll`), ELF (executables and `.so`) and Mach-O (executables, `.dylib`, bundles)
get the matching filter whatever language produced them; files that are already compressed (zip, gzip,
xz, zstd, bzip2, 7z, lz4, PNG, JPEG, GIF, WebP, WOFF2, Ogg) are stored; everything else gets LZMA2. A
file is stored when no candidate is smaller than the file. How a non-Rust app learns that an update
exists and triggers it from inside the app is not decided yet (it belongs to the client milestone).

## Configuration: `lunepack.toml`

Written by `lunepack init`, read by every other command. It holds public keys and the places to find
signers; it never holds a key. Unknown fields are errors. A parse error names the file and the line
and never repeats the text of the line.

```toml
app_id = "org.example.hello"

[root]            # the compiled-in root: what clients trust first
version = 1       # default 1
threshold = 1     # root keys that must sign a key set or a root rotation
keys = [
    "<64 lowercase hex characters>",
]

# Signers, used as `--sign <name>`. Exactly one of these forms per signer:
[signers.root]
file = "root.key"                # PKCS#8 PEM file, relative to this file

[signers.ci]
env = "LUNEPACK_SIGNING_KEY"     # PKCS#8 PEM in an environment variable

[signers.hsm]
command = ["my-signer", "--slot", "1"]
public = "<64 lowercase hex characters>"   # the key the command signs for

# Optional: where the publisher state file lives, relative to this file.
# state = "lunepack-state.json"            # the default
```

## The publisher state file (M3-R2-D1)

`lunepack-state.json`, next to `lunepack.toml` unless the config's `state` names another path (relative
to the config's directory). It records, per app id, what this publisher last signed or accepted: the
version of the root the last walk ended at, the version and threshold of the last `keys.json`, and the
`seq` of each channel's last feed. It holds these numbers only, never a key, a config value or a path.
`init` creates it (an existing file is checked and kept). `feed add`, `feed refresh`, `keys set` and
`keys rotate-root` update it, by temporary file and rename, after every document they place.

Why: the writers build on the previous documents in the release directory (the releases and rollouts
of the previous feed, the keys, windows and threshold of the previous `keys.json`), and they read them
with time checks skipped so an expired one can be renewed. A genuine but older document put back in the
directory would verify, and its values would be signed afresh with a new `seq` or version that clients
accept: a halted rollout undone, a dropped release listed again, a raised threshold lowered. The state
file is the publisher's own memory of what is current, kept where the release directory's writers
cannot reach it.

Before a writer builds on a previous document it compares the document with the record:

- equal, or newer (another trusted machine wrote since): it proceeds and records the new values;
- older than the record: it exits 1, writes nothing, and names the document, the recorded value and
  the value found ("the release directory may hold a replayed older copy"). `--allow-older-previous`
  builds on it anyway (recovery only), names each such document on stderr and records the new values;
- missing although recorded (a `keys.json` or `root-<k>.json` the state file records is not in the
  directory): treated like an older one. It exits 1, writes nothing, and names the document and the
  recorded value ("the release directory may be incomplete or tampered with"). Deleting `keys.json`
  would otherwise start the key set over at version 1, with a default threshold, under a record lowered
  to match. `--allow-older-previous` builds without it (to start over on purpose); `keys set` then
  requires `--threshold`, and the new key set's version 1 is below what clients that saw the old one
  accept, so restoring the missing file from the publisher's own storage is usually the better fix;
- no record (no state file, or a document it never saw, such as a feed of a channel another machine
  started): it exits 1 and writes nothing. `--trust-release-dir` accepts the directory's current
  documents as the baseline and records them. It trusts whatever the directory holds now, so use it only
  on a directory from the publisher's own storage. It does not cover a recorded document that is
  missing. A missing feed is the one exception: a feed that was removed can be started again with
  `feed add` (see Revoking a release key), and its new `seq` must still rise above the recorded one, or
  it exits 1 and writes nothing (`--allow-older-previous` overrides).

No writer lowers a recorded value (a root or `keys.json` version, a feed `seq`), or changes the recorded
threshold without a newer `keys.json`, unless `--allow-older-previous` is given; with it, each lowered
value is named on stderr. The record follows only what was placed.

One state file records one release directory per app: a second release directory of the same app
(staging and production, say) needs its own config directory or its own `state` path, or its writers
will be refused for the documents the other directory recorded.

Where to keep it: with the config, in the publisher's own storage. In CI, commit it next to
`lunepack.toml` and commit the update after each publish, or restore it from and save it to the CI's
own storage around the job. Never fetch the release directory from the public host (bucket, CDN or
mirror) as the base for writing without the state file: anyone with write access there can put an
older document back.

## Signer specs

`--sign <spec>` is repeatable. A spec is one of:

- `<name>`: a `[signers.<name>]` entry of the config;
- `file:<path>`: a PKCS#8 PEM key file;
- `env:<VAR>`: a PKCS#8 PEM key held in the environment variable `VAR`.

The distinct signers given must reach the threshold of the document being signed, and each must be a
key of the root (for `keys.json` and root documents) or of the key set (for manifests and feeds) and
inside its `not_before`..`not_after` window at the writer clock.

### Key file format (M3-D3)

A private key is Ed25519 as PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`, RFC 8410), the format `openssl
genpkey -algorithm ed25519` and most KMS and HSM exports use. `keys gen` writes it with `create_new`
(never over an existing file) and mode 0600 on Unix, and appends `.key` when the path has no
extension. On Unix a key file readable by group or others is refused at load. On Windows the file
inherits the ACL of its directory; lunepack neither sets nor checks it, so put keys in a directory only
you can read.

### Command signer protocol (M3-D4)

For a key that must not leave an HSM, KMS or signing service. The config gives `command` (an argv
vector, no shell) and `public` (the 32-byte Ed25519 public key as hex).

1. lunepack starts the command, writes the exact message to sign (the DSSE pre-authentication
   encoding of the document) to its stdin and closes it;
2. the command exits 0 and prints exactly 128 lowercase hex characters (the 64-byte signature),
   optionally followed by one newline, on stdout. lunepack reads at most 4 KiB;
3. lunepack verifies the signature against `public` before using it; a mismatch fails the command.

stderr is inherited and never captured or logged; the environment is inherited. An error names the
program (argv[0]) and the exit status only. Do not put a secret in the argv (it is visible to other
processes of the same user): pass it to the command through its environment.

## `SOURCE_DATE_EPOCH`

Commands that write documents (`keys set`, `keys rotate-root`, `pack`, `feed add`, `feed refresh`) take
"now" from `SOURCE_DATE_EPOCH` when it is set: ASCII decimal digits only, at most 2^53-1, otherwise the
command fails (the message names the variable and does not repeat its value). Without it they use the
system clock. `verify` and `inspect` use the system clock or `--at <unix>`; they ignore
`SOURCE_DATE_EPOCH`.

## Commands

### `lunepack init`

Writes a config with the compiled-in root and no signers; refuses to overwrite. Creates the publisher
state file next to it when there is none (an existing one is checked and kept).

```
lunepack init --app-id <APP_ID> --root-key <ROOT_KEYS> [--threshold <THRESHOLD>] [--config <CONFIG>]
```

- `--app-id`: lowercase letters, digits, `.`, `_`, `-`.
- `--root-key`: a root public key, 64 lowercase hex characters; repeat for several.
- `--threshold`: root keys that must sign (default 1).

### `lunepack keys gen`

```
lunepack keys gen <PATH> [--config <CONFIG>]
```

Writes a new private key file (see the key file format) and prints `public: <hex>` and `id: <hex>`
(the key id, SHA-256 of the public key) on stdout, nothing else.

### `lunepack keys show`

```
lunepack keys show --sign <SIGN> [--config <CONFIG>]
```

Prints the same two lines for a signer.

### `lunepack keys set`

Writes `keys.json`: exactly the listed release keys, signed by the root.

```
lunepack keys set --release-dir <RELEASE_DIR> --release-key <RELEASE_KEYS> --sign <SIGN>
    [--threshold <THRESHOLD>] [--not-before <NOT_BEFORE>] [--not-after <NOT_AFTER>]
    [--expires <EXPIRES>] [--allow-unverifiable-feeds] [--trust-release-dir]
    [--allow-older-previous] [--config <CONFIG>]
```

- `--release-key`: a release public key, 64 lowercase hex characters; repeat for several.
- `--threshold`: release keys that must sign a feed or manifest. Default 1 for a first key set (no
  `keys.json` and none recorded). When a `keys.json` exists, its threshold is kept only if the state
  file records the same value and the state check passed without an override; otherwise `--threshold`
  is required. It is also required when the state file records a key set that is missing (only
  reachable with `--allow-older-previous`).
- `--not-before`, `--not-after`: Unix times. A key already in the previous key set keeps its window
  unless these are given; a new key defaults to `now` .. `now` + two years.
- `--expires`: when the key set expires (Unix time); none by default.
- `--sign`: root signers; repeat to reach the root's threshold.
- The version is the previous version + 1.
- Before it places anything, `keys set` checks every `feed-*.json` in the directory, and every manifest
  each lists, against the new key set. If any would stop verifying it exits 1, places nothing and
  lists them (see Revoking a release key). `--allow-unverifiable-feeds` places `keys.json` anyway and
  names each feed that `verify` will now reject on stderr.
- Before placing, it prints one line on stdout, `change: version <n> -> <n+1>: ...`, naming what
  changes: the threshold, keys added and removed (by key id), changed windows and the expiry.
- The previous `keys.json` and the root walk are checked against the state file first;
  `--trust-release-dir` and `--allow-older-previous` as in The publisher state file.

### `lunepack keys rotate-root`

Writes `root-<k+1>.json` (signed by the current and the new root) and re-signs `keys.json` under the
new root (same keys and windows, version + 1). The root file is placed first.

```
lunepack keys rotate-root --release-dir <RELEASE_DIR> --new-root-key <NEW_ROOT_KEYS>
    --new-threshold <NEW_THRESHOLD> --sign <SIGN> --sign-new <SIGN_NEW>
    [--allow-unverifiable-feeds] [--trust-release-dir] [--allow-older-previous] [--config <CONFIG>]
```

- `--new-root-key`: a public key of the new root; repeat for several.
- `--sign`: signers of the current root; `--sign-new`: signers of the new root; each side must reach its
  own threshold. A key in both roots may be given on either side or both; it signs once.
- It runs the same feed check as `keys set`, with the same `--allow-unverifiable-feeds` override, and
  the same state file check, with the same `--trust-release-dir` and `--allow-older-previous`.

Publish `root-<k+1>.json` before `keys.json` (see the upload order); clients walk the rotation from
their compiled-in root. The config keeps the original root, and `verify` walks the same way.

### `lunepack pack`

Packages a build-output directory into `<version>/<target>.pack` and `<version>/<target>.manifest.json`
in the release directory.

```
lunepack pack --input <INPUT> --version <VERSION> --target <TARGET> --release-dir <RELEASE_DIR>
    --sign <SIGN> [--app-id <APP_ID>] [--jobs <JOBS>] [--memory-budget-mib <MEMORY_BUDGET_MIB>]
    [--config <CONFIG>]
```

- `--version`: SemVer 2.0.0, used verbatim as the directory name. A directory of equal precedence with
  other text (they differ only in build metadata) is refused.
- `--target`: one of `windows-x86_64`, `windows-aarch64`, `macos-x86_64`, `macos-aarch64`,
  `macos-universal`, `linux-x86_64`, `linux-aarch64`.
- `--jobs`: encoder threads (default: the available parallelism). The output does not depend on it.
- `--memory-budget-mib`: memory budget of the encoders (default 2048). A file that needs more than the
  whole budget is encoded alone.
- `--app-id`: when given, it must equal the config's.

Pre-checks run before any encoding: `keys.json` verifies; every `--sign` key is in the key set and
inside its window; the signers reach the threshold; the manifest and pack do not exist yet; the target
is valid for this host (below).

The stages, in order (C2): (1) assemble: copy the input into a temporary directory (removed on success
and on every error); (2) code-sign: a hook for OS code signing, the identity for now; (3) hash every
file; (4) pack: choose the smallest codec per file, round-trip it through the decoder a client uses,
and lay the frames out; (5) sign the manifest. `pack` then verifies its own output the way a client
does (a throwaway feed signed by the same signers, `verify_manifest`, the pack against the manifest's
size and SHA-256, every frame decoded) and only then writes the pack and, last, the manifest. Neither is
ever overwritten. Stdout has one line per stage and the totals: files, input bytes, pack bytes, files
per codec and the candidates that were dropped, with reasons.

Hosts and file kinds (M3-D10): `exec` is taken from the Unix mode (`mode & 0o111 != 0`). A Windows host
cannot know the bits, so it marks no file executable and refuses `linux-*` and `macos-*` targets.
Special files (fifo, socket, device) are refused everywhere. Hard links are packed as files; symlinks
are packed as links and must satisfy FORMAT 10.2 (symlinks exist only on `linux-*` and `macos-*`
targets; a `windows-*` pack with a symlink is refused).

### `lunepack feed add`

Adds a release, or more targets of it, to a channel's feed (`feed-<channel>.json`).

```
lunepack feed add --release-dir <RELEASE_DIR> --channel <CHANNEL> --version <VERSION> --sign <SIGN>
    [--rollout <ROLLOUT>] [--rollout-seed <ROLLOUT_SEED>] [--expires-after-days <N>]
    [--trust-release-dir] [--allow-older-previous] [--config <CONFIG>]
```

- The targets are every `<version>/<target>.manifest.json` in the directory. A release already in the
  feed keeps its existing target references byte for byte: a target whose manifest changed is an error,
  and new targets are added.
- `--rollout`: basis points of installs, 0 to 10000. Without it an existing release keeps its rollout.
  `--rollout-seed`: 64 lowercase hex characters (default: the release's existing seed, else
  `SHA-256("lunepack-rollout-v1" 0x00 app_id 0x00 version)`).
- `--expires-after-days`: the feed's lifetime (default 90).
- The previous feed is read with its signatures checked and its time checks skipped, so an expired feed
  can be extended. If it does not verify under `keys.json`, the command stops and says so; it never
  reads an unverified feed and never deletes one (see Revoking a release key).
- The root walk, `keys.json` and the previous feed are then checked against the state file (see The
  publisher state file); `--trust-release-dir` and `--allow-older-previous` are its overrides.
- `seq` is `max(previous seq + 1, now in milliseconds)`. Releases are sorted by version precedence.
- Before the feed is placed, the new feed is verified, and so is every release it lists: each manifest
  under the key set and each pack in full (size, SHA-256, every frame decoded). This is slower on a
  feed with many releases and is deliberate.

### `lunepack feed refresh`

Re-signs a channel's feed with a new `seq`, `issued` and `expires`; the releases stay.

```
lunepack feed refresh --release-dir <RELEASE_DIR> --channel <CHANNEL> --sign <SIGN>
    [--expires-after-days <N>] [--drop <DROP>]... [--trust-release-dir] [--allow-older-previous]
    [--config <CONFIG>]
```

- `--drop <version>`: removes that release from the feed (repeatable). The text must equal a release of
  the verified previous feed, or the command exits 1. A feed with no releases left is valid. The release's
  files stay in the directory (`verify` lists their manifests as `unreferenced`).
- The same reads and the same full verification as `feed add`.

### `lunepack verify`

```
lunepack verify <DIR> [--at <AT>] [--config <CONFIG>]
```

Checks a directory the way a client does, in the client's order: the root walk (`root-<k>.json` from the
config's root), `keys.json`, every `feed-*.json` (the channel comes from the file name; a name that is
not a channel is an error), and for every release and target the manifest through the feed's reference,
the pack against the manifest's size and SHA-256, and every frame through the decoder. A manifest no feed
references is listed as `unreferenced` and does not change the exit status. One line per document is
printed; the exit status is 0 only if every check held. `--at` checks at that Unix time (expiry and key
windows) instead of the system clock.

### `lunepack inspect`

```
lunepack inspect <DIR> [--at <AT>] [--channel <CHANNEL>] [--version <VERSION>] [--target <TARGET>]
    [--entries] [--config <CONFIG>]
```

Runs the same verification as `verify` first and shows nothing if it fails. Then it prints a summary:
the key set (version, threshold, key ids, windows), each feed (seq, issued, expires, releases and
targets, rollout) and each manifest (entry counts, input and pack bytes, files per codec, ratio).
`--channel`, `--version` and `--target` narrow the output. `--entries` lists every entry: path, type,
size, exec, codec and frame length. It reads the config for the root only and never resolves a signer.

## The release directory

```
<dir>/
  root-2.json                 # only after a root rotation
  keys.json
  feed-stable.json            # one per channel
  1.4.0/
    windows-x86_64.manifest.json
    windows-x86_64.pack
    linux-x86_64.manifest.json
    linux-x86_64.pack
```

Upload with any tool to any static host (D20; `lunepack publish` comes after v1). Order matters,
because a client that fetches a document must be able to fetch everything it points to:

1. packs (`<ver>/<target>.pack`);
2. manifests (`<ver>/<target>.manifest.json`);
3. `root-<k>.json` and `keys.json` (a feed signed by a new key needs the key set that lists it);
4. feeds (`feed-<channel>.json`) last. A feed is what makes a release visible.

Files already uploaded under a version are never changed: a manifest and a pack are never
overwritten by `pack`. To roll back a release, publish a feed without it.

## Revoking a release key

Revocation is a new `keys.json` without the key (FORMAT section 6). `lunepack` never reads a feed whose
signatures it cannot verify, so a feed signed by a removed key cannot be repaired in place. Revoke in
two moves (M3-R1-D1); nothing is uploaded between them, so the extra minutes the old key spends in the
local key set expose nothing.

1. Add the new key and keep the old one: `keys set` listing both. Sign with the new key:
   `pack` any new release, `feed add` it, and `feed refresh --sign <new>` (the previous feed still
   verifies, since the old key is listed). A release whose manifest only the old key signed cannot be
   carried: re-pack it as a new version, or drop it with `feed refresh --drop <version>`.
2. `keys set` listing only the new key. Then upload `keys.json` and the feeds (see the upload order).

`keys set` and `keys rotate-root` enforce this. If a feed, or a manifest it lists, would stop verifying
under the new key set, the command exits 1 and places nothing; stderr names each failing feed and each
`<version>/<target>`, and says: refresh the feed with a key you keep before removing this one, and drop
releases whose manifests only removed keys signed (`feed refresh --drop <version>`). No command leaves
a directory that `verify` would reject unless asked to with `--allow-unverifiable-feeds`, and then it
names each such feed.

Fallback, for an operator who already removed the key: `feed add` and `feed refresh` stop with
"the existing feed-<channel>.json does not verify". Delete that feed file yourself and run `feed add`
to start the channel again, or restore the previous `keys.json` and revoke in two moves. A restarted
channel loses its rollouts, and its `seq` restarts from the writer clock's milliseconds. Clients keep
the highest `seq` they have seen (FORMAT 11.2), so publish only with a clock later than the old feed's
`issued` time, or clients ignore the new feed as a replay.

Known limitation (owner: the milestone that revisits the threat model): a leaked release key that meets
the threshold can sign a feed with `seq` = 2^53-1. Clients then keep that floor, and the writer rule
"`seq` strictly increases" stops `feed refresh` on that channel. Workaround: publish under a new
channel name.

## Determinism (C2)

For the same input tree, version, target, config, key set and signers, and the same
`SOURCE_DATE_EPOCH`, the pack and the manifest are byte-identical: for any `--jobs`, for any
`--memory-budget-mib`, on a re-run, in a different temporary directory. This holds because file order,
codec choice, encoder settings (the equivalent of liblzma's 9e, a dictionary derived from each file's
length) and the layout are fixed, and Ed25519 signatures are deterministic. Not covered:

- documents written without `SOURCE_DATE_EPOCH` carry the wall-clock time (`issued`, `seq`);
- a command signer may not sign deterministically (that is the command's property);
- the `exec` bit and symlinks come from the file system, so a Windows and a Unix checkout of the same
  files differ;
- identical bytes on different CPU architectures (arm64 against x86-64) are asserted by known-answer
  tests, which first run on all three operating systems at the first push.

## Memory limit

The pack is built in memory (M3-D8): peak use is about the compressed pack plus the encoder budget
(`--memory-budget-mib`). An encoder at the highest preset holds about ten times its dictionary (at most
16 MiB), and each file in flight is counted at its input, up to twice its size for the best candidate so
far and the running candidate's output (an x86 executable's `bcj2` candidate is counted at up to five
times its size more, for its split streams), so very large single files and multi-gigabyte apps need
that much free RAM until a streaming pack writer exists. Raise
`--jobs` only if the budget allows it; lower the budget to trade speed for memory.
