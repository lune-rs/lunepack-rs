# lunepack format v1

Status: **draft**, awaiting approval. Nothing in this document is frozen until it is approved; after
approval, a change to any MUST or MUST NOT below is a format revision (a new DECISIONS row).

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
"Writer" means the lunepack packager (the only producer of these documents). "Reader" means any
lunepack verifier: the in-app library, the runtime, the privileged engine and `lunepack verify`.
All readers run the same core code, so every rule below holds for all of them alike.

A reader that meets anything this document does not allow MUST reject the whole document (fail
closed). There is no "best effort" mode and no warning-only path.

Decisions behind the format: `docs/DECISIONS.md` D6, D7, D21, D24, D25 and D33. The threat model
is `docs/THREAT-MODEL.md`.

## 1. Artifacts and names

A release directory on any static host holds:

| Name | Kind | Signed by |
|---|---|---|
| `root-<k>.json` | `root`: root version `k` (k ≥ 2), one per root rotation | root `k-1`'s threshold and root `k`'s threshold |
| `keys.json` | `keys`: the key set | the current root's threshold |
| `feed-<channel>.json` | `feed`: one per channel, listing every target | the key set's release threshold |
| `<ver>/<target>.manifest.json` | `manifest`: one per release and target | the key set's release threshold |
| `<ver>/<target>.pack` | pack: the release's file frames (section 9) | not signed itself; bound by size and SHA-256 in the manifest |

- `<k>` is the root version in decimal without leading zeros. `<channel>` is a channel id
  (section 10.5). `<ver>` is the release's version string exactly as in the feed (section 10.3).
  `<target>` is a target id (section 10.4).
- Delta files (`<ver>/<target>.from-<old>.delta`) are reserved names; their format is defined by a
  later revision and v1 readers never fetch them.
- Installers (`.exe`, `.dmg`, `.zip`, `.pkg`, `.tar.xz`, Linux `-setup`) are not part of the format;
  they carry the documents above unchanged.
- The writer MUST use exactly these names. Readers resolve the references inside documents
  (section 7.1) and MUST NOT rely on the names otherwise.
- Every `.json` artifact is a DSSE envelope (section 2) whose payload is one document (sections 3 and 5–8).

## 2. Envelope

Every document is a DSSE envelope serialised as JSON (DSSE protocol, JSON envelope).

### 2.1 Fields

The envelope is a JSON object with exactly these fields; any other field, at the envelope level or
inside a signature object, MUST be rejected:

| Field | Type | Rule |
|---|---|---|
| `payloadType` | string | exactly the type for the expected kind (2.2); compared byte for byte |
| `payload` | string | base64 (2.4) of the payload bytes |
| `signatures` | array | 1 to 16 signature objects |
| `signatures[].keyid` | string | REQUIRED (DSSE makes it optional); key id per 2.5 |
| `signatures[].sig` | string | base64 (2.4) of exactly 64 bytes (an Ed25519 signature) |

```json envelope
{
  "payloadType": "application/vnd.lunepack.keys.v1+json",
  "payload": "eyJmb3JtYXQiOjEsImtpbmQiOiJrZXlzIiwiY3JpdGljYWwiOltdfQ==",
  "signatures": [
    {
      "keyid": "69dff77e295327f8b3c2430b425e986b7020b92d03ec82b294ca6ed66cc4f72f",
      "sig": "p5GpjI7pdQDtYgJ4JCC3maaqprRBvxdbJxL19ybFeA1ePfUXHfwue7y7CAFp3VGHwqbdzbE08tVy/2WNLzoCJQ=="
    }
  ]
}
```

(The payload above is truncated to its common fields and the signature is a placeholder; the
example shows the shape only.)

### 2.2 Payload types

`payloadType` is `application/vnd.lunepack.<kind>.v1+json` with `<kind>` one of `root`, `keys`,
`feed`, `manifest`. The reader knows which kind it is opening and MUST reject any other type,
including a different case, extra whitespace or another version. The `v1` in the type and
`"format": 1` in the payload name the same format version.

### 2.3 Pre-authentication encoding (PAE)

Signatures are over `PAE(payloadType, payload)`, where `payload` is the decoded payload bytes (not
the base64 text, and not a re-serialisation):

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

`SP` is one space (0x20), `LEN(x)` is the byte length of `x` in ASCII decimal without leading
zeros, and `type` is encoded as UTF-8. Examples:

- `PAE("t", "x")` = `DSSEv1 1 t 1 x`
- `PAE("t", "")` = `DSSEv1 1 t 0 ` (ends with one space)
- `PAE("application/vnd.lunepack.keys.v1+json", "{}")` =
  `DSSEv1 37 application/vnd.lunepack.keys.v1+json 2 {}`

### 2.4 Base64

`payload` and `sig` use the standard base64 alphabet of RFC 4648 section 4 with `=` padding, in
canonical form only: the length is a multiple of 4, padding is present exactly when needed,
unused trailing bits are zero, and there is no whitespace or line break. URL-safe characters
(`-`, `_`) MUST be rejected.

This deliberately narrows DSSE, which says verifiers must accept both alphabets: each byte string
has exactly one accepted encoding, and lunepack's own writer is the only producer.

### 2.5 Keys, key ids and signatures

- The only signature algorithm in v1 is Ed25519 (RFC 8032), algorithm id `"ed25519"`. Any other
  `alg` value in a key list MUST be rejected.
- A public key is 32 bytes, written as 64 lowercase hex characters. It MUST be a canonical point
  encoding (decoding and re-encoding gives the same 32 bytes) and MUST NOT be a small-order point.
- A key id is the SHA-256 of the 32 raw public-key bytes, as 64 lowercase hex characters.
  Documents carry both the id and the public key; readers MUST recompute the id and reject a
  mismatch.
- A key list (in a root or a key set) MUST NOT contain the same public key twice, under any id.
- A signature is verified with strict Ed25519 verification: 64 bytes, `S` reduced (`S < L`), and
  small-order `R` or `A` rejected (`verify_strict` semantics).
- The envelope `keyid` only selects the key to try; it is an unauthenticated hint:
  - a `keyid` that is not 64 lowercase hex characters MUST fail the envelope;
  - a well-formed `keyid` not in the signing key list is skipped (it neither counts nor fails);
  - a signature that does not verify under the selected key is skipped;
  - the threshold counts distinct keys whose signature verified; two signatures by one key count
    once.

### 2.6 Opening an envelope

A reader opens an envelope in exactly this order and parses no payload field before step 7:

1. The document's byte length is at most the kind's size cap (section 4). Larger: reject before
   reading further.
2. Strict JSON check of the whole envelope (section 3.1).
3. Envelope fields per 2.1 (unknown fields rejected).
4. `payloadType` equals the expected kind's type (2.2).
5. 1 to 16 signatures; `payload` and every `sig` decode per 2.4; every `keyid` is well formed.
6. Each signature is verified over `PAE(payloadType, payload bytes)` per 2.5; the number of
   distinct verified keys is at least the threshold. Below threshold: reject.
7. Only now the payload bytes are parsed: strict JSON check (3.1), then the kind's fields.

## 3. Common payload rules

### 3.1 Strict JSON

Every envelope and every payload MUST pass these checks over the exact bytes that are then parsed:

- UTF-8 (RFC 8259) without a byte-order mark; invalid UTF-8 MUST be rejected.
- One JSON value whose top level is an object, followed only by JSON whitespace.
- No object, at any depth, has two members with the same name (after unescaping). This includes
  names the reader does not know.
- Nesting depth at most 32 (the top-level object is depth 1; each nested object or array adds 1).
- No escaped lone surrogate (`\ud800` without its pair, or the reverse).
- Integers are JSON numbers without sign, fraction or exponent, in `0 ..= 2^53 − 1`
  (9007199254740991). `-1`, `1.0`, `1e3` and `9007199254740992` MUST be rejected wherever an integer
  is expected. v1 has no non-integer numbers.
- Booleans are `true` or `false`; `null` is not a valid value for any v1 field (an optional field
  is written by omitting it).

### 3.2 Common fields

Every payload has:

| Field | Type | Rule |
|---|---|---|
| `format` | integer | MUST be `1` |
| `kind` | string | MUST equal the kind of the payload type (`root`, `keys`, `feed`, `manifest`) |
| `critical` | array of strings | REQUIRED, may be empty; at most 16 entries, each 1–64 bytes of `[a-z0-9-]`, no duplicates |

- **Critical features.** `critical` names features the payload uses that change its meaning. A
  reader MUST reject the document if any entry is not a feature it implements. v1 defines no
  critical features, so a v1 reader accepts only `"critical": []`.
- **Unknown fields.** Payload fields this document does not define are ignored (after the
  duplicate-key check). A future revision adds a field that old readers may ignore as a plain new
  field, and a field that changes meaning together with a `critical` entry.
- **Times** are integers: Unix seconds (UTC, leap seconds ignored).
- **Digests** (`sha256`) are 64 lowercase hex characters. Uppercase hex MUST be rejected.

## 4. Size and count caps

Readers MUST enforce these caps before the work they bound:

| Item | Cap |
|---|---|
| `root-<k>.json` document bytes | 64 KiB (65,536) |
| `keys.json` document bytes | 64 KiB |
| `feed-<channel>.json` document bytes | 8 MiB (8,388,608) |
| `<ver>/<target>.manifest.json` document bytes | 64 MiB (67,108,864) |
| signatures per envelope | 16 |
| keys in a root | 16 |
| release keys in a key set | 64 |
| releases in a feed | 10,000 |
| entries in a manifest | 200,000 |
| LZMA2 dictionary per stream | 16 MiB |
| JSON nesting depth | 32 |

A manifest is additionally capped by the size its feed entry signs (section 7.1), which a reader
checks before downloading more bytes.

## 5. Root

### 5.1 Root payload

```json root
{
  "format": 1,
  "kind": "root",
  "critical": [],
  "app_id": "org.example.hello",
  "version": 2,
  "threshold": 1,
  "keys": [
    {
      "id": "69dff77e295327f8b3c2430b425e986b7020b92d03ec82b294ca6ed66cc4f72f",
      "alg": "ed25519",
      "public": "1754e7aaaa6f5bf4314eafabe40324b24bf80a06f81d82adbc0936dc027431a4"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | app id (10.6) |
| `version` | integer ≥ 1 |
| `threshold` | integer, `1 ≤ threshold ≤ len(keys) ≤ 16` |
| `keys` | key objects `{id, alg, public}` per 2.5 |

### 5.2 Trusted root and rotation walk

- The app embeds a trusted root (its `app_id`, `version`, `threshold` and `keys`) at build time.
  A reader that has verified a higher root version before (persisted state) starts from that one
  instead: the higher version wins.
- Root version `k ≥ 2` is published as `root-<k>.json`. To rotate from trusted version `t`, the
  reader fetches `root-<t+1>.json` and accepts it only if all hold:
  1. the envelope opens (2.6) with root `t`'s keys and threshold;
  2. the same envelope also meets root `t+1`'s own threshold with root `t+1`'s own keys (the new
     root proves possession of its keys);
  3. `version` is exactly `t + 1` (no skipped versions);
  4. `app_id` equals the trusted root's;
  5. every key id is recomputed (2.5), no public key repeats, and the threshold is in range (5.1).
- The reader repeats with `t + 2`, `t + 3`, … until a `root-<k>.json` is absent, then checks
  `keys.json` against the last accepted root. Rotations are separate documents because a signature
  is checked before its payload is parsed: the key that signs a document cannot be learned from
  inside that document.
- A fetched root document that fails any check is an error, not "absent": the walk stops and the
  update check fails.
- The writer publishes `root-<k>.json` before a `keys.json` that names root version `k`.

## 6. Key set (`keys.json`)

```json keys
{
  "format": 1,
  "kind": "keys",
  "critical": [],
  "app_id": "org.example.hello",
  "root_version": 2,
  "version": 7,
  "expires": 1825027200,
  "threshold": 1,
  "keys": [
    {
      "id": "4e370fe519dde8336e0b4de9a949d6ef4108fd3aca913b6851cfd07ec77788aa",
      "alg": "ed25519",
      "public": "3e390113f06d1d397946537e7390f83a12d0738a67e9e4628dfb91040c1ecca5",
      "not_before": 1793491200,
      "not_after": 1888185600
    },
    {
      "id": "4238f924484cab5ac63b80b5320e731ee83d16771422b03efd4a1c737111e3ed",
      "alg": "ed25519",
      "public": "656b657b2e90cf78c88b90f16c9e51640dff79f6d1afa8ad5a96f370ce067491",
      "not_before": 1793491200,
      "not_after": 1888185600
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the trusted root's `app_id` |
| `root_version` | equals the trusted root's `version` after the walk (5.2) |
| `version` | integer ≥ 1; at least the reader's key-set floor (11.2); equal is allowed |
| `expires` | OPTIONAL time; when present, the key set is expired at `now ≥ expires` (11.3) |
| `threshold` | release threshold: integer, `1 ≤ threshold ≤ len(keys) ≤ 64` |
| `keys` | release keys `{id, alg, public, not_before, not_after}`: key rules per 2.5, `not_before < not_after` |

- The envelope is signed by the trusted root's threshold (2.6).
- A release key is *valid at time `now`* when `not_before ≤ now < not_after`.
- Revocation: the root signs a new key set (higher `version`) without the key. Readers that have
  seen the new key set never accept the old one again (11.2).

## 7. Feed (`feed-<channel>.json`)

```json feed
{
  "format": 1,
  "kind": "feed",
  "critical": [],
  "app_id": "org.example.hello",
  "channel": "stable",
  "seq": 42,
  "issued": 1794528000,
  "expires": 1802304000,
  "releases": [
    {
      "version": "1.2.0",
      "targets": {
        "linux-x86_64": {
          "path": "1.2.0/linux-x86_64.manifest.json",
          "size": 2481,
          "sha256": "1c18f178331f99666543847f636694bb40b68c5d2b409c573415962787aaded9"
        },
        "macos-universal": {
          "path": "1.2.0/macos-universal.manifest.json",
          "size": 2730,
          "sha256": "3f7d4c792a20acd292bf2cc41556532f69e3ef5b94113f6d01775f1ae4511539"
        }
      },
      "rollout": {
        "basis_points": 2500,
        "seed": "44abc528db54f66d40174cfcdd43bab36285a5d953cbd185c672350a46f89691"
      }
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the key set's `app_id` and the app id the reader expects |
| `channel` | channel id (10.5); equals the channel the reader asked for |
| `seq` | integer; at least the reader's floor for this channel (11.2); equal is allowed. The writer makes it strictly increasing per channel |
| `issued` | time the feed was written |
| `expires` | OPTIONAL time, `> issued`; the writer sets `issued + 90 days` (7,776,000 s) unless configured otherwise; expired at `now ≥ expires` (11.3) |
| `releases` | 0 to 10,000 release objects |
| `releases[].version` | version (10.3); no two releases in one feed have equal precedence (so two versions differing only in build metadata MUST be rejected) |
| `releases[].targets` | object, at least one member; each name is a target id (10.4), each value an artifact reference to that target's manifest |
| `releases[].rollout` | OPTIONAL; absent means everyone (10,000 basis points) |
| `rollout.basis_points` | integer `0 ..= 10000` (10000 = 100%) |
| `rollout.seed` | 32 bytes as 64 lowercase hex characters |

- The envelope is signed by the key set's release threshold, counting only keys valid at `now`
  (6; with the implausible-clock exception of 11.3).

### 7.1 Artifact references

An artifact reference is `{path, size, sha256}`:

- `path` is a relative reference to the artifact, resolved against the directory of the feed's own
  URL. It MUST pass the path rules of 10.1 and additionally use only ASCII `[A-Za-z0-9._+-]` in each
  component: so no scheme, query, fragment, percent sign or absolute form.
- `size` is the exact byte length and `sha256` the SHA-256 of the artifact's bytes. A reader MUST NOT
  read more than `size` bytes and MUST check both before using the artifact.

## 8. Manifest (`<ver>/<target>.manifest.json`)

```json manifest
{
  "format": 1,
  "kind": "manifest",
  "critical": [],
  "app_id": "org.example.hello",
  "version": "1.2.0",
  "target": "linux-x86_64",
  "issued": 1794528000,
  "pack": {
    "path": "1.2.0/linux-x86_64.pack",
    "size": 1113545,
    "sha256": "ee4f0443cd3cd07d4fb26e13101c3f4257ef94abe4ac6a6dc25d27decabc5577"
  },
  "entries": [
    {
      "path": "bin/hello",
      "type": "file",
      "size": 1048576,
      "sha256": "be4e2e81df0547f05c5ccf12af57ec1701c7f8465e1b542f6e1456b9d3f0876b",
      "exec": true,
      "frame": {
        "codec": "bcj-x86+lzma2",
        "offset": 0,
        "length": 412345,
        "sha256": "20333f298a01c85745b918b210674a2fbf82f0202474a7128fa12d0775f98262",
        "dict_size": 1048576
      }
    },
    {
      "path": "lib/libhello.so",
      "type": "symlink",
      "target": "libhello.so.1"
    },
    {
      "path": "lib/libhello.so.1",
      "type": "file",
      "size": 2000000,
      "sha256": "2460bf64dbd4b3339bb7f41c9fc8e20889a215e9ce1cf50ac76a7545fd0699e9",
      "exec": false,
      "frame": {
        "codec": "bcj2",
        "offset": 412345,
        "length": 700000,
        "sha256": "1bb5629b57e82f048ff63a42fd85dcd714fe5fd7b1861706a10c3e487b93461c",
        "streams": [
          { "length": 600000, "decoded_size": 1700000, "dict_size": 2097152 },
          { "length": 50000, "decoded_size": 200000, "dict_size": 262144 },
          { "length": 20000, "decoded_size": 100000, "dict_size": 65536 },
          { "length": 30000, "decoded_size": 30000 }
        ]
      }
    },
    {
      "path": "share/doc",
      "type": "dir"
    },
    {
      "path": "share/doc/README.txt",
      "type": "file",
      "size": 1200,
      "sha256": "f2f2e0c0de5d188f79d8aae7ac74f83fee226483f3d96924a2cea71b4c849987",
      "exec": false,
      "frame": {
        "codec": "stored",
        "offset": 1112345,
        "length": 1200,
        "sha256": "f2f2e0c0de5d188f79d8aae7ac74f83fee226483f3d96924a2cea71b4c849987"
      }
    },
    {
      "path": "share/doc/empty.txt",
      "type": "file",
      "size": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "exec": false
    }
  ]
}
```

| Field | Rule |
|---|---|
| `app_id` | equals the feed's `app_id` |
| `version` | byte-equal to the feed release's `version` it was reached from (so also equal precedence) |
| `target` | equals the target id under which the feed listed this manifest |
| `issued` | time the manifest was written |
| `pack` | artifact reference (7.1) to the release's pack; `size` may be 0 when no entry has a frame |
| `entries` | 0 to 200,000 entries (8.1); the set passes the tree rules (10.2) |
| `install` | reserved: defined by a later revision (install metadata: entry point, shortcuts, associations, minimum OS). v1 writers MUST NOT write it, and v1 readers reject a manifest that carries it |
| `deltas` | reserved: defined by a later revision (per-file delta assets). v1 writers MUST NOT write it, and v1 readers reject a manifest that carries it |

- The reader checks the manifest's byte length and SHA-256 against the feed's artifact reference
  **before** opening the envelope; then the envelope is signed by the key set's release threshold.
  Key validity windows are not checked for manifests: the feed, whose keys are window-checked,
  binds the manifest by hash.
- The writer lists entries sorted by `path` (byte order); readers do not depend on the order. Parent directories of an entry are implied;
  a `dir` entry is required only for an empty directory and allowed for any directory.

### 8.1 Entries

Every entry has `path` (10.1) and `type`, one of:

| `type` | Fields | Rules |
|---|---|---|
| `file` | `size`, `sha256`, `exec`, `frame` | `size` integer; `sha256` of the file's bytes; `exec` boolean, REQUIRED; `frame` present if and only if `size > 0` (a 0-byte file has no frame and `sha256` = SHA-256 of nothing) |
| `dir` | none | |
| `symlink` | `target` | only when the manifest's target is a `macos-*` or `linux-*` id; `target` per 10.2 |

There are no other mode bits: no permissions beyond `exec`, no owner, no timestamps, no extended
attributes. Readers create files non-executable unless `exec` is `true`, with the platform's
default permissions otherwise.

## 9. Frames and codecs

### 9.0 Frame descriptor

A file's `frame` describes one frame: a byte range of the pack holding the file's encoded bytes.

| Field | Rule |
|---|---|
| `codec` | one of the codec ids below, compared byte for byte |
| `offset` | integer; `offset + length ≤ pack.size` (computed without overflow) |
| `length` | integer ≥ 1 |
| `sha256` | SHA-256 of the frame's bytes `pack[offset .. offset + length]` |
| `dict_size` | the LZMA2 variants only (below) |
| `streams` | `bcj2` only (below) |

The codec-id set of v1 is closed:

| Codec id | Encoding | Extra fields |
|---|---|---|
| `stored` | the file's bytes unchanged | none; `length == size` and the frame's `sha256` equals the file's `sha256` |
| `lzma2` | one raw LZMA2 stream (no `.xz`, `.lzma` or `.7z` container) | `dict_size` |
| `bcj-x86+lzma2` | the x86 BCJ filter (start offset 0) applied before encoding, then one raw LZMA2 stream | `dict_size` |
| `bcj-arm64+lzma2` | the ARM64 BCJ filter (start offset 0) applied before encoding, then one raw LZMA2 stream | `dict_size` |
| `bcj2` | the BCJ2 x86 filter's four streams, concatenated (below) | `streams` |

- An unknown codec id, including a known id in another case, MUST fail the manifest (fail closed).
- `dict_size` is a power of two in `4096 ..= 16777216` (4 KiB to 16 MiB). Readers check it before
  allocating any decoder state; the decoder never uses a larger dictionary than the signed value.
- A field that belongs to another codec (a `dict_size` on `stored` or `bcj2`, `streams` on an LZMA2
  variant) MUST be rejected.

### 9.1 BCJ2 frames

A `bcj2` frame is exactly four sub-streams, concatenated in this order with no gap or padding:
MAIN, CALL, JUMP, RC. `streams` is an array of exactly four objects in that order:

| Stream | Encoding | Fields |
|---|---|---|
| MAIN | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| CALL | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| JUMP | raw LZMA2 | `length`, `decoded_size`, `dict_size` |
| RC | stored | `length`, `decoded_size` with `length == decoded_size`; no `dict_size` |

- Sub-stream `k` occupies frame bytes from the sum of the earlier lengths to that sum plus its own
  `length`. The four lengths MUST sum exactly to the frame's `length` (computed without overflow).
- Every `length` is ≥ 1. MAIN, CALL and JUMP `decoded_size` are each at most the file's `size`.
- `dict_size` per 9.0 for MAIN, CALL and JUMP.
- BCJ2 sub-streams carry no integrity check of their own: a changed byte decodes silently to
  different output. The frame hash (checked before decoding) and the file hash (checked after) are
  the only integrity checks, and both are required.

### 9.2 Decoding rules

A reader decoding a frame MUST, in this order:

1. read exactly `length` bytes of the frame (a different count is an error);
2. check the frame's SHA-256 against the signed `sha256` before any decoder sees a byte;
3. check the descriptor (9.0, 9.1) and allocate decoder state only within the signed `dict_size`s;
4. decode so that the output is exactly the file's `size` bytes: stop with an error as soon as the
   output would exceed `size`, and reject a short output;
5. require that every stream is consumed exactly: no trailing input after the end of an LZMA2
   stream, and each BCJ2 sub-stream decodes to exactly its `decoded_size`;
6. check the SHA-256 of the output against the file's `sha256` before the file is placed.

On any error the decoded output is discarded and never placed.

Frames may overlap or repeat inside the pack (identical files may share one frame): each frame is
hash-checked on its own. Pack bytes that no frame covers are allowed. The pack's own `sha256`
covers a full-pack download.

Decoder memory per frame is bounded by the signed dictionary sizes: one dictionary for the LZMA2
variants, the sum of three for `bcj2`, plus a small fixed overhead.

## 10. Shared rules

These rules are implemented once in the core and used by the writer and every reader.

### 10.1 Paths (`path` of an entry)

A path MUST be rejected when any of these holds. Several rules reject names that would be safe on
some systems: this is deliberate (fail closed against the Win32 path normaliser, NTFS, APFS and
Linux), and may be relaxed only by a format revision.

- It is empty, longer than 1024 bytes, or deeper than 32 components.
- It is not in Unicode NFC.
- It starts with `/`, or has an empty component (`a//b`, a trailing `/`).
- A component is `.` or `..`, or is longer than 255 bytes (UTF-8).
- It contains `\`, NUL, a C0 control character (U+0000–U+001F) or DEL (U+007F).
- It contains any of `<` `>` `:` `"` `|` `?` `*` (so drive letters, `\\?\` and UNC forms and NTFS
  alternate data streams cannot appear).
- A component ends with `.` or a space.
- A component is a Windows device name, in any case, with or without an extension and with or
  without trailing spaces before the extension: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`,
  `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹` `COM²` `COM³`, `LPT¹` `LPT²` `LPT³` (for example `con`,
  `Con.txt`, `CON .txt`, `lpt¹.log`). Names that only start with one are allowed (`CONSOLE`,
  `nul1.txt`, `com10`).
- A component contains `~` followed by an ASCII digit (an 8.3 short-name look-alike such as
  `PROGRA~1`). Over-rejects on purpose.
- A component's NFKC form contains any of `/ \ : * ? " < > |`, or is `.` or `..` (for example
  U+FF0E U+FF0E, U+FF3C). Over-rejects on purpose.

Accepted examples: `bin/app`, `Contents/MacOS/App`, `a b/c.d.e`, `ünïcode/文件` (NFC), `CONSOLE`,
`nul1.txt`, `com10`, a 255-byte component.

### 10.2 Trees (the entry set of one manifest)

- **Case folding.** No two entries have equal fold keys, where `fold(p) = NFC(lowercase(uppercase(p)))`
  with Unicode full case mapping, applied repeatedly until the string stops changing (one pass is
  not stable for U+1E9E: it gives `ß`, which gives `ss`). So `A` and `a`, `Straße` and `STRASSE`,
  `ẞ` (U+1E9E), `ß` and `ss`, `K` (U+212A KELVIN SIGN) and `k`, `Dir/x` and `dir/x` collide. Over-rejects on purpose: names that differ only in case or
  in case-folding forms are rejected even where the filesystem would keep them apart.
- **Nothing under a non-directory.** No entry's path has a proper prefix (by components, compared
  by fold key) that is a `file` or `symlink` entry (`a` as a file and `a/b`).
- **Symlinks** appear only on `macos-*` and `linux-*` targets; a symlink entry in a `windows-*`
  manifest MUST be rejected. A symlink `target`:
  - is non-empty, at most 1024 bytes, NFC, without `\`, NUL, C0 controls or DEL, and not absolute
    (does not start with `/`);
  - has no empty components;
  - resolved lexically from the symlink's parent directory (`..` pops one component, `.` is skipped:
    neither pushed nor popped, any other component is pushed), never leaves the tree (a `..` with nothing to pop is rejected);
  - never passes through another symlink entry as a non-final component (`s` → `.` together with
    `l` → `s/../x` is rejected), because lexical and physical resolution differ after a symlink.
  - Accepted: `Versions/Current` → `A`, `lib/x.so` → `x.so.1`. A target inside the tree that names no
    entry (dangling) is allowed.

### 10.3 Versions

- A version is a SemVer 2.0.0 string of at most 64 bytes, without a leading `v`. Leading zeros in
  numeric parts and missing parts (`01.0.0`, `1.0`) are rejected.
- Versions are ordered and compared for equality by SemVer **precedence** only: build metadata is
  kept for display and ignored for ordering, so `1.0.0+a` and `1.0.0+b` are equal.
  `1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0`.

### 10.4 Targets

The target ids of v1 are exactly:

`windows-x86_64`, `windows-aarch64`, `macos-x86_64`, `macos-aarch64`, `macos-universal`,
`linux-x86_64`, `linux-aarch64`.

Any other string (`linux-x86`, `Windows-x86_64`, `macos-arm64`) MUST be rejected. Fallbacks, tried
in order after the host's own id: `windows-aarch64` → `windows-x86_64`; `macos-x86_64` and
`macos-aarch64` → `macos-universal`. The others have no fallback.

### 10.5 Channels

A channel id is 1–32 bytes: `[a-z0-9]` first, then `[a-z0-9-]`.

### 10.6 App ids

An app id is 1–64 bytes: `[a-z0-9]` first, then `[a-z0-9._-]`; it contains no `..`, does not end
with `.`, and is not a Windows device name (10.1).

### 10.7 Relative references

See 7.1: the path rules of 10.1 plus ASCII `[A-Za-z0-9._+-]` per component.

## 11. Verification order and policy

### 11.1 Order

A reader checking for an update runs these steps in order; a failure stops the check, reports a
typed error and changes no state:

1. **Root.** Start from the trusted root (5.2) and walk `root-<k>.json` documents.
2. **Key set.** Open `keys.json` (2.6) with the root's keys and threshold; check `app_id`,
   `root_version`, the key-set floor, expiry and the key rules (6).
3. **Feed.** Open `feed-<channel>.json` with the key set's release keys valid at `now` and its
   release threshold; check `app_id`, `channel`, the seq floor, expiry, release uniqueness and the
   references (7).
4. **Candidate.** Select a release (11.4). No candidate: done, no update.
5. **Manifest.** Fetch at most the referenced `size` bytes; check length and SHA-256 against the
   feed; open the envelope with the release keys; check `app_id`, `version`, `target`, the tree
   (10.2) and every frame descriptor against `pack.size` (9).
6. **Files.** Fetch frames (or the pack) bounded by the signed sizes, and decode per 9.2.

Every document runs 2.6's order: size cap → strict JSON → envelope → payload type → signature
threshold → only then the payload parse → `format`, `kind`, `critical` → binding (app id, channel,
target, version, hash and size from the feed) → rollback floors → freshness. A verified value is
produced only after all of them pass.

### 11.2 Anti-rollback floors

The reader persists, per app, the highest values it has verified:

- the root version (5.2);
- the key-set `version`;
- the feed `seq`, per channel.

A document below its floor MUST be rejected; equal is allowed. After a check verifies documents,
the floors are raised to their values. Where the floors are persisted (the install-state record and,
for a per-machine install, the per-user counters records) and how a reader treats that record is
section 12.

### 11.3 Freshness and the implausible clock

- `now` comes from the reader's clock only (in the core, the `Clock` trait), never from a document.
- The key set is expired when `expires` is present and `now ≥ expires`; the feed likewise. Expired
  means "no update" and a reported error, never a downgrade.
- **Implausible clock.** The caller supplies a floor time: the `issued` of the installed release's
  manifest (none on a first install). When `now` is earlier than that floor, the clock is
  implausible: the expiry checks and the release-key validity windows are skipped, and the verified
  result reports that they were skipped. Every other check still runs.

### 11.4 Candidate selection

From the verified feed, the candidate is the release with the highest precedence such that:

- its version is strictly newer than the installed version by precedence (equal is not newer;
  never a downgrade);
- it is not marked bad locally (a version that failed its health check);
- it lists the host's target, or else its first available fallback (10.4), and that target is used;
- the install is inside its rollout (11.5).

A pre-release is a candidate only because the channel's feed lists it; there is no channel-switch
logic in the format.

### 11.5 Rollout bucket

- The install id is 16 random bytes generated by the reader at install time and never sent anywhere.
- `bucket = u64_be(SHA-256(install_id ‖ seed)[0..8]) mod 10000`, where `‖` is concatenation of the 16
  install-id bytes and the 32 seed bytes.
- The install is inside the rollout when `bucket < basis_points`. A release without `rollout` is
  inside for everyone; `basis_points = 0` is inside for no one; `10000` for everyone.
- Known answer: install id `000102030405060708090a0b0c0d0e0f` and seed
  `44abc528db54f66d40174cfcdd43bab36285a5d953cbd185c672350a46f89691` give the first 8 hash bytes
  `f728fb2e5aacef3c` and bucket `6700`.

## 12. Install state

An install keeps what it knows about itself (its versions, the staged tree, the versions marked bad
and the anti-rollback floors of 11.2) as numbered **records**. Unlike sections 2 to 9 these are not
signed documents and the packager never writes them: the writer is the reader side (the in-app
library, and later the runtime and the privileged engine). The record is a **cross-version
contract** (D28): one lunepack version writes it and another reads it, after an update or a
rollback, and the Windows stub (C5) reads it too. A per-user install's state is writable by that
user (THREAT-MODEL class 4), so a reader treats every record as untrusted local input and checks
every rule below, failing closed.

### 12.1 Files

- A store is one directory. Each record is its own file, `<seq>.rec`, where `<seq>` is the record's
  sequence number in exactly 20 decimal digits, zero-padded (`00000000000000000007.rec`), and
  `seq ≤ 2^53 − 1`.
- A record file is created once and never rewritten, renamed or appended to; a change is a new
  record with the next `seq`.
- Any other name (including a 20-digit name above `2^53 − 1`) is not a record. Readers ignore it
  and writers never delete it.

### 12.2 Frame

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic, the ASCII bytes `LPST` |
| 4 | 1 | frame format, `1` |
| 5 | 4 | `len`, the payload length, unsigned big-endian |
| 9 | `len` | payload: strict JSON (12.3) |
| 9 + `len` | 32 | SHA-256 of every byte before it (magic through payload) |

A record file is at most 1 MiB (1048576 bytes) in all, and its length is exactly `9 + len + 32`.

### 12.3 Payload

The payload follows 3.1 with one difference: `null` is the value of a field the tables mark "or
null", and every field in the tables is required (a nullable field is written as `null`, never
omitted). Integers follow 3.1 (`0 ..= 2^53 − 1`).

Every record has:

| Field | Type | Rule |
|---|---|---|
| `format` | integer | `1` |
| `kind` | string | `install-state` or `install-counters` |
| `critical` | array of strings | v1 writes `[]` (12.8) |
| `seq` | integer | equals the `<seq>` of the file name |
| `app_id` | string | the app id (10.6); equals the app's own |

An `install-state` record also has:

| Field | Type | Rule |
|---|---|---|
| `scope` | string | `user` or `machine` (12.6) |
| `install_id` | string | the install id of 11.5: 32 lowercase hex characters |
| `target` | string | the target the install uses (10.4) |
| `current` | object or null | `{version, issued}`: the installed version and its manifest's `issued` (the floor time of 11.3); `null` before the first install completes |
| `previous` | object or null | `{version}`: the version installed before `current` |
| `pending` | object or null | `{version, attempts}`: a version waiting for its health check (written from M5) |
| `staged` | object or null | `{version, target, manifest_sha256, tree}`: a staged version tree (12.7) |
| `bad` | array of strings | versions marked bad (11.4), in strictly increasing precedence (sorted, no precedence twice), at most 1000 |
| `floors` | object | the floors of 11.2, below |
| `health` | object or null | reserved for the health handshake (12.8) |

An `install-counters` record (12.6) has, besides the common fields, only `install_id` and
`floors`.

`floors` is `{root, keyset_version, feed_seq}`:

- `root` is the highest verified root (5.2) as its parts, `{version, threshold, keys}`, or `null`
  before the first check. `version ≥ 1`, `1 ≤ threshold ≤ len(keys) ≤ 16`, each key 64 lowercase hex
  characters, no key twice. The parts are kept, not just the version, so the rotation walk starts
  from that root even when the host no longer has `root-<k>.json`.
- `keyset_version` is the highest verified key-set `version` (`0`: none).
- `feed_seq` maps a channel id (10.5) to the highest verified feed `seq`; at most 64 channels.

Further rules: every version is a version of 10.3; `staged.tree` is one path component that passes
10.1 and equals the text of `staged.version`; `staged.manifest_sha256` is a digest (3.2). An object
inside a record (`current`, `previous`, `pending`, `staged`, `floors`, `floors.root`) has exactly
its listed members; an unknown member there makes the record invalid (12.8).

The lunepack writer emits the members of every object in byte order of their names. A reader does
not depend on member order. This example is generated by the writer (a test checks it):

<!-- golden: install-state, generated by crates/lunepack-core/tests/state.rs -->
```json
{
  "app_id": "org.example.hello",
  "bad": [
    "1.0.1"
  ],
  "critical": [],
  "current": {
    "issued": 1790000000,
    "version": "1.0.0"
  },
  "floors": {
    "feed_seq": {
      "stable": 42
    },
    "keyset_version": 3,
    "root": {
      "keys": [
        "fd60726cbdd246cb4f0e3363570e580a8af3c1a59eda73cf9c8672330459cb8f",
        "b960725ba13c46b7c70e3357e59a57fc7af3c2191d427457fc8672046509cb58"
      ],
      "threshold": 1,
      "version": 2
    }
  },
  "format": 1,
  "health": null,
  "install_id": "000102030405060708090a0b0c0d0e0f",
  "kind": "install-state",
  "pending": null,
  "previous": {
    "version": "0.9.0"
  },
  "scope": "user",
  "seq": 1,
  "staged": {
    "manifest_sha256": "3eb81763329a6df94982c6816f9e82b0e59f232d945ff3d24733debc97d1e321",
    "target": "linux-x86_64",
    "tree": "1.1.0",
    "version": "1.1.0"
  },
  "target": "linux-x86_64"
}
```

(The keys and digest in the example come from the test suite's fake hasher; they are not real
SHA-256 values.)

### 12.4 Reading

A reader loads the newest record that was completely written, or fails. It never returns an older
record while a newer whole one exists (M4-D23).

1. List the directory. A missing or empty directory has no record. The **next seq** is the highest
   record name plus 1 (1 when there is none), whatever the files hold, so the number of a torn file
   is never reused.
2. Try the record files from the highest `seq` down. A file whose kind is not a regular file, whose
   size is over the cap (read at most 1 MiB + 1 bytes), or that vanished is skipped. Any other read
   failure stops the load.
3. **Integrity checks; a failure skips the file** (it is torn, flipped or misnamed) and the next
   lower one is tried: the magic, a frame format byte of `0`, the length (`9 + len + 32` equals the
   file size), the SHA-256, and the payload's `seq` equal to the file name's. (The payload is parsed
   to read `seq`; a payload that fails the strict JSON check or has no integer `seq` stops, as in
   step 5.)
4. **Newer format; stops the load**, with nothing written: a frame format byte above `1`, a payload
   `format` above `1`, or any entry in `critical`.
5. **A whole record that is refused stops the load**, with nothing written: the payload fails the
   strict JSON check (3.1), `format` is `0`, `kind` is not the expected kind, `app_id` is not the
   app's, a field is missing, unknown inside an object or of the wrong type, or a rule of 12.3 is
   broken. Its checksum shows a writer wrote it whole, so falling back to an older record (with lower
   floors) would be a rollback.
6. Otherwise the first record that passes is the state.

### 12.5 Writing

The writer holds the install's lock (M4-D15) from the load to the end of the commit.

1. The new record's `seq` is the next seq of 12.4 (at most `2^53 − 1`) and its `app_id` is the
   app's. No floor is lower than the loaded record's (field by field, as in 12.6). The writer runs
   12.4's checks over the bytes it is about to write and writes only what passes.
2. Create the file with create-new semantics; an existing file is a conflict and nothing is written.
   Missing directories of the store are created first, each synced in its parent.
3. Write the frame, sync the file, then sync the directory. The record is committed when the
   directory sync returns.
4. Only then prune, best effort: of the record files below the new `seq`, delete those that fail an
   integrity check (12.4 step 3) and the valid ones beyond the 3 highest valid (the new one counts).
   Leave every other file, including a record that would stop a load and any file whose name is not a
   record name.

A crash at any point leaves the previous record or the new one as the state, and the new one once
step 3 completed.

### 12.6 Scopes

- **Per-user install** (`scope: user`): one store in the install's state directory, read and written
  by the library.
- **Per-machine install** (`scope: machine`): the `install-state` store in the machine state
  directory is written only by the privileged engine; the library reads it and never writes it.
  Each user keeps the floors they have verified for that install as `install-counters` records in
  `<user state dir>/<install_id as 32 hex>/`. A counters record whose `install_id` differs from the
  machine record's is invalid (the load stops). A check starts from the **effective floors**, the
  field-wise higher of the machine record's and the user's: the higher key-set version, per channel
  the higher feed `seq`, and the higher root, ordered by `version`, then `threshold`, then the key
  bytes in order (so a lower root version never replaces a higher one).

### 12.7 Trees on disk

- Version `V`'s tree is `<versions dir>/<V's version text>`; staging builds it there (M4-D18).
  Version texts that differ only in ASCII letter case (`1.0.0-RC1`, `1.0.0-rc1`) are different
  versions but one directory on a case-insensitive file system, so staging refuses a version whose
  directory name collides, ignoring case, with the current, previous, pending or staged version's, or
  with any entry of the versions directory (`Error::VersionDirCollision`); nothing is written.
- The **current tree** is the layout's explicit current tree when one is given (for a layout whose
  live tree is not under the versions directory), else `<versions dir>/<current.version text>`. It
  counts only when it is a real directory (a symlink is not followed); otherwise there is none and
  every file is fetched. A machine install's tree is only read.
- A `staged` entry is usable only when `staged.version` is newer than `current.version` by
  precedence, is not in `bad`, `staged.target` equals the record's `target`, and the tree directory
  `<versions dir>/<staged.tree>` exists as a real directory. Otherwise it is ignored and the next
  staging resumes or discards the tree.

### 12.8 Evolution

- (a) Within `format: 1`, an unknown **top-level** member is ignored by readers and kept verbatim by
  every writer through every change of the record. An unknown member inside a known object makes the
  record invalid, so new data is added as new top-level members. A writer that adds a member older
  readers must not ignore names it in `critical`; a reader that finds a name it does not implement in
  `critical` stops (12.4 step 4). v1 implements no critical name.
- (b) `format` (frame byte and payload) is raised only for a change an older reader cannot handle by
  (a): a frame layout change or a changed meaning. Additive changes never raise it; no raise is
  planned for v1.
- (c) An older reader that meets a newer format fails closed and writes nothing; the library reports
  it from every operation. A build that raises the format keeps writing the old one until its own
  version is confirmed healthy, so a rollback before that never leaves a record the previous version
  cannot read.
- `health` is reserved for the health handshake (M5, C4). v1 writes `null` and keeps any value it
  finds; when present it is an object or `null`.
