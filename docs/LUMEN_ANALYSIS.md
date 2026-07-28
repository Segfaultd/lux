# Legacy Lumen analysis

> Historical note: this document records the initial reverse-engineering input
> used to bootstrap Lux. It is not the Lux product specification. Current
> behavior is defined by [`OFFICIAL_LUMINA_PARITY.md`](OFFICIAL_LUMINA_PARITY.md)
> and the official Hex-Rays references linked there.

This document records the source-level analysis used to implement Lux. The analyzed sibling revision was `642fa35` (`update deps, fix clippy lints`).

## Lumen architecture

Lumen is a Rust workspace with two crates:

- `common` owns configuration, PostgreSQL access through Diesel, the Lumina codec and message structures, metadata parsing/scoring, the experimental HTTP API, and Prometheus metrics.
- `lumen` owns process startup, the TCP/TLS server, connection state machine, and Warp HTTP server.

At startup Lumen loads TOML, connects a PostgreSQL pool, optionally loads a PKCS#12 TLS identity, binds the Lumina listener, and optionally starts a separate HTTP listener. Each accepted client gets an asynchronous task. The server requires `HELO` first and then processes one RPC at a time until the peer disconnects or a timeout/error occurs.

## Packet framing

Every packet has:

| Field | Width | Encoding |
|---|---:|---|
| Payload length | 4 bytes | Big-endian; excludes the message-code byte |
| Message code | 1 byte | RPC discriminator |
| Payload | variable | Positional Lumina encoding |

Lumen caps pull requests at 50 MiB, push requests at 200 MiB, and other requests at 50 KiB. It recognizes common HTTP verbs on the TCP port and answers with an explanatory HTTP 400 page.

The positional encoding flattens structs in declaration order:

- `u8`: one byte
- `u32` (`dd`): 1, 2, 4, or 5 bytes depending on magnitude
- `u64` (`dq`): packed high `u32`, then packed low `u32`
- string: UTF-8 followed by NUL
- byte slice: packed element count followed by raw bytes
- sequence: packed element count followed by each encoded element
- fixed arrays/tuples: elements in order, with no length prefix

Lux has golden tests using the exact serializer example in Lumen's source as well as boundary tests for every packed-integer width.

## RPC messages

| Code | Direction | Message | Lux |
|---:|---|---|---|
| `0x0a` | both | OK | Supported |
| `0x0b` | server | Failure | Supported |
| `0x0c` | server | Notification | Recognized code; not emitted |
| `0x0d` | client | Hello, with optional credentials after protocol v2 | Supported |
| `0x0e` | client | Pull metadata | Supported |
| `0x0f` | server | Pull result | Supported |
| `0x10` | client | Push metadata | Supported |
| `0x11` | server | Push result | Supported |
| `0x18` | client | Delete history | Supported when enabled |
| `0x19` | server | Delete result | Supported |
| `0x2f` | client | Get function histories | Supported when enabled |
| `0x30` | server | Function histories | Supported |
| `0x31` | server | Protocol-v5+ hello result and feature flags | Supported |

Authenticated protocol versions 3–4 receive `OK` after hello. Versions 5 and newer receive `HelloResult`. Versions 0–2 cannot carry credentials and are rejected by Lux's authentication layer. Lumen advertises feature bit `0x02` when deletion is enabled; Lux does the same.

Lumen accepts only the username `guest` when credentials are present and does not validate the password. Lux requires credentials and authenticates database-managed, case-insensitive usernames against bcrypt password hashes. Operators can add, disable, rotate, and remove accounts at runtime.

## Persistent model

Lumen stores four related record types:

```text
users ──< databases >── files
              │
              └──< functions
```

- A user is identified by the six-byte license number, opaque license data, and hostname.
- A file is identified by its 16-byte MD5.
- A database associates a user, file, IDB path, and original file path.
- A function version associates a 16-byte function checksum with one database and stores its name, byte length, opaque IDA metadata, score, and timestamps.

The unique function key is `(checksum, database)`. Re-pushing from the same database updates that version; pushing from another database creates a history entry. Lux preserves these constraints in PostgreSQL and uses cascading foreign keys to keep cleanup deterministic.

Lux adds an `auth_accounts` table for runtime-managed Lumina credentials. Each database contribution stores both the account foreign key and a username snapshot, so deleting a login account does not erase historical attribution.

## Metadata selection

Lumen does not merge versions. For a pull it groups rows by function checksum, finds the maximum rank, and returns a row with that rank. Rank is ten points for each useful decoded comment. Known IDA/compiler-generated boilerplate comments are excluded.

Lux ports the metadata chunk parser and scoring rules. It also implements a lossless structured document model for all current SDK keys. Types, timing, comments, and stack points are decoded into fields; frame and operand chunks are identified but kept opaque because their standalone `opinfo_t` wire grammar is not public. Unknown keys are retained verbatim. This permits semantic history diffs and field-level editing without discarding metadata added by newer IDA versions.

Tie-breaking is explicit—score descending, update time descending, row ID descending—so one deterministic record is returned even if several versions have the same score. Lux also reports the number of stored versions as popularity, where Lumen currently returns zero.

## HTTP behavior

Lumen's optional Warp server provides:

- `/`: a minimal landing page
- `/api/files/{md5}`: function names, lengths, and hashes seen in a file
- `/api/funcs/{hash}`: best function metadata with decoded comments and containing files
- `/metrics`: Prometheus exposition

Lux retains both read-only API shapes, adds versioned management endpoints, and embeds an interactive console. The console includes raw and structured metadata inspection, typed chunk editing, and semantic revision diffs. Mutations are disabled by default and can be protected by a bearer token.

## Deliberate Lux differences

| Concern | Lumen | Lux |
|---|---|---|
| Language/runtime | Rust/Tokio | Go |
| Database | External PostgreSQL | PostgreSQL via pgx/database/sql |
| TLS identity | PKCS#12 | PEM certificate and key |
| HTTP | Optional separate minimal API | Embedded management console and API |
| Authentication | Hard-coded `guest`, password ignored | PostgreSQL-backed runtime account management with bcrypt passwords |
| Best-row ties | Database may return more than one max-rank row | Deterministic single row |
| Popularity | Always zero | Stored version count |
| Schema setup | Diesel migrations run separately | Automatic idempotent startup migration |

Lux uses PostgreSQL for durable storage and automatic schema creation. Docker Compose supplies a health-checked PostgreSQL service for single-command deployment, while `LUX_DATABASE_URL` supports managed or independently operated PostgreSQL installations without changing the protocol layer.
