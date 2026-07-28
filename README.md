# Lux

Lux is a compact, private [IDA Lumina](https://hex-rays.com/products/ida/lumina/) server written in Go. It speaks the Lumina RPC protocol used by IDA 7.2 and later, stores function metadata in PostgreSQL, and serves its management console from the same executable.

Lux targets the behavior exposed by native IDA clients and the official Lumina SDK and administration documentation. The compatibility matrix and normative references are in [`docs/OFFICIAL_LUMINA_PARITY.md`](docs/OFFICIAL_LUMINA_PARITY.md). The original Lumen investigation remains only as historical implementation research in [`docs/LUMEN_ANALYSIS.md`](docs/LUMEN_ANALYSIS.md).

## What it supports

- Lumina wire formats 0 through 5 and newer; authenticated operation requires credential-capable protocol version 3+
- IDA hello/login, metadata pull, metadata push, delete history, and function history RPCs
- Official higher-quality metadata replacement and deterministic pull selection
- Immutable push and per-function revision history with native IDA history responses
- PostgreSQL persistence with connection pooling, foreign keys, and automatic schema creation
- Optional TLS with a PEM certificate and key
- Embedded administration console for role-based accounts, live sessions, IDB projects, pushes, semantic revision diffs, files, functions, structured/raw metadata versions, restore, and protected deletion
- JSON management API, optional legacy read-only HTTP aliases, health check, and Prometheus metrics
- One static, CGO-free binary and a small scratch-based container image

## Quick start

The recommended startup path boots Lux and PostgreSQL together:

```sh
export LUX_ADMIN_TOKEN='choose-a-secret'
docker compose up --build -d
```

The defaults are:

- Lumina protocol: `0.0.0.0:1234`
- Management console: `http://localhost:8080`
- PostgreSQL: `127.0.0.1:55432`, database/user/password `lux` (Lux uses the private Compose network)
- Initial IDA credentials: username `guest`, password `change-me`

PostgreSQL data lives in the `postgres-data` Docker volume. Customize its credentials with `LUX_POSTGRES_DB`, `LUX_POSTGRES_USER`, and `LUX_POSTGRES_PASSWORD` before the first startup.
Compose passes credentials to Lux through PostgreSQL's `PG*` environment variables, so passwords do not need URL escaping.

To run the Go binary directly, Go 1.25 or newer and a reachable PostgreSQL server are required:

```sh
go build -o lux ./cmd/lux
LUX_DATABASE_URL='postgres://lux:lux@127.0.0.1:5432/lux?sslmode=disable' \
  ./lux -admin-token 'choose-a-secret'
```

## Configure IDA

In IDA 8.1 or later, open **Options → General → Lumina**, select **Use a private server**, and set:

- Host: the Lux host
- Port: `1234` (or your configured port)
- Username: `guest`
- Password: `change-me` with the default Compose configuration

For plaintext operation, launch IDA with `LUMINA_TLS=false` in its environment. For older IDA releases, set `LUMINA_HOST`, `LUMINA_PORT`, and `LUMINA_TLS = NO` in `ida.cfg` or `idauser.cfg`.

## Configuration

Every option has a command-line flag and an environment variable:

| Flag | Environment | Default | Purpose |
|---|---|---:|---|
| `-lumina-addr` | `LUX_LUMINA_ADDR` | `:1234` | IDA protocol listener |
| `-http-addr` | `LUX_HTTP_ADDR` | `:8080` | Management listener |
| `-database-url` | `LUX_DATABASE_URL` | `postgres://lux:lux@127.0.0.1:5432/lux?sslmode=disable` | PostgreSQL connection URL |
| `-server-name` | `LUX_SERVER_NAME` | `lux` | Name shown to clients |
| `-username` | `LUX_USERNAME` | `guest` | Initial IDA account, only used when the account table is empty |
| `-password` | `LUX_PASSWORD` | empty | Initial password; an empty value creates a disabled-for-login account until a password is assigned |
| `-admin-token` | `LUX_ADMIN_TOKEN` | empty | Bearer token for management changes |
| `-allow-deletes` | `LUX_ALLOW_DELETES` | `false` | Enable RPC and web deletion |
| `-history-limit` | `LUX_HISTORY_LIMIT` | `50` | Histories per hash; 0 disables |
| `-tls-cert` | `LUX_TLS_CERT` | empty | PEM server certificate |
| `-tls-key` | `LUX_TLS_KEY` | empty | PEM private key |

Set `LUX_LOG_LEVEL=debug` for protocol and request diagnostics.

### IDA login accounts

Lumina usernames, profile fields, privilege flags, and bcrypt password hashes are stored in PostgreSQL. On the first startup, Lux creates an administrator with history-deletion permission from `LUX_USERNAME` and `LUX_PASSWORD`; later environment changes do not overwrite database-managed credentials. Accounts created later are regular Lumina users.

Open **Authentication** in the management console to add accounts, edit email and license ID, assign the official administrator and history-deletion flags, rotate passwords, enable or disable access, and remove accounts without restarting Lux. Every regular user can pull, push, and inspect metadata history. `is_admin` grants server administration and `can_delete_history` independently permits native history deletion when deletion is globally enabled. The management token is required. Lux prevents disabling or deleting the final enabled account, and historical metadata remains attached to its original username even if that account is later removed. Password rotation, privilege/profile changes, disablement, and deletion immediately disconnect every active session for the affected account. Accounts created without a password cannot authenticate until one is assigned.

### TLS and IDA certificate pinning

Create a certificate and key:

```sh
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout lux.key -out lux.crt -days 365
./lux -tls-cert lux.crt -tls-key lux.key
```

IDA pins the Lumina server certificate. Copy the public certificate to `hexrays.crt` in the IDA installation directory. Lux uses PEM certificate/key pairs; it does not load PKCS#12 identities directly.

## Management API

| Method | Route | Description |
|---|---|---|
| `GET` | `/healthz` | Database-backed liveness check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/v1/stats` | Aggregate counts |
| `GET` | `/api/v1/functions?q=` | Search best function records |
| `GET` | `/api/v1/functions/{hash}` | Inspect all stored versions |
| `DELETE` | `/api/v1/functions/{hash}` | Delete all versions |
| `GET` | `/api/v1/files?q=` | Search source files |
| `GET` | `/api/v1/files/{md5}/functions` | List a file's functions |
| `GET` | `/api/v1/pushes?q=` | Search immutable native and administrative pushes |
| `GET` | `/api/v1/pushes/{id}` | Inspect one push and all of its changed functions |
| `DELETE` | `/api/v1/pushes/{id}` | Delete a push and reconcile affected functions |
| `GET` | `/api/v1/history?q=` | Search function revisions |
| `GET` | `/api/v1/history/{id}` | Inspect a revision and its previous-value diff |
| `POST` | `/api/v1/history/{id}/restore` | Restore a revision as a new current revision |
| `DELETE` | `/api/v1/history/{id}` | Delete a revision and reconcile its function |
| `GET` | `/api/v1/projects?q=` | Search contributed IDB projects |
| `GET` | `/api/v1/projects/{id}` | Inspect a project and its function versions |
| `PATCH` | `/api/v1/projects/{id}` | Change a project's file or IDB path |
| `DELETE` | `/api/v1/projects/{id}` | Delete a project and its contributed versions |
| `GET` | `/api/v1/metadata/{id}` | Inspect one function metadata version |
| `PATCH` | `/api/v1/metadata/{id}` | Change a version's name, length, or metadata bytes |
| `DELETE` | `/api/v1/metadata/{id}` | Delete one metadata version |
| `GET` | `/api/v1/metadata/{id}/structured` | Decode a version into lossless Lumina metadata chunks |
| `PATCH` | `/api/v1/metadata/{id}/structured` | Set, remove, or append metadata chunks |
| `GET`, `POST` | `/api/v1/accounts` | List or create IDA login accounts |
| `PUT` | `/api/v1/accounts/{username}/password` | Rotate an account password |
| `PATCH` | `/api/v1/accounts/{username}` | Change account profile, privilege flags, or enabled state |
| `DELETE` | `/api/v1/accounts/{username}` | Remove an account |
| `DELETE` | `/api/v1/accounts/{username}/sessions` | Terminate every active session for an account |
| `GET` | `/api/v1/sessions` | List authenticated Lumina sessions and activity |
| `DELETE` | `/api/v1/sessions/{id}` | Terminate one active Lumina session |

Deletion must be enabled with `LUX_ALLOW_DELETES=true`. Account management always requires a configured admin token, and all other mutations require it when configured. Send `Authorization: Bearer <token>`; the browser console keeps it only in session storage.

Push and history searches accept `q`, `username`, `project_id`, `from`, and `to`. History additionally accepts `hash` and `push_id`. Timestamps use RFC3339. Native pushes are recorded even when they contain no changed functions; only actual metadata changes create revisions. Restoring a revision creates a new auditable revision instead of rewriting history.

Legacy compatibility aliases are available at `GET /api/files/{md5}` and `GET /api/funcs/{hash}`. They are Lux extensions and are not part of the native Lumina protocol.

The management listener serves plain HTTP. Bind it to localhost or put it behind an HTTPS reverse proxy when it is reachable over an untrusted network; bearer tokens should never travel over unencrypted public connections.

### Structured metadata

IDA stores function metadata as a sequence of `[key][length][payload]` chunks. Lux recognizes the current SDK keys:

| Code | Field | Lux decoding/editing |
|---:|---|---|
| 1 | Function prototype and serialized types | Source flag plus lossless type/field hex |
| 2 | Decompiler elapsed time | Signed 64-bit seconds |
| 3–4 | Function regular/repeatable comments | UTF-8 text |
| 5–6 | Instruction regular/repeatable comments | Offset and UTF-8 text |
| 7 | Anterior/posterior comments | Offset, kind, and UTF-8 text |
| 8 | User-defined stack points | Offset and signed stack delta |
| 9 | Frame description and stack variables | Named, sized, and preserved as raw payload |
| 10–11 | Operand and extended operand representations | Named, sized, and preserved as raw payload |

Frame members and operand representations contain IDA-internal `opinfo_t` variants without a public standalone wire grammar. Lux therefore does not guess at those fields: the explorer exposes their exact payload, and any untouched chunk is reproduced byte-for-byte. Unknown future keys receive the same treatment. This keeps metadata from newer IDA releases safe when an older Lux instance views or edits another field.

The structured patch endpoint accepts ordered mutations. `set` and `remove` require a zero-based chunk `index`; `append` requires a non-zero `code`. A mutation must contain exactly one value: `text`, `elapsed_seconds`, `type`, `comments`, `stack_points`, or raw hexadecimal `payload`.

```json
{
  "mutations": [
    {"operation": "set", "index": 1, "text": "reviewed"},
    {"operation": "append", "code": 99, "payload": "deadbeef"}
  ]
}
```

Structured edits create the same immutable administrative push/revision records as raw edits. History detail responses contain both decoded documents and field-level semantic differences such as `metadata.function_comment`.

## Native protocol design

A TCP/TLS listener performs a credential-bearing hello exchange and then
handles a stream of request/response transactions. Packets use a four-byte
big-endian payload length, one message-code byte, and IDA's compact positional
encoding. PostgreSQL stores users, input files, IDBs, pushes, current function
metadata, and immutable history.

Native behavior follows the official compatibility matrix. Management features
that do not exist in the IDA protocol remain isolated HTTP extensions.

### IDA scoring oracle

The exact `ida_lumina.score_metadata()` formula is not public. To capture
authoritative fixtures from IDA 9.3 or newer, open an IDB and run:

```sh
ida -A -S"/absolute/path/to/tools/ida/export_lumina_scores.py /tmp/ida-scores.json" sample.i64
```

The exporter records each function's exact metadata bytes and the score
returned by IDA. See the compatibility document before treating Lux's
provisional scorer as byte-for-byte compatible.

## Development

```sh
docker compose up -d postgres
export LUX_TEST_DATABASE_URL='postgres://lux:lux@127.0.0.1:55432/lux?sslmode=disable'
make test
make coverage
go vet ./...
go build ./cmd/lux
```

Database tests create and remove an isolated PostgreSQL schema per test. They are skipped when `LUX_TEST_DATABASE_URL` is not set; CI always supplies it and enforces at least 90% statement coverage. No frontend build step is necessary because the console assets are embedded with `go:embed`.
