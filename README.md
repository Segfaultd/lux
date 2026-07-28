# Lux

> A self-hosted IDA Lumina server with PostgreSQL persistence and an embedded
> management console.

[![CI](https://github.com/Segfaultd/lux/actions/workflows/ci.yml/badge.svg)](https://github.com/Segfaultd/lux/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](go.mod)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)](compose.yaml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Lux accepts native Lumina connections from IDA, authenticates users against
PostgreSQL, stores contributed function metadata, and returns the selected
metadata for matching function hashes. The same Go executable serves a
browser-based administration console, a JSON management API, health checks,
and Prometheus metrics.

Lux is designed for private deployments where an organization wants to retain
its IDA metadata and manage its own users, projects, history, and retention
policy.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Connect IDA](#connect-ida)
- [Management console](#management-console)
- [Configuration](#configuration)
- [Authentication and authorization](#authentication-and-authorization)
- [Native protocol behavior](#native-protocol-behavior)
- [Metadata and history](#metadata-and-history)
- [Architecture](#architecture)
- [Operations](#operations)
- [Development](#development)
- [Compatibility](#compatibility)

## Features

### Native IDA service

- Credential-bearing Lumina hello exchange for protocol versions 3 and newer.
- Metadata pull and push with per-function result codes.
- Function history retrieval and optional history deletion.
- Popular-functions and server-information RPCs.
- Pull-frequency tracking, including `PULL_MD_SEEN_FILE`.
- Better-score, force-override, and do-not-override push modes.
- Full user profile flags for administrator and history-deletion privileges.
- Optional TLS 1.2+ using a PEM certificate and private key.
- Configurable hello, command, pull, and graceful-shutdown timeouts.

### Durable storage

- PostgreSQL is the only supported database.
- Automatic, idempotent schema creation during startup.
- Connection pooling through `pgx` and `database/sql`.
- Immutable push records and function revision history.
- Deterministic current-version selection for every function hash.
- Persistent attribution to username, license ID, email, host, IDB, and input
  file.
- Transactional cleanup when projects, revisions, or functions are deleted.

### Administration

- Self-served management console embedded in the Lux binary.
- Dynamic account creation, profile editing, password rotation, disablement,
  and deletion.
- Immediate session revocation after security-sensitive account changes.
- Live session inspection and termination.
- Browsing and searching of functions, files, projects, pushes, and revisions.
- Raw and structured metadata inspection and editing.
- Semantic revision diffs and auditable revision restore.
- Official-style user statistics and push/history filters.
- Bearer-token protection for management mutations.
- Global kill switch for destructive operations.

### Operations

- Docker Compose stack with a health-checked PostgreSQL service.
- Single, statically linked Go binary with embedded frontend assets.
- Scratch-based runtime container.
- Database-backed `/healthz` endpoint.
- Prometheus-compatible `/metrics` endpoint.
- Structured logs with an optional debug level.
- PostgreSQL-backed unit, integration, race, and coverage tests.

## Quick start

### Requirements

- Docker with Compose support.
- TCP port `1234` available for IDA clients.
- TCP port `8080` available for the management console.

### Start Lux and PostgreSQL

For a disposable local evaluation:

```bash
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/healthz
```

The development defaults are:

| Service | Address | Default credential |
|---|---|---|
| Lumina protocol | `127.0.0.1:1234` | `guest` / `change-me` |
| Management console | <http://127.0.0.1:8080> | bearer token `change-me` |
| PostgreSQL | `127.0.0.1:55432` | database/user/password `lux` |

For a persistent deployment, set real secrets before the first startup:

```bash
export LUX_PASSWORD='replace-with-a-long-password'
export LUX_ADMIN_TOKEN='replace-with-a-separate-management-token'
export LUX_POSTGRES_PASSWORD='replace-with-a-database-password'
docker compose up --build -d
```

> [!IMPORTANT]
> Bootstrap settings are used only while the account table is empty. Changing
> `LUX_USERNAME` or `LUX_PASSWORD` later does not overwrite accounts already
> stored in PostgreSQL. Use the management console to rotate an existing
> password. The PostgreSQL container likewise applies its database name, user,
> and password while initializing an empty data volume; changing those
> variables does not rewrite an existing PostgreSQL cluster.

PostgreSQL data is retained in the `postgres-data` volume. View service logs
with:

```bash
docker compose logs -f lux
```

### Run the binary directly

Go 1.25 or newer and a reachable PostgreSQL server are required:

```bash
go build -o lux ./cmd/lux

LUX_DATABASE_URL='postgres://lux:lux@127.0.0.1:5432/lux?sslmode=disable' \
LUX_PASSWORD='replace-with-a-long-password' \
LUX_ADMIN_TOKEN='replace-with-a-separate-management-token' \
./lux
```

Lux also accepts standard PostgreSQL `PG*` variables when
`LUX_DATABASE_URL` is empty:

```bash
PGHOST=127.0.0.1 \
PGPORT=5432 \
PGDATABASE=lux \
PGUSER=lux \
PGPASSWORD='database-password' \
PGSSLMODE=disable \
LUX_DATABASE_URL='' \
./lux
```

## Connect IDA

Configure IDA to use a private Lumina server and provide:

| Setting | Value |
|---|---|
| Host | Hostname or IP address of the Lux machine |
| Port | `1234`, unless `LUX_LUMINA_ADDR` was changed |
| Username | A Lux account, initially `guest` with Compose defaults |
| Password | The password assigned to that account |

The IDA menu and configuration-file location vary by release. See the
[official Lumina user documentation](https://docs.hex-rays.com/ida-9.2/user-guide/user-interface/menu-bar/common-actions-3)
for the controls available in your installation.

The client and server must agree on transport:

- For a plaintext Lux listener, launch IDA with `LUMINA_TLS=false`. Releases
  that use configuration files can set `LUMINA_TLS = NO` in `ida.cfg` or
  `idauser.cfg`.
- For a TLS-enabled listener, install the Lux public certificate where IDA
  expects its private-server certificate and enable TLS.

To create a self-signed test certificate:

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout lux.key \
  -out lux.crt \
  -days 365 \
  -subj '/CN=lux'

./lux -tls-cert lux.crt -tls-key lux.key
```

Lux loads PEM files and requires both the certificate and key. The native
listener enforces TLS 1.2 or newer when TLS is enabled. IDA pins the
private-server certificate; copy the public certificate to `hexrays.crt` in
the applicable IDA installation directory.

## Management console

Open <http://127.0.0.1:8080> and enter the configured management token in the
header. The token is kept in browser session storage and is cleared when the
tab session ends.

The console provides:

| Section | Operations |
|---|---|
| Overview | Storage totals, per-user statistics, and server configuration |
| Authentication | Accounts, profiles, privileges, passwords, and status |
| Sessions | Connected clients, activity, transfer counters, and termination |
| Projects / IDBs | Input files, IDB paths, contributors, and function versions |
| Push history | Push identity snapshots, revisions, filters, diffs, and restore |
| Functions | Current selections and every contributed version |
| Files | Input-file hashes and associated functions |
| Server | Listener, deletion, history, and observability state |

The management listener is plain HTTP. Bind it to a private interface or place
it behind an HTTPS reverse proxy when it crosses an untrusted network.

The complete HTTP reference, including request bodies and filter parameters, is
in [Management API](docs/MANAGEMENT_API.md).

## Configuration

Command-line flags override the corresponding environment-derived defaults.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `-lumina-addr` | `LUX_LUMINA_ADDR` | `:1234` | Native Lumina listen address |
| `-http-addr` | `LUX_HTTP_ADDR` | `:8080` | Management HTTP listen address |
| `-database-url` | `LUX_DATABASE_URL` | `postgres://lux:lux@127.0.0.1:5432/lux?sslmode=disable` | PostgreSQL URL; empty uses `PG*` variables |
| `-server-name` | `LUX_SERVER_NAME` | `lux` | Name included in client-facing messages |
| `-username` | `LUX_USERNAME` | `guest` | Initial account name when no accounts exist |
| `-password` | `LUX_PASSWORD` | empty | Initial password; empty creates a passwordless account that cannot log in |
| `-admin-token` | `LUX_ADMIN_TOKEN` | empty | Bearer token for management mutations |
| `-allow-deletes` | `LUX_ALLOW_DELETES` | `false` | Enables native and HTTP destructive operations |
| `-history-limit` | `LUX_HISTORY_LIMIT` | `50` | Maximum native history records per function; `0` disables history RPCs |
| `-tls-cert` | `LUX_TLS_CERT` | empty | PEM certificate for the native listener |
| `-tls-key` | `LUX_TLS_KEY` | empty | PEM private key for the native listener |
| `-command-timeout` | `LUX_COMMAND_TIMEOUT` | `1h` | Idle timeout after authentication |
| `-hello-timeout` | `LUX_HELLO_TIMEOUT` | `15s` | Deadline for the initial hello packet |
| `-pull-timeout` | `LUX_PULL_TIMEOUT` | `4m` | Database deadline for pull and popular-function queries |
| `-shutdown-timeout` | `LUX_SHUTDOWN_TIMEOUT` | `10s` | Graceful HTTP shutdown window |

Set `LUX_LOG_LEVEL=debug` to include protocol and HTTP request diagnostics.
Invalid boolean, unsigned-integer, and duration environment values fall back to
their defaults.

## Authentication and authorization

Lux keeps native IDA accounts in PostgreSQL and stores passwords as bcrypt
hashes. Usernames are matched case-insensitively.

The first account is created at startup from `LUX_USERNAME` and `LUX_PASSWORD`.
It receives both official feature flags:

- `UF_IS_ADMIN`
- `UF_CAN_DEL_HISTORY`

Every enabled account with a password can pull, push, and read function
history. Administrator and history-deletion flags are independent profile
attributes. Native deletion additionally requires the global
`LUX_ALLOW_DELETES=true` setting.

Account rules enforced by the service:

- Usernames are 1–128 bytes and cannot contain control characters, `/`, or `\`.
- Passwords are 8–72 bytes.
- License IDs are empty or use `XX-XXXX-XXXX-XX` hexadecimal notation.
- Email values are optional, limited to 320 bytes, and cannot contain control
  characters.
- Accounts without a password cannot authenticate.
- The final enabled account cannot be disabled or deleted.
- Password, profile, privilege, disable, and delete operations revoke that
  account's active sessions immediately.
- Deleting an account does not remove its historical username attribution.

The management bearer token is separate from native IDA credentials. Account
and session administration always requires a configured bearer token. Other
mutations require the token when one is configured.

## Native protocol behavior

Lux implements the native packet framing and positional encoding used by the
public Lumina SDK:

```text
┌──────────────────────┬──────────────┬─────────────────────┐
│ 4-byte payload length│ 1-byte opcode│ encoded payload ... │
│ big-endian           │              │                     │
└──────────────────────┴──────────────┴─────────────────────┘
```

Supported transactions:

| Transaction | Behavior |
|---|---|
| Hello | Requires username and password; versions 3–4 receive `OK`, newer versions receive a full user profile |
| Pull metadata | Returns the selected record for each known 16-byte function hash |
| Push metadata | Records the push, stores changed versions, and updates selection according to push mode |
| Get histories | Returns newest-first immutable records up to `LUX_HISTORY_LIMIT` |
| Delete history | Removes all stored versions for requested hashes when both privilege and global policy allow it |
| Get popular | Returns selected functions ordered by observed pull frequency |
| Get server info | Returns peer, user, session, server-version, start-time, and current-time fields |

Pulls increment the persisted function frequency unless the client sends
`PULL_MD_SEEN_FILE`. Repeated occurrences of the same hash in one request share
the same resulting frequency value.

See [Compatibility](docs/COMPATIBILITY.md) for exact status, deliberate
extensions, and behaviors that still require validation against IDA.

## Metadata and history

Each native push stores:

- The authenticated username, license ID, and email snapshot.
- The IDA license bytes and client hostname.
- The input-file path and MD5.
- The IDB path and protocol version.
- Submitted and changed function counts.
- An immutable revision for every changed function.

Lux keeps every contribution while selecting one current record per function
hash. The default push mode replaces the selected record only when the incoming
metadata score is higher. Force-override always selects the incoming revision;
do-not-override selects it only when no record exists. Equal or lower-scoring
revisions remain available in history.

Metadata is stored losslessly as IDA chunks. Lux decodes and edits the public
formats for:

- Serialized function types.
- Decompiler elapsed time.
- Function and instruction comments.
- Repeatable comments.
- Anterior and posterior comments.
- User-defined stack points.

Frame descriptions, operand representations, malformed chunks, and unknown
future keys retain their exact payload bytes. Editing another field does not
discard those opaque chunks.

Administrative edits and restores create new push and revision records instead
of silently rewriting history.

## Architecture

```mermaid
flowchart LR
    IDA["IDA clients"] -->|"native TCP or TLS :1234"| RPC["Lumina service"]
    Browser["Web browser / API client"] -->|"HTTP :8080"| Web["Management service"]
    RPC --> Auth["Authentication and policy"]
    Web --> Auth
    RPC --> Store["Store and selection logic"]
    Web --> Store
    Auth --> PG[("PostgreSQL")]
    Store --> PG
    Metrics["Health and Prometheus metrics"] --> Web
```

The native and management listeners share one process, one PostgreSQL-backed
store, one authentication service, and one live-session registry. Frontend
HTML, CSS, and JavaScript are embedded with `go:embed`; no frontend build step
or external asset server is required.

## Operations

### Health check

`GET /healthz` performs a database-backed statistics query:

```bash
curl --fail http://127.0.0.1:8080/healthz
```

```json
{"functions":0,"status":"ok"}
```

The endpoint returns `503 Service Unavailable` when PostgreSQL cannot answer.

### Metrics

`GET /metrics` exposes:

- `lux_active_connections`
- `lux_connections_total`
- `lux_pushes_total`
- `lux_new_functions_total`
- `lux_pulls_total`
- `lux_queried_functions_total`
- `lux_rpc_failures_total`
- `lux_protocol_connections_total{version="..."}`

### Backup and restore

The Compose stack stores database files in the `postgres-data` volume. Use
PostgreSQL-native tools for portable backups:

```bash
docker compose exec -T postgres \
  pg_dump --clean --if-exists --no-owner --username lux lux > lux.sql
```

Restore into an empty or disposable database:

```bash
docker compose exec -T postgres \
  psql --username lux --dbname lux < lux.sql
```

> [!CAUTION]
> A restore can overwrite existing database objects. Inspect the target and
> backup file before running it against a production deployment.

### Upgrades

Build the new image and recreate only the application container:

```bash
docker compose up --build -d lux
docker compose logs --tail=100 lux
curl --fail http://127.0.0.1:8080/healthz
```

Lux runs idempotent schema migrations before it opens either listener.

## Development

Start the test database:

```bash
docker compose up -d postgres
export LUX_TEST_DATABASE_URL='postgres://lux:lux@127.0.0.1:55432/lux?sslmode=disable'
```

Run the complete suite:

```bash
make test
make coverage
go vet ./...
go build ./cmd/lux
```

Database tests create isolated PostgreSQL schemas and remove them afterward.
They skip when `LUX_TEST_DATABASE_URL` is unset. CI always supplies PostgreSQL,
runs the race detector, enforces at least 90% statement coverage, executes the
IDA scoring-oracle tests, and builds Lux on Linux, macOS, and Windows.

To capture authoritative metadata-score fixtures from IDA 9.3 or newer:

```bash
ida -A \
  -S"/absolute/path/to/tools/ida/export_lumina_scores.py /tmp/ida-scores.json" \
  sample.i64
```

The exporter records exact metadata bytes and the score returned by
`ida_lumina.score_metadata()`. It does not upload the IDB or function bytes.

## Compatibility

Lux follows the public IDA SDK structures and the documented private-server
behavior. It is not presented as a byte-for-byte clone of every commercial
server component.

The current compatibility matrix and primary sources are maintained in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Documentation

- [Management API](docs/MANAGEMENT_API.md)
- [Native compatibility matrix](docs/COMPATIBILITY.md)
- [Hex-Rays Lumina server guide](https://docs.hex-rays.com/admin-guide/lumina-server)
- [Hex-Rays client and administration reference](https://docs.hex-rays.com/user-guide/lumina/lc_user_manual)
- [IDA C++ Lumina SDK](https://cpp.docs.hex-rays.com/lumina_8hpp.html)
- [IDA Python Lumina API](https://python.docs.hex-rays.com/ida_lumina/index.html)

## License

Lux is released under the [MIT License](LICENSE).
