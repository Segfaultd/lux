# Lux

Lux is a compact, private [IDA Lumina](https://hex-rays.com/products/ida/lumina/) server written in Go. It speaks the Lumina RPC protocol used by IDA 7.2 and later, stores function metadata in a single SQLite file, and serves its management console from the same executable.

Lux was independently implemented from the protocol behavior in the sibling `lumen` source tree. It does not depend on Lumen at build or run time. The detailed source analysis and compatibility map are in [`docs/LUMEN_ANALYSIS.md`](docs/LUMEN_ANALYSIS.md).

## What it supports

- Lumina protocol versions 0 through 5 and newer
- IDA hello/login, metadata pull, metadata push, delete history, and function history RPCs
- Lumen-compatible best-metadata scoring and selection
- SQLite persistence with WAL, foreign keys, and automatic schema creation
- Optional TLS with a PEM certificate and key
- Embedded management dashboard with function/file search, metadata histories, decoded comments, and protected deletion
- JSON management API, Lumen-compatible read-only HTTP routes, health check, and Prometheus metrics
- One static, CGO-free binary and a small scratch-based container image

## Quick start

Go 1.25 or newer is required.

```sh
go build -o lux ./cmd/lux
./lux -admin-token 'choose-a-secret'
```

The defaults are:

- Lumina protocol: `0.0.0.0:1234`
- Management console: `http://localhost:8080`
- Database: `./lux.db`
- IDA credentials: username `guest`, any password

Container deployment:

```sh
export LUX_ADMIN_TOKEN='choose-a-secret'
docker compose up --build -d
```

## Configure IDA

In IDA 8.1 or later, open **Options → General → Lumina**, select **Use a private server**, and set:

- Host: the Lux host
- Port: `1234` (or your configured port)
- Username: `guest`
- Password: any value unless `LUX_PASSWORD` is configured

For plaintext operation, launch IDA with `LUMINA_TLS=false` in its environment. For older IDA releases, set `LUMINA_HOST`, `LUMINA_PORT`, and `LUMINA_TLS = NO` in `ida.cfg` or `idauser.cfg`.

## Configuration

Every option has a command-line flag and an environment variable:

| Flag | Environment | Default | Purpose |
|---|---|---:|---|
| `-lumina-addr` | `LUX_LUMINA_ADDR` | `:1234` | IDA protocol listener |
| `-http-addr` | `LUX_HTTP_ADDR` | `:8080` | Management listener |
| `-database` | `LUX_DATABASE` | `lux.db` | SQLite file |
| `-server-name` | `LUX_SERVER_NAME` | `lux` | Name shown to clients |
| `-username` | `LUX_USERNAME` | `guest` | IDA login username |
| `-password` | `LUX_PASSWORD` | empty | Empty accepts any password |
| `-admin-token` | `LUX_ADMIN_TOKEN` | empty | Bearer token for web deletion |
| `-allow-deletes` | `LUX_ALLOW_DELETES` | `false` | Enable RPC and web deletion |
| `-history-limit` | `LUX_HISTORY_LIMIT` | `50` | Histories per hash; 0 disables |
| `-tls-cert` | `LUX_TLS_CERT` | empty | PEM server certificate |
| `-tls-key` | `LUX_TLS_KEY` | empty | PEM private key |

Set `LUX_LOG_LEVEL=debug` for protocol and request diagnostics.

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

Deletion must be enabled with `LUX_ALLOW_DELETES=true`. If an admin token is configured, send `Authorization: Bearer <token>`; the browser console keeps it only in session storage.

Compatibility aliases are available at `GET /api/files/{md5}` and `GET /api/funcs/{hash}`.

The management listener serves plain HTTP. Bind it to localhost or put it behind an HTTPS reverse proxy when it is reachable over an untrusted network; bearer tokens should never travel over unencrypted public connections.

## Design notes from Lumen

The sibling Lumen project has four important layers:

1. A TCP/TLS listener performs a hello exchange, then handles a stream of request/response transactions.
2. Packets use a four-byte big-endian payload length, one message-code byte, and a positional compact encoding. Integers are variable-width; strings are NUL-terminated; byte arrays and sequences carry packed lengths.
3. PostgreSQL records identities, input files, IDA databases, and function metadata versions. Pull chooses the highest-scoring metadata for each 128-bit function hash.
4. A separate Warp server exposes a small read-only HTTP API and Prometheus metrics.

Lux preserves the behavior that matters to IDA while changing the operations model: a standard-library Go server, embedded UI, and local SQLite database replace the Rust async stack, PostgreSQL, and separate minimal web page. Function versions remain isolated by contributor/database rather than being merged. Pulls deterministically choose score, update time, then row ID.

## Development

```sh
go test ./...
make coverage
go vet ./...
go build ./cmd/lux
```

The unit and integration suite covers every package and CI enforces at least 90% statement coverage. No frontend build step is necessary because the console assets are embedded with `go:embed`.
