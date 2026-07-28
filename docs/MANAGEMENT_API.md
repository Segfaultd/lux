# Management API

Lux serves its browser console and JSON API from the management listener,
`LUX_HTTP_ADDR` (`:8080` by default).

## Conventions

### Base URL

Examples in this document use:

```text
http://127.0.0.1:8080
```

### Authentication

Pass the configured `LUX_ADMIN_TOKEN` as a bearer token:

```bash
curl \
  --header 'Authorization: Bearer replace-with-management-token' \
  http://127.0.0.1:8080/api/v1/accounts
```

Access rules:

| Request class | Requirement |
|---|---|
| Read-only storage and configuration endpoints | No token |
| Account and session endpoints | A configured and valid token |
| Other mutations | Valid token when `LUX_ADMIN_TOKEN` is configured |
| Destructive mutations | `LUX_ALLOW_DELETES=true`, plus a valid token when configured |

If no management token is configured, account and session administration
returns `403 Forbidden`; it is never exposed without authentication.

### Content type and errors

JSON responses use `application/json` and `Cache-Control: no-store`. Mutation
requests accept one JSON object up to 16 KiB, reject unknown fields, and reject
trailing JSON values.

Errors have a stable envelope:

```json
{
  "error": "human-readable message"
}
```

### Pagination

Collection endpoints accept:

| Parameter | Default | Range |
|---|---:|---:|
| `limit` | `50` | `1`–`500` |
| `offset` | `0` | `0` or greater |

Invalid values fall back to the defaults. Paginated responses contain
`items`, `limit`, and `offset`.

## Service endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Database-backed liveness check |
| `GET` | `/metrics` | Prometheus text exposition |
| `GET` | `/api/v1/config` | Public runtime configuration |
| `GET` | `/api/v1/stats` | Aggregate storage statistics |
| `GET` | `/api/v1/stats?username=alice,bob` | Statistics for 1–100 named users |

Example:

```bash
curl http://127.0.0.1:8080/api/v1/config
```

```json
{
  "account_management": true,
  "admin_protected": true,
  "allow_deletes": false,
  "history_limit": 50,
  "lumina_addr": ":1234",
  "server_name": "lux",
  "tls": false
}
```

The aggregate statistics response includes function hashes, versions, files,
native client identities, accounts, projects/IDBs, pushes, and history records.

## Functions and files

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/functions` | List selected functions |
| `GET` | `/api/v1/functions/{hash}` | List every stored version of a 16-byte function hash |
| `DELETE` | `/api/v1/functions/{hash}` | Delete every version and revision for a hash |
| `GET` | `/api/v1/files` | List input files |
| `GET` | `/api/v1/files/{md5}/functions` | List functions associated with an input-file MD5 |

Function and file collections accept `q`, `limit`, and `offset`. Function
search matches function names and hexadecimal hashes. File search matches paths
and hexadecimal MD5 values.

Hashes and MD5 values contain exactly 32 hexadecimal characters.

```bash
curl \
  'http://127.0.0.1:8080/api/v1/functions?q=decrypt&limit=25'
```

## Projects / IDBs

A project represents one contributed IDB identity: input file, client identity,
IDB path, and authenticated username.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/projects` | List projects |
| `GET` | `/api/v1/projects/{id}` | Get a project and its function versions |
| `PATCH` | `/api/v1/projects/{id}` | Change the recorded input-file or IDB path |
| `DELETE` | `/api/v1/projects/{id}` | Delete a project and its versions |

The collection accepts `q`, `limit`, and `offset`.

Update example:

```bash
curl --request PATCH \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{
    "file_path": "/srv/samples/program.bin",
    "idb_path": "/srv/idbs/program.i64"
  }' \
  http://127.0.0.1:8080/api/v1/projects/42
```

At least one of `file_path` or `idb_path` is required.

## Metadata versions

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/metadata/{id}` | Get a raw metadata version |
| `PATCH` | `/api/v1/metadata/{id}` | Edit its name, length, or metadata bytes |
| `DELETE` | `/api/v1/metadata/{id}` | Delete one metadata version |
| `GET` | `/api/v1/metadata/{id}/structured` | Inspect metadata as lossless chunks |
| `PATCH` | `/api/v1/metadata/{id}/structured` | Apply ordered chunk mutations |

Raw metadata is represented as hexadecimal:

```bash
curl --request PATCH \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{
    "name": "parse_header",
    "length": 96,
    "metadata": "03087265766965776564"
  }' \
  http://127.0.0.1:8080/api/v1/metadata/17
```

Every field is optional, but at least one must be present.

### Structured mutations

A request contains one or more ordered mutations:

| Operation | Required fields | Behavior |
|---|---|---|
| `set` | `index` and one value | Replaces the payload of an existing chunk without changing its code |
| `remove` | `index` | Removes an existing chunk |
| `append` | non-zero `code` and one value | Appends a new chunk |

Exactly one value is accepted:

- `payload`: raw hexadecimal for any key.
- `text`: function-comment keys.
- `elapsed_seconds`: decompiler elapsed-time key.
- `type`: serialized type fields.
- `comments`: instruction or extra-comment keys.
- `stack_points`: user-defined stack-point key.

Example:

```bash
curl --request PATCH \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{
    "mutations": [
      {
        "operation": "set",
        "index": 1,
        "text": "reviewed"
      },
      {
        "operation": "append",
        "code": 99,
        "payload": "deadbeef"
      }
    ]
  }' \
  http://127.0.0.1:8080/api/v1/metadata/17/structured
```

Untouched chunks, including unknown keys, retain their exact bytes.
Administrative edits create auditable push and history records.

## Push audit

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/pushes` | List native and administrative pushes |
| `GET` | `/api/v1/pushes/{id}` | Get a push and all changed functions |
| `DELETE` | `/api/v1/pushes/{id}` | Delete a push and reconcile affected selections |

Filters:

| Parameter | Match |
|---|---|
| `q` | Username, hostname, IDB path, input path, or input MD5 |
| `username` | Exact username, case-insensitive |
| `license_id` | Exact license ID, case-insensitive |
| `project_id` | Positive project/IDB ID |
| `from` | Inclusive RFC3339 lower timestamp |
| `to` | Inclusive RFC3339 upper timestamp |
| `chronological` | `true` for oldest-first; default is newest-first |

Example:

```bash
curl \
  'http://127.0.0.1:8080/api/v1/pushes?username=analyst&from=2026-01-01T00%3A00%3A00Z&chronological=true'
```

Push records snapshot the username, license ID, license name, email, hostname,
paths, input MD5, protocol version, and submitted/changed counts at write time.

## Function history

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/history` | List function revisions |
| `GET` | `/api/v1/history/{id}` | Get a revision, its predecessor, decoded documents, and semantic diff |
| `POST` | `/api/v1/history/{id}/restore` | Restore a revision as a new revision |
| `DELETE` | `/api/v1/history/{id}` | Delete a revision and reconcile the selected record |

Filters:

| Parameter | Match |
|---|---|
| `q` | Name, function hash, username, IDB path, or input path |
| `username` | Exact username |
| `license_id` | Exact license ID |
| `name` | Function-name substring |
| `hash` | Exact 32-character function hash |
| `idb` | IDB-path substring |
| `input` | Input-file-path substring |
| `file_md5` | Exact 32-character input MD5 |
| `project_id` | Exact positive project/IDB ID |
| `push_id` | Exact positive push ID |
| `history_id_from` | Inclusive history-ID lower bound |
| `history_id_to` | Inclusive history-ID upper bound |
| `push_id_from` | Inclusive push-ID lower bound |
| `push_id_to` | Inclusive push-ID upper bound |
| `from` | Inclusive RFC3339 timestamp |
| `to` | Inclusive RFC3339 timestamp |
| `chronological` | `true` for oldest-first |

The lower bound of an ID or time range cannot exceed its upper bound.

Restore example:

```bash
curl --request POST \
  --header 'Authorization: Bearer replace-with-management-token' \
  http://127.0.0.1:8080/api/v1/history/105/restore
```

Restore does not rewrite the target record. It creates a new administrative
push and a new immutable revision containing the selected historical value.

## Accounts

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/accounts` | List native IDA accounts |
| `POST` | `/api/v1/accounts` | Create an account |
| `PUT` | `/api/v1/accounts/{username}/password` | Set or rotate a password |
| `PATCH` | `/api/v1/accounts/{username}` | Update status, profile, or privileges |
| `DELETE` | `/api/v1/accounts/{username}` | Delete an account |
| `DELETE` | `/api/v1/accounts/{username}/sessions` | Disconnect all sessions for a username |

Create an account:

```bash
curl --request POST \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{
    "username": "analyst",
    "password": "replace-with-a-long-password",
    "email": "analyst@example.test",
    "license_id": "12-3456-789A-BC",
    "is_admin": false,
    "can_delete_history": false
  }' \
  http://127.0.0.1:8080/api/v1/accounts
```

`password` may be omitted during creation. Such an account remains unable to
authenticate until a password is assigned.

Rotate a password:

```bash
curl --request PUT \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{"password":"new-long-password"}' \
  http://127.0.0.1:8080/api/v1/accounts/analyst/password
```

Update selected fields:

```bash
curl --request PATCH \
  --header 'Authorization: Bearer replace-with-management-token' \
  --header 'Content-Type: application/json' \
  --data '{
    "enabled": true,
    "is_admin": true,
    "can_delete_history": false
  }' \
  http://127.0.0.1:8080/api/v1/accounts/analyst
```

At least one of `enabled`, `email`, `license_id`, `is_admin`, or
`can_delete_history` is required. Password, profile, privilege, disable, and
delete operations revoke active sessions for the affected account.

## Live sessions

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/sessions` | List authenticated native sessions |
| `DELETE` | `/api/v1/sessions/{id}` | Terminate one session |

Session records include:

- Account and username.
- Administrator and deletion flags.
- Remote address and client hostname.
- Protocol version.
- Connection and last-activity timestamps.
- Current and previous operations.
- Request, error, and byte counters.

Termination closes the underlying network connection.

## Read-only compatibility routes

Lux retains two unversioned read-only routes:

| Method | Path | Response |
|---|---|---|
| `GET` | `/api/files/{md5}` | Function name, length, and hash entries for a file |
| `GET` | `/api/funcs/{hash}` | Selected function, decoded comments, and containing files |

New integrations should use `/api/v1/*`.

## Prometheus metrics

| Metric | Type | Description |
|---|---|---|
| `lux_active_connections` | Gauge | Currently open native connections |
| `lux_connections_total` | Counter | Accepted native connections |
| `lux_pushes_total` | Counter | Function metadata submissions processed |
| `lux_new_functions_total` | Counter | Previously unknown function hashes added |
| `lux_pulls_total` | Counter | Metadata records returned |
| `lux_queried_functions_total` | Counter | Function hashes queried |
| `lux_rpc_failures_total` | Counter | Failure packets returned |
| `lux_protocol_connections_total{version}` | Counter | Connections grouped by native protocol version |
