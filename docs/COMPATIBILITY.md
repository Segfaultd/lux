# Native Lumina compatibility

Lux targets the native behavior exposed by current IDA clients and the public
Lumina SDK. This document distinguishes implemented wire behavior, Lux
management extensions, and areas that cannot yet be claimed as exact.

## Primary references

- [Lumina server administrator guide](https://docs.hex-rays.com/admin-guide/lumina-server)
- [`lc` command reference](https://docs.hex-rays.com/user-guide/lumina/lc_user_manual)
- [IDA Lumina user actions](https://docs.hex-rays.com/ida-9.2/user-guide/user-interface/menu-bar/common-actions-3)
- [`ida_lumina` Python API](https://python.docs.hex-rays.com/ida_lumina/index.html)
- [`lumina.hpp` C++ API](https://cpp.docs.hex-rays.com/lumina_8hpp.html)
- [`lumina.hpp` source reference](https://cpp.docs.hex-rays.com/lumina_8hpp_source.html)

## Compatibility matrix

| Behavior | Status | Lux implementation |
|---|---|---|
| Credential-bearing hello | Implemented | Protocol versions 3+ require a database-managed username and password |
| Legacy hello result | Implemented | Protocol versions 3–4 receive `PKT_OK` |
| Full user hello result | Implemented | Protocol versions 5+ receive the SDK user structure; Lux fills identity and feature flags and currently reports zero for karma and last-active time |
| Metadata pull | Implemented | Per-pattern results preserve request order and return the selected revision |
| Metadata push | Implemented | Push identity, project, versions, and immutable changes are committed in one transaction |
| Default better-score selection | Implemented | The incoming revision is selected only when its score exceeds the selected score |
| Force-override mode | Implemented | The incoming changed revision becomes selected |
| Do-not-override mode | Implemented | The incoming revision is selected only when the hash has no existing record |
| Server-side merge mode | Partial | The flag is accepted, but Lux applies default score selection and does not merge metadata chunks |
| Pull frequency | Implemented | Successful pulls increment a PostgreSQL-backed counter |
| `PULL_MD_SEEN_FILE` | Implemented | Returns the current frequency without incrementing it |
| Popular-functions RPC | Implemented | Returns selected metadata, pattern, frequency, source host/file/MD5, and address |
| Server-information RPC | Implemented | Returns client session/user fields and server version/start/current time |
| Function histories | Implemented | Returns immutable revisions newest first, limited by `LUX_HISTORY_LIMIT` |
| Native history deletion | Implemented | Requires `LUX_ALLOW_DELETES` and the account deletion privilege |
| `UF_IS_ADMIN` | Implemented | Stored independently on each account and returned in the user profile |
| `UF_CAN_DEL_HISTORY` | Implemented | Stored independently and advertised only while deletion is globally enabled |
| Per-user statistics | Implemented as HTTP management | Counts functions, pushes, history, IDBs, and input files |
| Push and history filters | Implemented as HTTP management | Supports identity, path, hash, ID range, time range, and ordering filters |
| Live session administration | Implemented as HTTP management | Lists and terminates native connections |
| Wire-compatible `lc` administration | Not implemented | Use the embedded console or JSON API |
| Teams and Vault delegated identity | Not implemented | Lux accounts authenticate directly |
| Telemetry service | Not implemented | No telemetry packets are accepted or stored |
| Decompiler service features | Not implemented | Lux implements function metadata synchronization only |

## Operation result values

The public SDK defines:

| Value | SDK name | Meaning |
|---:|---|---|
| `-3` | `PDRES_BADPTN` | Invalid pattern |
| `-2` | `PDRES_NOT_FOUND` | Pattern not found |
| `-1` | `PDRES_ERROR` | Operation error |
| `0` | `PDRES_OK` | Existing pattern accepted or resolved |
| `1` | `PDRES_ADDED` | Previously unknown pattern added |

Lux validates function patterns as 16-byte hashes before they reach the store.
Malformed requests receive a protocol failure packet. Push results use
`PDRES_ADDED` only when the function hash was globally unknown before the
transaction; an additional contribution for a known hash receives
`PDRES_OK`.

## Push modes

The low nibble of the push flags selects the mode:

| Value | SDK definition | Lux behavior |
|---:|---|---|
| `0x0` | `PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT` | Select only when the submitted score is higher |
| `0x1` | `PMF_PUSH_OVERRIDE` | Select the submitted changed revision |
| `0x2` | `PMF_PUSH_DO_NOT_OVERRIDE` | Preserve any existing selection |
| `0x3` | `PMF_PUSH_MERGE` | Store the revision and apply default score selection; no chunk merge |

Every changed submission remains in history regardless of whether it becomes
the selected record. Repeating identical content from the same project updates
the stored address when necessary but does not create a duplicate revision.

## Metadata keys

Lux recognizes every key currently enumerated by the public SDK:

| Code | SDK field | Structured support |
|---:|---|---|
| `1` | Serialized function type | Decoded and editable |
| `2` | Decompiler elapsed time | Decoded and editable |
| `3` | Function comment | Decoded and editable |
| `4` | Repeatable function comment | Decoded and editable |
| `5` | Instruction comments | Decoded and editable |
| `6` | Repeatable instruction comments | Decoded and editable |
| `7` | Anterior/posterior comments | Decoded and editable |
| `8` | User-defined stack points | Decoded and editable |
| `9` | Frame description | Identified and preserved as opaque bytes |
| `10` | Operand representations | Identified and preserved as opaque bytes |
| `11` | Extended operand representations | Identified and preserved as opaque bytes |

All chunks retain their original payload. Unknown keys and payloads that cannot
be decoded are preserved, displayed as hexadecimal, and reproduced
byte-for-byte when untouched.

## Metadata scoring

IDA exposes `ida_lumina.score_metadata(func_info_t)` but does not publish its
implementation. Lux currently assigns ten points for each useful decoded
comment and excludes known compiler/runtime and switch-analysis boilerplate.

This scorer is deliberately described as provisional. The repository includes
[`tools/ida/export_lumina_scores.py`](../tools/ida/export_lumina_scores.py),
which exports:

- The function address and name.
- The exact metadata byte sequence.
- The score returned by the installed IDA release.

Run it from IDA 9.3 or newer:

```bash
ida -A \
  -S"/absolute/path/to/tools/ida/export_lumina_scores.py /tmp/ida-scores.json" \
  sample.i64
```

Fixtures produced by a licensed IDA installation are required before exact
scoring parity can be claimed.

## Deterministic selection

Lux serializes concurrent submissions for the same hash with a PostgreSQL
transaction advisory lock. The selected revision is explicit in the history
table. Reads then order by:

1. Selected status.
2. Score descending.
3. Revision ID ascending.

This makes pull results deterministic even when multiple revisions have equal
scores.

## Lux management extensions

The following features are intentionally outside the native protocol:

- Embedded browser console.
- Versioned JSON management API.
- PostgreSQL schema management.
- Semantic metadata explorer and diff engine.
- Administrative metadata edits and restores.
- Live session registry and termination.
- Prometheus metrics and database-backed health checks.
- Optional read-only compatibility HTTP routes.

These extensions operate on the same store but do not add project trust,
review weights, or user-specific ranking to native metadata selection.
