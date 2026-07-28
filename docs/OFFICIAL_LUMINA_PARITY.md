# Official Lumina compatibility

Lux targets the behavior exposed by current IDA clients, the public `ida_lumina`
and `lumina.hpp` SDK interfaces, the Hex-Rays Lumina server administrator guide,
and the `lc` command reference.

The sibling Lumen source tree was useful during initial packet discovery, but it
is not a behavioral specification for Lux.

## Normative references

- [Lumina server administrator guide](https://docs.hex-rays.com/admin-guide/lumina-server)
- [`lc` command reference](https://docs.hex-rays.com/user-guide/lumina/lc_user_manual)
- [IDA Lumina user actions](https://docs.hex-rays.com/ida-9.2/user-guide/user-interface/menu-bar/common-actions-3)
- [`ida_lumina` Python API](https://python.docs.hex-rays.com/ida_lumina/index.html)
- [`lumina.hpp` C++ API](https://cpp.docs.hex-rays.com/lumina_8hpp.html)

## Compatibility matrix

| Official behavior | Lux status |
|---|---|
| Credential-bearing hello and user profile response | Implemented for native IDA protocol versions 3+ |
| Metadata pull and per-function result codes | Implemented |
| Metadata push and per-function result codes | Implemented |
| Replace current metadata only when the submitted metadata is better | Implemented |
| Explicit override and do-not-override push modes | Implemented |
| Server-side metadata merge push mode | Planned |
| Exact `score_metadata()` parity | Oracle exporter implemented; real IDA fixtures required |
| Immutable push and accepted-change history | Implemented |
| Function-history retrieval and deletion | Implemented |
| Pull frequency and `PULL_MD_SEEN_FILE` behavior | Implemented |
| Popular-functions RPC (`PKT_GET_POP`) | Planned |
| Server-information RPC (`PKT_GET_LUMINA_INFO`) | Planned |
| Regular users plus `UF_IS_ADMIN` and `UF_CAN_DEL_HISTORY` flags | Implemented |
| `lc info`, users, statistics, history, and session administration behavior | Exposed through the management API and console |
| Wire-compatible `lc` administration protocol | Not yet implemented |
| Teams/Vault delegated identity | Not implemented |
| Telemetry and decompiler features | Not implemented |

## Deliberate Lux extensions

The embedded HTTP management console, JSON API, PostgreSQL backend,
Prometheus endpoint, TLS configuration, semantic metadata explorer, and
Lumen-compatible read-only HTTP aliases are Lux extensions. They must not
change the native Lumina RPC results returned to IDA.

## Scoring authority

Hex-Rays exports `ida_lumina.score_metadata(func_info_t)` but does not publish
its implementation. `tools/ida/export_lumina_scores.py` extracts real function
metadata and the score returned by IDA 9.3 or newer. This workspace has no IDA
installation, so no fixture is presented as authoritative yet. The current Go
scorer remains provisional until fixtures produced by a licensed IDA
installation are added and its results are proven against them.

Lux does not add contributor trust, review weights, or project-specific ranking
to native pull selection.
