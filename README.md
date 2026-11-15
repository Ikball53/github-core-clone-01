# Forge — a single-file GitHub-compatible git forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Ikball53/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Ikball53/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

> Built for the [github-core-clone-01 bounty](https://make.fun/bounty/github-core-clone-01) on make.fun.

One Node process that behaves like a small GitHub: smart-HTTP git
(clone and push), the REST v3 surface for repos, issues, pull requests
and file contents, a GraphQL v4 endpoint, and an MCP server with the six
repository tools. Zero dependencies, everything in memory, nothing
written to disk.

## Run it

```sh
MAKEFUN_SHOP_TOKEN=secret PORT=8080 node main.ts
```

With no `MAKEFUN_ENV_URL` set the server simply serves forever. Under the
competition harness it registers itself, serves until the coordinator
reports done, then exits.

Environment:

| Variable | Meaning |
| --- | --- |
| `MAKEFUN_SHOP_TOKEN` | Bearer token clients must present |
| `MAKEFUN_ENV_URL` | Coordinator URL (register / done polling) |
| `MAKEFUN_TRIAL_NOW` | Frozen "now" used for every timestamp |
| `PORT` | Port to listen on (`0` picks one) |

## What it serves

- **Git** — upload-pack v0 and v2 (`ls-refs`, `fetch`, shallow and
  deepen), receive-pack v0 with report-status and fast-forward
  enforcement. Packs are written with no deltas; incoming packs may
  carry ofs-delta and ref-delta entries. Shallow boundaries are
  honoured on both sides of a fetch.
- **REST v3** — repo CRUD, branches, commits, contents (create, read,
  update, delete, with branch creation from the default tip), labels,
  issues (create, list with state/sort/direction, read, close,
  comments), pull requests (create, list, files, squash merge with
  real conflict detection and a real merge commit).
- **GraphQL v4** — viewer, repository, node, `__type` introspection,
  issue and pull-request connections with cursor pagination, and the
  `createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`
  and `addComment` mutations. Global ids are opaque base64 tokens.
- **MCP** — Streamable HTTP JSON-RPC 2.0: `server/discover`,
  `initialize`, `tools/list` (byte-stable), `tools/call` for
  `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`.

## How it stays fast

- Issue reads are served from a pre-serialised JSON string per issue,
  rebuilt only when the issue changes.
- Git advertisements are cached per repository and rebuilt only when a
  ref moves.
- Fetch closures walk only as far as they must: depth-limited walks
  stop at the depth boundary, incremental fetches prune at objects the
  client already holds, and shallow boundaries are never crossed.
- Pack building writes whole objects with a single deflate each — no
  delta search, no re-compression of cached data.

## Layout

```
main.ts    the whole forge
README.md  this file
LICENSE    MIT
```

## License

MIT — see `LICENSE`.
