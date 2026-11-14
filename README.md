# Forge — a GitHub-compatible git forge in one file

A single-process, standard-library-only Node 22 implementation of a
GitHub-compatible git forge. It serves four surfaces from one in-memory
store:

- **Git smart HTTP** at `/{owner}/{repo}.git` — `git-upload-pack` protocol
  v2 (with a v0 fallback) and `git-receive-pack` v0. Packfiles are parsed
  (zlib inflate, SHA-1 objects, OFS/REF deltas) and generated (full objects,
  no deltas) in-process; there is no git binary anywhere. Pushes are
  fast-forward only: a non-fast-forward ref is refused with
  `ng <ref> non-fast-forward` while the other refs in the same push still
  apply.
- **REST v3** at `/api/v3` — repos, branches, commits, file contents,
  labels, issues, comments and pull requests (including squash merge with
  three-way conflict detection). Every reply is JSON with a non-empty
  `X-GitHub-Request-Id` header.
- **GraphQL** at `/api/graphql` — `viewer`, `repository`, `node` (Relay
  global ids), issues/pull-request connections with cursor pagination,
  introspection, and the `createIssue`, `closeIssue`, `createPullRequest`,
  `mergePullRequest` and `addComment` mutations. Batched operation
  documents answer in order.
- **MCP** at `/mcp` — JSON-RPC 2.0 Streamable HTTP: `server/discover`
  (revision `2026-07-28`) and the legacy `initialize` handshake, plus six
  tools (`create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`) that act on the same store
  as REST and GraphQL.

## Running it

```sh
MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts
```

- It binds an ephemeral port (or `$PORT`) on `127.0.0.1` and logs the port.
- With `MAKEFUN_ENV_URL` set it registers with
  `POST $MAKEFUN_ENV_URL/register`, then long-polls
  `GET $MAKEFUN_ENV_URL/done` until `{"done": true}` and exits 0.
  Without it, it just serves and stays up (local development).
- `GET /healthz` answers 200.
- Authentication: when `MAKEFUN_SHOP_TOKEN` is set, REST, GraphQL and MCP
  require `Authorization: Bearer <token>` (401 otherwise). Git endpoints
  do not enforce auth. The authenticated user is the scenario viewer
  `adaiversen`; a repo name under another owner is 404, never 403.

## Determinism

No wall clock or unseeded randomness reaches state or responses: every
timestamp is a fixed constant (or `MAKEFUN_TRIAL_NOW` when set), ids come
from counters, and ordering is stable everywhere.

## Layout

- `main.ts` — the whole forge (about 3,300 lines, stdlib only).
- `github-core-clone-01-kit/` — the competition kit (spec, suite source,
  local runner); not part of the entry.
