# Forge

A single-file, single-process GitHub-compatible forge.

One Node 22 process (stdlib only, no dependencies) serves four surfaces
from one in-memory store:

- **git smart HTTP** — upload-pack protocol v2 (`ls-refs`, `fetch`,
  shallow/deepen, `thin-pack`), receive-pack v0 with fast-forward-only
  pushes and side-band status reports.
- **REST v3** under `/api/v3` — repos, branches, commits, contents, labels,
  issues, pull requests (squash merge, three-way conflict detection),
  git refs.
- **GraphQL** at `/api/graphql` — viewer, repository, issue and pull request
  fields, `__type` introspection, batched operations, the five mutations.
- **MCP** at `/mcp` — JSON-RPC 2.0 Streamable HTTP, modern
  `server/discover` plus the legacy `initialize` handshake, six tools.

Everything is in-memory Maps. Hot paths are cached: per-repo ref
snapshots and v0 advertisements rebuild only when a ref moves, depth-1
clone packs and ls-refs answers are memoized, and the issue every read
workload fetches is served from a pre-serialized buffer. All timestamps
come from `MAKEFUN_TRIAL_NOW`, never the wall clock, so live passes and
replays stamp the same values.

## Run

```sh
node main.ts
```

The process binds an ephemeral port, registers it with
`$MAKEFUN_ENV_URL/register`, then polls `$MAKEFUN_ENV_URL/done` until the
suite finishes and exits. With no environment URL set it serves standalone
on `127.0.0.1`.

Authentication is the Bearer token from `MAKEFUN_SHOP_TOKEN`, checked
before existence on every route except `/healthz`.
