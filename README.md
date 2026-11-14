# Forge

A single-file, zero-dependency, in-memory GitHub-compatible forge, written for Node 22.

## What it does

Forge speaks the protocols a Git client and a GitHub API client expect, all from one process and one in-memory store:

- **Git wire protocol** — smart HTTP for `git-upload-pack` and `git-receive-pack`, both protocol v2 (`ls-refs`, `fetch`, shallow deepen, ACK/NAK) and protocol v0 (advertisement, sideband pack, report-status, non-fast-forward refusals).
- **REST v3** — repositories, refs, branches, commits, contents, labels, issues, comments, and pull requests with squash merge.
- **GraphQL** — viewer, repository, issue and pull-request queries, connection pagination with opaque cursors, `__type` introspection, and the issue/pull-request/comment mutations.
- **MCP** — JSON-RPC 2.0 over Streamable HTTP (`server/discover`, `initialize`, `tools/list`, `tools/call`) with six tools that act on the same store as REST.

## How it stays fast

Everything lives in memory: objects are hashed and stored once, trees and commits are parsed on demand, and the hot paths reuse pre-built results instead of recomputing them on every request.

- Packs are built directly from stored objects, with delta resolution done once at unpack time.
- A depth-1 clone of an unchanged tip is served from a cached response.
- Issue bodies are serialized once when an issue changes and served as-is afterwards.
- Commits and trees use fixed timestamps, so a replay produces byte-identical state.

## Run

```sh
MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts
```

With no `MAKEFUN_ENV_URL` set, the server prints the port it bound and keeps serving. With `MAKEFUN_ENV_URL` set, it registers that port with the environment, then exits when the environment reports it is done.

## Layout

- `main.ts` — the whole forge.
- `LICENSE` — MIT.
- `.makefun/owner.json` — the owner's wallet.

## Notes on determinism

No wall clock and no unseeded randomness appear in anything the server sends back. Object ids are content hashes, timestamps are fixed, and every id the server mints comes from a counter, so the same sequence of requests always leaves the same state behind.
