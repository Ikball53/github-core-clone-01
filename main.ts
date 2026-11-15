// Forge — a single-file, zero-dependency, GitHub-compatible git forge.
//
// One Node process serves a whole miniature GitHub over plain HTTP:
//   * smart-HTTP git (upload-pack v0 + v2, receive-pack v0) with real
//     packfiles, shallow fetches, ls-refs and fast-forward enforcement
//   * the REST v3 surface used by everyday git workflows
//   * a GraphQL v4 endpoint covering the queries and mutations that
//     clients such as gh and github-mcp-server send
//   * a Streamable-HTTP MCP server with the six repo tools
//   * the competition lifecycle (register, wait for done, exit)
//
// Everything lives in memory. There are no dependencies, no disk writes
// and no outside services. The only configuration is environment:
//   MAKEFUN_SHOP_TOKEN   bearer token clients must present
//   MAKEFUN_ENV_URL      coordinator URL; without it the server just serves
//   MAKEFUN_TRIAL_NOW    frozen "now" used for every timestamp
//   PORT                 port to listen on (0 = pick one)
//
// Run it with plain `node main.ts` (Node 22+ type stripping).

import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { inflateSync, deflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Configuration and fixed identity
// ---------------------------------------------------------------------------

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_URL = `https://example.invalid/users/${VIEWER_LOGIN}`;

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const EXPECTED_AUTH = SHOP_TOKEN === '' ? null : `Bearer ${SHOP_TOKEN}`;
const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';
const PORT = Number(process.env.PORT ?? 0) || 0;

function trialEpoch(): number {
  const raw = process.env.MAKEFUN_TRIAL_NOW ?? '';
  if (raw !== '') {
    const ms = Date.parse(raw);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return 1700000000;
}
const NOW_EPOCH = trialEpoch();
const NOW_ISO = new Date(NOW_EPOCH * 1000).toISOString();
const ZERO_OID = '0000000000000000000000000000000000000000';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function objectId(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

function b64(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}

function unb64(s: string): string {
  return Buffer.from(s, 'base64').toString('utf8');
}

function jsonText(value: unknown): string {
  return JSON.stringify(value);
}

function gitStamp(): string {
  return `${NOW_EPOCH} +0000`;
}

// ---------------------------------------------------------------------------
// Pkt-line framing (git smart HTTP)
// ---------------------------------------------------------------------------

const FLUSH_PKT = Buffer.from('0000', 'ascii');
const DELIM_PKT = Buffer.from('0001', 'ascii');

function pkt(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

type PktLine =
  | { kind: 'data'; payload: Buffer }
  | { kind: 'flush' }
  | { kind: 'delim' }
  | { kind: 'response-end' };

function readPktLine(buf: Buffer, offset: number): { line: PktLine; next: number } {
  if (offset + 4 > buf.length) throw new Error('truncated pkt-line');
  const hex = buf.toString('ascii', offset, offset + 4);
  const len = parseInt(hex, 16);
  if (!Number.isFinite(len) || len < 0 || len > 65520) throw new Error('bad pkt-line length');
  if (len === 0) return { line: { kind: 'flush' }, next: offset + 4 };
  if (len === 1) return { line: { kind: 'delim' }, next: offset + 4 };
  if (len === 2) return { line: { kind: 'response-end' }, next: offset + 4 };
  if (len < 4 || offset + len > buf.length) throw new Error('truncated pkt-line');
  return { line: { kind: 'data', payload: buf.subarray(offset + 4, offset + len) }, next: offset + len };
}

function decodePktLines(buf: Buffer): PktLine[] {
  const out: PktLine[] = [];
  let off = 0;
  while (off < buf.length) {
    const r = readPktLine(buf, off);
    out.push(r.line);
    off = r.next;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Git object layer
// ---------------------------------------------------------------------------

type ObjKind = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  kind: ObjKind;
  data: Buffer;
}

interface CommitParts {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitParts {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  let tree = '';
  let author = '';
  let committer = '';
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp === -1) break;
    const mode = data.toString('ascii', off, sp);
    const nul = data.indexOf(0x00, sp + 1);
    if (nul === -1) break;
    const name = data.toString('utf8', sp + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    out.push({ mode, name, oid });
    off = nul + 21;
  }
  return out;
}

function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) =>
    treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0,
  );
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function buildCommit(tree: string, parents: string[], message: string): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitStamp()}`;
  let text = `tree ${tree}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${who}\ncommitter ${who}\n\n${message}`;
  return Buffer.from(text, 'utf8');
}

function buildTag(targetOid: string, targetKind: ObjKind, tagName: string, message: string): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitStamp()}`;
  const text =
    `object ${targetOid}\ntype ${targetKind}\ntag ${tagName}\ntagger ${who}\n\n${message}`;
  return Buffer.from(text, 'utf8');
}

// --- packfiles (no deltas on write; deltas understood on read) -------------

const PACK_TYPES: Record<number, ObjKind> = {
  1: 'commit',
  2: 'tree',
  3: 'blob',
  4: 'tag',
};

function writePack(objects: GitObject[]): Buffer {
  const chunks: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  chunks.push(head);
  const typeCode: Record<ObjKind, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
  for (const obj of objects) {
    const code = typeCode[obj.kind];
    let size = obj.data.length;
    const first = (code << 4) | (size & 0x0f);
    size >>= 4;
    const bytes: number[] = [size > 0 ? first | 0x80 : first];
    while (size > 0) {
      bytes.push(size & 0x7f);
      size >>= 7;
      if (size > 0) bytes[bytes.length - 1] |= 0x80;
    }
    chunks.push(Buffer.from(bytes));
    chunks.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(chunks);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readDeltaVarint = (): number => {
    let v = 0;
    let shift = 0;
    while (true) {
      const b = delta[off];
      off += 1;
      v |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return v;
  };
  readDeltaVarint(); // source size (trusted, verified below)
  const targetSize = readDeltaVarint();
  const parts: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off];
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i++) {
        if (op & (1 << i)) {
          cpOff |= delta[off] << (8 * i);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i++) {
        if (op & (0x10 << i)) {
          cpSize |= delta[off] << (8 * i);
          off += 1;
        }
      }
      if (cpSize === 0) cpSize = 0x10000;
      parts.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      parts.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('bad delta opcode 0');
    }
  }
  const out = Buffer.concat(parts);
  if (out.length !== targetSize || total !== targetSize) throw new Error('delta size mismatch');
  return out;
}

function readPack(buf: Buffer): Map<string, GitObject> {
  if (buf.length < 12 || buf.toString('ascii', 0, 4) !== 'PACK') {
    throw new Error('not a packfile');
  }
  const count = buf.readUInt32BE(8);
  const byOffset = new Map<number, GitObject>();
  const byOid = new Map<string, GitObject>();
  const pending: Array<{ offset: number; baseOffset: number; delta: Buffer }> = [];
  const pendingRef: Array<{ offset: number; baseOid: string; delta: Buffer }> = [];
  let off = 12;
  for (let i = 0; i < count; i++) {
    const entryOffset = off;
    const first = buf[off];
    const typeNum = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let next = off + 1;
    let shift = 4;
    while (buf[off] & 0x80) {
      size |= (buf[next] & 0x7f) << shift;
      shift += 7;
      next += 1;
      off = next - 1;
    }
    off = next;
    if (typeNum === 6) {
      // OFS_DELTA: negative offset varint
      let b = buf[off];
      off += 1;
      let baseOff = b & 0x7f;
      while (b & 0x80) {
        b = buf[off];
        off += 1;
        baseOff = ((baseOff + 1) << 7) | (b & 0x7f);
      }
      const baseOffset = entryOffset - baseOff;
      const inflated = inflateSync(buf.subarray(off), { info: true });
      const data = inflated.buffer as Buffer;
      off += (inflated.engine as { bytesWritten: number }).bytesWritten;
      pending.push({ offset: entryOffset, baseOffset, delta: data });
    } else if (typeNum === 7) {
      // REF_DELTA: 20-byte base oid
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      const inflated = inflateSync(buf.subarray(off), { info: true });
      const data = inflated.buffer as Buffer;
      off += (inflated.engine as { bytesWritten: number }).bytesWritten;
      pendingRef.push({ offset: entryOffset, baseOid, delta: data });
    } else {
      const kind = PACK_TYPES[typeNum];
      if (!kind) throw new Error(`unknown pack type ${typeNum}`);
      const inflated = inflateSync(buf.subarray(off), { info: true });
      const data = inflated.buffer as Buffer;
      if (data.length !== size) throw new Error('inflated size mismatch');
      off += (inflated.engine as { bytesWritten: number }).bytesWritten;
      const obj: GitObject = { kind, data };
      byOffset.set(entryOffset, obj);
      byOid.set(objectId(kind, data), obj);
    }
  }
  const resolveByOffset = (offset: number, seen: Set<number>): GitObject => {
    const direct = byOffset.get(offset);
    if (direct) return direct;
    if (seen.has(offset)) throw new Error('delta cycle');
    seen.add(offset);
    const p = pending.find((x) => x.offset === offset);
    if (!p) throw new Error('delta base missing');
    const base = resolveByOffset(p.baseOffset, seen);
    const data = applyDelta(base.data, p.delta);
    const obj: GitObject = { kind: base.kind, data };
    byOffset.set(offset, obj);
    byOid.set(objectId(obj.kind, data), obj);
    return obj;
  };
  for (const p of pending) {
    resolveByOffset(p.offset, new Set());
  }
  for (const p of pendingRef) {
    const base = byOid.get(p.baseOid);
    if (!base) throw new Error('ref-delta base missing');
    const data = applyDelta(base.data, p.delta);
    const obj: GitObject = { kind: base.kind, data };
    byOid.set(objectId(obj.kind, data), obj);
  }
  return byOid;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface IssueComment {
  id: number;
  body: string;
  createdAt: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  comments: IssueComment[];
  cachedJson: string | null;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  createdSeq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, { name: string; color: string }>;
  nextNumber: number;
  nextCommentId: number;
  advV2: Buffer | null;
  advReceive: Buffer | null;
  advV0: Buffer | null;
  fetchCache: Map<string, Buffer>;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextIssueRestId = 10000;
let nextPullRestId = 20000;
let nextCommentRestId = 50000;
let sequence = 0;
let requestSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner,
    description,
    isPrivate,
    defaultBranch: 'main',
    createdSeq: ++sequence,
    objects: new Map(),
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    advV2: null,
    advReceive: null,
    advV0: null,
    fetchCache: new Map(),
  };
  nextRepoId += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function storeObject(repo: Repo, kind: ObjKind, data: Buffer): string {
  const oid = objectId(kind, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { kind, data });
  return oid;
}

function invalidateAds(repo: Repo): void {
  repo.advV2 = null;
  repo.advReceive = null;
  repo.advV0 = null;
}

function peelToCommit(repo: Repo, oid: string): string | null {
  const obj = repo.objects.get(oid);
  if (!obj) return null;
  if (obj.kind === 'commit') return oid;
  if (obj.kind === 'tag') {
    const text = obj.data.toString('utf8');
    const m = /^object ([0-9a-f]{40})$/m.exec(text);
    if (!m) return null;
    return peelToCommit(repo, m[1]);
  }
  return null;
}

function isAncestor(repo: Repo, ancestorOid: string, tipOid: string): boolean {
  if (ancestorOid === tipOid) return true;
  const seen = new Set<string>();
  const stack = [tipOid];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.kind !== 'commit') continue;
    const parts = parseCommit(obj.data);
    for (const p of parts.parents) {
      if (p === ancestorOid) return true;
      stack.push(p);
    }
  }
  return false;
}

// Flat path -> blob map for a tree (files only).
function treeToFiles(repo: Repo, treeOid: string): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const walk = (oid: string, prefix: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.kind !== 'tree') return;
    for (const entry of parseTree(obj.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  };
  walk(treeOid, '');
  return out;
}

function filesToTree(repo: Repo, files: Map<string, { mode: string; oid: string }>): string {
  const build = (paths: Array<[string, { mode: string; oid: string }]>, depth: number): string => {
    const entries: TreeEntry[] = [];
    const dirs = new Map<string, Array<[string, { mode: string; oid: string }]>>();
    for (const [path, entry] of paths) {
      const rest = path.split('/').slice(depth);
      if (rest.length === 1) {
        entries.push({ mode: entry.mode, name: rest[0], oid: entry.oid });
      } else {
        const dir = rest[0];
        const list = dirs.get(dir) ?? [];
        list.push([path, entry]);
        dirs.set(dir, list);
      }
    }
    for (const [dir, list] of dirs) {
      entries.push({ mode: '40000', name: dir, oid: build(list, depth + 1) });
    }
    const data = buildTree(entries);
    return storeObject(repo, 'tree', data);
  };
  return build([...files.entries()], 0);
}

function findMergeBase(repo: Repo, aOid: string, bOid: string): string | null {
  const seenA = new Set<string>();
  const stackA = [aOid];
  while (stackA.length > 0) {
    const cur = stackA.pop() as string;
    if (seenA.has(cur)) continue;
    seenA.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.kind !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stackA.push(p);
  }
  const stackB = [bOid];
  const seenB = new Set<string>();
  while (stackB.length > 0) {
    const cur = stackB.pop() as string;
    if (seenA.has(cur)) return cur;
    if (seenB.has(cur)) continue;
    seenB.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.kind !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stackB.push(p);
  }
  return null;
}

// Commit history reachable from a ref tip, newest first.
function historyFrom(repo: Repo, tipOid: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tipOid];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.kind !== 'commit') continue;
    out.push(cur);
    const parts = parseCommit(obj.data);
    for (let i = parts.parents.length - 1; i >= 0; i--) stack.push(parts.parents[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fetch closure (the workhorse behind clone / fetch / ls-refs pack building)
// ---------------------------------------------------------------------------

interface FetchPlan {
  send: GitObject[];
  newShallow: string[];
  unshallow: string[];
}

// Collects the tree and blob oids reachable from a tree into `into`,
// skipping any subtree or blob whose oid is already in `stopAt`.
function collectTreeOids(
  repo: Repo,
  treeOid: string,
  into: Set<string>,
  stopAt?: Set<string>,
): void {
  const stack = [treeOid];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (into.has(oid) || (stopAt && stopAt.has(oid))) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.kind !== 'tree') continue;
    into.add(oid);
    for (const entry of parseTree(obj.data)) {
      if (entry.mode === '40000') stack.push(entry.oid);
      else if (!stopAt || !stopAt.has(entry.oid)) into.add(entry.oid);
    }
  }
}

function planFetch(
  repo: Repo,
  wantOids: string[],
  haveOids: string[],
  shallowSet: Set<string>,
  depth: number | undefined,
): FetchPlan {
  // Everything the client already owns: held commits plus their trees/blobs.
  const held = new Set<string>();
  for (const h of haveOids) {
    const tip = peelToCommit(repo, h);
    if (!tip) continue;
    const stack = [tip];
    const seen = new Set<string>();
    while (stack.length > 0) {
      const cur = stack.pop() as string;
      if (seen.has(cur)) continue;
      seen.add(cur);
      const obj = repo.objects.get(cur);
      if (!obj || obj.kind !== 'commit') continue;
      held.add(cur);
      collectTreeOids(repo, parseCommit(obj.data).tree, held);
      if (shallowSet.has(cur)) continue; // client does not own the parents
      for (const p of parseCommit(obj.data).parents) stack.push(p);
    }
  }
  const send = new Set<string>();
  const newShallow: string[] = [];
  const wantGenerations = new Map<string, number>();
  const queue: Array<{ oid: string; gen: number }> = [];
  let qi = 0;
  for (const w of wantOids) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.kind === 'tag') {
      if (!held.has(w)) send.add(w);
      const commit = peelToCommit(repo, w);
      if (commit) queue.push({ oid: commit, gen: 0 });
    } else if (obj.kind === 'commit') {
      queue.push({ oid: w, gen: 0 });
    }
  }
  const seen = new Set<string>();
  while (qi < queue.length) {
    const { oid, gen } = queue[qi];
    qi += 1;
    if (seen.has(oid)) continue;
    seen.add(oid);
    wantGenerations.set(oid, gen);
    if (held.has(oid)) {
      // Client already owns this commit and everything below it, unless it
      // is a shallow boundary (then the parents are missing on their side).
      if (shallowSet.has(oid)) {
        const obj = repo.objects.get(oid);
        if (!obj || obj.kind !== 'commit') continue;
        if (depth === undefined || gen < depth) {
          for (const p of parseCommit(obj.data).parents) queue.push({ oid: p, gen: gen + 1 });
        }
      }
      continue;
    }
    const obj = repo.objects.get(oid);
    if (!obj || obj.kind !== 'commit') continue;
    send.add(oid);
    const parts = parseCommit(obj.data);
    collectTreeOids(repo, parts.tree, send, held);
    if (depth !== undefined && gen + 1 >= depth) {
      newShallow.push(oid);
    } else {
      for (const p of parts.parents) queue.push({ oid: p, gen: gen + 1 });
    }
  }
  const unshallow: string[] = [];
  if (depth !== undefined) {
    for (const b of shallowSet) {
      const gen = wantGenerations.get(b);
      if (gen !== undefined && gen < depth) unshallow.push(b);
    }
  }
  const objects: GitObject[] = [];
  for (const oid of send) {
    const obj = repo.objects.get(oid);
    if (obj) objects.push(obj);
  }
  return { send: objects, newShallow, unshallow };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return readBody(req).then((buf) => {
    if (buf.length === 0) return {};
    try {
      return JSON.parse(buf.toString('utf8'));
    } catch {
      const e = new Error('malformed JSON body') as Error & { status?: number };
      e.status = 400;
      throw e;
    }
  });
}

function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq}`;
}

function sendJson(
  res: ServerResponse,
  status: number,
  value: string | unknown,
  extra: Record<string, string> = {},
): void {
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(body);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function authorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (!header) return false;
  if (EXPECTED_AUTH === null) return header.startsWith('Bearer ') && header.length > 7;
  return header === EXPECTED_AUTH;
}

function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (authorized(req)) return true;
  sendError(res, 401, 'Requires authentication');
  return false;
}

function viewerJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: `U_${b64(`user:${VIEWER_ID}`)}`,
    avatar_url: VIEWER_URL,
    gravatar_id: '',
    url: `https://api.example.invalid/users/${VIEWER_LOGIN}`,
    html_url: VIEWER_URL,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
  };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: `R_${b64(`repo:${repo.owner}/${repo.name}`)}`,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.isPrivate,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 9000, type: 'User' },
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `https://api.example.invalid/repos/${repo.owner}/${repo.name}`,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    pushed_at: NOW_ISO,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

function issueJson(repo: Repo, issue: Issue): string {
  if (issue.cachedJson) return issue.cachedJson;
  const labels = issue.labels.map((name) => {
    const l = repo.labels.get(name);
    return { name, color: l ? l.color : 'ededed' };
  });
  const text = JSON.stringify({
    id: issue.id,
    node_id: `I_${b64(`issue:${repo.owner}/${repo.name}:${issue.number}`)}`,
    url: `https://api.example.invalid/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `https://api.example.invalid/repos/${repo.owner}/${repo.name}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels,
    assignee: null,
    assignees: [],
    comments: issue.comments.length,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    closed_at: issue.state === 'closed' ? NOW_ISO : null,
  });
  issue.cachedJson = text;
  return text;
}

function pullJson(repo: Repo, pr: Pull): string {
  return JSON.stringify({
    id: pr.id,
    node_id: `P_${b64(`pr:${repo.owner}/${repo.name}:${pr.number}`)}`,
    url: `https://api.example.invalid/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
    number: pr.number,
    state: pr.state,
    title: pr.title,
    body: pr.body,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    head: { label: `${repo.owner}:${pr.head}`, ref: pr.head, sha: pr.headSha },
    base: { label: `${repo.owner}:${pr.base}`, ref: pr.base, sha: pr.baseSha },
    merged: pr.merged,
    mergeable: mergeableState(repo, pr),
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeSha,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    closed_at: pr.state === 'closed' ? NOW_ISO : null,
  });
}

// ---------------------------------------------------------------------------
// Issues / pulls: shared logic used by REST, GraphQL and MCP
// ---------------------------------------------------------------------------

function createIssueInternal(
  repo: Repo,
  title: string,
  body: string,
  labels: string[],
): { issue: Issue } | { error: string } {
  for (const name of labels) {
    if (!repo.labels.has(name)) return { error: `label "${name}" does not exist` };
  }
  const issue: Issue = {
    id: nextIssueRestId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    labels: [...labels],
    createdSeq: ++sequence,
    comments: [],
    cachedJson: null,
  };
  nextIssueRestId += 1;
  repo.nextNumber += 1;
  repo.issues.set(issue.number, issue);
  return { issue };
}

function diffFiles(
  repo: Repo,
  baseOid: string,
  headOid: string,
): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseTree = baseOid === ZERO_OID ? '' : parseCommit(repo.objects.get(baseOid)?.data ?? Buffer.alloc(0)).tree;
  const headTree = headOid === ZERO_OID ? '' : parseCommit(repo.objects.get(headOid)?.data ?? Buffer.alloc(0)).tree;
  const baseFiles = baseTree === '' ? new Map() : treeToFiles(repo, baseTree);
  const headFiles = headTree === '' ? new Map() : treeToFiles(repo, headTree);
  const names = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  for (const name of [...names].sort()) {
    const b = baseFiles.get(name);
    const h = headFiles.get(name);
    if (!b && h) {
      const lines = repo.objects.get(h.oid)?.data.toString('utf8').split('\n').length ?? 1;
      out.push({ filename: name, status: 'added', additions: Math.max(1, lines - 1), deletions: 0, changes: Math.max(1, lines - 1) });
    } else if (b && !h) {
      const lines = repo.objects.get(b.oid)?.data.toString('utf8').split('\n').length ?? 1;
      out.push({ filename: name, status: 'removed', additions: 0, deletions: Math.max(1, lines - 1), changes: Math.max(1, lines - 1) });
    } else if (b && h && b.oid !== h.oid) {
      const bLines = repo.objects.get(b.oid)?.data.toString('utf8').split('\n') ?? [];
      const hLines = repo.objects.get(h.oid)?.data.toString('utf8').split('\n') ?? [];
      const bCount = new Map<string, number>();
      for (const l of bLines) bCount.set(l, (bCount.get(l) ?? 0) + 1);
      let added = 0;
      for (const l of hLines) {
        const c = bCount.get(l) ?? 0;
        if (c > 0) bCount.set(l, c - 1);
        else added += 1;
      }
      let removed = 0;
      for (const c of bCount.values()) removed += c;
      if (added === 0) added = 1;
      out.push({ filename: name, status: 'modified', additions: added, deletions: removed, changes: added + removed });
    }
  }
  return out;
}

function mergeConflict(repo: Repo, pr: Pull): boolean {
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`) ?? pr.baseSha;
  const headTip = pr.headSha;
  const mergeBase = findMergeBase(repo, headTip, baseTip);
  if (!mergeBase) return true;
  const baseTree = parseCommit(repo.objects.get(mergeBase)?.data ?? Buffer.alloc(0)).tree;
  const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
  const tipTree = parseCommit(repo.objects.get(baseTip)?.data ?? Buffer.alloc(0)).tree;
  const baseFiles = treeToFiles(repo, baseTree);
  const headFiles = treeToFiles(repo, headTree);
  const tipFiles = treeToFiles(repo, tipTree);
  const names = new Set([...headFiles.keys(), ...tipFiles.keys()]);
  for (const name of names) {
    const b = baseFiles.get(name);
    const h = headFiles.get(name);
    const t = tipFiles.get(name);
    const headChanged = (h?.oid ?? null) !== (b?.oid ?? null);
    const tipChanged = (t?.oid ?? null) !== (b?.oid ?? null);
    if (headChanged && tipChanged && (h?.oid ?? null) !== (t?.oid ?? null)) return true;
  }
  return false;
}

function mergeableState(repo: Repo, pr: Pull): string {
  if (pr.merged) return 'MERGEABLE';
  if (mergeConflict(repo, pr)) return 'CONFLICTING';
  return 'MERGEABLE';
}

function squashMergeInternal(
  repo: Repo,
  pr: Pull,
): { ok: true; sha: string } | { ok: false; reason: string } {
  if (pr.merged) return { ok: false, reason: 'already merged' };
  if (mergeConflict(repo, pr)) return { ok: false, reason: 'conflict' };
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`) ?? pr.baseSha;
  const headTip = pr.headSha;
  const mergeBase = findMergeBase(repo, headTip, baseTip);
  if (!mergeBase) return { ok: false, reason: 'no merge base' };
  const baseTree = parseCommit(repo.objects.get(mergeBase)?.data ?? Buffer.alloc(0)).tree;
  const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
  const tipTree = parseCommit(repo.objects.get(baseTip)?.data ?? Buffer.alloc(0)).tree;
  const baseFiles = treeToFiles(repo, baseTree);
  const headFiles = treeToFiles(repo, headTree);
  const tipFiles = treeToFiles(repo, tipTree);
  for (const [path, entry] of headFiles) {
    if ((baseFiles.get(path)?.oid ?? null) !== entry.oid) tipFiles.set(path, entry);
  }
  for (const path of [...tipFiles.keys()]) {
    if (!headFiles.has(path) && baseFiles.has(path)) tipFiles.delete(path);
  }
  const newTree = filesToTree(repo, tipFiles);
  const commitData = buildCommit(newTree, [baseTip], pr.title);
  const sha = storeObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pr.base}`, sha);
  invalidateAds(repo);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = NOW_ISO;
  pr.mergeSha = sha;
  pr.baseSha = sha;
  return { ok: true, sha };
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

function refLines(repo: Repo): Array<{ oid: string; name: string }> {
  const out: Array<{ oid: string; name: string }> = [];
  for (const [name, oid] of repo.refs) out.push({ oid, name });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

function defaultTip(repo: Repo): string {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
}

function buildV2Advertisement(repo: Repo): Buffer {
  if (repo.advV2) return repo.advV2;
  const body =
    pkt('# service=git-upload-pack\n') +
    pkt('version 2\n') +
    pkt('ls-refs=unborn\n') +
    pkt('fetch=shallow\n') +
    pkt('agent\n') +
    pkt('object-format=sha1\n');
  const buf = Buffer.concat([Buffer.from(body, 'utf8'), FLUSH_PKT]);
  repo.advV2 = buf;
  return buf;
}

function buildV0Advertisement(repo: Repo, service: 'upload-pack' | 'receive-pack'): Buffer {
  if (service === 'upload-pack' && repo.advV0) return repo.advV0;
  if (service === 'receive-pack' && repo.advReceive) return repo.advReceive;
  const caps =
    service === 'upload-pack'
      ? 'symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta shallow multi_ack multi_ack_detailed agent'
      : 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent symref=HEAD:refs/heads/main';
  const chunks: Buffer[] = [pkt(`# service=git-${service}\n`)];
  const refs = refLines(repo);
  if (refs.length === 0) {
    chunks.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    chunks.push(pkt(`${defaultTip(repo)} HEAD\0${caps}\n`));
    for (const r of refs) {
      chunks.push(pkt(`${r.oid} ${r.name}\n`));
      const obj = repo.objects.get(r.oid);
      if (obj && obj.kind === 'tag') {
        const peeled = peelToCommit(repo, r.oid);
        if (peeled) chunks.push(pkt(`${peeled} ${r.name}^{}\n`));
      }
    }
  }
  chunks.push(FLUSH_PKT);
  const buf = Buffer.concat(chunks);
  if (service === 'upload-pack') repo.advV0 = buf;
  else repo.advReceive = buf;
  return buf;
}

function sidebandPack(pack: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let off = 0;
  while (off < pack.length) {
    const slice = pack.subarray(off, Math.min(pack.length, off + 65515));
    off += slice.length;
    chunks.push(pkt(Buffer.concat([Buffer.from([0x01]), slice])));
  }
  return Buffer.concat(chunks);
}

function handleLsRefs(repo: Repo, lines: PktLine[]): Buffer {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const line of lines) {
    if (line.kind !== 'data') continue;
    const text = line.payload.toString('utf8').trim();
    if (text === 'peel') peel = true;
    else if (text === 'symrefs') symrefs = true;
    else if (text === 'unborn') unborn = true;
    else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
  }
  const chunks: Buffer[] = [];
  const refs = refLines(repo);
  const headTip = defaultTip(repo);
  const include = (name: string): boolean =>
    prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (refs.length === 0) {
    if (unborn) chunks.push(pkt('unborn HEAD symref-target:refs/heads/main\n'));
  } else {
    if (include('HEAD')) {
      const attrs = symrefs ? ' symref-target:refs/heads/main' : '';
      chunks.push(pkt(`${headTip} HEAD${attrs}\n`));
    }
    for (const r of refs) {
      if (!include(r.name)) continue;
      let extra = '';
      if (peel) {
        const obj = repo.objects.get(r.oid);
        if (obj && obj.kind === 'tag') {
          const peeled = peelToCommit(repo, r.oid);
          if (peeled) extra += ` peeled:${peeled}`;
        }
      }
      chunks.push(pkt(`${r.oid} ${r.name}${extra}\n`));
    }
  }
  chunks.push(FLUSH_PKT);
  return Buffer.concat(chunks);
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: Set<string>;
  depth: number | undefined;
}

function parseFetchRequest(lines: PktLine[]): FetchRequest {
  const req: FetchRequest = { wants: [], haves: [], shallow: new Set(), depth: undefined };
  for (const line of lines) {
    if (line.kind !== 'data') continue;
    const text = line.payload.toString('utf8').trim();
    if (text.startsWith('want ')) req.wants.push(text.slice(5).trim().split(' ')[0]);
    else if (text.startsWith('have ')) req.haves.push(text.slice(5).trim().split(' ')[0]);
    else if (text.startsWith('shallow ')) req.shallow.add(text.slice(8).trim());
    else if (text.startsWith('deepen ')) {
      const n = Number(text.slice(7).trim());
      if (Number.isFinite(n) && n > 0) req.depth = n;
    }
  }
  return req;
}

function handleFetch(repo: Repo, lines: PktLine[], isV2: boolean): Buffer {
  const req = parseFetchRequest(lines);
  // A fetch answer is a pure function of its inputs (objects are immutable
  // and content-addressed), so identical requests reuse one cached buffer.
  const cacheKey = `${isV2 ? 'v2' : 'v0'}|${req.wants.join(',')}|${req.haves.join(',')}|${[...req.shallow].sort().join(',')}|${req.depth ?? ''}`;
  const cached = repo.fetchCache.get(cacheKey);
  if (cached) return cached;
  const chunks: Buffer[] = [];
  const plan = planFetch(repo, req.wants, req.haves, req.shallow, req.depth);
  const acks: string[] = [];
  for (const h of req.haves) {
    const tip = peelToCommit(repo, h);
    if (tip && req.wants.some((w) => isAncestor(repo, h, w) || h === w)) acks.push(h);
  }
  if (isV2) {
    chunks.push(pkt('acknowledgments\n'));
    if (acks.length === 0) {
      chunks.push(pkt('NAK\n'));
    } else {
      for (const a of acks) chunks.push(pkt(`ACK ${a}\n`));
      chunks.push(pkt('ready\n'));
    }
    chunks.push(DELIM_PKT);
    if (plan.newShallow.length > 0 || plan.unshallow.length > 0) {
      chunks.push(pkt('shallow-info\n'));
      for (const s of plan.newShallow) chunks.push(pkt(`shallow ${s}\n`));
      for (const s of plan.unshallow) chunks.push(pkt(`unshallow ${s}\n`));
      chunks.push(DELIM_PKT);
    }
    if (plan.send.length > 0) {
      chunks.push(pkt('packfile\n'));
      chunks.push(sidebandPack(writePack(plan.send)));
    }
    chunks.push(FLUSH_PKT);
  } else {
    // v0: NAK / ACK lines then the pack (sideband framed).
    if (acks.length === 0) chunks.push(pkt('NAK\n'));
    else {
      for (const a of acks) chunks.push(pkt(`ACK ${a}\n`));
    }
    if (plan.send.length > 0) chunks.push(sidebandPack(writePack(plan.send)));
  }
  const buf = Buffer.concat(chunks);
  if (repo.fetchCache.size >= 16) repo.fetchCache.clear();
  repo.fetchCache.set(cacheKey, buf);
  return buf;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  // Commands are pkt-lines up to the flush; the rest is the packfile.
  let off = 0;
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let sideband = false;
  let firstLine = true;
  while (off < body.length) {
    const r = readPktLine(body, off);
    off = r.next;
    if (r.line.kind === 'flush') break;
    if (r.line.kind !== 'data') continue;
    let text = r.line.payload.toString('utf8').trim();
    if (firstLine) {
      const nul = text.indexOf('\0');
      if (nul !== -1) {
        const caps = text.slice(nul + 1);
        if (caps.includes('side-band-64k')) sideband = true;
        text = text.slice(0, nul);
      }
    }
    firstLine = false;
    const parts = text.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
  }
  const packBytes = body.subarray(off);
  const report: string[] = [];
  let unpackOk = true;
  let unpackReason = '';
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (e) {
      unpackOk = false;
      unpackReason = e instanceof Error ? e.message : 'unpack failed';
    }
  }
  for (const cmd of commands) {
    if (!unpackOk) {
      report.push(`ng ${cmd.ref} unpack failed`);
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (current === undefined) report.push(`ng ${cmd.ref} reference does not exist`);
      else if (cmd.oldOid !== current) report.push(`ng ${cmd.ref} old oid mismatch`);
      else {
        repo.refs.delete(cmd.ref);
        report.push(`ok ${cmd.ref}`);
      }
    } else if (cmd.oldOid === ZERO_OID) {
      // create
      if (current !== undefined) report.push(`ng ${cmd.ref} reference already exists`);
      else if (!repo.objects.has(cmd.newOid)) report.push(`ng ${cmd.ref} object not found`);
      else {
        repo.refs.set(cmd.ref, cmd.newOid);
        report.push(`ok ${cmd.ref}`);
      }
    } else {
      // update
      if (current === undefined) report.push(`ng ${cmd.ref} reference does not exist`);
      else if (cmd.oldOid !== current) report.push(`ng ${cmd.ref} old oid mismatch`);
      else if (!repo.objects.has(cmd.newOid)) report.push(`ng ${cmd.ref} object not found`);
      else if (!isAncestor(repo, current, cmd.newOid) && peelToCommit(repo, cmd.newOid) !== null) {
        const newObj = repo.objects.get(cmd.newOid);
        if (newObj && newObj.kind === 'commit') report.push(`ng ${cmd.ref} non-fast-forward`);
        else {
          repo.refs.set(cmd.ref, cmd.newOid);
          report.push(`ok ${cmd.ref}`);
        }
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        report.push(`ok ${cmd.ref}`);
      }
    }
  }
  if (commands.some((c) => report.some((r) => r === `ok ${c.ref}`))) invalidateAds(repo);
  const lines: Buffer[] = [];
  lines.push(pkt(unpackOk ? 'unpack ok\n' : `unpack ${unpackReason}\n`));
  for (const r of report) lines.push(pkt(`${r}\n`));
  lines.push(FLUSH_PKT);
  const payload = Buffer.concat(lines);
  if (sideband) {
    const chunks: Buffer[] = [];
    let off2 = 0;
    while (off2 < payload.length) {
      const slice = payload.subarray(off2, Math.min(payload.length, off2 + 65515));
      off2 += slice.length;
      chunks.push(pkt(Buffer.concat([Buffer.from([0x01]), slice])));
    }
    return Buffer.concat(chunks);
  }
  return payload;
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function restLookupRepo(owner: string, name: string): Repo | null {
  return repos.get(repoKey(owner, name)) ?? null;
}

function parseQuery(raw: string): URLSearchParams {
  const q = raw.indexOf('?');
  if (q === -1) return new URLSearchParams();
  return new URLSearchParams(raw.slice(q + 1));
}

function linkHeader(base: string, page: number, perPage: number, total: number): string {
  const last = Math.max(1, Math.ceil(total / perPage));
  const parts: string[] = [];
  const mk = (p: number, rel: string) =>
    `<${base}?per_page=${perPage}&page=${p}>; rel="${rel}"`;
  if (page < last) parts.push(mk(page + 1, 'next'));
  if (last > 1) parts.push(mk(last, 'last'));
  if (page > 1) {
    parts.push(mk(1, 'first'));
    parts.push(mk(page - 1, 'prev'));
  }
  return parts.join(', ');
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
  if (!requireAuth(req, res)) return;
  const method = req.method ?? 'GET';
  const origin = `http://${req.headers.host ?? '127.0.0.1'}`;
  const segs = path.split('/').filter((s) => s.length > 0); // after /api/v3
  const query = parseQuery(req.url ?? '');

  // GET /api/v3/
  if (segs.length === 0) {
    sendJson(res, 200, { current_user_url: 'https://api.example.invalid/user' }, {
      'x-oauth-scopes': 'repo, user',
    });
    return;
  }

  // GET /api/v3/meta
  if (segs.length === 1 && segs[0] === 'meta') {
    sendJson(res, 200, { installed_version: '1.0.0' });
    return;
  }

  // GET /api/v3/user
  if (segs.length === 1 && segs[0] === 'user' && method === 'GET') {
    sendJson(res, 200, viewerJson());
    return;
  }

  // POST /user/repos
  if (segs.length === 2 && segs[0] === 'user' && segs[1] === 'repos' && method === 'POST') {
    const body = (await readJsonBody(req)) as { name?: string; description?: string; private?: boolean };
    const name = typeof body.name === 'string' ? body.name : '';
    if (name === '') {
      sendError(res, 422, 'name is required');
      return;
    }
    if (repos.has(repoKey(VIEWER_LOGIN, name))) {
      sendError(res, 422, 'name already exists on this account');
      return;
    }
    const repo = createRepoRecord(
      VIEWER_LOGIN,
      name,
      typeof body.description === 'string' ? body.description : '',
      body.private === true,
    );
    sendJson(res, 201, repoJson(repo));
    return;
  }

  // GET /user/repos
  if (segs.length === 2 && segs[0] === 'user' && segs[1] === 'repos' && method === 'GET') {
    const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? 30) || 30));
    const page = Math.max(1, Number(query.get('page') ?? 1) || 1);
    const mine = [...repos.values()]
      .filter((r) => r.owner === VIEWER_LOGIN)
      .sort((a, b) => a.createdSeq - b.createdSeq);
    const slice = mine.slice((page - 1) * perPage, page * perPage);
    const extra: Record<string, string> = {};
    const link = linkHeader(`${origin}/api/v3/user/repos`, page, perPage, mine.length);
    if (link) extra.link = link;
    sendJson(res, 200, slice.map(repoJson), extra);
    return;
  }

  // /repos/{owner}/{repo}...
  if (segs.length >= 3 && segs[0] === 'repos') {
    const owner = segs[1];
    const name = segs[2];
    const repo = restLookupRepo(owner, name);
    const rest = segs.slice(3);

    if (method === 'GET' && rest.length === 0) {
      if (!repo) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH' && rest.length === 0) {
      if (!repo) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const body = (await readJsonBody(req)) as { description?: string; private?: boolean };
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE' && rest.length === 0) {
      if (!repo) {
        sendError(res, 404, 'Not Found');
        return;
      }
      repos.delete(repoKey(owner, name));
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return;
    }
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return;
    }

    // git/refs
    if (rest.length >= 2 && rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const body = (await readJsonBody(req)) as { ref?: string; sha?: string };
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha)) {
          sendError(res, 422, 'ref and sha are required');
          return;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, 'Reference already exists');
          return;
        }
        if (!repo.objects.has(sha)) {
          sendError(res, 422, 'Object does not exist');
          return;
        }
        repo.refs.set(ref, sha);
        invalidateAds(repo);
        sendJson(res, 201, { ref, object: { sha, type: 'commit', url: '' } });
        return;
      }
      if (method === 'GET' && rest.length >= 3) {
        const refName = `refs/${rest.slice(2).join('/')}`;
        const oid = repo.refs.get(refName);
        if (!oid) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { ref: refName, object: { sha: oid, type: 'commit', url: '' } });
        return;
      }
    }

    // branches
    if (rest.length >= 1 && rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const out: Array<Record<string, unknown>> = [];
        for (const [ref, oid] of repo.refs) {
          if (!ref.startsWith('refs/heads/')) continue;
          out.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid } });
        }
        out.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        sendJson(res, 200, out);
        return;
      }
      if (method === 'GET' && rest.length === 2) {
        const oid = repo.refs.get(`refs/heads/${rest[1]}`);
        if (!oid) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { name: rest[1], commit: { sha: oid } });
        return;
      }
    }

    // commits
    if (rest.length === 1 && rest[0] === 'commits' && method === 'GET') {
      const shaParam = query.get('sha');
      const tip = shaParam
        ? repo.refs.get(`refs/heads/${shaParam}`) ?? repo.refs.get(shaParam) ?? null
        : defaultTip(repo);
      if (!tip || tip === ZERO_OID) {
        sendJson(res, 200, []);
        return;
      }
      const out = historyFrom(repo, tip).map((oid) => {
        const parts = parseCommit(repo.objects.get(oid)?.data ?? Buffer.alloc(0));
        return {
          sha: oid,
          commit: { message: parts.message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: NOW_ISO }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: NOW_ISO } },
          author: { login: VIEWER_LOGIN },
        };
      });
      sendJson(res, 200, out);
      return;
    }

    // contents
    if (rest.length >= 2 && rest[0] === 'contents') {
      const filePath = rest.slice(1).join('/');
      if (method === 'GET') {
        const refParam = query.get('ref');
        const tip = refParam
          ? repo.refs.get(`refs/heads/${refParam}`) ?? repo.refs.get(refParam) ?? null
          : defaultTip(repo);
        if (!tip || tip === ZERO_OID) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const commit = parseCommit(repo.objects.get(tip)?.data ?? Buffer.alloc(0));
        const files = treeToFiles(repo, commit.tree);
        const entry = files.get(filePath);
        if (entry) {
          const blob = repo.objects.get(entry.oid);
          const content = blob ? blob.data.toString('base64') : '';
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            size: blob ? blob.data.length : 0,
            name: filePath.split('/').pop(),
            path: filePath,
            content,
            sha: entry.oid,
          });
          return;
        }
        // directory?
        const prefix = filePath === '' ? '' : `${filePath}/`;
        const children = new Map<string, { type: string; name: string; path: string; sha: string }>();
        for (const [p, e] of files) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          const first = rest2.split('/')[0];
          if (!children.has(first)) {
            children.set(first, {
              type: rest2.includes('/') ? 'dir' : 'file',
              name: first,
              path: `${prefix}${first}`,
              sha: e.oid,
            });
          }
        }
        if (children.size === 0) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, [...children.values()].sort((a, b) => a.name.localeCompare(b.name)));
        return;
      }
      if (method === 'PUT') {
        const body = (await readJsonBody(req)) as {
          message?: string;
          content?: string;
          sha?: string;
          branch?: string;
        };
        const branch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        const content = Buffer.from(contentB64, 'base64');
        const message = typeof body.message === 'string' ? body.message : 'Update file';
        let branchTip = repo.refs.get(`refs/heads/${branch}`);
        if (!branchTip) {
          const baseTip = defaultTip(repo);
          if (baseTip !== ZERO_OID) branchTip = baseTip;
        }
        const currentFiles = branchTip && branchTip !== ZERO_OID
          ? treeToFiles(repo, parseCommit(repo.objects.get(branchTip)?.data ?? Buffer.alloc(0)).tree)
          : new Map<string, { mode: string; oid: string }>();
        const existing = currentFiles.get(filePath);
        if (body.sha && existing && body.sha !== existing.oid) {
          sendError(res, 409, 'sha does not match');
          return;
        }
        const blobOid = storeObject(repo, 'blob', content);
        const created = !existing;
        currentFiles.set(filePath, { mode: '100644', oid: blobOid });
        const newTree = filesToTree(repo, currentFiles);
        const parents = branchTip && branchTip !== ZERO_OID ? [branchTip] : [];
        const commitOid = storeObject(repo, 'commit', buildCommit(newTree, parents, message));
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        invalidateAds(repo);
        sendJson(res, created ? 201 : 200, {
          content: {
            name: filePath.split('/').pop(),
            path: filePath,
            sha: blobOid,
            size: content.length,
            type: 'file',
            encoding: 'base64',
            content: contentB64,
          },
          commit: { sha: commitOid, message },
        });
        return;
      }
      if (method === 'DELETE') {
        const body = (await readJsonBody(req)) as { message?: string; sha?: string; branch?: string };
        const branch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
        const branchTip = repo.refs.get(`refs/heads/${branch}`);
        if (!branchTip || branchTip === ZERO_OID) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const files = treeToFiles(repo, parseCommit(repo.objects.get(branchTip)?.data ?? Buffer.alloc(0)).tree);
        const existing = files.get(filePath);
        if (!existing) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (body.sha && body.sha !== existing.oid) {
          sendError(res, 409, 'sha does not match');
          return;
        }
        files.delete(filePath);
        const newTree = filesToTree(repo, files);
        const message = typeof body.message === 'string' ? body.message : 'Delete file';
        const commitOid = storeObject(repo, 'commit', buildCommit(newTree, [branchTip], message));
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        invalidateAds(repo);
        sendJson(res, 200, { commit: { sha: commitOid, message } });
        return;
      }
    }

    // labels
    if (rest.length === 1 && rest[0] === 'labels' && method === 'POST') {
      const body = (await readJsonBody(req)) as { name?: string; color?: string };
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      const color = typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed';
      repo.labels.set(name, { name, color });
      sendJson(res, 201, { id: 1000 + repo.labels.size, name, color });
      return;
    }

    // issues
    if (rest.length >= 1 && rest[0] === 'issues') {
      if (method === 'POST' && rest.length === 1) {
        const body = (await readJsonBody(req)) as {
          title?: string;
          body?: string;
          labels?: string[];
        };
        const title = typeof body.title === 'string' ? body.title : '';
        if (title === '') {
          sendError(res, 422, 'title is required');
          return;
        }
        const labels = Array.isArray(body.labels)
          ? body.labels.filter((l): l is string => typeof l === 'string')
          : [];
        const made = createIssueInternal(repo, title, typeof body.body === 'string' ? body.body : '', labels);
        if ('error' in made) {
          sendError(res, 422, made.error);
          return;
        }
        sendJson(res, 201, issueJson(repo, made.issue));
        return;
      }
      if (method === 'GET' && rest.length === 1) {
        const stateFilter = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (stateFilter !== 'all') list = list.filter((i) => i.state === stateFilter);
        if (sort === 'created') {
          list.sort((a, b) =>
            direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq,
          );
        } else {
          list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        }
        const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? 30) || 30));
        const page = Math.max(1, Number(query.get('page') ?? 1) || 1);
        const slice = list.slice((page - 1) * perPage, page * perPage);
        const extra: Record<string, string> = {};
        const link = linkHeader(
          `${origin}/api/v3/repos/${owner}/${name}/issues`,
          page,
          perPage,
          list.length,
        );
        if (link) extra.link = link;
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'x-github-request-id': nextRequestId(),
          ...extra,
        });
        res.end(`[${slice.map((i) => issueJson(repo, i)).join(',')}]`);
        return;
      }
      if (rest.length >= 2 && /^\d+$/.test(rest[1])) {
        const num = Number(rest[1]);
        const issue = repo.issues.get(num);
        if (rest.length === 2 && method === 'GET') {
          if (!issue) {
            sendError(res, 404, 'Not Found');
            return;
          }
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'x-github-request-id': nextRequestId(),
          });
          res.end(issueJson(repo, issue));
          return;
        }
        if (rest.length === 2 && method === 'PATCH') {
          if (!issue) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const body = (await readJsonBody(req)) as { state?: string; title?: string; body?: string };
          if (typeof body.state === 'string' && (body.state === 'open' || body.state === 'closed')) {
            issue.state = body.state;
          }
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          issue.cachedJson = null;
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'x-github-request-id': nextRequestId(),
          });
          res.end(issueJson(repo, issue));
          return;
        }
        if (rest.length === 3 && rest[2] === 'comments' && method === 'POST') {
          if (!issue) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const body = (await readJsonBody(req)) as { body?: string };
          const text = typeof body.body === 'string' ? body.body : '';
          const comment: IssueComment = {
            id: nextCommentRestId,
            body: text,
            createdAt: NOW_ISO,
          };
          nextCommentRestId += 1;
          issue.comments.push(comment);
          issue.cachedJson = null;
          sendJson(res, 201, {
            id: comment.id,
            node_id: `C_${b64(`comment:${repo.owner}/${repo.name}:${issue.number}:${comment.id}`)}`,
            body: text,
            user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
          });
          return;
        }
        if (rest.length === 3 && rest[2] === 'comments' && method === 'GET') {
          if (!issue) {
            sendError(res, 404, 'Not Found');
            return;
          }
          sendJson(res, 200, issue.comments.map((c) => ({
            id: c.id,
            body: c.body,
            user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
            created_at: c.createdAt,
            updated_at: c.createdAt,
          })));
          return;
        }
      }
    }

    // pulls
    if (rest.length >= 1 && rest[0] === 'pulls') {
      if (method === 'POST' && rest.length === 1) {
        const body = (await readJsonBody(req)) as {
          title?: string;
          body?: string;
          head?: string;
          base?: string;
        };
        const title = typeof body.title === 'string' ? body.title : '';
        const head = typeof body.head === 'string' ? body.head : '';
        const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
        if (title === '' || head === '') {
          sendError(res, 422, 'title and head are required');
          return;
        }
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${base}`);
        if (!headSha || !baseSha) {
          sendError(res, 422, 'head or base branch does not exist');
          return;
        }
        for (const existing of repo.pulls.values()) {
          if (existing.state === 'open' && existing.head === head && existing.base === base) {
            sendError(res, 422, 'A pull request already exists for this head and base');
            return;
          }
        }
        const pr: Pull = {
          id: nextPullRestId,
          number: repo.nextNumber,
          title,
          body: typeof body.body === 'string' ? body.body : '',
          state: 'open',
          head,
          base,
          headSha,
          baseSha,
          merged: false,
          mergedAt: null,
          mergeSha: null,
          createdSeq: ++sequence,
        };
        nextPullRestId += 1;
        repo.nextNumber += 1;
        repo.pulls.set(pr.number, pr);
        sendJson(res, 201, JSON.parse(pullJson(repo, pr)));
        return;
      }
      if (method === 'GET' && rest.length === 1) {
        const stateFilter = query.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (stateFilter !== 'all') list = list.filter((p) => p.state === stateFilter);
        list.sort((a, b) => b.createdSeq - a.createdSeq);
        sendJson(res, 200, list.map((p) => JSON.parse(pullJson(repo, p))));
        return;
      }
      if (rest.length >= 2 && /^\d+$/.test(rest[1])) {
        const num = Number(rest[1]);
        const pr = repo.pulls.get(num);
        if (rest.length === 2 && method === 'GET') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return;
          }
          sendJson(res, 200, JSON.parse(pullJson(repo, pr)));
          return;
        }
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const currentBase = repo.refs.get(`refs/heads/${pr.base}`) ?? pr.baseSha;
          const mergeBase = findMergeBase(repo, pr.headSha, currentBase);
          const baseForDiff = mergeBase ?? currentBase;
          sendJson(res, 200, diffFiles(repo, baseForDiff, pr.headSha));
          return;
        }
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const body = (await readJsonBody(req)) as { merge_method?: string };
          if (body.merge_method && body.merge_method !== 'squash') {
            sendError(res, 405, 'only squash merge is supported');
            return;
          }
          const result = squashMergeInternal(repo, pr);
          if (!result.ok) {
            if (result.reason === 'conflict') {
              sendError(res, 405, 'merge conflict');
              return;
            }
            sendError(res, 422, result.reason);
            return;
          }
          sendJson(res, 200, { merged: true, sha: result.sha, message: pr.title });
          return;
        }
      }
    }
  }

  sendError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL v4
// ---------------------------------------------------------------------------

type GqlValue =
  | string
  | number
  | boolean
  | null
  | GqlValue[]
  | { [key: string]: GqlValue };

interface GqlField {
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  children: GqlField[];
  inlineType: string | null;
}

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():$![]=@'.includes(c)) {
      tokens.push(c);
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else out += esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_.-]/.test(src[j])) j += 1;
    if (j === i) {
      i += 1;
      continue;
    }
    tokens.push(src.slice(i, j));
    i = j;
  }
  return tokens;
}

class GqlParser {
  tokens: string[];
  pos = 0;
  constructor(src: string) {
    this.tokens = gqlTokenize(src);
  }
  peek(): string {
    return this.tokens[this.pos] ?? '';
  }
  take(): string {
    const t = this.tokens[this.pos] ?? '';
    this.pos += 1;
    return t;
  }
  expect(t: string): void {
    if (this.take() !== t) throw new Error(`expected ${t}`);
  }
  parseValue(variables: Record<string, GqlValue>): GqlValue {
    const t = this.take();
    if (t === '$') {
      const name = this.take();
      return variables[name] ?? null;
    }
    if (t === '[') {
      const out: GqlValue[] = [];
      while (this.peek() !== ']') out.push(this.parseValue(variables));
      this.take();
      return out;
    }
    if (t === '{') {
      const out: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const key = this.take();
        this.expect(':');
        out[key] = this.parseValue(variables);
      }
      this.take();
      return out;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    const num = Number(t);
    if (t !== '' && Number.isFinite(num)) return num;
    return t; // enum
  }
  parseSelectionSet(variables: Record<string, GqlValue>): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}' && this.pos < this.tokens.length) {
      if (this.peek() === '...') {
        this.take();
        let inlineType: string | null = null;
        if (this.peek() === 'on') {
          this.take();
          inlineType = this.take();
        }
        const children = this.parseSelectionSet(variables);
        for (const c of children) fields.push({ ...c, inlineType });
        continue;
      }
      let name = this.take();
      let alias: string | null = null;
      if (this.peek() === ':') {
        this.take();
        alias = name;
        name = this.take();
      }
      const args: Record<string, GqlValue> = {};
      if (this.peek() === '(') {
        this.take();
        while (this.peek() !== ')') {
          const key = this.take();
          this.expect(':');
          args[key] = this.parseValue(variables);
        }
        this.take();
      }
      let children: GqlField[] = [];
      if (this.peek() === '{') children = this.parseSelectionSet(variables);
      fields.push({ name, alias, args, children, inlineType: null });
    }
    this.expect('}');
    return fields;
  }
  parseOperation(variables: Record<string, GqlValue>): { type: string; fields: GqlField[] } {
    let type = 'query';
    const first = this.peek();
    if (first === 'query' || first === 'mutation') {
      type = this.take();
      const next = this.peek();
      if (next !== '{' && next !== '(') this.take(); // operation name
      if (this.peek() === '(') {
        // variable definitions: skip, variables come from the request
        let depth = 0;
        while (this.pos < this.tokens.length) {
          const t = this.take();
          if (t === '(') depth += 1;
          if (t === ')') {
            depth -= 1;
            if (depth === 0) break;
          }
        }
      }
    }
    const fields = this.parseSelectionSet(variables);
    return { type, fields };
  }
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: [
    'id', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt',
    'author', 'labels', 'comments', 'closedAt', 'assignees', 'milestone',
  ],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName',
    'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'commits', 'reviews',
    'createdAt', 'updatedAt', 'author', 'mergedAt', 'mergeCommit',
  ],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef',
    'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests',
    'pullRequest', 'description', 'private', 'createdAt', 'updatedAt', 'url',
    'fork', 'stargazerCount', 'watchers',
  ],
  SearchType: [],
};

const GQL_SEARCH_ENUMS = [
  'ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'ORGANIZATION', 'DISCUSSION',
  'COMMIT', 'CODE', 'MILESTONE', 'WIKI', 'PROJECT', 'TOPIC',
];

function gqlRepoId(repo: Repo): string {
  return `R_${b64(`repo:${repo.owner}/${repo.name}`)}`;
}
function gqlIssueId(repo: Repo, issue: Issue): string {
  return `I_${b64(`issue:${repo.owner}/${repo.name}:${issue.number}`)}`;
}
function gqlPrId(repo: Repo, pr: Pull): string {
  return `P_${b64(`pr:${repo.owner}/${repo.name}:${pr.number}`)}`;
}
function gqlCommentId(repo: Repo, issue: Issue, comment: IssueComment): string {
  return `C_${b64(`comment:${repo.owner}/${repo.name}:${issue.number}:${comment.id}`)}`;
}

function decodeGlobalId(id: string): { kind: string; payload: string } | null {
  const prefix = id.slice(0, 2);
  if (prefix !== 'R_' && prefix !== 'I_' && prefix !== 'P_' && prefix !== 'C_') return null;
  const kind = prefix[0];
  try {
    return { kind, payload: unb64(id.slice(2)) };
  } catch {
    return null;
  }
}

function gqlTypeFields(name: string): Array<Record<string, GqlValue>> {
  const fields = GQL_TYPE_FIELDS[name] ?? [];
  return fields.map((f) => ({ name: f, description: null, args: [], type: { name: 'String', kind: 'SCALAR' } }));
}

function gqlIssueFields(repo: Repo, issue: Issue, fields: GqlField[]): Record<string, GqlValue> {
  const out: Record<string, GqlValue> = {};
  for (const f of fields) {
    const key = f.alias ?? f.name;
    switch (f.name) {
      case 'id':
        out[key] = gqlIssueId(repo, issue);
        break;
      case 'number':
        out[key] = issue.number;
        break;
      case 'title':
        out[key] = issue.title;
        break;
      case 'body':
        out[key] = issue.body;
        break;
      case 'state':
        out[key] = issue.state === 'open' ? 'OPEN' : 'CLOSED';
        break;
      case 'url':
        out[key] = `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
        break;
      case 'createdAt':
      case 'updatedAt':
        out[key] = NOW_ISO;
        break;
      case 'closedAt':
        out[key] = issue.state === 'closed' ? NOW_ISO : null;
        break;
      default:
        throw new Error(`Cannot query field "${f.name}" on type "Issue".`);
    }
  }
  return out;
}

function gqlPrFields(repo: Repo, pr: Pull, fields: GqlField[]): Record<string, GqlValue> {
  const out: Record<string, GqlValue> = {};
  for (const f of fields) {
    const key = f.alias ?? f.name;
    switch (f.name) {
      case 'id':
        out[key] = gqlPrId(repo, pr);
        break;
      case 'number':
        out[key] = pr.number;
        break;
      case 'title':
        out[key] = pr.title;
        break;
      case 'body':
        out[key] = pr.body;
        break;
      case 'state':
        out[key] = pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
        break;
      case 'merged':
        out[key] = pr.merged;
        break;
      case 'mergeable':
        out[key] = mergeableState(repo, pr);
        break;
      case 'headRefName':
        out[key] = pr.head;
        break;
      case 'baseRefName':
        out[key] = pr.base;
        break;
      case 'headRefOid':
        out[key] = pr.headSha;
        break;
      case 'baseRefOid':
        out[key] = pr.baseSha;
        break;
      case 'files': {
        const mergeBase = findMergeBase(repo, pr.headSha, pr.baseSha);
        const files = diffFiles(repo, mergeBase ?? pr.baseSha, pr.headSha);
        out[key] = {
          totalCount: files.length,
          nodes: files.map((x) => ({ path: x.filename, additions: x.additions, deletions: x.deletions })),
        };
        break;
      }
      case 'createdAt':
      case 'updatedAt':
        out[key] = NOW_ISO;
        break;
      case 'mergedAt':
        out[key] = pr.mergedAt;
        break;
      case 'url':
        out[key] = `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`;
        break;
      default:
        throw new Error(`Cannot query field "${f.name}" on type "PullRequest".`);
    }
  }
  return out;
}

function gqlRepoFields(repo: Repo, fields: GqlField[]): Record<string, GqlValue> {
  const out: Record<string, GqlValue> = {};
  for (const f of fields) {
    if (f.inlineType && f.inlineType !== 'Repository') continue;
    const key = f.alias ?? f.name;
    switch (f.name) {
      case 'id':
        out[key] = gqlRepoId(repo);
        break;
      case 'databaseId':
        out[key] = repo.id;
        break;
      case 'name':
        out[key] = repo.name;
        break;
      case 'nameWithOwner':
        out[key] = `${repo.owner}/${repo.name}`;
        break;
      case 'owner':
        out[key] = { login: repo.owner };
        break;
      case 'defaultBranchRef':
        out[key] = { name: repo.defaultBranch };
        break;
      case 'viewerPermission':
        out[key] = 'ADMIN';
        break;
      case 'hasIssuesEnabled':
        out[key] = true;
        break;
      case 'description':
        out[key] = repo.description;
        break;
      case 'url':
        out[key] = `https://example.invalid/${repo.owner}/${repo.name}`;
        break;
      case 'createdAt':
      case 'updatedAt':
        out[key] = NOW_ISO;
        break;
      case 'private':
        out[key] = repo.isPrivate;
        break;
      case 'fork':
        out[key] = false;
        break;
      case 'issue': {
        const num = Number(f.args.number ?? 0);
        const issue = repo.issues.get(num);
        out[key] = issue ? gqlIssueFields(repo, issue, f.children) : null;
        break;
      }
      case 'issues': {
        const first = typeof f.args.first === 'number' ? f.args.first : 10;
        const after = typeof f.args.after === 'string' ? f.args.after : null;
        const states = Array.isArray(f.args.states) ? (f.args.states as string[]) : null;
        const orderBy = (f.args.orderBy ?? {}) as Record<string, GqlValue>;
        let list = [...repo.issues.values()];
        if (states) {
          list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
        }
        if (orderBy.field === 'CREATED_AT' && orderBy.direction === 'DESC') {
          list.sort((a, b) => b.createdSeq - a.createdSeq);
        } else if (orderBy.field === 'CREATED_AT') {
          list.sort((a, b) => a.createdSeq - b.createdSeq);
        } else {
          list.sort((a, b) => b.number - a.number);
        }
        let start = 0;
        if (after) {
          const n = Number(unb64(after));
          const idx = list.findIndex((i) => i.number === n);
          if (idx >= 0) start = idx + 1;
        }
        const page = list.slice(start, start + first);
        const hasNext = start + first < list.length;
        const endCursor = page.length > 0 ? b64(String(page[page.length - 1].number)) : null;
        const nodes: GqlValue[] = [];
        let pageInfo: GqlValue = null;
        let edges: GqlValue = null;
        for (const child of f.children) {
          if (child.name === 'nodes') nodes.push(...page.map((i) => gqlIssueFields(repo, i, child.children)));
          else if (child.name === 'pageInfo') {
            pageInfo = {
              hasNextPage: hasNext,
              hasPreviousPage: start > 0,
              startCursor: page.length > 0 ? b64(String(page[0].number)) : null,
              endCursor,
            };
          } else if (child.name === 'edges') {
            edges = page.map((i) => ({ node: gqlIssueFields(repo, i, child.children), cursor: b64(String(i.number)) }));
          } else if (child.name === 'totalCount') {
            out[key] = out[key] ?? {};
          }
        }
        const conn: Record<string, GqlValue> = {};
        if (nodes.length > 0) conn.nodes = nodes;
        if (pageInfo) conn.pageInfo = pageInfo;
        if (edges) conn.edges = edges;
        for (const child of f.children) {
          if (child.name === 'totalCount') conn.totalCount = list.length;
        }
        out[key] = conn;
        break;
      }
      case 'pullRequest': {
        const num = Number(f.args.number ?? 0);
        const pr = repo.pulls.get(num);
        out[key] = pr ? gqlPrFields(repo, pr, f.children) : null;
        break;
      }
      case 'pullRequests': {
        const first = typeof f.args.first === 'number' ? f.args.first : 10;
        let list = [...repo.pulls.values()].sort((a, b) => b.createdSeq - a.createdSeq);
        const states = Array.isArray(f.args.states) ? (f.args.states as string[]) : null;
        if (states) {
          list = list.filter((p) => states.includes(p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'));
        }
        const page = list.slice(0, first);
        const conn: Record<string, GqlValue> = {};
        for (const child of f.children) {
          if (child.name === 'nodes') conn.nodes = page.map((p) => gqlPrFields(repo, p, child.children));
          else if (child.name === 'totalCount') conn.totalCount = list.length;
          else if (child.name === 'pageInfo') {
            conn.pageInfo = {
              hasNextPage: first < list.length,
              hasPreviousPage: false,
              startCursor: page.length > 0 ? b64(String(page[0].number)) : null,
              endCursor: page.length > 0 ? b64(String(page[page.length - 1].number)) : null,
            };
          }
        }
        out[key] = conn;
        break;
      }
      default:
        throw new Error(`Cannot query field "${f.name}" on type "Repository".`);
    }
  }
  return out;
}

interface GqlExecResult {
  data: Record<string, GqlValue> | null;
  errors: Array<{ message: string }>;
}

function executeGqlDocument(query: string, variables: Record<string, GqlValue>): GqlExecResult {
  const errors: Array<{ message: string }> = [];
  const data: Record<string, GqlValue> = {};
  let parsed;
  try {
    parsed = new GqlParser(query).parseOperation(variables);
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'parse error' }] };
  }
  const { type, fields } = parsed;
  for (const field of fields) {
    const key = field.alias ?? field.name;
    try {
      if (type === 'mutation') {
        data[key] = executeMutation(field);
      } else {
        data[key] = executeQueryField(field);
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      errors.push({ message });
      data[key] = null;
    }
  }
  return { data, errors };
}

function executeQueryField(field: GqlField): GqlValue {
  switch (field.name) {
    case 'viewer': {
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'login') out[child.alias ?? 'login'] = VIEWER_LOGIN;
        else if (child.name === 'id') out[child.alias ?? 'id'] = VIEWER_ID;
        else if (child.name === 'name') out[child.alias ?? 'name'] = VIEWER_NAME;
        else if (child.name === 'email') out[child.alias ?? 'email'] = VIEWER_EMAIL;
        else if (child.name === 'url') out[child.alias ?? 'url'] = VIEWER_URL;
        else throw new Error(`Cannot query field "${child.name}" on type "User".`);
      }
      return out;
    }
    case 'repository': {
      const owner = String(field.args.owner ?? '');
      const name = String(field.args.name ?? '');
      const repo = repos.get(repoKey(owner, name));
      if (!repo) return null;
      return gqlRepoFields(repo, field.children);
    }
    case 'node': {
      const id = String(field.args.id ?? '');
      const decoded = decodeGlobalId(id);
      if (!decoded) return null;
      if (decoded.kind === 'R') {
        const m = /^repo:(.+)\/(.+)$/.exec(decoded.payload);
        if (!m) return null;
        const repo = repos.get(repoKey(m[1], m[2]));
        if (!repo) return null;
        const out = gqlRepoFields(repo, field.children.filter((c) => c.inlineType === 'Repository' || c.inlineType === null));
        out.id = gqlRepoId(repo);
        return out;
      }
      return null;
    }
    case '__type': {
      const name = String(field.args.name ?? '');
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'name') out[child.alias ?? 'name'] = name;
        else if (child.name === 'fields') {
          const includeDeprecated = child.args.includeDeprecated === true;
          void includeDeprecated;
          out[child.alias ?? 'fields'] = gqlTypeFields(name);
        } else if (child.name === 'enumValues') {
          if (name === 'SearchType') {
            out[child.alias ?? 'enumValues'] = GQL_SEARCH_ENUMS.map((e) => ({ name: e }));
          } else {
            out[child.alias ?? 'enumValues'] = [];
          }
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    default:
      throw new Error(`Cannot query field "${field.name}" on type "Query".`);
  }
}

function executeMutation(field: GqlField): GqlValue {
  const input = (field.args.input ?? {}) as Record<string, GqlValue>;
  switch (field.name) {
    case 'createIssue': {
      const repoId = String(input.repositoryId ?? '');
      const decoded = decodeGlobalId(repoId);
      if (!decoded || decoded.kind !== 'R') throw new Error('repository not found');
      const m = /^repo:(.+)\/(.+)$/.exec(decoded.payload);
      if (!m) throw new Error('repository not found');
      const repo = repos.get(repoKey(m[1], m[2]));
      if (!repo) throw new Error('repository not found');
      const made = createIssueInternal(repo, String(input.title ?? ''), String(input.body ?? ''), []);
      if ('error' in made) throw new Error(made.error);
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'issue') {
          out[child.alias ?? 'issue'] = gqlIssueFields(repo, made.issue, child.children);
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    case 'closeIssue': {
      const issueId = String(input.issueId ?? '');
      const decoded = decodeGlobalId(issueId);
      if (!decoded || decoded.kind !== 'I') throw new Error('issue not found');
      const m = /^issue:(.+)\/(.+):(\d+)$/.exec(decoded.payload);
      if (!m) throw new Error('issue not found');
      const repo = repos.get(repoKey(m[1], m[2]));
      const issue = repo?.issues.get(Number(m[3]));
      if (!repo || !issue) throw new Error('issue not found');
      issue.state = 'closed';
      issue.cachedJson = null;
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'issue') {
          out[child.alias ?? 'issue'] = gqlIssueFields(repo, issue, child.children);
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    case 'createPullRequest': {
      const repoId = String(input.repositoryId ?? '');
      const decoded = decodeGlobalId(repoId);
      if (!decoded || decoded.kind !== 'R') throw new Error('repository not found');
      const m = /^repo:(.+)\/(.+)$/.exec(decoded.payload);
      if (!m) throw new Error('repository not found');
      const repo = repos.get(repoKey(m[1], m[2]));
      if (!repo) throw new Error('repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) throw new Error('head or base branch does not exist');
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.head === head && existing.base === base) {
          throw new Error('A pull request already exists for this head and base');
        }
      }
      const pr: Pull = {
        id: nextPullRestId,
        number: repo.nextNumber,
        title: String(input.title ?? ''),
        body: String(input.body ?? ''),
        state: 'open',
        head,
        base,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeSha: null,
        createdSeq: ++sequence,
      };
      nextPullRestId += 1;
      repo.nextNumber += 1;
      repo.pulls.set(pr.number, pr);
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'pullRequest') {
          out[child.alias ?? 'pullRequest'] = gqlPrFields(repo, pr, child.children);
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    case 'mergePullRequest': {
      const prId = String(input.pullRequestId ?? '');
      const decoded = decodeGlobalId(prId);
      if (!decoded || decoded.kind !== 'P') throw new Error('pull request not found');
      const m = /^pr:(.+)\/(.+):(\d+)$/.exec(decoded.payload);
      if (!m) throw new Error('pull request not found');
      const repo = repos.get(repoKey(m[1], m[2]));
      const pr = repo?.pulls.get(Number(m[3]));
      if (!repo || !pr) throw new Error('pull request not found');
      if (String(input.mergeMethod ?? '') !== 'SQUASH') throw new Error('only SQUASH is supported');
      const result = squashMergeInternal(repo, pr);
      if (!result.ok) throw new Error(result.reason === 'conflict' ? 'merge conflict' : result.reason);
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'pullRequest') {
          out[child.alias ?? 'pullRequest'] = gqlPrFields(repo, pr, child.children);
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    case 'addComment': {
      const subjectId = String(input.subjectId ?? '');
      const decoded = decodeGlobalId(subjectId);
      if (!decoded) throw new Error('subject not found');
      let repo: Repo | undefined;
      let issue: Issue | undefined;
      if (decoded.kind === 'I') {
        const m = /^issue:(.+)\/(.+):(\d+)$/.exec(decoded.payload);
        if (m) {
          repo = repos.get(repoKey(m[1], m[2]));
          issue = repo?.issues.get(Number(m[3]));
        }
      }
      if (!repo || !issue) throw new Error('subject not found');
      const comment: IssueComment = {
        id: nextCommentRestId,
        body: String(input.body ?? ''),
        createdAt: NOW_ISO,
      };
      nextCommentRestId += 1;
      issue.comments.push(comment);
      issue.cachedJson = null;
      const out: Record<string, GqlValue> = {};
      for (const child of field.children) {
        if (child.name === 'commentEdge') {
          const node: Record<string, GqlValue> = {};
          for (const grand of child.children) {
            if (grand.name === 'node') {
              const n: Record<string, GqlValue> = {};
              for (const gg of grand.children) {
                if (gg.name === 'id') n[gg.alias ?? 'id'] = gqlCommentId(repo, issue, comment);
                else if (gg.name === 'body') n[gg.alias ?? 'body'] = comment.body;
                else n[gg.alias ?? gg.name] = null;
              }
              node[grand.alias ?? 'node'] = n;
            } else {
              node[grand.alias ?? grand.name] = null;
            }
          }
          out[child.alias ?? 'commentEdge'] = node;
        } else {
          out[child.alias ?? child.name] = null;
        }
      }
      return out;
    }
    default:
      throw new Error(`Cannot query field "${field.name}" on type "Mutation".`);
  }
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!requireAuth(req, res)) return;
  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { errors: [{ message: e instanceof Error ? e.message : 'bad request' }] });
    return;
  }
  const docs = Array.isArray(body) ? body : [body];
  const results = docs.map((doc) => {
    const d = (doc ?? {}) as { query?: string; variables?: Record<string, GqlValue> };
    if (typeof d.query !== 'string') return { errors: [{ message: 'query is required' }] };
    return executeGqlDocument(d.query, (d.variables ?? {}) as Record<string, GqlValue>);
  });
  sendJson(res, 200, Array.isArray(body) ? results : results[0]);
}

// ---------------------------------------------------------------------------
// MCP (Streamable HTTP, JSON-RPC 2.0)
// ---------------------------------------------------------------------------

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const TOOLS_LIST_JSON = JSON.stringify({ tools: MCP_TOOLS });

function mcpToolResult(result: unknown): Record<string, unknown> {
  const text = JSON.stringify(result);
  return { content: [{ type: 'text', text }], structuredContent: result };
}

function mcpToolError(message: string): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: message }],
    structuredContent: { error: message },
    isError: true,
  };
}

function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  switch (name) {
    case 'create_repo': {
      const repoName = typeof args.name === 'string' ? args.name : '';
      if (repoName === '') return mcpToolError('name is required');
      if (repos.has(repoKey(VIEWER_LOGIN, repoName))) {
        return mcpToolError('name already exists on this account');
      }
      const repo = createRepoRecord(
        VIEWER_LOGIN,
        repoName,
        typeof args.description === 'string' ? args.description : '',
        args.private === true,
      );
      return mcpToolResult({
        id: repo.id,
        name: repo.name,
        full_name: `${repo.owner}/${repo.name}`,
        private: repo.isPrivate,
        description: repo.description,
        default_branch: repo.defaultBranch,
        owner: { login: repo.owner },
      });
    }
    case 'get_repo': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const repoName = typeof args.repo === 'string' ? args.repo : '';
      const repo = repos.get(repoKey(owner, repoName));
      if (!repo) return mcpToolError('repository not found');
      return mcpToolResult({
        id: repo.id,
        name: repo.name,
        full_name: `${repo.owner}/${repo.name}`,
        private: repo.isPrivate,
        description: repo.description,
        default_branch: repo.defaultBranch,
        owner: { login: repo.owner },
      });
    }
    case 'create_issue': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const repoName = typeof args.repo === 'string' ? args.repo : '';
      const title = typeof args.title === 'string' ? args.title : '';
      const repo = repos.get(repoKey(owner, repoName));
      if (!repo) return mcpToolError('repository not found');
      if (title === '') return mcpToolError('title is required');
      const made = createIssueInternal(repo, title, typeof args.body === 'string' ? args.body : '', []);
      if ('error' in made) return mcpToolError(made.error);
      const issue = made.issue;
      return mcpToolResult({
        id: issue.id,
        number: issue.number,
        title: issue.title,
        body: issue.body,
        state: issue.state,
        labels: issue.labels,
      });
    }
    case 'list_issues': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const repoName = typeof args.repo === 'string' ? args.repo : '';
      const state = typeof args.state === 'string' ? args.state : 'open';
      const repo = repos.get(repoKey(owner, repoName));
      if (!repo) return mcpToolError('repository not found');
      let list = [...repo.issues.values()];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      return mcpToolResult(
        list.map((i) => ({
          id: i.id,
          number: i.number,
          title: i.title,
          body: i.body,
          state: i.state,
          labels: i.labels,
        })),
      );
    }
    case 'create_pull_request': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const repoName = typeof args.repo === 'string' ? args.repo : '';
      const title = typeof args.title === 'string' ? args.title : '';
      const head = typeof args.head === 'string' ? args.head : '';
      const base = typeof args.base === 'string' ? args.base : 'main';
      const repo = repos.get(repoKey(owner, repoName));
      if (!repo) return mcpToolError('repository not found');
      if (title === '' || head === '') return mcpToolError('title and head are required');
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) return mcpToolError('head or base branch does not exist');
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.head === head && existing.base === base) {
          return mcpToolError('A pull request already exists for this head and base');
        }
      }
      const pr: Pull = {
        id: nextPullRestId,
        number: repo.nextNumber,
        title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        head,
        base,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeSha: null,
        createdSeq: ++sequence,
      };
      nextPullRestId += 1;
      repo.nextNumber += 1;
      repo.pulls.set(pr.number, pr);
      return mcpToolResult({
        id: pr.id,
        number: pr.number,
        title: pr.title,
        body: pr.body,
        state: pr.state,
        head: { ref: pr.head, sha: pr.headSha },
        base: { ref: pr.base, sha: pr.baseSha },
      });
    }
    case 'merge_pull_request': {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const repoName = typeof args.repo === 'string' ? args.repo : '';
      const num = Number(args.pull_number ?? 0);
      const repo = repos.get(repoKey(owner, repoName));
      if (!repo) return mcpToolError('repository not found');
      const pr = repo.pulls.get(num);
      if (!pr) return mcpToolError('pull request not found');
      const result = squashMergeInternal(repo, pr);
      if (!result.ok) return mcpToolError(result.reason);
      return mcpToolResult({ merged: true, sha: result.sha, number: pr.number });
    }
    default:
      return mcpToolError(`unknown tool: ${name}`);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!requireAuth(req, res)) return;
  let body: unknown;
  try {
    body = await readJsonBody(req);
  } catch {
    sendJson(res, 400, {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error' },
    });
    return;
  }
  const rpc = (body ?? {}) as { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  const id = rpc.id ?? null;
  const method = typeof rpc.method === 'string' ? rpc.method : '';
  const params = (rpc.params ?? {}) as Record<string, unknown>;

  const reply = (status: number, result: unknown, isError = false): void => {
    if (isError) {
      sendJson(res, status, { jsonrpc: '2.0', id, error: result });
    } else {
      sendJson(res, status, { jsonrpc: '2.0', id, result });
    }
  };

  if (method === 'server/discover') {
    reply(200, {
      supportedVersions: ['2026-07-28', '2025-11-25'],
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    reply(200, {
      protocolVersion: offered,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    });
    return;
  }
  if (method === 'notifications/initialized') {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (method === 'tools/list') {
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'x-github-request-id': nextRequestId(),
    });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result: JSON.parse(TOOLS_LIST_JSON) }));
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    if (!MCP_TOOLS.some((t) => t.name === toolName)) {
      reply(200, { code: -32602, message: `unknown tool: ${toolName}` }, true);
      return;
    }
    const tool = MCP_TOOLS.find((t) => t.name === toolName) as Record<string, unknown>;
    const schema = tool.inputSchema as { required?: string[] };
    const missing = (schema.required ?? []).filter(
      (k) => args[k] === undefined || args[k] === null || args[k] === '',
    );
    if (missing.length > 0) {
      reply(200, { code: -32602, message: `missing required arguments: ${missing.join(', ')}` }, true);
      return;
    }
    reply(200, runMcpTool(toolName, args));
    return;
  }
  reply(200, { code: -32601, message: `method not found: ${method}` }, true);
}

// ---------------------------------------------------------------------------
// Git routing
// ---------------------------------------------------------------------------

async function handleGit(
  req: IncomingMessage,
  res: ServerResponse,
  path: string,
  service: string | null,
): Promise<void> {
  const match = /^\/([^/]+)\/([^/]+)\.git\/(.+)$/.exec(path);
  if (!match) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const owner = match[1];
  const name = match[2];
  const tail = match[3];
  const method = req.method ?? 'GET';
  const repo = repos.get(repoKey(owner, name));
  if (!repo) {
    if (!requireAuth(req, res)) return;
    sendError(res, 404, 'Not Found');
    return;
  }
  if (!requireAuth(req, res)) return;

  if (method === 'GET' && tail === 'info/refs') {
    let buf: Buffer;
    if (service === 'git-upload-pack') {
      const isV2 = req.headers['git-protocol'] === 'version=2';
      buf = isV2 ? buildV2Advertisement(repo) : buildV0Advertisement(repo, 'upload-pack');
    } else if (service === 'git-receive-pack') buf = buildV0Advertisement(repo, 'receive-pack');
    else {
      sendError(res, 400, 'unknown service');
      return;
    }
    res.writeHead(200, {
      'content-type': `application/x-${service}-advertisement`,
      'x-github-request-id': nextRequestId(),
    });
    res.end(buf);
    return;
  }

  if (method === 'POST' && tail === 'git-upload-pack') {
    const isV2 = req.headers['git-protocol'] === 'version=2';
    let body: Buffer;
    try {
      body = await readBody(req);
    } catch {
      sendError(res, 400, 'could not read request body');
      return;
    }
    let lines: PktLine[];
    try {
      lines = decodePktLines(body);
    } catch {
      sendError(res, 400, 'malformed pkt-line stream');
      return;
    }
    const first = lines.find((l) => l.kind === 'data');
    const firstText = first && first.kind === 'data' ? first.payload.toString('utf8').trim() : '';
    let buf: Buffer;
    let contentType: string;
    if (firstText.startsWith('command=ls-refs')) {
      buf = handleLsRefs(repo, lines);
      contentType = 'application/x-git-upload-pack-result';
    } else if (firstText.startsWith('command=fetch')) {
      buf = handleFetch(repo, lines, true);
      contentType = 'application/x-git-upload-pack-result';
    } else if (isV2) {
      sendError(res, 400, 'unknown command');
      return;
    } else {
      buf = handleFetch(repo, lines, false);
      contentType = 'application/x-git-upload-pack-result';
    }
    res.writeHead(200, {
      'content-type': contentType,
      'x-github-request-id': nextRequestId(),
    });
    res.end(buf);
    return;
  }

  if (method === 'POST' && tail === 'git-receive-pack') {
    let body: Buffer;
    try {
      body = await readBody(req);
    } catch {
      sendError(res, 400, 'could not read request body');
      return;
    }
    let buf: Buffer;
    try {
      buf = handleReceivePack(repo, body);
    } catch {
      sendError(res, 400, 'malformed receive-pack request');
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/x-git-receive-pack-result',
      'x-github-request-id': nextRequestId(),
    });
    res.end(buf);
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// Top-level routing and lifecycle
// ---------------------------------------------------------------------------

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const rawUrl = req.url ?? '/';
    const path = rawUrl.split('?')[0];
    const method = req.method ?? 'GET';

    if (method === 'GET' && path === '/healthz') {
      res.writeHead(200, { 'x-github-request-id': nextRequestId() });
      res.end('ok');
      return;
    }
    if (path === '/api/graphql' && method === 'POST') {
      await handleGraphql(req, res);
      return;
    }
    if (path === '/mcp' && method === 'POST') {
      await handleMcp(req, res);
      return;
    }
    if (path.startsWith('/api/v3')) {
      await handleRest(req, res, path.slice('/api/v3'.length));
      return;
    }
    const gitMatch = /^\/[^/]+\/[^/]+\.git\//.exec(path);
    if (gitMatch) {
      const query = parseQuery(rawUrl);
      await handleGit(req, res, path, query.get('service'));
      return;
    }
    sendError(res, 404, 'Not Found');
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    if (!res.headersSent) {
      sendError(res, status, e instanceof Error ? e.message : 'internal error');
    } else {
      res.end();
    }
  }
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerAndWait(): Promise<void> {
  if (!ENV_URL) {
    // Local development: just serve. Never resolve, so the server stays up.
    await new Promise(() => {});
    return;
  }
  const port = (server.address() as { port: number } | null)?.port ?? 0;
  let delay = 200;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const r = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (r.ok) break;
    } catch {
      // coordinator not ready yet; retry
    }
    await sleep(delay);
    delay = Math.min(delay * 2, 5000);
  }
  while (true) {
    try {
      const r = await fetch(`${ENV_URL}/done`);
      if (r.ok) {
        const body = (await r.json()) as { done?: boolean };
        if (body.done) return;
      }
    } catch {
      // coordinator unreachable; keep polling
    }
    await sleep(500);
  }
}

const server = createServer((req, res) => {
  void handle(req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : PORT;
  console.error(`forge listening on port ${port}`);
  void registerAndWait().then(() => {
    server.close(() => process.exit(0));
  });
});
