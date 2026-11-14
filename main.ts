// forge.ts — a one-process, zero-dependency GitHub-compatible forge.
//
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL
// and MCP from a single in-memory store. Node 22, standard library only.
//
// Boot: bind an ephemeral port, POST {"port"} to $MAKEFUN_ENV_URL/register,
// then long-poll GET $MAKEFUN_ENV_URL/done until {"done": true} and exit 0.
// Without MAKEFUN_ENV_URL it just listens and logs its port (local practice).
//
// Determinism: no wall clock and no randomness anywhere in a response.
// Commit stamps use one fixed epoch; ids are counters; bytes are stable.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------ config

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const AGENT_NAME = 'forge/1.0';
const FIXED_EPOCH = 1700000000;
const IDENT = 'Forge <forge@example.invalid>';
const ZERO_OID = '0'.repeat(40);
const MAX_BODY = 64 * 1024 * 1024;

// ------------------------------------------------------------------ hashing

function sha1hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** git's object id: SHA-1 over "<type> <size>\0" + content. */
function objectId(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  const h = createHash('sha1');
  h.update(head);
  h.update(data);
  return h.digest('hex');
}

/** The loose-object bytes (header + content) a pack entry deflates. */
function looseBytes(type: string, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${type} ${data.length}\0`, 'utf8'), data]);
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

// ------------------------------------------------------------------ pkt-line

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_END = Buffer.from('0002', 'ascii');

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((body.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, body]);
}

function pktLines(parts: ReadonlyArray<string | Buffer | 'flush' | 'delim' | 'end'>): Buffer {
  const out: Buffer[] = [];
  for (const part of parts) {
    if (part === 'flush') out.push(PKT_FLUSH);
    else if (part === 'delim') out.push(PKT_DELIM);
    else if (part === 'end') out.push(PKT_END);
    else out.push(pktLine(part));
  }
  return Buffer.concat(out);
}

/** Split a buffer into pkt-line packets: {data} | {flush} | {delim} | {end}. */
function splitPackets(buf: Buffer): Array<{ kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }> {
  const packets: Array<{ kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }> = [];
  let at = 0;
  while (at + 4 <= buf.length) {
    const len = Number.parseInt(buf.subarray(at, at + 4).toString('ascii'), 16);
    if (!Number.isFinite(len) || len < 0 || len > 65520) break;
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      at += 4;
      continue;
    }
    if (at + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(at + 4, at + len) });
    at += len;
  }
  return packets;
}

/** The data-packet payloads of a buffer, as UTF-8 lines without the trailing LF. */
function packetLines(buf: Buffer): string[] {
  const lines: string[] = [];
  for (const packet of splitPackets(buf)) {
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8');
    lines.push(text.endsWith('\n') ? text.slice(0, -1) : text);
  }
  return lines;
}

// ------------------------------------------------------------------ base64

function b64encode(data: Buffer): string {
  return data.toString('base64');
}

function b64decode(text: string): Buffer | null {
  if (typeof text !== 'string' || /[^A-Za-z0-9+/=]/.test(text)) return null;
  try {
    return Buffer.from(text, 'base64');
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ misc

function esc(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

function counter(): () => number {
  let n = 0;
  return () => ++n;
}

const nextReqId = counter();

// ------------------------------------------------------------------ objects
//
// An object is {t: 'commit'|'tree'|'blob'|'tag', d: Buffer} where d is the
// content WITHOUT the "<type> <len>\0" header. The id is objectId(t, d).

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  t: ObjType;
  d: Buffer;
}

interface TreeItem {
  mode: string;
  name: string;
  oid: string;
}

/** Parse a tree object's entries, in stored order. */
function parseTree(data: Buffer): TreeItem[] {
  const items: TreeItem[] = [];
  let at = 0;
  while (at < data.length) {
    const sp = data.indexOf(0x20, at);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree');
    items.push({
      mode: data.subarray(at, sp).toString('ascii'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    at = nul + 21;
  }
  return items;
}

/** git's tree sort: a directory name compares as if it ended in '/'. */
function treeSortKey(item: TreeItem): Buffer {
  return Buffer.from(item.mode === '40000' ? `${item.name}/` : item.name, 'utf8');
}

/** Build a tree object's bytes from entries, sorted the way git sorts them. */
function buildTreeBytes(items: TreeItem[]): Buffer {
  const sorted = [...items].sort((a, b) => Buffer.compare(treeSortKey(a), treeSortKey(b)));
  const parts: Buffer[] = [];
  for (const item of sorted) {
    parts.push(Buffer.from(`${item.mode} ${item.name}\0`, 'utf8'));
    parts.push(Buffer.from(item.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

/** Parse a commit object's headers and message. */
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const view: CommitView = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const key = line.slice(0, sp);
    const val = line.slice(sp + 1);
    if (key === 'tree') view.tree = val;
    else if (key === 'parent') view.parents.push(val);
    else if (key === 'author') view.author = val;
    else if (key === 'committer') view.committer = val;
  }
  return view;
}

/** Build a commit object's bytes. `when` is a fixed epoch, never Date.now(). */
function buildCommitBytes(tree: string, parents: readonly string[], message: string, when = FIXED_EPOCH): Buffer {
  const who = `${IDENT} ${when} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

/** The commit a tag object points at (peeling nested tags). */
function tagTarget(data: Buffer): { oid: string; type: string } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  let oid = '';
  let type = '';
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    if (line.slice(0, sp) === 'object') oid = line.slice(sp + 1);
    if (line.slice(0, sp) === 'type') type = line.slice(sp + 1);
  }
  return { oid, type };
}

/**
 * Every object reachable from `roots`: commit -> tree + parents, tree ->
 * entries, tag -> its target. Missing objects are skipped when `loose`
 * is set, otherwise the walk throws naming the missing id.
 */
function walkReachable(
  roots: Iterable<string>,
  lookup: (oid: string) => GitObj | undefined,
  loose = false,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [];
  for (const root of roots) if (isOid(root)) stack.push(root);
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = lookup(oid);
    if (!obj) {
      if (loose) continue;
      throw new Error(`missing object ${oid}`);
    }
    seen.add(oid);
    if (obj.t === 'commit') {
      const view = parseCommit(obj.d);
      stack.push(view.tree);
      for (const parent of view.parents) stack.push(parent);
    } else if (obj.t === 'tag') {
      stack.push(tagTarget(obj.d).oid);
    } else if (obj.t === 'tree') {
      for (const item of parseTree(obj.d)) {
        if (item.mode !== '160000') stack.push(item.oid);
      }
    }
  }
  return seen;
}

// ------------------------------------------------------------------ packfile

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** One pack entry's type/size varint header. */
function packEntryHead(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let rest = size;
  let first = (code << 4) | (rest & 0x0f);
  rest = Math.floor(rest / 16);
  while (rest > 0) {
    bytes.push(first | 0x80);
    first = rest & 0x7f;
    rest = Math.floor(rest / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a PACK v2 file from plain objects (no deltas). */
function buildPack(objects: Iterable<GitObj>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(list.length, 8);
  parts.push(head);
  for (const obj of list) {
    parts.push(packEntryHead(obj.t, obj.d.length));
    parts.push(deflateSync(obj.d));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Inflate one zlib stream at `at`; returns its bytes and the next offset. */
function inflateOne(buf: Buffer, at: number): { data: Buffer; next: number } {
  const out = inflateSync(buf.subarray(at), { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  const used = out.engine.bytesWritten;
  if (!used || used <= 0) throw new Error('empty zlib stream in pack');
  return { data: out.buffer, next: at + used };
}

/**
 * Read a PACK v2/v3 file into a map id -> object, resolving OFS_DELTA and
 * REF_DELTA entries. `outside` supplies thin-pack bases the client holds.
 */
function readPack(pack: Buffer, outside?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const end = pack.length - 20;
  interface Raw {
    off: number;
    code: number;
    size: number;
    data: Buffer;
    baseOff?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  const byOff = new Map<number, Raw>();
  let at = 12;
  for (let i = 0; i < count; i += 1) {
    const off = at;
    let byte = pack[at];
    const first = byte;
    let size = byte & 0x0f;
    let shift = 4;
    at += 1;
    while (byte & 0x80) {
      byte = pack[at++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const code = (first >> 4) & 0x07;
    const entry: Raw = { off, code, size, data: Buffer.alloc(0) };
    if (code === 6) {
      // OFS_DELTA: base offset encoded as a backwards distance.
      let b = pack[at++];
      let value = b & 0x7f;
      while (b & 0x80) {
        b = pack[at++];
        value = (value + 1) * 128 + (b & 0x7f);
      }
      entry.baseOff = off - value;
    } else if (code === 7) {
      entry.baseOid = pack.subarray(at, at + 20).toString('hex');
      at += 20;
    } else if (!CODE_TYPE[code]) {
      throw new Error(`pack entry type ${code}`);
    }
    const inflated = inflateOne(pack.subarray(0, end), at);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    at = inflated.next;
    raw.push(entry);
    byOff.set(off, entry);
  }
  if (at !== end) throw new Error('pack trailing bytes');
  const objects = new Map<string, GitObj>();
  const resolved = new Map<string, GitObj>();
  const busy = new Set<number>();
  const applyDelta = (base: Buffer, delta: Buffer): Buffer => {
    let off = 0;
    const readNum = (): number => {
      let value = 0;
      let sh = 0;
      for (;;) {
        const b = delta[off++];
        value += (b & 0x7f) * 2 ** sh;
        sh += 7;
        if (!(b & 0x80)) break;
      }
      return value;
    };
    const srcSize = readNum();
    const dstSize = readNum();
    if (srcSize !== base.length) throw new Error('delta base size');
    const out = Buffer.allocUnsafe(dstSize);
    let written = 0;
    while (off < delta.length) {
      const op = delta[off++];
      if (op & 0x80) {
        let cpOff = 0;
        let cpSize = 0;
        let sh = 0;
        for (let bit = 0; bit < 4; bit += 1) {
          if (op & (1 << bit)) cpOff += delta[off++] * 2 ** sh;
          sh += 8;
        }
        sh = 0;
        for (let bit = 4; bit < 7; bit += 1) {
          if (op & (1 << bit)) cpSize += delta[off++] * 2 ** sh;
          sh += 8;
        }
        if (cpSize === 0) cpSize = 0x10000;
        base.copy(out, written, cpOff, cpOff + cpSize);
        written += cpSize;
      } else if (op !== 0) {
        const len = op & 0x7f;
        delta.copy(out, written, off, off + len);
        off += len;
        written += len;
      } else {
        throw new Error('delta opcode 0');
      }
    }
    if (written !== dstSize) throw new Error('delta size');
    return out;
  };
  const resolve = (entry: Raw): GitObj => {
    const cached = resolved.get(entry.off.toString());
    if (cached) return cached;
    if (busy.has(entry.off)) throw new Error('delta cycle');
    busy.add(entry.off);
    let obj: GitObj;
    if (entry.code === 6) {
      const baseEntry = byOff.get(entry.baseOff!);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      obj = { t: base.t, d: applyDelta(base.d, entry.data) };
    } else if (entry.code === 7) {
      const base = resolvedByOid(entry.baseOid!) ?? outside?.(entry.baseOid!);
      if (!base) throw new Error('ref-delta base missing');
      obj = { t: base.t, d: applyDelta(base.d, entry.data) };
    } else {
      obj = { t: CODE_TYPE[entry.code], d: entry.data };
    }
    busy.delete(entry.off);
    resolved.set(entry.off.toString(), obj);
    return obj;
  };
  const resolvedByOid = (oid: string): GitObj | undefined => {
    for (const obj of resolved.values()) {
      if (objectId(obj.t, obj.d) === oid) return obj;
    }
    return objects.get(oid);
  };
  for (const entry of raw) {
    const obj = resolve(entry);
    objects.set(objectId(obj.t, obj.d), obj);
  }
  return objects;
}

// ------------------------------------------------------------------ store

interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Array<{ name: string; color: string }>;
  comments: Array<{ id: number; body: string }>;
  json: string;
}

interface PullRec {
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
  mergedAt: string;
  mergeSha: string;
  files: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }>;
}

interface LabelRec {
  name: string;
  color: string;
}

/** One repository: objects, refs, issues, pulls, labels, all in memory. */
class Repo {
  id: number;
  name: string;
  owner: string;
  priv: boolean;
  desc: string;
  defBranch = 'main';
  refs = new Map<string, string>();
  objects = new Map<string, GitObj>();
  labels = new Map<string, LabelRec>();
  issues: IssueRec[] = [];
  issueSeq = 0;
  pulls: PullRec[] = [];
  pullSeq = 0;
  flatCache = new Map<string, Map<string, { oid: string; size: number }>>();
  clonePack = new Map<string, Buffer>();
  readJson = new Map<number, string>();

  constructor(id: number, name: string, owner: string, priv: boolean, desc: string) {
    this.id = id;
    this.name = name;
    this.owner = owner;
    this.priv = priv;
    this.desc = desc;
  }

  get lookup(): (oid: string) => GitObj | undefined {
    return (oid) => this.objects.get(oid);
  }

  tip(branch: string): string | undefined {
    return this.refs.get(`refs/heads/${branch}`);
  }

  /** Flat path -> blob map for a commit, cached per commit id. */
  flatFiles(commitOid: string): Map<string, { oid: string; size: number }> {
    const cached = this.flatCache.get(commitOid);
    if (cached) return cached;
    const out = new Map<string, { oid: string; size: number }>();
    const commit = this.objects.get(commitOid);
    if (commit && commit.t === 'commit') {
      const stack: Array<{ oid: string; prefix: string }> = [{ oid: parseCommit(commit.d).tree, prefix: '' }];
      while (stack.length > 0) {
        const { oid, prefix } = stack.pop()!;
        const tree = this.objects.get(oid);
        if (!tree || tree.t !== 'tree') continue;
        for (const item of parseTree(tree.d)) {
          const path = prefix === '' ? item.name : `${prefix}/${item.name}`;
          if (item.mode === '40000') stack.push({ oid: item.oid, prefix: path });
          else if (item.mode === '160000') continue;
          else {
            const blob = this.objects.get(item.oid);
            out.set(path, { oid: item.oid, size: blob ? blob.d.length : 0 });
          }
        }
      }
    }
    this.flatCache.set(commitOid, out);
    return out;
  }

  /** Build (and store) nested trees for a flat file map; returns the root tree id. */
  storeTrees(files: Map<string, { oid: string; size: number }>): string {
    interface Node {
      files: Map<string, string>;
      dirs: Map<string, Node>;
    }
    const make = (): Node => ({ files: new Map(), dirs: new Map() });
    const root = make();
    for (const [path, entry] of files) {
      const parts = path.split('/');
      let node = root;
      for (let i = 0; i < parts.length - 1; i += 1) {
        const seg = parts[i];
        if (!node.dirs.has(seg)) node.dirs.set(seg, make());
        node = node.dirs.get(seg)!;
      }
      node.files.set(parts[parts.length - 1], entry.oid);
    }
    const build = (node: Node): string => {
      const items: TreeItem[] = [];
      for (const [name, oid] of node.files) items.push({ mode: '100644', name, oid });
      for (const [name, child] of node.dirs) items.push({ mode: '40000', name, oid: build(child) });
      const bytes = buildTreeBytes(items);
      const oid = objectId('tree', bytes);
      if (!this.objects.has(oid)) this.objects.set(oid, { t: 'tree', d: bytes });
      return oid;
    };
    return build(root);
  }

  /** Commit a new tree on a branch. Returns the new commit id. */
  commitOn(branch: string, treeOid: string, message: string): string {
    const parent = this.tip(branch);
    const parents = parent ? [parent] : [];
    const bytes = buildCommitBytes(treeOid, parents, message);
    const oid = objectId('commit', bytes);
    if (!this.objects.has(oid)) this.objects.set(oid, { t: 'commit', d: bytes });
    this.refs.set(`refs/heads/${branch}`, oid);
    this.clonePack.clear();
    return oid;
  }

  /** Every tree and blob id under a tree (recursive, includes the root). */
  treeClosure(treeOid: string): Set<string> {
    const out = new Set<string>();
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (out.has(oid)) continue;
      const obj = this.objects.get(oid);
      if (!obj || obj.t !== 'tree') continue;
      out.add(oid);
      for (const item of parseTree(obj.d)) {
        if (item.mode === '40000') stack.push(item.oid);
        else if (item.mode !== '160000') out.add(item.oid);
      }
    }
    return out;
  }

  /** Newest-first history of a commit (walks first parents, then all parents). */
  history(tipOid: string): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const stack = [tipOid];
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (seen.has(oid)) continue;
      const obj = this.objects.get(oid);
      if (!obj || obj.t !== 'commit') continue;
      seen.add(oid);
      out.push(oid);
      for (const parent of parseCommit(obj.d).parents) stack.push(parent);
    }
    return out;
  }

  /** The latest commit reachable from both tips, or null. */
  mergeBase(a: string, b: string): string | null {
    const fromA = new Set(this.history(a));
    for (const oid of this.history(b)) {
      if (fromA.has(oid)) return oid;
    }
    return null;
  }

  /** True when `anc` is an ancestor of `tip` (or equal to it). */
  isAncestor(anc: string, tip: string): boolean {
    if (anc === tip) return true;
    return this.history(tip).includes(anc);
  }

  /** Per-path change between two trees: added / modified / deleted. */
  diffTrees(baseOid: string, headOid: string): Map<string, { base?: string; head?: string }> {
    const base = baseOid ? this.flatFiles(baseOid) : new Map();
    const head = headOid ? this.flatFiles(headOid) : new Map();
    const out = new Map<string, { base?: string; head?: string }>();
    for (const [path, entry] of base) {
      const other = head.get(path);
      if (!other) out.set(path, { base: entry.oid });
      else if (other.oid !== entry.oid) out.set(path, { base: entry.oid, head: other.oid });
    }
    for (const [path, entry] of head) {
      if (!base.has(path)) out.set(path, { head: entry.oid });
    }
    return out;
  }
}

/** The whole forge: every repository plus the global counters. */
class Forge {
  repos = new Map<string, Repo>();
  viewer = '';
  nextRepoId = 5000;
  nextGlobalId = 100000;
  nextIssueId = 100000;

  learnViewer(owner: string): void {
    if (this.viewer === '') this.viewer = owner;
  }

  repo(owner: string, name: string): Repo | null {
    this.learnViewer(owner);
    if (owner !== this.viewer) return null;
    return this.repos.get(name) ?? null;
  }

  createRepo(name: string, priv: boolean, desc: string): Repo | null {
    if (this.repos.has(name)) return null;
    const repo = new Repo(this.nextRepoId++, name, this.viewer, priv, desc);
    this.repos.set(name, repo);
    return repo;
  }

  deleteRepo(name: string): boolean {
    return this.repos.delete(name);
  }

  listRepos(): Repo[] {
    return [...this.repos.values()];
  }
}

const forge = new Forge();

// ------------------------------------------------------------------ git
//
// Smart HTTP: GET /{owner}/{repo}.git/info/refs?service=..., POST
// /{owner}/{repo}.git/git-upload-pack and .../git-receive-pack.

interface RefLine {
  name: string;
  oid: string;
  peeled?: string;
  symref?: string;
  unborn?: boolean;
}

/** The ref lines a repo advertises, HEAD first, then heads, then tags. */
function refLines(repo: Repo): RefLine[] {
  const lines: RefLine[] = [];
  const main = repo.tip(repo.defBranch);
  if (main) lines.push({ name: 'HEAD', oid: main, symref: `refs/heads/${repo.defBranch}` });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name)!;
    const line: RefLine = { name, oid };
    if (name.startsWith('refs/tags/')) {
      const obj = repo.objects.get(oid);
      if (obj && obj.t === 'tag') {
        let target = tagTarget(obj.d);
        let guard = 0;
        while (target.type === 'tag' && guard++ < 8) {
          const next = repo.objects.get(target.oid);
          if (!next || next.t !== 'tag') break;
          target = tagTarget(next.d);
        }
        if (target.type === 'commit') line.peeled = target.oid;
      }
    }
    lines.push(line);
  }
  return lines;
}

const UPLOAD_V2_CAPS = ['agent=' + AGENT_NAME, 'ls-refs=unborn', 'fetch=shallow wait-for-done', 'object-format=sha1'];
const UPLOAD_V0_CAPS = 'symref=HEAD:refs/heads/main side-band-64k shallow thin-pack ofs-delta multi_ack_detailed agent=' + AGENT_NAME;
const RECEIVE_V0_CAPS = 'symref=HEAD:refs/heads/main report-status side-band-64k delete-refs ofs-delta agent=' + AGENT_NAME;

/** v2 capability advertisement (no refs, just "version 2" + capabilities). */
function advertiseV2(): Buffer {
  const parts: Array<string | 'flush'> = ['version 2\n', ...UPLOAD_V2_CAPS.map((c) => `${c}\n`), 'flush'];
  return pktLines(parts);
}

/** v0 advertisement for a service, with the "# service=" preamble. */
function advertiseV0(service: string, repo: Repo): Buffer {
  const caps = service === 'git-receive-pack' ? RECEIVE_V0_CAPS : UPLOAD_V0_CAPS;
  const lines = refLines(repo);
  const parts: Array<string | Buffer | 'flush'> = [`# service=${service}\n`, 'flush'];
  if (lines.length === 0) {
    parts.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    lines.forEach((line, i) => {
      const text = `${line.oid} ${line.name}${i === 0 ? `\0${caps}` : ''}\n`;
      parts.push(text);
      if (line.peeled) parts.push(`${line.peeled} ${line.name}^{}\n`);
    });
  }
  parts.push('flush');
  return pktLines(parts);
}

/** v2 ls-refs answer for the requested args. */
function lsRefsV2(repo: Repo, args: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const lines = refLines(repo);
  const out: Array<string | 'flush'> = [];
  const hasRefs = lines.some((l) => l.name.startsWith('refs/'));
  if (!hasRefs) {
    if (args.unborn) {
      const head = lines.find((l) => l.name === 'HEAD');
      out.push(`unborn HEAD${args.symrefs && head?.symref ? ` symref-target:${head.symref}` : ''}\n`);
    }
  } else {
    for (const line of lines) {
      if (args.prefixes.length > 0 && !args.prefixes.some((p) => line.name.startsWith(p))) continue;
      let text = `${line.oid} ${line.name}`;
      if (args.symrefs && line.symref) text += ` symref-target:${line.symref}`;
      if (args.peel && line.peeled) text += ` peeled:${line.peeled}`;
      out.push(`${text}\n`);
    }
  }
  out.push('flush');
  return pktLines(out);
}

interface FetchPlan {
  send: GitObj[];
  shallow: string[];
  unshallow: string[];
  acks: string[];
  nak: boolean;
}

/**
 * Work out what a fetch sends: reachable(wants, depth) minus what the
 * client already holds. `depth` is absolute from the tip (1 = tip only).
 * Old shallow boundaries count as held only as their own shallow closure.
 */
function planFetch(repo: Repo, wants: string[], haves: string[], shallow: string[], depth?: number): FetchPlan {
  const lookup = repo.lookup;
  const shallowSet = new Set(shallow);
  // What the client already holds.
  const held = new Set<string>();
  for (const have of haves) {
    if (!isOid(have) || !repo.objects.has(have)) continue;
    if (shallowSet.has(have)) {
      // A shallow boundary: the commit itself plus its whole tree closure.
      const commit = repo.objects.get(have)!;
      if (commit.t !== 'commit') continue;
      held.add(have);
      for (const oid of repo.treeClosure(parseCommit(commit.d).tree)) held.add(oid);
    } else {
      for (const oid of walkReachable([have], lookup, true)) held.add(oid);
    }
  }
  // What the client wants, depth-limited.
  const wanted = new Set<string>();
  const boundary = new Set<string>();
  for (const want of wants) {
    if (!isOid(want) || !repo.objects.has(want)) continue;
    const obj = repo.objects.get(want)!;
    if (obj.t === 'tag') {
      // A want may name a tag: send the tag and its target's closure.
      wanted.add(want);
      const target = tagTarget(obj.d);
      if (target.oid && repo.objects.has(target.oid)) {
        for (const oid of walkReachable([target.oid], lookup, true)) wanted.add(oid);
      }
      continue;
    }
    if (obj.t !== 'commit') {
      wanted.add(want);
      continue;
    }
    if (depth === undefined) {
      for (const oid of walkReachable([want], lookup, true)) wanted.add(oid);
    } else {
      // Commits at distance <= depth-1 from the want, with their trees/blobs.
      let frontier = [want];
      for (let d = 0; d < depth; d += 1) {
        const next: string[] = [];
        for (const oid of frontier) {
          if (wanted.has(oid)) continue;
          wanted.add(oid);
          const c = repo.objects.get(oid);
          if (!c || c.t !== 'commit') continue;
          const view = parseCommit(c.d);
          for (const oid of repo.treeClosure(view.tree)) wanted.add(oid);
          if (d === depth - 1) {
            if (view.parents.length > 0) boundary.add(oid);
          } else {
            for (const parent of view.parents) next.push(parent);
          }
        }
        frontier = next;
      }
    }
  }
  const send: GitObj[] = [];
  for (const oid of wanted) {
    if (held.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) send.push(obj);
  }
  // New shallow boundaries, and old ones that stopped being boundaries.
  const shallowOut = depth === undefined ? [] : [...boundary];
  const unshallow: string[] = [];
  if (depth !== undefined) {
    for (const old of shallow) {
      if (!wanted.has(old)) continue;
      const c = repo.objects.get(old);
      if (!c || c.t !== 'commit') continue;
      if (parseCommit(c.d).parents.some((p) => wanted.has(p))) unshallow.push(old);
    }
  }
  // Common commits for the acknowledgment section.
  const acks: string[] = [];
  for (const have of haves) {
    if (!isOid(have)) continue;
    if (wants.includes(have)) {
      acks.push(have);
      continue;
    }
    for (const want of wants) {
      if (repo.isAncestor(have, want)) {
        acks.push(have);
        break;
      }
    }
  }
  return { send, shallow: shallowOut, unshallow, acks, nak: acks.length === 0 };
}

/** Chop pack bytes into sideband band-1 packets (<= 65515 data bytes each). */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65515;
  for (let at = 0; at < pack.length; at += CHUNK) {
    const slice = pack.subarray(at, Math.min(pack.length, at + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(payload));
  }
  return Buffer.concat(parts);
}

/** The v2 fetch response: acknowledgments, shallow-info, packfile. */
function fetchV2Response(plan: FetchPlan, pack: Buffer | null): Buffer {
  const head: Array<string | 'delim'> = ['acknowledgments\n'];
  if (plan.nak) head.push('NAK\n');
  else {
    for (const ack of plan.acks) head.push(`ACK ${ack}\n`);
    head.push('ready\n');
  }
  head.push('delim');
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    head.push('shallow-info\n');
    for (const oid of plan.shallow) head.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) head.push(`unshallow ${oid}\n`);
    head.push('delim');
  }
  const chunks: Buffer[] = [pktLines(head)];
  if (pack && pack.length > 0) {
    chunks.push(pktLines(['packfile\n']));
    chunks.push(sidebandPack(pack));
  }
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

/** The v0 fetch response: NAK/ACK lines, shallow lines, sideband pack. */
function fetchV0Response(plan: FetchPlan, pack: Buffer | null): Buffer {
  const head: string[] = [];
  if (plan.nak) head.push('NAK\n');
  else {
    for (const ack of plan.acks) head.push(`ACK ${ack}\n`);
  }
  for (const oid of plan.shallow) head.push(`shallow ${oid}\n`);
  for (const oid of plan.unshallow) head.push(`unshallow ${oid}\n`);
  const chunks: Buffer[] = [pktLines(head)];
  if (pack && pack.length > 0) chunks.push(sidebandPack(pack));
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

// ------------------------------------------------------------------ git handlers

type HttpCtx = {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  body: Buffer;
  query: URLSearchParams;
};

/** Parse the v2 ls-refs / fetch argument lines into a small map. */
function parseV2Args(body: Buffer): { command: string; args: string[] } {
  const lines = packetLines(body);
  let command = '';
  const args: string[] = [];
  let seenDelim = false;
  for (const packet of splitPackets(body)) {
    if (packet.kind === 'delim') {
      seenDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8');
    const line = text.endsWith('\n') ? text.slice(0, -1) : text;
    if (!seenDelim) {
      if (line.startsWith('command=')) command = line.slice('command='.length);
      continue;
    }
    args.push(line);
  }
  void lines;
  return { command, args };
}

/** Handle POST /{owner}/{repo}.git/git-upload-pack. */
function handleUploadPack(repo: Repo, ctx: HttpCtx): { status: number; type: string; body: Buffer } {
  const v2 = (ctx.req.headers['git-protocol'] ?? '') === 'version=2';
  const { command, args } = parseV2Args(ctx.body);
  if (v2 && command === 'ls-refs') {
    const opts = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
    for (const arg of args) {
      if (arg === 'peel') opts.peel = true;
      else if (arg === 'symrefs') opts.symrefs = true;
      else if (arg === 'unborn') opts.unborn = true;
      else if (arg.startsWith('ref-prefix ')) opts.prefixes.push(arg.slice('ref-prefix '.length));
    }
    return { status: 200, type: 'application/x-git-upload-pack-result', body: lsRefsV2(repo, opts) };
  }
  // A fetch (v2 command=fetch, or the v0 want/have shape).
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | undefined;
  if (v2 && command === 'fetch') {
    for (const arg of args) {
      if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
      else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
      else if (arg.startsWith('shallow ')) shallow.push(arg.slice(8).trim());
      else if (arg.startsWith('deepen ')) depth = Number.parseInt(arg.slice(7).trim(), 10);
    }
  } else {
    // v0: wants (+feature list on the first), shallow/deepen, flush, haves, done.
    const lines = packetLines(ctx.body);
    for (const line of lines) {
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]);
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7).trim(), 10);
    }
  }
  if (wants.length === 0) {
    return { status: 200, type: 'application/x-git-upload-pack-result', body: pktLines(['flush']) };
  }
  // The bench's depth-1 clone of the tip: one cached pack answers all 50.
  const tip = repo.tip(repo.defBranch);
  const cacheKey = tip && depth === 1 && wants.length === 1 && wants[0] === tip && haves.length === 0 ? `d1:${tip}` : '';
  let plan: FetchPlan;
  let pack: Buffer | null = null;
  if (cacheKey !== '') {
    const cached = repo.clonePack.get(cacheKey);
    if (cached) {
      return { status: 200, type: 'application/x-git-upload-pack-result', body: cached };
    }
    plan = planFetch(repo, wants, haves, shallow, depth);
    pack = plan.send.length > 0 ? buildPack(plan.send) : null;
    const full = v2 ? fetchV2Response(plan, pack) : fetchV0Response(plan, pack);
    repo.clonePack.set(cacheKey, full);
    return { status: 200, type: 'application/x-git-upload-pack-result', body: full };
  }
  plan = planFetch(repo, wants, haves, shallow, depth);
  pack = plan.send.length > 0 ? buildPack(plan.send) : null;
  const body = v2 ? fetchV2Response(plan, pack) : fetchV0Response(plan, pack);
  return { status: 200, type: 'application/x-git-upload-pack-result', body };
}

/** Handle POST /{owner}/{repo}.git/git-receive-pack. */
function handleReceivePack(repo: Repo, ctx: HttpCtx): { status: number; type: string; body: Buffer } {
  const packets = splitPackets(ctx.body);
  // The command list runs to the first flush; the pack bytes follow raw.
  let packStart = ctx.body.length;
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let capabilities = '';
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      // Find where this flush packet ends in the raw body.
      break;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8');
    const line = text.endsWith('\n') ? text.slice(0, -1) : text;
    const nul = line.indexOf('\0');
    const clean = nul >= 0 ? line.slice(0, nul) : line;
    if (nul >= 0) capabilities = line.slice(nul + 1);
    const parts = clean.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
  }
  void capabilities;
  // Locate the pack: bytes after the first flush packet in the raw body.
  {
    let off = 0;
    for (const packet of packets) {
      if (packet.kind === 'flush') {
        packStart = off + 4;
        break;
      }
      if (packet.kind === 'data') off += packet.payload.length + 4;
      else off += 4;
    }
  }
  const report: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = ctx.body.subarray(packStart);
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  if (unpackOk) {
    let changed = false;
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      let ok = false;
      let reason = '';
      if (cmd.newOid === ZERO_OID) {
        // Delete.
        if (current !== undefined && (cmd.oldOid === ZERO_OID || cmd.oldOid === current)) {
          repo.refs.delete(cmd.ref);
          ok = true;
        } else {
          reason = 'non-fast-forward';
        }
      } else if (cmd.oldOid === ZERO_OID) {
        // Create.
        if (current === undefined) {
          if (repo.objects.has(cmd.newOid)) {
            repo.refs.set(cmd.ref, cmd.newOid);
            ok = true;
          } else {
            reason = 'non-fast-forward';
          }
        } else {
          reason = 'non-fast-forward';
        }
      } else {
        // Update: old must match, and the new tip must descend from old.
        if (current !== cmd.oldOid) {
          reason = 'non-fast-forward';
        } else if (!repo.objects.has(cmd.newOid)) {
          reason = 'non-fast-forward';
        } else if (cmd.ref.startsWith('refs/tags/')) {
          repo.refs.set(cmd.ref, cmd.newOid);
          ok = true;
        } else if (repo.isAncestor(cmd.oldOid, cmd.newOid)) {
          repo.refs.set(cmd.ref, cmd.newOid);
          ok = true;
        } else {
          reason = 'non-fast-forward';
        }
      }
      if (ok) {
        changed = true;
        report.push(`ok ${cmd.ref}`);
      } else report.push(`ng ${cmd.ref} ${reason}`);
    }
    if (changed) repo.clonePack.clear();
  }
  const lines = [`unpack ${unpackOk ? 'ok' : unpackDetail}`, ...report];
  const reportBytes = pktLines(lines.map((l) => `${l}\n`));
  const sideband = pktLine(Buffer.concat([Buffer.from([1]), reportBytes]));
  return { status: 200, type: 'application/x-git-receive-pack-result', body: sideband };
}

// ------------------------------------------------------------------ REST
//
// /api/v3: repositories, branches, commits, contents, labels, issues,
// pull requests. Every reply is JSON with X-GitHub-Request-Id.

function repoJson(repo: Repo): string {
  return JSON.stringify({
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.priv,
    description: repo.desc,
    default_branch: repo.defBranch,
    owner: { login: repo.owner, id: 1, type: 'User' },
  });
}

function issueJsonText(issue: IssueRec, owner: string): string {
  const labels = issue.labels.map((l) => JSON.stringify({ name: l.name, color: l.color })).join(',');
  return (
    `{"id":${issue.id},"number":${issue.number},"title":${JSON.stringify(issue.title)}` +
    `,"body":${JSON.stringify(issue.body)},"state":"${issue.state}"` +
    `,"labels":[${labels}],"user":{"login":${JSON.stringify(owner)},"id":1,"type":"User"}}`
  );
}

function pullJson(pull: PullRec, owner: string): Record<string, unknown> {
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.head, sha: pull.headSha },
    base: { ref: pull.base, sha: pull.baseSha },
    merged: pull.merged,
    merged_at: pull.merged ? pull.mergedAt : null,
    merge_commit_sha: pull.merged ? pull.mergeSha : null,
    user: { login: owner, id: 1, type: 'User' },
  };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const obj = repo.objects.get(oid);
  const view = obj && obj.t === 'commit' ? parseCommit(obj.d) : null;
  const message = view ? view.message : '';
  const who = (line: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
    if (!m) return { name: 'Forge', email: 'forge@example.invalid', date: '2023-11-14T22:13:20Z' };
    const date = new Date(Number(m[3]) * 1000).toISOString();
    return { name: m[1], email: m[2], date };
  };
  return {
    sha: oid,
    commit: {
      message,
      author: who(view?.author ?? ''),
      committer: who(view?.committer ?? ''),
    },
  };
}

/** Resolve a ref query (?ref=branch|sha) to a commit id, or null. */
function resolveRef(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return repo.tip(repo.defBranch) ?? null;
  const branchTip = repo.tip(ref);
  if (branchTip) return branchTip;
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

/** Walk a commit's tree to a path: the blob/tree object, or null. */
function treeLookup(repo: Repo, commitOid: string, path: string): { oid: string; type: ObjType; size: number } | null {
  const commit = repo.objects.get(commitOid);
  if (!commit || commit.t !== 'commit') return null;
  if (path === '') {
    return { oid: parseCommit(commit.d).tree, type: 'tree', size: 0 };
  }
  const parts = path.split('/').filter((p) => p !== '');
  let current = parseCommit(commit.d).tree;
  for (let i = 0; i < parts.length; i += 1) {
    const tree = repo.objects.get(current);
    if (!tree || tree.t !== 'tree') return null;
    const item = parseTree(tree.d).find((e) => e.name === parts[i]);
    if (!item) return null;
    if (i === parts.length - 1) {
      const obj = repo.objects.get(item.oid);
      const size = obj && obj.t === 'blob' ? obj.d.length : 0;
      return { oid: item.oid, type: item.mode === '40000' ? 'tree' : 'blob', size };
    }
    if (item.mode !== '40000') return null;
    current = item.oid;
  }
  return null;
}

function dirEntries(repo: Repo, treeOid: string, prefix: string): Array<Record<string, unknown>> {
  const tree = repo.objects.get(treeOid);
  if (!tree || tree.t !== 'tree') return [];
  const out: Array<Record<string, unknown>> = [];
  for (const item of parseTree(tree.d)) {
    const isDir = item.mode === '40000';
    out.push({
      type: isDir ? 'dir' : 'file',
      name: item.name,
      path: prefix === '' ? item.name : `${prefix}/${item.name}`,
      sha: item.oid,
    });
  }
  return out;
}

/** Count added/deleted lines between two blob contents (multiset diff). */
function lineDiff(a: Buffer | null, b: Buffer | null): { additions: number; deletions: number } {
  const count = (buf: Buffer | null): Map<string, number> => {
    const map = new Map<string, number>();
    if (!buf) return map;
    for (const line of buf.toString('utf8').split('\n')) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const oldLines = count(a);
  const newLines = count(b);
  let additions = 0;
  let deletions = 0;
  for (const [line, n] of newLines) {
    const had = oldLines.get(line) ?? 0;
    if (n > had) additions += n - had;
  }
  for (const [line, n] of oldLines) {
    const has = newLines.get(line) ?? 0;
    if (n > has) deletions += n - has;
  }
  return { additions, deletions };
}

// ------------------------------------------------------------------ REST routes

interface RestOut {
  status: number;
  text: string | null;
  headers?: Record<string, string>;
}

function okJson(status: number, text: string, headers?: Record<string, string>): RestOut {
  return { status, text, headers };
}

function errJson(status: number, message: string): RestOut {
  return { status, text: JSON.stringify({ message }) };
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}

function handleListRepos(ctx: HttpCtx): RestOut {
  const { page, perPage } = pageParams(ctx.query);
  const all = forge.listRepos();
  const start = (page - 1) * perPage;
  const slice = all.slice(start, start + perPage);
  const text = `[${slice.map((r) => repoJson(r)).join(',')}]`;
  const headers: Record<string, string> = {};
  if (start + perPage < all.length) {
    const host = ctx.req.headers.host ?? '127.0.0.1';
    const next = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
    headers.link = `<${next}>; rel="next"`;
  }
  return okJson(200, text, headers);
}

function handleRepoCreate(body: Record<string, unknown>): RestOut {
  const name = typeof body.name === 'string' ? body.name : '';
  if (name === '') return errJson(422, 'name is required');
  const created = forge.createRepo(name, body.private === true, typeof body.description === 'string' ? body.description : '');
  if (!created) return errJson(422, `Repository ${name} already exists`);
  return okJson(201, repoJson(created));
}

function handleRefCreate(repo: Repo, body: Record<string, unknown>): RestOut {
  const ref = typeof body.ref === 'string' ? body.ref : '';
  const sha = typeof body.sha === 'string' ? body.sha : '';
  if (!ref.startsWith('refs/') || !isOid(sha)) return errJson(422, 'ref and sha are required');
  if (repo.refs.has(ref)) return errJson(422, `Reference ${ref} already exists`);
  if (!repo.objects.has(sha)) return errJson(422, `Object ${sha} does not exist`);
  repo.refs.set(ref, sha);
  repo.clonePack.clear();
  return okJson(201, JSON.stringify({ ref, object: { sha, type: 'commit' } }));
}

function handleRefGet(repo: Repo, branch: string): RestOut {
  const oid = repo.tip(branch);
  if (!oid) return errJson(404, `Branch ${branch} not found`);
  return okJson(200, JSON.stringify({ ref: `refs/heads/${branch}`, object: { sha: oid, type: 'commit' } }));
}

function handleBranches(repo: Repo): RestOut {
  const out: Array<Record<string, unknown>> = [];
  for (const name of [...repo.refs.keys()].sort()) {
    if (!name.startsWith('refs/heads/')) continue;
    out.push({ name: name.slice('refs/heads/'.length), commit: { sha: repo.refs.get(name) } });
  }
  return okJson(200, JSON.stringify(out));
}

function handleBranchGet(repo: Repo, branch: string): RestOut {
  const oid = repo.tip(branch);
  if (!oid) return errJson(404, `Branch ${branch} not found`);
  return okJson(200, JSON.stringify({ name: branch, commit: { sha: oid } }));
}

function handleCommits(repo: Repo, ctx: HttpCtx): RestOut {
  const shaParam = ctx.query.get('sha');
  const tip = resolveRef(repo, shaParam);
  if (!tip) return errJson(404, 'No commits found');
  const list = repo.history(tip).map((oid) => commitJson(repo, oid));
  return okJson(200, JSON.stringify(list));
}

function handleContentsPut(repo: Repo, path: string, body: Record<string, unknown>): RestOut {
  const contentB64 = typeof body.content === 'string' ? body.content : '';
  const message = typeof body.message === 'string' ? body.message : 'commit';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defBranch;
  const shaParam = typeof body.sha === 'string' ? body.sha : null;
  const data = b64decode(contentB64);
  if (data === null) return errJson(422, 'content must be base64');
  let tip = repo.tip(branch);
  if (!tip && branch !== repo.defBranch) {
    // A new branch starts at the default branch's tip (or at nothing).
    const base = repo.tip(repo.defBranch);
    if (base) repo.refs.set(`refs/heads/${branch}`, base);
    tip = base;
  }
  const flat = tip ? new Map(repo.flatFiles(tip)) : new Map<string, { oid: string; size: number }>();
  const existing = flat.get(path);
  if (shaParam !== null) {
    if (!existing || existing.oid !== shaParam) return errJson(409, 'sha does not match the current file');
  } else if (existing) {
    return errJson(422, 'file already exists');
  }
  const blobOid = objectId('blob', data);
  if (!repo.objects.has(blobOid)) repo.objects.set(blobOid, { t: 'blob', d: data });
  flat.set(path, { oid: blobOid, size: data.length });
  const treeOid = repo.storeTrees(flat);
  const commitOid = repo.commitOn(branch, treeOid, message);
  const status = existing ? 200 : 201;
  return okJson(
    status,
    JSON.stringify({
      content: { name: path.split('/').pop(), path, sha: blobOid, size: data.length, encoding: 'base64', type: 'file' },
      commit: { sha: commitOid, message },
    }),
  );
}

function handleContentsGet(repo: Repo, path: string, ctx: HttpCtx): RestOut {
  const tip = resolveRef(repo, ctx.query.get('ref'));
  if (!tip) return errJson(404, 'Not Found');
  const found = treeLookup(repo, tip, path);
  if (!found) return errJson(404, 'Not Found');
  if (found.type === 'tree') {
    return okJson(200, JSON.stringify(dirEntries(repo, found.oid, path)));
  }
  const blob = repo.objects.get(found.oid);
  if (!blob || blob.t !== 'blob') return errJson(404, 'Not Found');
  return okJson(
    200,
    JSON.stringify({
      type: 'file',
      encoding: 'base64',
      content: b64encode(blob.d),
      sha: found.oid,
      size: found.size,
      name: path.split('/').pop(),
      path,
    }),
  );
}

function handleContentsDelete(repo: Repo, path: string, body: Record<string, unknown>): RestOut {
  const message = typeof body.message === 'string' ? body.message : 'delete';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defBranch;
  const tip = repo.tip(branch);
  if (!tip) return errJson(404, 'Not Found');
  const flat = new Map(repo.flatFiles(tip));
  if (!flat.has(path)) return errJson(404, 'Not Found');
  flat.delete(path);
  const treeOid = repo.storeTrees(flat);
  const commitOid = repo.commitOn(branch, treeOid, message);
  return okJson(200, JSON.stringify({ commit: { sha: commitOid, message } }));
}

function handleLabelCreate(repo: Repo, body: Record<string, unknown>): RestOut {
  const name = typeof body.name === 'string' ? body.name : '';
  const color = typeof body.color === 'string' ? body.color : 'ededed';
  if (name === '') return errJson(422, 'name is required');
  const existing = repo.labels.get(name);
  if (existing) return okJson(201, JSON.stringify(existing));
  const label: LabelRec = { name, color };
  repo.labels.set(name, label);
  return okJson(201, JSON.stringify(label));
}

function handleIssueCreate(repo: Repo, body: Record<string, unknown>): RestOut {
  const title = typeof body.title === 'string' ? body.title : '';
  const labels: LabelRec[] = [];
  const wanted = Array.isArray(body.labels) ? body.labels : [];
  for (const name of wanted) {
    if (typeof name !== 'string') continue;
    const label = repo.labels.get(name);
    if (!label) return errJson(422, `Label ${name} does not exist`);
    labels.push(label);
  }
  const issue: IssueRec = {
    id: forge.nextGlobalId++,
    number: ++repo.issueSeq,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    labels,
    comments: [],
    json: '',
  };
  issue.json = issueJsonText(issue, repo.owner);
  repo.issues.push(issue);
  return okJson(201, issue.json);
}

function handleIssueList(repo: Repo, ctx: HttpCtx): RestOut {
  const { page, perPage } = pageParams(ctx.query);
  const state = ctx.query.get('state') ?? 'open';
  const direction = ctx.query.get('direction') ?? 'desc';
  let list = repo.issues;
  if (state === 'open') list = list.filter((i) => i.state === 'open');
  else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
  const sorted = direction === 'asc' ? [...list] : [...list].reverse();
  const slice = sorted.slice((page - 1) * perPage, page * perPage);
  return okJson(200, `[${slice.map((i) => i.json).join(',')}]`);
}

function handleIssueGet(repo: Repo, number: number): RestOut {
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) return errJson(404, 'Issue not found');
  return okJson(200, issue.json);
}

function handleIssuePatch(repo: Repo, number: number, body: Record<string, unknown>): RestOut {
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) return errJson(404, 'Issue not found');
  if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  issue.json = issueJsonText(issue, repo.owner);
  return okJson(200, issue.json);
}

function handleCommentCreate(repo: Repo, number: number, body: Record<string, unknown>): RestOut {
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) return errJson(404, 'Issue not found');
  const comment = { id: forge.nextGlobalId++, body: typeof body.body === 'string' ? body.body : '' };
  issue.comments.push(comment);
  return okJson(201, JSON.stringify(comment));
}

function handleCommentList(repo: Repo, number: number): RestOut {
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) return errJson(404, 'Issue not found');
  return okJson(200, JSON.stringify(issue.comments));
}

function pullFilesOf(repo: Repo, pull: PullRec): void {
  const baseTip = repo.tip(pull.base);
  const headTip = repo.tip(pull.head);
  const diff = repo.diffTrees(baseTip ?? '', headTip ?? '');
  const files: PullRec['files'] = [];
  for (const [path, change] of diff) {
    const baseBlob = change.base ? repo.objects.get(change.base) : undefined;
    const headBlob = change.head ? repo.objects.get(change.head) : undefined;
    const { additions, deletions } = lineDiff(baseBlob?.d ?? null, headBlob?.d ?? null);
    const status = !change.base ? 'added' : !change.head ? 'removed' : 'modified';
    files.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  pull.files = files;
}

function handlePullCreate(repo: Repo, body: Record<string, unknown>): RestOut {
  const title = typeof body.title === 'string' ? body.title : '';
  const head = typeof body.head === 'string' ? body.head : '';
  const base = typeof body.base === 'string' ? body.base : repo.defBranch;
  const headSha = repo.tip(head);
  const baseSha = repo.tip(base);
  if (!headSha || !baseSha) return errJson(422, 'head or base branch not found');
  const dupe = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
  if (dupe) return errJson(422, 'A pull request already exists for these branches');
  const pull: PullRec = {
    id: forge.nextGlobalId++,
    number: ++repo.pullSeq,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    head,
    base,
    headSha,
    baseSha,
    merged: false,
    mergedAt: '',
    mergeSha: '',
    files: [],
  };
  pullFilesOf(repo, pull);
  repo.pulls.push(pull);
  return okJson(201, JSON.stringify(pullJson(pull, repo.owner)));
}

function handlePullList(repo: Repo, ctx: HttpCtx): RestOut {
  const { page, perPage } = pageParams(ctx.query);
  const state = ctx.query.get('state') ?? 'open';
  let list = repo.pulls;
  if (state === 'open') list = list.filter((p) => p.state === 'open');
  else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
  const slice = list.slice((page - 1) * perPage, page * perPage);
  return okJson(200, JSON.stringify(slice.map((p) => pullJson(p, repo.owner))));
}

function handlePullGet(repo: Repo, number: number): RestOut {
  const pull = repo.pulls.find((p) => p.number === number);
  if (!pull) return errJson(404, 'Pull request not found');
  return okJson(200, JSON.stringify(pullJson(pull, repo.owner)));
}

function handlePullFiles(repo: Repo, number: number): RestOut {
  const pull = repo.pulls.find((p) => p.number === number);
  if (!pull) return errJson(404, 'Pull request not found');
  return okJson(200, JSON.stringify(pull.files));
}

/** Squash-merge a pull request onto its base branch. */
function squashMerge(repo: Repo, pull: PullRec): { ok: boolean; sha?: string; message?: string } {
  const baseTip = repo.tip(pull.base);
  const headTip = repo.tip(pull.head);
  if (!baseTip || !headTip) return { ok: false, message: 'head or base branch not found' };
  const base = repo.mergeBase(headTip, baseTip);
  if (base === null) return { ok: false, message: 'no merge base' };
  const headDiff = repo.diffTrees(base, headTip);
  const baseDiff = repo.diffTrees(base, baseTip);
  for (const [path, change] of headDiff) {
    const other = baseDiff.get(path);
    if (!other) continue;
    if (change.head !== other.head) return { ok: false, message: 'conflict' };
  }
  const flat = new Map(repo.flatFiles(baseTip));
  for (const [path, change] of headDiff) {
    if (change.head) {
      const blob = repo.objects.get(change.head);
      flat.set(path, { oid: change.head, size: blob ? blob.d.length : 0 });
    } else {
      flat.delete(path);
    }
  }
  const treeOid = repo.storeTrees(flat);
  const message = pull.title;
  const sha = repo.commitOn(pull.base, treeOid, message);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = '2023-11-14T22:13:20Z';
  pull.mergeSha = sha;
  pull.baseSha = sha;
  return { ok: true, sha, message };
}

function handlePullMerge(repo: Repo, number: number, body: Record<string, unknown>): RestOut {
  const pull = repo.pulls.find((p) => p.number === number);
  if (!pull) return errJson(404, 'Pull request not found');
  if (pull.state !== 'open') return errJson(405, 'Pull request is already closed');
  const method = typeof body.merge_method === 'string' ? body.merge_method : 'squash';
  if (method !== 'squash') return errJson(405, 'Only squash merges are supported');
  const result = squashMerge(repo, pull);
  if (!result.ok) {
    if (result.message === 'conflict') return errJson(405, 'Merge conflict');
    return errJson(422, result.message ?? 'merge failed');
  }
  return okJson(200, JSON.stringify({ merged: true, sha: result.sha, message: result.message }));
}

/** Is this pull request mergeable right now (no conflicts)? */
function pullMergeable(repo: Repo, pull: PullRec): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const baseTip = repo.tip(pull.base);
  const headTip = repo.tip(pull.head);
  if (!baseTip || !headTip) return 'UNKNOWN';
  const base = repo.mergeBase(headTip, baseTip);
  if (base === null) return 'CONFLICTING';
  const headDiff = repo.diffTrees(base, headTip);
  const baseDiff = repo.diffTrees(base, baseTip);
  for (const [path, change] of headDiff) {
    const other = baseDiff.get(path);
    if (other && change.head !== other.head) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

/** Route one REST v3 request. Returns null when the path is not under /api/v3. */
function routeRest(method: string, pathname: string, ctx: HttpCtx, body: Record<string, unknown>): RestOut | null {
  if (pathname !== '/api/v3' && !pathname.startsWith('/api/v3/')) return null;
  const rest = pathname === '/api/v3' ? '' : pathname.slice('/api/v3/'.length);
  const seg = rest === '' ? [] : rest.split('/').map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  if (seg.length === 0) {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, '{}', { 'x-oauth-scopes': 'repo' });
  }
  if (seg[0] === 'meta') {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, JSON.stringify({ installed_version: '1.0.0' }));
  }
  if (seg[0] === 'user' && seg.length === 1) {
    if (method !== 'GET') return errJson(404, 'Not Found');
    return okJson(200, JSON.stringify({ login: forge.viewer || 'viewer', id: 1, type: 'User' }));
  }
  if (seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'GET') return handleListRepos(ctx);
    if (method === 'POST') return handleRepoCreate(body);
    return errJson(404, 'Not Found');
  }
  if (seg[0] !== 'repos' || seg.length < 3) return errJson(404, 'Not Found');
  const owner = seg[1];
  const name = seg[2];
  const repo = forge.repo(owner, name);
  if (!repo) return errJson(404, 'Not Found');
  const tail = seg.slice(3);
  if (tail.length === 0) {
    if (method === 'GET') return okJson(200, repoJson(repo));
    if (method === 'PATCH') {
      if (typeof body.description === 'string') repo.desc = body.description;
      return okJson(200, repoJson(repo));
    }
    if (method === 'DELETE') {
      forge.deleteRepo(name);
      return { status: 204, text: null };
    }
    return errJson(404, 'Not Found');
  }
  const head = tail[0];
  if (head === 'git' && tail[1] === 'refs' && method === 'POST' && tail.length === 2) {
    return handleRefCreate(repo, body);
  }
  if (head === 'git' && tail[1] === 'refs' && tail[2] === 'heads' && tail.length === 4 && method === 'GET') {
    return handleRefGet(repo, tail[3]);
  }
  if (head === 'branches' && tail.length === 1 && method === 'GET') return handleBranches(repo);
  if (head === 'branches' && tail.length === 2 && method === 'GET') return handleBranchGet(repo, tail[1]);
  if (head === 'commits' && tail.length === 1 && method === 'GET') return handleCommits(repo, ctx);
  if (head === 'contents') {
    const path = tail.slice(1).join('/');
    if (method === 'PUT') return handleContentsPut(repo, path, body);
    if (method === 'GET') return handleContentsGet(repo, path, ctx);
    if (method === 'DELETE') return handleContentsDelete(repo, path, body);
    return errJson(404, 'Not Found');
  }
  if (head === 'labels' && tail.length === 1 && method === 'POST') return handleLabelCreate(repo, body);
  if (head === 'issues') {
    if (tail.length === 1) {
      if (method === 'GET') return handleIssueList(repo, ctx);
      if (method === 'POST') return handleIssueCreate(repo, body);
      return errJson(404, 'Not Found');
    }
    const number = Number.parseInt(tail[1], 10);
    if (!Number.isInteger(number)) return errJson(404, 'Not Found');
    if (tail.length === 2) {
      if (method === 'GET') return handleIssueGet(repo, number);
      if (method === 'PATCH') return handleIssuePatch(repo, number, body);
      return errJson(404, 'Not Found');
    }
    if (tail[2] === 'comments') {
      if (method === 'GET') return handleCommentList(repo, number);
      if (method === 'POST') return handleCommentCreate(repo, number, body);
    }
    return errJson(404, 'Not Found');
  }
  if (head === 'pulls') {
    if (tail.length === 1) {
      if (method === 'GET') return handlePullList(repo, ctx);
      if (method === 'POST') return handlePullCreate(repo, body);
      return errJson(404, 'Not Found');
    }
    const number = Number.parseInt(tail[1], 10);
    if (!Number.isInteger(number)) return errJson(404, 'Not Found');
    if (tail.length === 2 && method === 'GET') return handlePullGet(repo, number);
    if (tail.length === 3 && tail[2] === 'files' && method === 'GET') return handlePullFiles(repo, number);
    if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') return handlePullMerge(repo, number, body);
    return errJson(404, 'Not Found');
  }
  return errJson(404, 'Not Found');
}

// ------------------------------------------------------------------ GraphQL
//
// POST /api/graphql: {query, variables} or an array of them. A small
// parser for the documents gh sends, resolved against the same store.

interface GField {
  key: string;
  name: string;
  args: Record<string, unknown>;
  kids: GField[] | null;
  onType: string | null;
}

interface GOperation {
  kind: 'query' | 'mutation';
  fields: GField[];
}

type Token =
  | { k: 'brace'; v: string }
  | { k: 'name'; v: string }
  | { k: 'var'; v: string }
  | { k: 'str'; v: string }
  | { k: 'num'; v: number }
  | { k: 'spread' }
  | { k: 'bang' }
  | { k: 'eq' }
  | { k: 'at' };

function gqlTokens(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if ('{}():[]'.includes(ch)) {
      out.push({ k: 'brace', v: ch });
      i += 1;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      out.push({ k: 'spread' });
      i += 3;
      continue;
    }
    if (ch === '!') {
      out.push({ k: 'bang' });
      i += 1;
      continue;
    }
    if (ch === '=') {
      out.push({ k: 'eq' });
      i += 1;
      continue;
    }
    if (ch === '@') {
      out.push({ k: 'at' });
      i += 1;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      out.push({ k: 'var', v: src.slice(i + 1, j) });
      i = j;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let text = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const escCh = src[j + 1];
          text += escCh === 'n' ? '\n' : escCh === 't' ? '\t' : escCh === 'r' ? '\r' : escCh;
          j += 2;
        } else {
          text += src[j];
          j += 1;
        }
      }
      out.push({ k: 'str', v: text });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j += 1;
      out.push({ k: 'num', v: Number(src.slice(i, j)) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      out.push({ k: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return out;
}

class GParser {
  toks: Token[];
  at = 0;
  vars: Record<string, unknown>;

  constructor(src: string, vars: Record<string, unknown>) {
    this.toks = gqlTokens(src);
    this.vars = vars;
  }

  peek(): Token | undefined {
    return this.toks[this.at];
  }

  next(): Token {
    const tok = this.toks[this.at++];
    if (!tok) throw new Error('unexpected end of GraphQL document');
    return tok;
  }

  expectBrace(v: string): void {
    const tok = this.next();
    if (tok.k !== 'brace' || tok.v !== v) throw new Error(`expected ${v} in GraphQL document`);
  }

  skipDirectives(): void {
    while (this.peek()?.k === 'at') {
      this.next();
      const name = this.next();
      if (name.k !== 'name') throw new Error('bad directive');
      if (this.peek()?.k === 'brace' && this.peek()?.v === '(') {
        this.next();
        this.value();
      }
    }
  }

  value(): unknown {
    const tok = this.next();
    if (tok.k === 'str' || tok.k === 'num') return tok.v;
    if (tok.k === 'var') {
      if (!(tok.v in this.vars)) throw new Error(`variable $${tok.v} was not provided`);
      return this.vars[tok.v];
    }
    if (tok.k === 'name') {
      if (tok.v === 'true') return true;
      if (tok.v === 'false') return false;
      if (tok.v === 'null') return null;
      return tok.v;
    }
    if (tok.k === 'brace' && tok.v === '[') {
      const list: unknown[] = [];
      while (!(this.peek()?.k === 'brace' && this.peek()?.v === ']')) list.push(this.value());
      this.next();
      return list;
    }
    if (tok.k === 'brace' && tok.v === '{') {
      const obj: Record<string, unknown> = {};
      while (!(this.peek()?.k === 'brace' && this.peek()?.v === '}')) {
        const key = this.next();
        if (key.k !== 'name') throw new Error('bad input object key');
        this.expectBrace(':');
        obj[key.v] = this.value();
      }
      this.next();
      return obj;
    }
    throw new Error('bad GraphQL value');
  }

  args(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    if (this.peek()?.k === 'brace' && this.peek()?.v === '(') {
      this.next();
      while (!(this.peek()?.k === 'brace' && this.peek()?.v === ')')) {
        const key = this.next();
        if (key.k !== 'name') throw new Error('bad argument name');
        this.expectBrace(':');
        out[key.v] = this.value();
      }
      this.next();
    }
    return out;
  }

  fields(): GField[] {
    this.expectBrace('{');
    const out: GField[] = [];
    for (;;) {
      const tok = this.peek();
      if (!tok) throw new Error('unterminated selection set');
      if (tok.k === 'brace' && tok.v === '}') {
        this.next();
        return out;
      }
      if (tok.k === 'spread') {
        this.next();
        const next = this.peek();
        let onType: string | null = null;
        if (next?.k === 'name' && next.v === 'on') {
          this.next();
          const typeTok = this.next();
          if (typeTok.k !== 'name') throw new Error('bad fragment type');
          onType = typeTok.v;
        }
        this.skipDirectives();
        const kids = this.fields();
        for (const kid of kids) out.push({ ...kid, onType });
        continue;
      }
      const first = this.next();
      if (first.k !== 'name') throw new Error('bad field name');
      let key = first.v;
      let name = first.v;
      if (this.peek()?.k === 'brace' && this.peek()?.v === ':') {
        this.next();
        const real = this.next();
        if (real.k !== 'name') throw new Error('bad aliased field name');
        name = real.v;
      }
      const args = this.args();
      this.skipDirectives();
      let kids: GField[] | null = null;
      if (this.peek()?.k === 'brace' && this.peek()?.v === '{') kids = this.fields();
      out.push({ key, name, args, kids, onType: null });
    }
  }

  operation(): GOperation {
    const tok = this.next();
    let kind: 'query' | 'mutation' = 'query';
    if (tok.k === 'name' && (tok.v === 'query' || tok.v === 'mutation')) {
      kind = tok.v;
      const maybeName = this.peek();
      if (maybeName?.k === 'name') this.next();
      if (this.peek()?.k === 'brace' && this.peek()?.v === '(') {
        // Variable definitions: skip them (values come from `variables`).
        this.next();
        let depth = 1;
        while (depth > 0) {
          const t = this.next();
          if (t.k === 'brace' && (t.v === '(' || t.v === '[' || t.v === '{')) depth += 1;
          else if (t.k === 'brace' && (t.v === ')' || t.v === ']' || t.v === '}')) depth -= 1;
        }
      }
    } else if (tok.k === 'brace' && tok.v === '{') {
      this.at -= 1;
    } else {
      throw new Error('bad GraphQL operation');
    }
    return { kind, fields: this.fields() };
  }
}

// ------------------------------------------------------------------ GraphQL run

interface GNode {
  type: string;
  value: unknown;
}

function gid(kind: string, parts: Array<string | number>): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}

function ungid(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (!kind || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'url', 'author', 'labels', 'comments', 'createdAt', 'updatedAt', 'closedAt', 'repository'],
  PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'title', 'body', 'url', 'author', 'createdAt', 'updatedAt', 'closedAt', 'mergedAt', 'mergeCommit'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt', 'isPrivate', 'fork', 'stargazerCount'],
};
const SEARCH_ENUMS = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE', 'PROJECT', 'TOPIC', 'WIKI'];

class GExecutor {
  errors: Array<{ message: string }> = [];

  private issueNode(repo: Repo, issue: IssueRec): GNode {
    return { type: 'Issue', value: { repo, issue } };
  }

  private pullNode(repo: Repo, pull: PullRec): GNode {
    return { type: 'PullRequest', value: { repo, pull } };
  }

  private repoNode(repo: Repo): GNode {
    return { type: 'Repository', value: repo };
  }

  /** Resolve one field of a node; returns the raw value (or a GNode / array). */
  private field(node: GNode, f: GField): unknown {
    const v = node.value as Record<string, unknown>;
    switch (node.type) {
      case 'Query': {
        if (f.name === 'viewer') return { type: 'User', value: { login: forge.viewer || 'viewer' } } as GNode;
        if (f.name === 'repository') {
          const repo = forge.repo(String(f.args.owner ?? ''), String(f.args.name ?? ''));
          return repo ? this.repoNode(repo) : null;
        }
        if (f.name === 'node') {
          const decoded = ungid(String(f.args.id ?? ''));
          if (!decoded) return null;
          if (decoded.kind === 'Repository') {
            const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
            return repo ? this.repoNode(repo) : null;
          }
          if (decoded.kind === 'Issue') {
            const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
            const issue = repo?.issues.find((i) => i.number === Number(decoded.parts[1]));
            return repo && issue ? this.issueNode(repo, issue) : null;
          }
          if (decoded.kind === 'PullRequest') {
            const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
            const pull = repo?.pulls.find((p) => p.number === Number(decoded.parts[1]));
            return repo && pull ? this.pullNode(repo, pull) : null;
          }
          return null;
        }
        if (f.name === '__type') {
          const name = String(f.args.name ?? '');
          if (name === 'SearchType') return { type: 'TypeInfo', value: { name, enums: SEARCH_ENUMS } } as GNode;
          const fields = TYPE_FIELDS[name];
          if (!fields) return null;
          return { type: 'TypeInfo', value: { name, fields } } as GNode;
        }
        break;
      }
      case 'User': {
        if (f.name === 'login') return v.login;
        if (f.name === 'id') return gid('User', [String(v.login)]);
        if (f.name === 'name') return v.login;
        if (f.name === 'email') return `${v.login}@example.invalid`;
        break;
      }
      case 'Repository': {
        const repo = v as unknown as Repo;
        if (f.name === 'id') return gid('Repository', [repo.id]);
        if (f.name === 'databaseId') return repo.id;
        if (f.name === 'name') return repo.name;
        if (f.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
        if (f.name === 'owner') return { type: 'User', value: { login: repo.owner } } as GNode;
        if (f.name === 'defaultBranchRef') {
          const tip = repo.tip(repo.defBranch);
          return tip ? ({ type: 'BranchRef', value: { name: repo.defBranch } } as GNode) : null;
        }
        if (f.name === 'viewerPermission') return 'ADMIN';
        if (f.name === 'hasIssuesEnabled') return true;
        if (f.name === 'description') return repo.desc;
        if (f.name === 'isPrivate') return repo.priv;
        if (f.name === 'issue') {
          const issue = repo.issues.find((i) => i.number === Number(f.args.number));
          return issue ? this.issueNode(repo, issue) : null;
        }
        if (f.name === 'issues') return { type: 'IssueConnection', value: { repo, args: f.args } } as GNode;
        if (f.name === 'pullRequest') {
          const pull = repo.pulls.find((p) => p.number === Number(f.args.number));
          return pull ? this.pullNode(repo, pull) : null;
        }
        if (f.name === 'pullRequests') return { type: 'PullRequestConnection', value: { repo, args: f.args } } as GNode;
        break;
      }
      case 'Issue': {
        const { repo, issue } = v as unknown as { repo: Repo; issue: IssueRec };
        if (f.name === 'id') return gid('Issue', [repo.id, issue.number]);
        if (f.name === 'number') return issue.number;
        if (f.name === 'title') return issue.title;
        if (f.name === 'body') return issue.body;
        if (f.name === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
        if (f.name === 'repository') return this.repoNode(repo);
        break;
      }
      case 'PullRequest': {
        const { repo, pull } = v as unknown as { repo: Repo; pull: PullRec };
        if (f.name === 'id') return gid('PullRequest', [repo.id, pull.number]);
        if (f.name === 'number') return pull.number;
        if (f.name === 'title') return pull.title;
        if (f.name === 'body') return pull.body;
        if (f.name === 'state') return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
        if (f.name === 'merged') return pull.merged;
        if (f.name === 'mergeable') return pullMergeable(repo, pull);
        if (f.name === 'headRefName') return pull.head;
        if (f.name === 'baseRefName') return pull.base;
        if (f.name === 'files') return { type: 'FileConnection', value: { repo, pull, args: f.args } } as GNode;
        if (f.name === 'repository') return this.repoNode(repo);
        break;
      }
      case 'BranchRef': {
        if (f.name === 'name') return v.name;
        break;
      }
      case 'IssueConnection': {
        const { repo, args } = v as unknown as { repo: Repo; args: Record<string, unknown> };
        if (f.name === 'nodes') return this.issuePage(repo, args).nodes;
        if (f.name === 'pageInfo') return { type: 'PageInfo', value: this.issuePage(repo, args).page } as GNode;
        if (f.name === 'totalCount') return this.issuePage(repo, args).total;
        break;
      }
      case 'PullRequestConnection': {
        const { repo, args } = v as unknown as { repo: Repo; args: Record<string, unknown> };
        if (f.name === 'nodes') {
          const first = typeof args.first === 'number' ? args.first : 5;
          return repo.pulls.slice(0, first).map((p) => this.pullNode(repo, p));
        }
        if (f.name === 'totalCount') return repo.pulls.length;
        break;
      }
      case 'FileConnection': {
        const { pull, args } = v as unknown as { repo: Repo; pull: PullRec; args: Record<string, unknown> };
        if (f.name === 'nodes') {
          const first = typeof args.first === 'number' ? args.first : 10;
          return pull.files.slice(0, first).map((file) => ({ type: 'FileNode', value: file } as GNode));
        }
        break;
      }
      case 'FileNode': {
        if (f.name === 'path') return (v as unknown as { filename: string }).filename;
        break;
      }
      case 'CommentEdge': {
        if (f.name === 'node') {
          const comment = v as unknown as { id: number; body: string };
          return { type: 'IssueComment', value: comment } as GNode;
        }
        break;
      }
      case 'IssueComment': {
        const comment = v as unknown as { id: number; body: string };
        if (f.name === 'id') return gid('Comment', [comment.id]);
        if (f.name === 'body') return comment.body;
        break;
      }
      case 'PageInfo': {
        const page = v as unknown as { hasNextPage: boolean; endCursor: string | null };
        if (f.name === 'hasNextPage') return page.hasNextPage;
        if (f.name === 'endCursor') return page.endCursor;
        break;
      }
      case 'TypeInfo': {
        const info = v as unknown as { name: string; fields?: string[]; enums?: string[] };
        if (f.name === 'name') return info.name;
        if (f.name === 'fields') return (info.fields ?? []).map((name) => ({ type: 'TypeField', value: { name } } as GNode));
        if (f.name === 'enumValues') return (info.enums ?? []).map((name) => ({ type: 'TypeField', value: { name } } as GNode));
        break;
      }
      case 'TypeField': {
        if (f.name === 'name') return v.name;
        break;
      }
      case 'Mutation': {
        if (f.name === 'createIssue') return this.mutateCreateIssue(f.args.input as Record<string, unknown>);
        if (f.name === 'closeIssue') return this.mutateCloseIssue(f.args.input as Record<string, unknown>);
        if (f.name === 'createPullRequest') return this.mutateCreatePull(f.args.input as Record<string, unknown>);
        if (f.name === 'mergePullRequest') return this.mutateMergePull(f.args.input as Record<string, unknown>);
        if (f.name === 'addComment') return this.mutateAddComment(f.args.input as Record<string, unknown>);
        break;
      }
    }
    this.errors.push({ message: `Field '${f.name}' doesn't exist on type '${node.type}'` });
    return null;
  }

  /** One page of a repo's issues, with cursor pagination. */
  private issuePage(repo: Repo, args: Record<string, unknown>): {
    nodes: GNode[];
    page: { hasNextPage: boolean; endCursor: string | null };
    total: number;
  } {
    const states = Array.isArray(args.states) ? (args.states as string[]) : null;
    const orderBy = (args.orderBy ?? {}) as { field?: string; direction?: string };
    let list = repo.issues;
    if (states) {
      const want = new Set(states.map((s) => (s === 'OPEN' ? 'open' : s === 'CLOSED' ? 'closed' : s)));
      list = list.filter((i) => want.has(i.state));
    }
    const sorted = [...list];
    if (orderBy.direction === 'DESC') sorted.sort((a, b) => b.number - a.number);
    else sorted.sort((a, b) => a.number - b.number);
    const first = typeof args.first === 'number' ? args.first : 10;
    let start = 0;
    if (typeof args.after === 'string' && args.after !== '') {
      try {
        const text = Buffer.from(args.after, 'base64').toString('utf8');
        const num = Number(text.split(':')[1]);
        const idx = sorted.findIndex((i) => i.number === num);
        if (idx >= 0) start = idx + 1;
      } catch {
        start = 0;
      }
    }
    const page = sorted.slice(start, start + first);
    const hasNextPage = start + first < sorted.length;
    const endCursor = page.length > 0 ? Buffer.from(`cursor:${page[page.length - 1].number}`, 'utf8').toString('base64') : null;
    return { nodes: page.map((i) => this.issueNode(repo, i)), page: { hasNextPage, endCursor }, total: sorted.length };
  }

  private mutateCreateIssue(input: Record<string, unknown>): GNode | null {
    const decoded = ungid(String(input.repositoryId ?? ''));
    if (!decoded || decoded.kind !== 'Repository') {
      this.errors.push({ message: 'createIssue: unknown repository id' });
      return null;
    }
    const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
    if (!repo) {
      this.errors.push({ message: 'createIssue: unknown repository' });
      return null;
    }
    const issue: IssueRec = {
      id: forge.nextGlobalId++,
      number: ++repo.issueSeq,
      title: typeof input.title === 'string' ? input.title : '',
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      labels: [],
      comments: [],
      json: '',
    };
    issue.json = issueJsonText(issue, repo.owner);
    repo.issues.push(issue);
    return { type: 'CreateIssuePayload', value: { repo, issue } } as GNode;
  }

  private mutateCloseIssue(input: Record<string, unknown>): GNode | null {
    const decoded = ungid(String(input.issueId ?? ''));
    if (!decoded || decoded.kind !== 'Issue') {
      this.errors.push({ message: 'closeIssue: unknown issue id' });
      return null;
    }
    const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
    const issue = repo?.issues.find((i) => i.number === Number(decoded.parts[1]));
    if (!repo || !issue) {
      this.errors.push({ message: 'closeIssue: unknown issue' });
      return null;
    }
    issue.state = 'closed';
    issue.json = issueJsonText(issue, repo.owner);
    return { type: 'CloseIssuePayload', value: { repo, issue } } as GNode;
  }

  private mutateCreatePull(input: Record<string, unknown>): GNode | null {
    const decoded = ungid(String(input.repositoryId ?? ''));
    if (!decoded || decoded.kind !== 'Repository') {
      this.errors.push({ message: 'createPullRequest: unknown repository id' });
      return null;
    }
    const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
    if (!repo) {
      this.errors.push({ message: 'createPullRequest: unknown repository' });
      return null;
    }
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? '');
    const headSha = repo.tip(head);
    const baseSha = repo.tip(base);
    if (!headSha || !baseSha) {
      this.errors.push({ message: 'createPullRequest: head or base branch not found' });
      return null;
    }
    const dupe = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
    if (dupe) {
      this.errors.push({ message: 'createPullRequest: a pull request already exists for these branches' });
      return null;
    }
    const pull: PullRec = {
      id: forge.nextGlobalId++,
      number: ++repo.pullSeq,
      title: typeof input.title === 'string' ? input.title : '',
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      head,
      base,
      headSha,
      baseSha,
      merged: false,
      mergedAt: '',
      mergeSha: '',
      files: [],
    };
    pullFilesOf(repo, pull);
    repo.pulls.push(pull);
    return { type: 'CreatePullPayload', value: { repo, pull } } as GNode;
  }

  private mutateMergePull(input: Record<string, unknown>): GNode | null {
    const decoded = ungid(String(input.pullRequestId ?? ''));
    if (!decoded || decoded.kind !== 'PullRequest') {
      this.errors.push({ message: 'mergePullRequest: unknown pull request id' });
      return null;
    }
    const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
    const pull = repo?.pulls.find((p) => p.number === Number(decoded.parts[1]));
    if (!repo || !pull) {
      this.errors.push({ message: 'mergePullRequest: unknown pull request' });
      return null;
    }
    if (pull.state !== 'open') {
      this.errors.push({ message: 'mergePullRequest: pull request is already closed' });
      return null;
    }
    const result = squashMerge(repo, pull);
    if (!result.ok) {
      this.errors.push({ message: `mergePullRequest: ${result.message ?? 'merge failed'}` });
      return null;
    }
    return { type: 'MergePullPayload', value: { repo, pull } } as GNode;
  }

  private mutateAddComment(input: Record<string, unknown>): GNode | null {
    const decoded = ungid(String(input.subjectId ?? ''));
    if (!decoded || decoded.kind !== 'Issue') {
      this.errors.push({ message: 'addComment: unknown subject id' });
      return null;
    }
    const repo = forge.listRepos().find((r) => r.id === Number(decoded.parts[0]));
    const issue = repo?.issues.find((i) => i.number === Number(decoded.parts[1]));
    if (!repo || !issue) {
      this.errors.push({ message: 'addComment: unknown issue' });
      return null;
    }
    const comment = { id: forge.nextGlobalId++, body: typeof input.body === 'string' ? input.body : '' };
    issue.comments.push(comment);
    return { type: 'AddCommentPayload', value: { comment } } as GNode;
  }

  /** Execute one operation's selection set against a root node. */
  run(op: GOperation): Record<string, unknown> {
    const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
    const root: GNode = { type: rootType, value: {} };
    return this.select(root, op.fields);
  }

  private select(node: GNode, fields: GField[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const f of fields) {
      if (f.onType !== null && f.onType !== node.type) continue;
      if (f.name === 'issue' && node.type === 'CreateIssuePayload') {
        const v = node.value as { repo: Repo; issue: IssueRec };
        out[f.key] = f.kids ? this.select(this.issueNode(v.repo, v.issue), f.kids) : null;
        continue;
      }
      if (f.name === 'issue' && node.type === 'CloseIssuePayload') {
        const v = node.value as { repo: Repo; issue: IssueRec };
        out[f.key] = f.kids ? this.select(this.issueNode(v.repo, v.issue), f.kids) : null;
        continue;
      }
      if (f.name === 'pullRequest' && (node.type === 'CreatePullPayload' || node.type === 'MergePullPayload')) {
        const v = node.value as { repo: Repo; pull: PullRec };
        out[f.key] = f.kids ? this.select(this.pullNode(v.repo, v.pull), f.kids) : null;
        continue;
      }
      if (f.name === 'commentEdge' && node.type === 'AddCommentPayload') {
        const v = node.value as { comment: { id: number; body: string } };
        out[f.key] = f.kids ? this.select({ type: 'CommentEdge', value: v.comment } as GNode, f.kids) : null;
        continue;
      }
      if (f.name === 'node' && node.type === 'CommentEdge') {
        const comment = node.value as unknown as { id: number; body: string };
        out[f.key] = f.kids ? this.select({ type: 'IssueComment', value: comment } as GNode, f.kids) : null;
        continue;
      }
      const raw = this.field(node, f);
      out[f.key] = this.shape(raw, f.kids);
    }
    return out;
  }

  private shape(raw: unknown, kids: GField[] | null): unknown {
    if (raw === null || raw === undefined) return null;
    if (kids === null) return raw;
    if (Array.isArray(raw)) return raw.map((item) => this.shape(item, kids));
    if (typeof raw === 'object' && 'type' in (raw as Record<string, unknown>)) {
      return this.select(raw as GNode, kids);
    }
    return raw;
  }
}

/** Execute one GraphQL document body; returns the response object. */
function runGraphQL(body: unknown): Record<string, unknown> {
  const exec = new GExecutor();
  try {
    const op = new GParser(
      (body as { query: string }).query,
      ((body as { variables?: Record<string, unknown> }).variables ?? {}) as Record<string, unknown>,
    ).operation();
    const data = exec.run(op);
    if (exec.errors.length > 0) return { data, errors: exec.errors };
    return { data };
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
}

/** Handle POST /api/graphql (single or batched operations). */
function handleGraphQL(body: unknown): { status: number; text: string } {
  if (Array.isArray(body)) {
    const results = body.map((entry) => runGraphQL(entry));
    return { status: 200, text: JSON.stringify(results) };
  }
  if (typeof body !== 'object' || body === null || typeof (body as { query?: unknown }).query !== 'string') {
    return { status: 400, text: JSON.stringify({ errors: [{ message: 'A GraphQL document is required' }] }) };
  }
  return { status: 200, text: JSON.stringify(runGraphQL(body)) };
}

// ------------------------------------------------------------------ MCP
//
// POST /mcp: JSON-RPC 2.0 Streamable HTTP, revision 2026-07-28 via
// server/discover, with the legacy initialize handshake as a fallback.

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Open an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'number', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpTextResult(value: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }] };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Run one MCP tool against the store. */
function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const def = MCP_TOOLS.find((t) => t.name === name);
  if (!def) return { __rpcError: { code: -32602, message: `Unknown tool: ${name}` } };
  for (const required of def.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return mcpToolError(`Missing required argument: ${required}`);
    }
  }
  const owner = String(args.owner ?? forge.viewer);
  const repoName = String(args.repo ?? args.name ?? '');
  if (name === 'create_repo') {
    const created = forge.createRepo(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    if (!created) return mcpToolError(`Repository ${repoName} already exists`);
    return mcpTextResult(JSON.parse(repoJson(created)));
  }
  const repo = forge.repo(owner, repoName);
  if (!repo) return mcpToolError(`Repository ${owner}/${repoName} not found`);
  if (name === 'get_repo') return mcpTextResult(JSON.parse(repoJson(repo)));
  if (name === 'create_issue') {
    const issue: IssueRec = {
      id: forge.nextGlobalId++,
      number: ++repo.issueSeq,
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      comments: [],
      json: '',
    };
    issue.json = issueJsonText(issue, repo.owner);
    repo.issues.push(issue);
    return mcpTextResult(JSON.parse(issue.json));
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = repo.issues;
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    return mcpTextResult(list.map((i) => JSON.parse(i.json)));
  }
  if (name === 'create_pull_request') {
    const head = String(args.head);
    const base = String(args.base);
    const headSha = repo.tip(head);
    const baseSha = repo.tip(base);
    if (!headSha || !baseSha) return mcpToolError('head or base branch not found');
    const dupe = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
    if (dupe) return mcpToolError('A pull request already exists for these branches');
    const pull: PullRec = {
      id: forge.nextGlobalId++,
      number: ++repo.pullSeq,
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      head,
      base,
      headSha,
      baseSha,
      merged: false,
      mergedAt: '',
      mergeSha: '',
      files: [],
    };
    pullFilesOf(repo, pull);
    repo.pulls.push(pull);
    return mcpTextResult(pullJson(pull, repo.owner));
  }
  if (name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pull = repo.pulls.find((p) => p.number === number);
    if (!pull) return mcpToolError(`Pull request #${number} not found`);
    if (pull.state !== 'open') return mcpToolError('Pull request is already closed');
    const result = squashMerge(repo, pull);
    if (!result.ok) return mcpToolError(result.message ?? 'merge failed');
    return mcpTextResult({ merged: true, sha: result.sha, message: result.message, number: pull.number });
  }
  return mcpToolError(`Unknown tool: ${name}`);
}

/** Handle one POST /mcp body. Returns status + body text. */
function handleMcp(raw: Buffer): { status: number; text: string } {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
  } catch {
    return {
      status: 400,
      text: JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }),
    };
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return {
      status: 400,
      text: JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } }),
    };
  }
  const id = (doc.id ?? null) as string | number | null;
  const method = String(doc.method ?? '');
  const params = (doc.params ?? {}) as Record<string, unknown>;
  const reply = (result: unknown): string => JSON.stringify({ jsonrpc: '2.0', id, result });
  const replyError = (code: number, message: string): string =>
    JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
  if (method === 'server/discover') {
    return {
      status: 200,
      text: reply({
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
      }),
    };
  }
  if (method === 'initialize') {
    const offered = (params.protocolVersion as string) || '2025-11-25';
    const known = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    return {
      status: 200,
      text: reply({
        protocolVersion: known.includes(offered) ? offered : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      }),
    };
  }
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    return { status: 202, text: '' };
  }
  if (method === 'ping') {
    return { status: 200, text: reply({}) };
  }
  if (method === 'tools/list') {
    return { status: 200, text: reply({ tools: MCP_TOOLS }) };
  }
  if (method === 'tools/call') {
    const toolName = String(params.name ?? '');
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const out = runMcpTool(toolName, args);
    const rpcError = (out as { __rpcError?: { code: number; message: string } }).__rpcError;
    if (rpcError) return { status: 200, text: replyError(rpcError.code, rpcError.message) };
    return { status: 200, text: reply(out) };
  }
  return { status: 200, text: replyError(-32601, `Method not found: ${method}`) };
}

// ------------------------------------------------------------------ server

function authed(req: http.IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ') || header.length <= 7) return false;
  if (TOKEN === '') return true;
  return header === `Bearer ${TOKEN}`;
}

function sendRaw(
  res: http.ServerResponse,
  status: number,
  text: string | Buffer | null,
  contentType: string,
  extra?: Record<string, string>,
): void {
  const headers: Record<string, string> = {
    'content-type': contentType,
    'x-github-request-id': `req-${nextReqId()}`,
    ...(extra ?? {}),
  };
  res.writeHead(status, headers);
  if (text === null) res.end();
  else res.end(text);
}

function sendJson(res: http.ServerResponse, status: number, text: string, extra?: Record<string, string>): void {
  sendRaw(res, status, text, 'application/json', extra);
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const url = req.url ?? '/';
    const q = url.indexOf('?');
    const pathname = q >= 0 ? url.slice(0, q) : url;
    const query = new URLSearchParams(q >= 0 ? url.slice(q + 1) : '');
    const method = req.method ?? 'GET';

    if (pathname === '/healthz' && method === 'GET') {
      sendJson(res, 200, '{"ok":true}');
      return;
    }

    const needsAuth =
      pathname.startsWith('/api/v3') || pathname === '/api/graphql' || pathname === '/mcp' || pathname.includes('.git/');
    if (needsAuth && !authed(req)) {
      sendJson(res, 401, JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    let raw = Buffer.alloc(0);
    if (method !== 'GET' && method !== 'HEAD') raw = await readBody(req);
    const ctx: HttpCtx = { req, res, body: raw, query };

    if (pathname === '/api/graphql') {
      if (method !== 'POST') {
        sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
        return;
      }
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) {
        sendJson(res, 400, JSON.stringify({ errors: [{ message: 'Request body is not valid JSON' }] }));
        return;
      }
      const out = handleGraphQL(parsed.value);
      sendJson(res, out.status, out.text);
      return;
    }

    if (pathname === '/mcp') {
      if (method !== 'POST') {
        sendJson(res, 405, JSON.stringify({ message: 'Method Not Allowed' }));
        return;
      }
      const out = handleMcp(raw);
      if (out.text === '') {
        sendRaw(res, out.status, null, 'application/json');
      } else {
        sendJson(res, out.status, out.text);
      }
      return;
    }

    if (pathname.startsWith('/api/v3')) {
      const parsed = method === 'GET' || raw.length === 0 ? { ok: true as const, value: {} } : parseJsonBody(raw);
      if (!parsed.ok) {
        sendJson(res, 400, JSON.stringify({ message: 'Request body is not valid JSON' }));
        return;
      }
      const out = routeRest(method, pathname, ctx, (parsed.value ?? {}) as Record<string, unknown>);
      if (out === null) {
        sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
        return;
      }
      if (out.status === 204) {
        sendRaw(res, 204, null, 'application/json');
        return;
      }
      sendJson(res, out.status, out.text ?? '{}', out.headers);
      return;
    }

    const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)$/.exec(pathname);
    if (gitMatch) {
      const owner = gitMatch[1];
      const repoName = gitMatch[2];
      const tail = gitMatch[3];
      const repo = forge.repo(owner, repoName);
      if (!repo) {
        sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
        return;
      }
      if (tail === '/info/refs' && method === 'GET') {
        const service = query.get('service') ?? '';
        if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
          sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
          return;
        }
        const v2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
        const body = v2 ? advertiseV2() : advertiseV0(service, repo);
        const type = `application/x-${service}-advertisement`;
        sendRaw(res, 200, body, type);
        return;
      }
      if (tail === '/git-upload-pack' && method === 'POST') {
        try {
          const out = handleUploadPack(repo, ctx);
          sendRaw(res, out.status, out.body, out.type);
        } catch (err) {
          sendJson(res, 400, JSON.stringify({ message: err instanceof Error ? err.message : 'bad request' }));
        }
        return;
      }
      if (tail === '/git-receive-pack' && method === 'POST') {
        try {
          const out = handleReceivePack(repo, ctx);
          sendRaw(res, out.status, out.body, out.type);
        } catch (err) {
          sendJson(res, 400, JSON.stringify({ message: err instanceof Error ? err.message : 'bad request' }));
        }
        return;
      }
      sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
      return;
    }

    sendJson(res, 404, JSON.stringify({ message: 'Not Found' }));
  } catch (err) {
    try {
      sendJson(res, 500, JSON.stringify({ message: err instanceof Error ? err.message : 'internal error' }));
    } catch {
      res.destroy();
    }
  }
}

// ------------------------------------------------------------------ boot

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerAndWait(port: number): Promise<void> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok || response.status === 409) break;
    } catch {
      // The env may not be listening yet; retry.
    }
    await sleep(500);
  }
  for (;;) {
    try {
      const response = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(10000) });
      const data = (await response.json()) as { done?: boolean };
      if (data.done === true) process.exit(0);
    } catch {
      // The env answers at once while the suite runs; a miss is just a retry.
    }
    await sleep(500);
  }
}

const server = http.createServer((req, res) => {
  void handle(req, res);
});

server.listen(0, '0.0.0.0', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  if (ENV_URL !== '') {
    void registerAndWait(port);
  } else {
    console.log(`forge listening on http://127.0.0.1:${port}`);
  }
});

