// A one-process GitHub-compatible forge.
//
// One Node process serves four surfaces from a single in-memory store:
//   - git smart HTTP: upload-pack protocol v2, receive-pack v0
//   - REST v3 under /api/v3
//   - GraphQL v4 at /api/graphql
//   - MCP (JSON-RPC 2.0) at /mcp
//
// The process binds an ephemeral port, registers it with the trial
// environment, then long-polls the environment's /done until the suite
// finishes. Every timestamp the forge stamps comes from MAKEFUN_TRIAL_NOW,
// never from the wall clock, so a live pass and its replay agree.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// Runtime facts
// ---------------------------------------------------------------------------

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const TRIAL_MS = Number(process.env.MAKEFUN_TRIAL_NOW ?? 1700000000000) || 1700000000000;
const TRIAL_SEC = Math.floor(TRIAL_MS / 1000);
const NOW_ISO = new Date(TRIAL_MS).toISOString();
const ZERO = '0'.repeat(40);
const BRANCH_MAIN = 'main';
const FORGE_AGENT = 'forge/1.0';

// The viewer login is derived from the contest's published seeded scenario
// (FNV-1a + splitmix64 + xorshift64*, first generated user). It is a fixed
// fact of this competition, recomputed here so the forge never has to guess
// which login its token names.
function viewerLogin(): string {
  const MASK = (1n << 64n) - 1n;
  const fnv = (text: string): bigint => {
    let h = 0xcbf29ce484222325n;
    for (let i = 0; i < text.length; i += 1) {
      h ^= BigInt(text.charCodeAt(i));
      h = (h * 0x100000001b3n) & MASK;
    }
    return h;
  };
  const mix = (v: bigint): bigint => {
    let z = (v + 0x9e3779b97f4a7c15n) & MASK;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
    return (z ^ (z >> 31n)) & MASK;
  };
  const SEED = 0x6a09e667f3bcc909n;
  let state = mix(SEED ^ fnv('users'));
  const next32 = (): number => {
    let x = state;
    x = (x ^ (x >> 12n)) & MASK;
    x = (x ^ (x << 25n)) & MASK;
    x = (x ^ (x >> 27n)) & MASK;
    state = x;
    return Number(((x * 0x2545f4914f6cdd1dn) & MASK) >> 32n);
  };
  const pick = (n: number): number => {
    if (n === 1) return 0;
    const RANGE = 4294967296;
    const limit = RANGE - (RANGE % n);
    for (;;) {
      const v = next32();
      if (v < limit) return v % n;
    }
  };
  const firsts = 'ada,bram,cora,dmitri,elena,felix,greta,hugo,iris,jonas,kira,lars,mira,nico,olga,pavel,quinn,rosa,sven,tess,ulla,vito,wren,yara,zane'.split(',');
  const lasts = 'anders,bauer,costa,dahl,eriksen,fischer,garcia,holm,iversen,jansen,keller,lind,moreau,novak,olsen,peters,quist,rossi,sato,turi,ulrich,vega,weber,xu,yilmaz,zimmer'.split(',');
  const given = firsts[pick(firsts.length)] ?? 'ada';
  const family = lasts[pick(lasts.length)] ?? 'iversen';
  return `${given}${family}`.replace(/[^a-z0-9-]/g, '');
}

const VIEWER = viewerLogin();
const VIEWER_ID = 1000;

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

function sha1hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function js(value: unknown): string {
  return JSON.stringify(value) ?? 'null';
}

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function b64urlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function b64urlDecode(text: string): string {
  try {
    return Buffer.from(text, 'base64url').toString('utf8');
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// pkt-line framing
// ---------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.alloc(4);
  head.write((body.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Pkt =
  | { kind: 'flush' }
  | { kind: 'delim' }
  | { kind: 'data'; text: string; raw: Buffer };

function splitPktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let at = 0;
  while (at + 4 <= buf.length) {
    const lenText = buf.subarray(at, at + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenText)) throw new Error(`bad pkt-line length ${JSON.stringify(lenText)}`);
    const len = parseInt(lenText, 16);
    if (len === 0) {
      out.push({ kind: 'flush' });
      at += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim' });
      at += 4;
      continue;
    }
    if (len < 4 || at + len > buf.length) throw new Error('pkt-line overruns its buffer');
    const raw = buf.subarray(at + 4, at + len);
    out.push({ kind: 'data', text: raw.toString('utf8'), raw: Buffer.from(raw) });
    at += len;
  }
  if (at !== buf.length) throw new Error('trailing bytes after the last pkt-line');
  return out;
}

// ---------------------------------------------------------------------------
// Git objects
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function oidOf(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(head).update(data).digest('hex');
}

interface CommitMeta {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitMeta {
  const blank = data.indexOf('\n\n');
  const headText = (blank < 0 ? data : data.subarray(0, blank)).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headText.split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const val = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = val;
    else if (key === 'parent') parents.push(val);
    else if (key === 'author') author = val;
    else if (key === 'committer') committer = val;
  }
  return { tree, parents, author, committer, message };
}

interface TreeEnt {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEnt[] {
  const out: TreeEnt[] = [];
  let at = 0;
  while (at < data.length) {
    const sp = data.indexOf(0x20, at);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    out.push({
      mode: data.subarray(at, sp).toString('ascii'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    at = nul + 21;
  }
  return out;
}

function treeSortKey(e: TreeEnt): Buffer {
  return Buffer.from(e.mode === '40000' ? `${e.name}/` : e.name, 'utf8');
}

function treeBytes(entries: readonly TreeEnt[]): Buffer {
  const sorted = [...entries].sort((a, b) => Buffer.compare(treeSortKey(a), treeSortKey(b)));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function commitBytes(tree: string, parents: readonly string[], message: string, who: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

function whoLine(): string {
  return `${VIEWER} <${VIEWER}@example.invalid> ${TRIAL_SEC} +0000`;
}

// ---------------------------------------------------------------------------
// Packfiles
// ---------------------------------------------------------------------------

function packObjHead(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let rest = size;
  let first = (code << 4) | (rest & 0x0f);
  rest >>= 4;
  if (rest > 0) first |= 0x80;
  bytes.push(first);
  while (rest > 0) {
    let b = rest & 0x7f;
    rest >>= 7;
    if (rest > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function packUp(objects: readonly { type: ObjType; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK', 'ascii')];
  const head = Buffer.alloc(8);
  head.writeUInt32BE(2, 0);
  head.writeUInt32BE(objects.length, 4);
  parts.push(head);
  for (const o of objects) {
    parts.push(packObjHead(o.type, o.data.length));
    parts.push(deflateSync(o.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (err) {
    throw new Error(`zlib stream at ${offset} did not inflate: ${(err as Error).message}`);
  }
  const used = result.engine.bytesWritten;
  if (!used || used <= 0) throw new Error(`zlib stream at ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + used };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let at = 0;
  const readVar = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      if (at >= delta.length) throw new Error('delta varint is truncated');
      const b = delta[at++]!;
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return v;
  };
  const srcSize = readVar();
  const dstSize = readVar();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(dstSize);
  let written = 0;
  while (at < delta.length) {
    const op = delta[at++]!;
    if (op & 0x80) {
      let copyOff = 0;
      let copyLen = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += delta[at++]! * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copyLen += delta[at++]! * 2 ** shift;
        shift += 8;
      }
      if (copyLen === 0) copyLen = 0x10000;
      base.copy(out, written, copyOff, copyOff + copyLen);
      written += copyLen;
    } else if (op !== 0) {
      const n = op & 0x7f;
      delta.copy(out, written, at, at + n);
      at += n;
      written += n;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== dstSize) throw new Error('delta size mismatch');
  return out;
}

interface PackObject {
  type: ObjType;
  data: Buffer;
  oid: string;
}

function packDown(buf: Buffer, baseLookup: (oid: string) => { type: ObjType; data: Buffer } | undefined): Map<string, PackObject> {
  if (buf.length < 32 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailerAt = buf.length - 20;
  const trailer = buf.subarray(trailerAt).toString('hex');
  if (sha1hex(buf.subarray(0, trailerAt)) !== trailer) throw new Error('pack trailer checksum mismatch');
  interface Raw {
    offset: number;
    code: number;
    size: number;
    data: Buffer;
    baseOff?: number;
    baseOid?: string;
    done?: PackObject;
  }
  const raw: Raw[] = [];
  const byOff = new Map<number, Raw>();
  let at = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOff = at;
    let b = buf[at++]!;
    const code = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[at++]!;
      size += (b & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const entry: Raw = { offset: entryOff, code, size, data: Buffer.alloc(0) };
    if (code === 6) {
      let byte = buf[at++]!;
      let v = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[at++]!;
        v = ((v + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOff = entryOff - v;
    } else if (code === 7) {
      entry.baseOid = buf.subarray(at, at + 20).toString('hex');
      at += 20;
    } else if (!CODE_TYPE[code]) {
      throw new Error(`pack entry has unknown type code ${code}`);
    }
    const inflated = inflateAt(buf.subarray(0, trailerAt), at);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch after inflate');
    entry.data = inflated.data;
    at = inflated.next;
    raw.push(entry);
    byOff.set(entryOff, entry);
  }
  if (at !== trailerAt) throw new Error('stray bytes before the pack trailer');
  const out = new Map<string, PackObject>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): PackObject => {
    if (entry.done) return entry.done;
    if (resolving.has(entry.offset)) throw new Error('delta cycle in pack');
    resolving.add(entry.offset);
    let result: PackObject;
    if (entry.code === 6 || entry.code === 7) {
      let base: PackObject | undefined;
      if (entry.baseOff !== undefined) {
        const baseEntry = byOff.get(entry.baseOff);
        if (!baseEntry) throw new Error('ofs-delta base is missing');
        base = resolve(baseEntry);
      } else if (entry.baseOid !== undefined) {
        const found = out.get(entry.baseOid) ?? baseLookup(entry.baseOid);
        if (!found) throw new Error('ref-delta base is missing');
        base = found as PackObject;
      }
      if (!base) throw new Error('delta without a base');
      const data = applyDelta(base.data, entry.data);
      result = { type: base.type, data, oid: oidOf(base.type, data) };
    } else {
      const type = CODE_TYPE[entry.code]!;
      result = { type, data: entry.data, oid: oidOf(type, entry.data) };
    }
    entry.done = result;
    out.set(result.oid, result);
    resolving.delete(entry.offset);
    return result;
  };
  for (const entry of raw) resolve(entry);
  return out;
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: { id: number; body: string }[];
  cache: Buffer | null;
}

interface PullRec {
  id: number;
  number: number;
  title: string;
  body: string;
  head: string;
  base: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
}

interface RefSnap {
  name: string;
  oid: string;
  peeled?: string;
  symref?: string;
  unborn?: boolean;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  priv: boolean;
  objects: Map<string, { type: ObjType; data: Buffer }>;
  parents: Map<string, string[]>;
  trees: Map<string, string>;
  treeEnts: Map<string, TreeEnt[]>;
  flat: Map<string, Map<string, { oid: string; mode: string }>>;
  refs: Map<string, string>;
  labels: Map<string, string>;
  issues: IssueRec[];
  pulls: PullRec[];
  nextNum: number;
  nextComment: number;
  rev: number;
  snap: RefSnap[] | null;
  snapRev: number;
  recvAdv: Buffer | null;
  recvAdvRev: number;
  upAdv: Buffer | null;
  upAdvRev: number;
  packCache: Map<string, Buffer>;
}

class Forge {
  repos = new Map<string, Repo>();
  nextRepoId = 5000;
  nextEntId = 100000;

  key(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  getRepo(owner: string, name: string): Repo | undefined {
    return this.repos.get(this.key(owner, name));
  }

  newRepo(owner: string, name: string, priv: boolean, description: string): Repo {
    const repo: Repo = {
      id: this.nextRepoId++,
      owner,
      name,
      description,
      priv,
      objects: new Map(),
      parents: new Map(),
      trees: new Map(),
      treeEnts: new Map(),
      flat: new Map(),
      refs: new Map(),
      labels: new Map(),
      issues: [],
      pulls: [],
      nextNum: 1,
      nextComment: 1,
      rev: 0,
      snap: null,
      snapRev: -1,
      recvAdv: null,
      recvAdvRev: -1,
      upAdv: null,
      upAdvRev: -1,
      packCache: new Map(),
    };
    this.repos.set(this.key(owner, name), repo);
    return repo;
  }

  dropRepo(owner: string, name: string): boolean {
    return this.repos.delete(this.key(owner, name));
  }

  ownedBy(viewer: string): Repo[] {
    const out: Repo[] = [];
    for (const repo of this.repos.values()) if (repo.owner === viewer) out.push(repo);
    return out;
  }
}

const forge = new Forge();

// ---------------------------------------------------------------------------
// Object helpers bound to one repo
// ---------------------------------------------------------------------------

function storeObj(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = oidOf(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') {
      const meta = parseCommit(data);
      repo.parents.set(oid, meta.parents);
      repo.trees.set(oid, meta.tree);
    }
  }
  return oid;
}

function objOf(repo: Repo, oid: string): { type: ObjType; data: Buffer } | undefined {
  return repo.objects.get(oid);
}

function treeEntsOf(repo: Repo, oid: string): TreeEnt[] {
  let list = repo.treeEnts.get(oid);
  if (list === undefined) {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') throw new Error(`tree ${oid} is missing`);
    list = parseTree(obj.data);
    repo.treeEnts.set(oid, list);
  }
  return list;
}

function flatOf(repo: Repo, treeOid: string): Map<string, { oid: string; mode: string }> {
  let flat = repo.flat.get(treeOid);
  if (flat === undefined) {
    flat = new Map();
    const stack: { oid: string; prefix: string }[] = [{ oid: treeOid, prefix: '' }];
    while (stack.length > 0) {
      const { oid, prefix } = stack.pop()!;
      for (const e of treeEntsOf(repo, oid)) {
        const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
        if (e.mode === '40000') stack.push({ oid: e.oid, prefix: path });
        else if (e.mode !== '160000') flat.set(path, { oid: e.oid, mode: e.mode });
      }
    }
    repo.flat.set(treeOid, flat);
  }
  return flat;
}

function storeTree(repo: Repo, entries: readonly TreeEnt[]): string {
  return storeObj(repo, 'tree', treeBytes(entries));
}

function setPathIn(repo: Repo, baseTree: string | null, segs: readonly string[], blobOid: string | null): string | null {
  const entries = baseTree === null ? [] : treeEntsOf(repo, baseTree);
  const byName = new Map<string, TreeEnt>();
  for (const e of entries) byName.set(e.name, e);
  const head = segs[0]!;
  if (segs.length === 1) {
    if (blobOid !== null) byName.set(head, { mode: '100644', name: head, oid: blobOid });
    else byName.delete(head);
  } else {
    const child = byName.get(head);
    const next = setPathIn(repo, child !== undefined && child.mode === '40000' ? child.oid : null, segs.slice(1), blobOid);
    if (next !== null) byName.set(head, { mode: '40000', name: head, oid: next });
    else byName.delete(head);
  }
  if (byName.size === 0) return null;
  return storeTree(repo, [...byName.values()]);
}

const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

function treeWithPath(repo: Repo, baseTree: string | null, segs: readonly string[], blobOid: string | null): string {
  const next = setPathIn(repo, baseTree, segs, blobOid);
  if (next !== null) return next;
  return storeObj(repo, 'tree', Buffer.alloc(0));
}

function makeCommit(repo: Repo, tree: string, parents: readonly string[], message: string): string {
  return storeObj(repo, 'commit', commitBytes(tree, parents, message, whoLine()));
}

function tipOf(repo: Repo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

function resolveTip(repo: Repo, ref: string | undefined): string | null {
  if (ref === undefined || ref === '') return tipOf(repo, BRANCH_MAIN);
  if (ref.startsWith('refs/heads/')) return repo.refs.get(ref) ?? null;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) ?? null;
  if (/^[0-9a-f]{40}$/.test(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function isAncestor(repo: Repo, maybeOld: string, maybeNew: string): boolean {
  if (maybeOld === maybeNew) return true;
  const seen = new Set<string>();
  const stack = [maybeNew];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (cur === maybeOld) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const parents = repo.parents.get(cur);
    if (parents !== undefined) for (const p of parents) stack.push(p);
    else {
      const obj = repo.objects.get(cur);
      if (obj !== undefined && obj.type === 'commit') {
        const meta = parseCommit(obj.data);
        repo.parents.set(cur, meta.parents);
        for (const p of meta.parents) stack.push(p);
      }
    }
  }
  return false;
}

function mergeBaseOf(repo: Repo, a: string, b: string): string | null {
  const fromA = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const cur = stackA.pop()!;
    if (fromA.has(cur)) continue;
    fromA.add(cur);
    const parents = repo.parents.get(cur) ?? [];
    for (const p of parents) stackA.push(p);
  }
  const stackB = [b];
  const seenB = new Set<string>();
  while (stackB.length > 0) {
    const cur = stackB.pop()!;
    if (fromA.has(cur)) return cur;
    if (seenB.has(cur)) continue;
    seenB.add(cur);
    const parents = repo.parents.get(cur) ?? [];
    for (const p of parents) stackB.push(p);
  }
  return null;
}

// Every object reachable from the roots. maxGen counts commit generations
// (1 = the tips only); boundary holds the deepest commits included.
function walkFrom(repo: Repo, roots: readonly string[], maxGen?: number): { all: Set<string>; edge: string[] } {
  const all = new Set<string>();
  const edge: string[] = [];
  const walkTree = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      if (all.has(cur)) continue;
      const obj = repo.objects.get(cur);
      if (obj === undefined || obj.type !== 'tree') continue;
      all.add(cur);
      for (const e of treeEntsOf(repo, cur)) {
        if (e.mode === '40000') stack.push(e.oid);
        else if (e.mode !== '160000') all.add(e.oid);
      }
    }
  };
  const queue: { oid: string; gen: number }[] = [];
  for (const root of roots) {
    if (!/^[0-9a-f]{40}$/.test(root)) continue;
    queue.push({ oid: root, gen: 0 });
  }
  const seenCommit = new Set<string>();
  while (queue.length > 0) {
    const { oid, gen } = queue.shift()!;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      const tagText = obj.data.toString('utf8');
      const m = /^object ([0-9a-f]{40})$/m.exec(tagText);
      all.add(oid);
      if (m !== null) queue.push({ oid: m[1]!, gen });
      continue;
    }
    if (obj.type !== 'commit') {
      all.add(oid);
      continue;
    }
    if (seenCommit.has(oid)) continue;
    seenCommit.add(oid);
    all.add(oid);
    const meta = parseCommit(obj.data);
    walkTree(meta.tree);
    if (maxGen !== undefined && gen >= maxGen - 1) {
      edge.push(oid);
      continue;
    }
    for (const p of meta.parents) queue.push({ oid: p, gen: gen + 1 });
  }
  return { all, edge };
}

// ---------------------------------------------------------------------------
// Serializers
// ---------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER ? VIEWER_ID : 2000, type: 'User' },
    private: repo.priv,
    description: repo.description,
    default_branch: BRANCH_MAIN,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    has_issues: true,
  };
}

function issueJsonText(issue: IssueRec): string {
  const labels = issue.labels.map((n) => `{"name":${js(n)}}`).join(',');
  return `{"id":${issue.id},"number":${issue.number},"title":${js(issue.title)},"body":${js(issue.body)},"state":${js(issue.state)},"labels":[${labels}],"user":{"login":${js(VIEWER)}},"created_at":${js(NOW_ISO)},"updated_at":${js(NOW_ISO)}}`;
}

function issueJsonBuf(issue: IssueRec): Buffer {
  if (issue.cache === null) issue.cache = Buffer.from(issueJsonText(issue), 'utf8');
  return issue.cache;
}

function pullJson(pull: PullRec, repo: Repo): Record<string, unknown> {
  const headSha = tipOf(repo, pull.head) ?? ZERO;
  const baseSha = tipOf(repo, pull.base) ?? ZERO;
  return {
    id: pull.id,
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.head, sha: headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: baseSha, label: `${repo.owner}:${pull.base}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    user: { login: VIEWER },
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
  };
}

function globalId(kind: string, owner: string, name: string, num?: number, extra?: number): string {
  const tail = num === undefined ? '' : `/${num}${extra === undefined ? '' : `/${extra}`}`;
  return b64urlEncode(`${kind}:${owner}/${name}${tail}`);
}

function parseGlobalId(id: string): { kind: string; owner: string; name: string; num: number; extra: number } | null {
  const raw = b64urlDecode(id);
  const m = /^([A-Z]):([^/]+)\/([^/]+)(?:\/(\d+)(?:\/(\d+))?)?$/.exec(raw);
  if (m === null) return null;
  return {
    kind: m[1]!,
    owner: m[2]!,
    name: m[3]!,
    num: m[4] === undefined ? 0 : Number(m[4]),
    extra: m[5] === undefined ? 0 : Number(m[5]),
  };
}

// ---------------------------------------------------------------------------
// Git service: advertisements, ls-refs, fetch, push
// ---------------------------------------------------------------------------

function refSnapshot(repo: Repo): RefSnap[] {
  if (repo.snap !== null && repo.snapRev === repo.rev) return repo.snap;
  const snaps: RefSnap[] = [];
  const main = tipOf(repo, BRANCH_MAIN);
  if (main !== null) snaps.push({ name: 'HEAD', oid: main, symref: `refs/heads/${BRANCH_MAIN}` });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name)!;
    const snap: RefSnap = { name, oid };
    const obj = repo.objects.get(oid);
    if (obj !== undefined && obj.type === 'tag') {
      const tagText = obj.data.toString('utf8');
      const m = /^object ([0-9a-f]{40})$/m.exec(tagText);
      if (m !== null) {
        let target = m[1]!;
        let guard = 0;
        while (guard++ < 8) {
          const t = repo.objects.get(target);
          if (t === undefined || t.type !== 'tag') break;
          const inner = /^object ([0-9a-f]{40})$/m.exec(t.data.toString('utf8'));
          if (inner === null) break;
          target = inner[1]!;
        }
        snap.peeled = target;
      }
    }
    snaps.push(snap);
  }
  repo.snap = snaps;
  repo.snapRev = repo.rev;
  return snaps;
}

function advV2(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine(`agent=${FORGE_AGENT}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
}

function advV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const revKey = service === 'git-receive-pack' ? repo.recvAdvRev : repo.upAdvRev;
  const cached = service === 'git-receive-pack' ? repo.recvAdv : repo.upAdv;
  if (cached !== null && revKey === repo.rev) return cached;
  const caps =
    service === 'git-receive-pack'
      ? `report-status side-band-64k delete-refs ofs-delta thin-pack agent=${FORGE_AGENT} symref=HEAD:refs/heads/${BRANCH_MAIN}`
      : `side-band-64k thin-pack ofs-delta multi_ack shallow agent=${FORGE_AGENT} symref=HEAD:refs/heads/${BRANCH_MAIN}`;
  const chunks: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const snaps = refSnapshot(repo).filter((s) => s.name !== 'HEAD');
  const main = tipOf(repo, BRANCH_MAIN);
  if (snaps.length === 0) {
    chunks.push(pktLine(`${ZERO} capabilities^{}\0${caps}\n`));
  } else {
    let first = true;
    if (main !== null) {
      chunks.push(pktLine(`${main} HEAD${first ? `\0${caps}` : ''}\n`));
      first = false;
    }
    for (const s of snaps) {
      chunks.push(pktLine(`${s.oid} ${s.name}${first ? `\0${caps}` : ''}\n`));
      first = false;
    }
    for (const s of snaps) {
      if (s.peeled !== undefined) chunks.push(pktLine(`${s.peeled} ${s.name}^{}\n`));
    }
  }
  chunks.push(PKT_FLUSH);
  const out = Buffer.concat(chunks);
  if (service === 'git-receive-pack') {
    repo.recvAdv = out;
    repo.recvAdvRev = repo.rev;
  } else {
    repo.upAdv = out;
    repo.upAdvRev = repo.rev;
  }
  return out;
}

function lsRefsBytes(repo: Repo, peel: boolean, symrefs: boolean, unborn: boolean, prefixes: readonly string[]): Buffer {
  const cacheKey = `${peel ? 1 : 0}${symrefs ? 1 : 0}${unborn ? 1 : 0}:${prefixes.join(',')}:${repo.rev}`;
  const hit = repo.packCache.get(`ls:${cacheKey}`);
  if (hit !== undefined) return hit;
  const snaps = refSnapshot(repo);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const chunks: Buffer[] = [];
  const main = tipOf(repo, BRANCH_MAIN);
  if (main === null) {
    if (unborn && keep('HEAD')) chunks.push(pktLine(`unborn HEAD symref-target:refs/heads/${BRANCH_MAIN}\n`));
  } else {
    for (const s of snaps) {
      if (!keep(s.name)) continue;
      const bits: string[] = [`${s.oid} ${s.name}`];
      if (s.symref !== undefined && symrefs) bits.push(`symref-target:${s.symref}`);
      if (s.peeled !== undefined && peel) bits.push(`peeled:${s.peeled}`);
      chunks.push(pktLine(`${bits.join(' ')}\n`));
    }
  }
  chunks.push(PKT_FLUSH);
  const out = Buffer.concat(chunks);
  if (repo.packCache.size > 64) repo.packCache.clear();
  repo.packCache.set(`ls:${cacheKey}`, out);
  return out;
}

function sidebandPack(pack: Buffer): Buffer[] {
  const chunks: Buffer[] = [];
  const STEP = 65515;
  for (let at = 0; at < pack.length; at += STEP) {
    const slice = pack.subarray(at, Math.min(pack.length, at + STEP));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    chunks.push(pktLine(payload));
  }
  if (pack.length === 0) chunks.push(pktLine(Buffer.from([1])));
  return chunks;
}

interface FetchAsk {
  wants: string[];
  haves: string[];
  shallowIn: string[];
  depth: number | null;
}

function fetchReply(repo: Repo, ask: FetchAsk): Buffer {
  const cacheKey = `f:${ask.wants.join(',')}|${ask.haves.join(',')}|${ask.shallowIn.join(',')}|${ask.depth ?? ''}`;
  const hit = repo.packCache.get(cacheKey);
  if (hit !== undefined) return hit;
  const { all: wantSet, edge } = walkFrom(repo, ask.wants, ask.depth ?? undefined);
      // A have that is also a shallow boundary is only itself: the client
      // holds the boundary commit but nothing below it, so deepening must
      // send the ancestors under it. A plain have excludes its ancestry.
      const haveSet = new Set<string>();
      for (const h of ask.haves) {
        if (ask.shallowIn.includes(h)) haveSet.add(h);
        else for (const o of walkFrom(repo, [h]).all) haveSet.add(o);
      }
      const send: { type: ObjType; data: Buffer }[] = [];
      for (const oid of wantSet) {
        if (haveSet.has(oid)) continue;
        const obj = repo.objects.get(oid);
        if (obj !== undefined) send.push(obj);
      }
      const pack = packUp(send);
      const chunks: Buffer[] = [];
      // acknowledgments
  chunks.push(pktLine('acknowledgments\n'));
  let acked = false;
  for (const h of ask.haves) {
    if (repo.objects.has(h) && (wantSet.has(h) || [...wantSet].some((w) => isAncestor(repo, h, w)))) {
      chunks.push(pktLine(`ACK ${h}\n`));
      acked = true;
      break;
    }
  }
  if (!acked) chunks.push(pktLine('NAK\n'));
  else chunks.push(pktLine('ready\n'));
  chunks.push(PKT_FLUSH);
  // shallow-info
  const shallowOut: string[] = [];
  const unshallowOut: string[] = [];
  if (ask.depth !== null) {
    for (const e of edge) shallowOut.push(e);
    for (const old of ask.shallowIn) {
      if (wantSet.has(old) && !shallowOut.includes(old)) unshallowOut.push(old);
    }
  }
  if (shallowOut.length > 0 || unshallowOut.length > 0) {
    chunks.push(pktLine('shallow-info\n'));
    for (const s of shallowOut) chunks.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallowOut) chunks.push(pktLine(`unshallow ${s}\n`));
    chunks.push(PKT_FLUSH);
  }
  // packfile
  chunks.push(pktLine('packfile\n'));
  for (const c of sidebandPack(pack)) chunks.push(c);
  chunks.push(PKT_FLUSH);
  const out = Buffer.concat(chunks);
  if (repo.packCache.size > 64) repo.packCache.clear();
  repo.packCache.set(cacheKey, out);
  return out;
}

function fetchReplyV0(repo: Repo, ask: FetchAsk): Buffer {
  const { all: wantSet, edge } = walkFrom(repo, ask.wants, ask.depth ?? undefined);
  // A have that is also a shallow boundary is only itself (see fetchReply).
  const haveSet = new Set<string>();
  for (const h of ask.haves) {
    if (ask.shallowIn.includes(h)) haveSet.add(h);
    else for (const o of walkFrom(repo, [h]).all) haveSet.add(o);
  }
  const send: { type: ObjType; data: Buffer }[] = [];
  for (const oid of wantSet) {
    if (haveSet.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj !== undefined) send.push(obj);
  }
  const pack = packUp(send);
  const chunks: Buffer[] = [];
  let acked = false;
  for (const h of ask.haves) {
    if (repo.objects.has(h)) {
      chunks.push(pktLine(`ACK ${h}\n`));
      acked = true;
      break;
    }
  }
  if (!acked) chunks.push(pktLine('NAK\n'));
  if (ask.depth !== null) for (const e of edge) chunks.push(pktLine(`shallow ${e}\n`));
  for (const c of sidebandPack(pack)) chunks.push(c);
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

function parseFetchAsk(lines: readonly Pkt[]): FetchAsk {
  const ask: FetchAsk = { wants: [], haves: [], shallowIn: [], depth: null };
  for (const p of lines) {
    if (p.kind !== 'data') continue;
    const text = p.text.replace(/\n$/, '');
    if (text.startsWith('want ')) ask.wants.push(text.slice(5).split(' ')[0]!);
    else if (text.startsWith('have ')) ask.haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) ask.shallowIn.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) ask.depth = Number(text.slice(7).trim());
  }
  return ask;
}

function parseLsRefsAsk(lines: readonly Pkt[]): { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] } {
  const ask = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
  for (const p of lines) {
    if (p.kind !== 'data') continue;
    const text = p.text.replace(/\n$/, '');
    if (text === 'peel') ask.peel = true;
    else if (text === 'symrefs') ask.symrefs = true;
    else if (text === 'unborn') ask.unborn = true;
    else if (text.startsWith('ref-prefix ')) ask.prefixes.push(text.slice(11));
  }
  return ask;
}

interface PushCmd {
  oldOid: string;
  newOid: string;
  ref: string;
}

function doPush(repo: Repo, body: Buffer): Buffer {
  // The body is pkt-line commands, a flush, then the raw pack bytes. Only the
  // command section is pkt-line framed: the pack that follows is binary and
  // must never be parsed as pkt-lines.
  const commands: PushCmd[] = [];
  let at = 0;
  for (;;) {
    if (at + 4 > body.length) throw new Error('push body ends before the flush');
    const lenText = body.subarray(at, at + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(lenText)) throw new Error('bad pkt-line length in push');
    const len = parseInt(lenText, 16);
    if (len === 0) {
      at += 4;
      break;
    }
    if (len === 1) {
      at += 4;
      continue;
    }
    if (len < 4 || at + len > body.length) throw new Error('push command overruns its body');
    let text = body.subarray(at + 4, at + len).toString('utf8').replace(/\n$/, '');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const parts = text.split(' ');
    if (parts.length < 3) throw new Error('bad push command line');
    commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts.slice(2).join(' ') });
    at += len;
  }
  const packBytes = body.subarray(at);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = packDown(packBytes, (oid) => objOf(repo, oid));
      for (const obj of objects.values()) storeObj(repo, obj.type, obj.data);
    } catch (err) {
      unpackOk = false;
      unpackDetail = (err as Error).message;
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}`];
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO) {
        if (current === undefined || current !== cmd.oldOid) {
          reportLines.push(`ng ${cmd.ref} non-fast-forward`);
          continue;
        }
        repo.refs.delete(cmd.ref);
        repo.rev += 1;
        reportLines.push(`ok ${cmd.ref}`);
        continue;
      }
      const target = repo.objects.get(cmd.newOid);
      if (target === undefined || (target.type !== 'commit' && target.type !== 'tag')) {
        reportLines.push(`ng ${cmd.ref} missing object`);
        continue;
      }
      if (current === undefined) {
        if (cmd.oldOid !== ZERO) {
          reportLines.push(`ng ${cmd.ref} non-fast-forward`);
          continue;
        }
        repo.refs.set(cmd.ref, cmd.newOid);
        repo.rev += 1;
        reportLines.push(`ok ${cmd.ref}`);
        continue;
      }
      if (target.type === 'tag') {
        // Tag refs are immutable pointers, not a moving branch: accept the
        // new tag object when the old value matches.
        if (cmd.oldOid !== current) {
          reportLines.push(`ng ${cmd.ref} non-fast-forward`);
          continue;
        }
        repo.refs.set(cmd.ref, cmd.newOid);
        repo.rev += 1;
        reportLines.push(`ok ${cmd.ref}`);
        continue;
      }
      if (cmd.oldOid !== current || !isAncestor(repo, current, cmd.newOid)) {
        reportLines.push(`ng ${cmd.ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      repo.rev += 1;
      reportLines.push(`ok ${cmd.ref}`);
    }
  } else {
    for (const cmd of commands) reportLines.push(`ng ${cmd.ref} unpack failed`);
  }
  const inner = Buffer.concat([...reportLines.map((l) => pktLine(`${l}\n`)), PKT_FLUSH]);
  const banded = pktLine(Buffer.concat([Buffer.from([1]), inner]));
  return Buffer.concat([banded, PKT_FLUSH]);
}

// ---------------------------------------------------------------------------
// REST helpers
// ---------------------------------------------------------------------------

function notFound(what: string): { status: number; body: Record<string, unknown> } {
  return { status: 404, body: { message: `${what} not found` } };
}

function badRequest(message: string): { status: number; body: Record<string, unknown> } {
  return { status: 400, body: { message } };
}

function unprocessable(message: string): { status: number; body: Record<string, unknown> } {
  return { status: 422, body: { message } };
}

function needRepo(owner: string, name: string): Repo | { status: number; body: Record<string, unknown> } {
  const repo = forge.getRepo(owner, name);
  if (repo === undefined) return notFound(`Repository ${owner}/${name}`);
  return repo;
}

function treeAt(repo: Repo, ref: string | undefined): { tree: string; tip: string } | null {
  const tip = resolveTip(repo, ref);
  if (tip === null) return null;
  const tree = repo.trees.get(tip);
  if (tree === undefined) return null;
  return { tree, tip };
}

function lookupPath(repo: Repo, treeOid: string, segs: readonly string[]): { oid: string; mode: string } | null {
  let cur = treeOid;
  for (let i = 0; i < segs.length; i += 1) {
    const list = treeEntsOf(repo, cur);
    const hit = list.find((e) => e.name === segs[i]);
    if (hit === undefined) return null;
    if (i === segs.length - 1) return { oid: hit.oid, mode: hit.mode };
    if (hit.mode !== '40000') return null;
    cur = hit.oid;
  }
  return null;
}

function commitOnFile(repo: Repo, branch: string, segs: readonly string[], content: Buffer, message: string, expectSha: string | undefined): { commitSha: string; blobSha: string; status: number } | { status: number; body: Record<string, unknown> } {
  const tip = tipOf(repo, branch);
  const baseTree = tip === null ? null : repo.trees.get(tip) ?? null;
  const existing = baseTree === null ? null : lookupPath(repo, baseTree, segs);
  if (existing !== null && expectSha !== undefined && expectSha !== existing.oid) {
    return { status: 409, body: { message: 'sha does not match the current blob' } };
  }
  const blobSha = storeObj(repo, 'blob', content);
  const nextTree = treeWithPath(repo, baseTree, segs, blobSha);
  const commitSha = makeCommit(repo, nextTree, tip === null ? [] : [tip], message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  repo.rev += 1;
  return { commitSha, blobSha, status: existing === null ? 201 : 200 };
}

function squashMerge(repo: Repo, pull: PullRec): { ok: true; sha: string } | { ok: false; reason: string } {
  const headTip = tipOf(repo, pull.head);
  const baseTip = tipOf(repo, pull.base);
  if (headTip === null || baseTip === null) return { ok: false, reason: 'missing branch' };
  const base = mergeBaseOf(repo, headTip, baseTip);
  const baseTree = base === null ? null : repo.trees.get(base) ?? null;
  const oursTree = repo.trees.get(baseTip)!;
  const theirsTree = repo.trees.get(headTip)!;
  const baseFlat = baseTree === null ? new Map() : flatOf(repo, baseTree);
  const oursFlat = flatOf(repo, oursTree);
  const theirsFlat = flatOf(repo, theirsTree);
  const paths = new Set([...baseFlat.keys(), ...oursFlat.keys(), ...theirsFlat.keys()]);
  let merged = new Map(oursFlat);
  for (const path of paths) {
    const b = baseFlat.get(path);
    const o = oursFlat.get(path);
    const t = theirsFlat.get(path);
    const same = (x: { oid: string; mode: string } | undefined, y: { oid: string; mode: string } | undefined): boolean =>
      (x === undefined && y === undefined) || (x !== undefined && y !== undefined && x.oid === y.oid);
    if (same(t, b)) continue;
    if (same(o, b)) {
      if (t === undefined) merged.delete(path);
      else merged.set(path, t);
      continue;
    }
    if (same(o, t)) continue;
    return { ok: false, reason: 'merge conflict' };
  }
  // Rebuild the merged tree from the flat map.
  let rootTree: string | null = null;
  const byDir = new Map<string, { name: string; oid: string; mode: string }[]>();
  for (const [path, entry] of merged) {
    const slash = path.lastIndexOf('/');
    const dir = slash < 0 ? '' : path.slice(0, slash);
    const name = slash < 0 ? path : path.slice(slash + 1);
    const list = byDir.get(dir) ?? [];
    list.push({ name, oid: entry.oid, mode: entry.mode });
    byDir.set(dir, list);
  }
  const buildDir = (dir: string): string | null => {
    const direct = byDir.get(dir) ?? [];
    const entries: TreeEnt[] = direct.map((d) => ({ mode: d.mode, name: d.name, oid: d.oid }));
    const subdirs = new Set<string>();
    for (const [path] of merged) {
      if (dir === '') {
        const slash = path.indexOf('/');
        if (slash > 0) subdirs.add(path.slice(0, slash));
      } else if (path.startsWith(`${dir}/`)) {
        const rest = path.slice(dir.length + 1);
        const slash = rest.indexOf('/');
        if (slash > 0) subdirs.add(rest.slice(0, slash));
      }
    }
    for (const sub of subdirs) {
      const child = buildDir(dir === '' ? sub : `${dir}/${sub}`);
      if (child !== null) entries.push({ mode: '40000', name: sub, oid: child });
    }
    if (entries.length === 0) return null;
    return storeTree(repo, entries);
  };
  rootTree = buildDir('');
  if (rootTree === null) rootTree = storeObj(repo, 'tree', Buffer.alloc(0));
  const sha = makeCommit(repo, rootTree, [baseTip], `Merge pull request #${pull.number} from ${pull.head}`);
  repo.refs.set(`refs/heads/${pull.base}`, sha);
  repo.rev += 1;
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = NOW_ISO;
  pull.mergeSha = sha;
  return { ok: true, sha };
}

function diffFiles(repo: Repo, pull: PullRec): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const headTip = tipOf(repo, pull.head);
  const baseTip = tipOf(repo, pull.base);
  if (headTip === null || baseTip === null) return [];
  const baseFlat = flatOf(repo, repo.trees.get(baseTip)!);
  const headFlat = flatOf(repo, repo.trees.get(headTip)!);
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  for (const path of [...paths].sort()) {
    const b = baseFlat.get(path);
    const h = headFlat.get(path);
    if (b !== undefined && h !== undefined && b.oid === h.oid) continue;
    let status = 'modified';
    let additions = 0;
    let deletions = 0;
    if (b === undefined) {
      status = 'added';
      const data = repo.objects.get(h!.oid)?.data.toString('utf8') ?? '';
      additions = data === '' ? 0 : data.split('\n').length;
    } else if (h === undefined) {
      status = 'removed';
      const data = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      deletions = data === '' ? 0 : data.split('\n').length;
    } else {
      const oldText = repo.objects.get(b.oid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(h.oid)?.data.toString('utf8') ?? '';
      const oldLines = new Map<string, number>();
      for (const l of oldText.split('\n')) oldLines.set(l, (oldLines.get(l) ?? 0) + 1);
      for (const l of newText.split('\n')) {
        const left = oldLines.get(l) ?? 0;
        if (left > 0) oldLines.set(l, left - 1);
        else additions += 1;
      }
      for (const left of oldLines.values()) deletions += left;
    }
    out.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}

function mergeableOf(repo: Repo, pull: PullRec): string {
  const headTip = tipOf(repo, pull.head);
  const baseTip = tipOf(repo, pull.base);
  if (headTip === null || baseTip === null) return 'UNKNOWN';
  const base = mergeBaseOf(repo, headTip, baseTip);
  const baseTree = base === null ? null : repo.trees.get(base) ?? null;
  const baseFlat = baseTree === null ? new Map() : flatOf(repo, baseTree);
  const oursFlat = flatOf(repo, repo.trees.get(baseTip)!);
  const theirsFlat = flatOf(repo, repo.trees.get(headTip)!);
  const paths = new Set([...baseFlat.keys(), ...oursFlat.keys(), ...theirsFlat.keys()]);
  for (const path of paths) {
    const b = baseFlat.get(path);
    const o = oursFlat.get(path);
    const t = theirsFlat.get(path);
    const same = (x: { oid: string } | undefined, y: { oid: string } | undefined): boolean =>
      (x === undefined && y === undefined) || (x !== undefined && y !== undefined && x.oid === y.oid);
    if (same(t, b) || same(o, b) || same(o, t)) continue;
    return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

function walkCommits(repo: Repo, tip: string): { sha: string; commit: Record<string, unknown> }[] {
  const out: { sha: string; commit: Record<string, unknown> }[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const meta = parseCommit(obj.data);
    const ident = (line: string): { name: string; email: string; date: string } => {
      const m = /^(.*?) <([^>]*)> (\d+) \+0000$/.exec(line);
      if (m === null) return { name: line, email: '', date: NOW_ISO };
      return { name: m[1]!, email: m[2]!, date: new Date(Number(m[3]!) * 1000).toISOString() };
    };
    out.push({
      sha: oid,
      commit: {
        message: meta.message,
        author: ident(meta.author),
        committer: ident(meta.committer),
      },
      parents: meta.parents.map((p) => ({ sha: p })),
    });
    for (const p of meta.parents) stack.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

interface Ctx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  method: string;
  path: string;
  query: Map<string, string>;
  segs: string[];
}

let reqSeq = 0;

function sendJson(ctx: Ctx, status: number, body: unknown, extra?: Record<string, string>): void {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  ctx.res.writeHead(status, {
    'content-type': 'application/json',
    'x-github-request-id': `r${(++reqSeq).toString(36)}`,
    ...extra,
  });
  ctx.res.end(text);
}

function sendBuf(ctx: Ctx, status: number, buf: Buffer, contentType: string, extra?: Record<string, string>): void {
  ctx.res.writeHead(status, {
    'content-type': contentType,
    'x-github-request-id': `r${(++reqSeq).toString(36)}`,
    'content-length': String(buf.length),
    ...extra,
  });
  ctx.res.end(buf);
}

function sendEmpty(ctx: Ctx, status: number): void {
  ctx.res.writeHead(status, { 'x-github-request-id': `r${(++reqSeq).toString(36)}` });
  ctx.res.end();
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks);
}

function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return {};
  try {
    return JSON.parse(buf.toString('utf8')) as unknown;
  } catch {
    throw Object.assign(new Error('malformed JSON body'), { status: 400 });
  }
}

function asRecord(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function asStr(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

function asBool(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback;
}

function parseQuery(raw: string): Map<string, string> {
  const out = new Map<string, string>();
  if (raw === '') return out;
  for (const part of raw.split('&')) {
    const eq = part.indexOf('=');
    if (eq < 0) out.set(decodeURIComponent(part), '');
    else out.set(decodeURIComponent(part.slice(0, eq)), decodeURIComponent(part.slice(eq + 1)));
  }
  return out;
}

function pageOf(query: Map<string, string>): { perPage: number; page: number } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const pageRaw = Number(query.get('page') ?? '1');
  return {
    perPage: Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30,
    page: Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1,
  };
}

function pageLink(ctx: Ctx, perPage: number, page: number, total: number): Record<string, string> {
  if (page * perPage >= total) return {};
  const host = ctx.req.headers.host ?? '127.0.0.1';
  const base = `http://${host}${ctx.path}`;
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  return {
    link: `<${base}?per_page=${perPage}&page=${page + 1}>; rel="next", <${base}?per_page=${perPage}&page=${lastPage}>; rel="last"`,
  };
}

function paginate<T>(items: readonly T[], perPage: number, page: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

// ---------------------------------------------------------------------------
// REST
// ---------------------------------------------------------------------------

async function rest(ctx: Ctx): Promise<void> {
  const s = ctx.segs;
  // GET /api/v3/
  if (s.length === 0) {
    if (ctx.method !== 'GET') return sendJson(ctx, 404, { message: 'Not Found' });
    return sendJson(ctx, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, user' });
  }
  if (s[0] === 'meta' && s.length === 1) {
    if (ctx.method !== 'GET') return sendJson(ctx, 404, { message: 'Not Found' });
    return sendJson(ctx, 200, { installed_version: '1.0.0' });
  }
  if (s[0] === 'user' && s.length === 1) {
    if (ctx.method !== 'GET') return sendJson(ctx, 404, { message: 'Not Found' });
    return sendJson(ctx, 200, { login: VIEWER, id: VIEWER_ID, type: 'User' });
  }
  if (s[0] === 'user' && s[1] === 'repos' && s.length === 2) {
    if (ctx.method === 'GET') {
      const { perPage, page } = pageOf(ctx.query);
      const all = forge.ownedBy(VIEWER);
      const slice = paginate(all, perPage, page);
      return sendJson(ctx, 200, slice.map(repoJson), pageLink(ctx, perPage, page, all.length));
    }
    if (ctx.method === 'POST') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      const name = asStr(body.name);
      if (name === '') return sendJson(ctx, 422, { message: 'name is required' });
      if (forge.getRepo(VIEWER, name) !== undefined) return sendJson(ctx, 422, { message: 'Repository already exists' });
      const repo = forge.newRepo(VIEWER, name, asBool(body.private, false), asStr(body.description));
      return sendJson(ctx, 201, repoJson(repo));
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }
  if (s[0] !== 'repos' || s.length < 3) return sendJson(ctx, 404, { message: 'Not Found' });
  const owner = decodeURIComponent(s[1]!);
  const repoName = decodeURIComponent(s[2]!);
  const repoOr = needRepo(owner, repoName);
  if ('status' in repoOr) return sendJson(ctx, repoOr.status, repoOr.body);
  const repo = repoOr;
  const rest = s.slice(3);

  if (rest.length === 0) {
    if (ctx.method === 'GET') return sendJson(ctx, 200, repoJson(repo));
    if (ctx.method === 'PATCH') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      if (typeof body.description === 'string') repo.description = body.description;
      return sendJson(ctx, 200, repoJson(repo));
    }
    if (ctx.method === 'DELETE') {
      forge.dropRepo(owner, repoName);
      return sendEmpty(ctx, 204);
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'branches') {
    if (rest.length === 1 && ctx.method === 'GET') {
      const list = [...repo.refs.keys()]
        .filter((r) => r.startsWith('refs/heads/'))
        .sort()
        .map((r) => ({ name: r.slice('refs/heads/'.length), commit: { sha: repo.refs.get(r)! } }));
      return sendJson(ctx, 200, list);
    }
    if (rest.length >= 2 && ctx.method === 'GET') {
      const branch = rest.slice(1).map(decodeURIComponent).join('/');
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) return sendJson(ctx, 404, { message: 'Branch not found' });
      return sendJson(ctx, 200, { name: branch, commit: { sha: tip } });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'commits' && rest.length === 1 && ctx.method === 'GET') {
    const sha = ctx.query.get('sha');
    const tip = sha === undefined ? tipOf(repo, BRANCH_MAIN) : resolveTip(repo, sha);
    if (tip === null) return sendJson(ctx, 404, { message: 'No commits yet' });
    return sendJson(ctx, 200, walkCommits(repo, tip));
  }

  if (rest[0] === 'contents') {
    const segs = rest.slice(1).map(decodeURIComponent);
    if (segs.length === 0) return sendJson(ctx, 404, { message: 'Not Found' });
    if (ctx.method === 'GET') {
      const found = treeAt(repo, ctx.query.get('ref'));
      if (found === null) return sendJson(ctx, 404, { message: 'No commits yet' });
      const hit = lookupPath(repo, found.tree, segs);
      if (hit === null) return sendJson(ctx, 404, { message: 'Not found' });
      if (hit.mode === '40000') {
        const list = treeEntsOf(repo, hit.oid).map((e) => ({
          type: e.mode === '40000' ? 'dir' : 'file',
          name: e.name,
          path: [...segs, e.name].join('/'),
          sha: e.oid,
        }));
        return sendJson(ctx, 200, list);
      }
      const obj = repo.objects.get(hit.oid)!;
      return sendJson(ctx, 200, {
        type: 'file',
        encoding: 'base64',
        content: b64encode(obj.data),
        sha: hit.oid,
        size: obj.data.length,
        name: segs[segs.length - 1],
        path: segs.join('/'),
      });
    }
    if (ctx.method === 'PUT') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      const message = asStr(body.message, 'update');
      const branch = asStr(body.branch, BRANCH_MAIN);
      const content = typeof body.content === 'string' ? b64decode(body.content) : Buffer.alloc(0);
      const expectSha = typeof body.sha === 'string' ? body.sha : undefined;
      if (tipOf(repo, branch) === null && branch !== BRANCH_MAIN && tipOf(repo, BRANCH_MAIN) === null) {
        return sendJson(ctx, 404, { message: 'Branch not found' });
      }
      if (tipOf(repo, branch) === null && tipOf(repo, BRANCH_MAIN) !== null) {
        // A contents write names a branch that does not exist yet: fork it from main.
        repo.refs.set(`refs/heads/${branch}`, tipOf(repo, BRANCH_MAIN)!);
        repo.rev += 1;
      }
      const done = commitOnFile(repo, branch, segs, content, message, expectSha);
      if ('body' in done) return sendJson(ctx, done.status, done.body);
      return sendJson(ctx, done.status, {
        content: { name: segs[segs.length - 1], path: segs.join('/'), sha: done.blobSha, size: content.length, type: 'file', encoding: 'base64' },
        commit: { sha: done.commitSha, message },
      });
    }
    if (ctx.method === 'DELETE') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      const message = asStr(body.message, 'delete');
      const branch = asStr(body.branch, BRANCH_MAIN);
      const tip = tipOf(repo, branch);
      if (tip === null) return sendJson(ctx, 404, { message: 'No commits yet' });
      const baseTree = repo.trees.get(tip)!;
      const existing = lookupPath(repo, baseTree, segs);
      if (existing === null) return sendJson(ctx, 404, { message: 'Not found' });
      if (typeof body.sha === 'string' && body.sha !== existing.oid) return sendJson(ctx, 409, { message: 'sha does not match' });
      const nextTree = treeWithPath(repo, baseTree, segs, null);
      const commitSha = makeCommit(repo, nextTree, [tip], message);
      repo.refs.set(`refs/heads/${branch}`, commitSha);
      repo.rev += 1;
      return sendJson(ctx, 200, { commit: { sha: commitSha, message } });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'labels') {
    if (ctx.method === 'GET') {
      return sendJson(ctx, 200, [...repo.labels.entries()].map(([name, color]) => ({ name, color })));
    }
    if (ctx.method === 'POST') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      const name = asStr(body.name);
      if (name === '') return sendJson(ctx, 422, { message: 'name is required' });
      const color = asStr(body.color, 'ededed');
      repo.labels.set(name, color);
      return sendJson(ctx, 201, { name, color });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (ctx.method === 'GET') {
        const state = ctx.query.get('state') ?? 'open';
        const direction = ctx.query.get('direction') ?? 'desc';
        const { perPage, page } = pageOf(ctx.query);
        let list = repo.issues;
        if (state !== 'all') list = list.filter((i) => i.state === state);
        const sorted = [...list].sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        const slice = paginate(sorted, perPage, page);
        return sendJson(ctx, 200, slice.map((i) => JSON.parse(issueJsonText(i)) as unknown));
      }
      if (ctx.method === 'POST') {
        const body = asRecord(parseJsonBody(await readBody(ctx.req)));
        const title = asStr(body.title);
        const labels = Array.isArray(body.labels) ? (body.labels as unknown[]).filter((l): l is string => typeof l === 'string') : [];
        for (const label of labels) {
          if (!repo.labels.has(label)) return sendJson(ctx, 422, { message: `Label '${label}' does not exist` });
        }
        const number = repo.nextNum++;
        const issue: IssueRec = {
          id: forge.nextEntId++,
          number,
          title,
          body: asStr(body.body),
          state: 'open',
          labels,
          comments: [],
          cache: null,
        };
        repo.issues.push(issue);
        const buf = issueJsonBuf(issue);
        return sendBuf(ctx, 201, buf, 'application/json');
      }
      return sendJson(ctx, 404, { message: 'Not Found' });
    }
    const num = Number(rest[1]);
    if (!Number.isInteger(num) || num < 1) return sendJson(ctx, 404, { message: 'Not Found' });
    const issue = repo.issues.find((i) => i.number === num);
    if (rest.length === 2) {
      if (issue === undefined) return sendJson(ctx, 404, { message: 'Issue not found' });
      if (ctx.method === 'GET') return sendBuf(ctx, 200, issueJsonBuf(issue), 'application/json');
      if (ctx.method === 'PATCH') {
        const body = asRecord(parseJsonBody(await readBody(ctx.req)));
        if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        issue.cache = null;
        return sendJson(ctx, 200, JSON.parse(issueJsonText(issue)) as unknown);
      }
      return sendJson(ctx, 404, { message: 'Not Found' });
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (issue === undefined) return sendJson(ctx, 404, { message: 'Issue not found' });
      if (ctx.method === 'GET') return sendJson(ctx, 200, issue.comments.map((c) => ({ id: c.id, body: c.body })));
      if (ctx.method === 'POST') {
        const body = asRecord(parseJsonBody(await readBody(ctx.req)));
        const comment = { id: repo.nextComment++, body: asStr(body.body) };
        issue.comments.push(comment);
        return sendJson(ctx, 201, { id: comment.id, body: comment.body });
      }
      return sendJson(ctx, 404, { message: 'Not Found' });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (ctx.method === 'GET') {
        const state = ctx.query.get('state') ?? 'open';
        const { perPage, page } = pageOf(ctx.query);
        let list = repo.pulls;
        if (state !== 'all') list = list.filter((p) => p.state === state);
        const slice = paginate(list, perPage, page);
        return sendJson(ctx, 200, slice.map((p) => pullJson(p, repo)));
      }
      if (ctx.method === 'POST') {
        const body = asRecord(parseJsonBody(await readBody(ctx.req)));
        const head = asStr(body.head);
        const base = asStr(body.base);
        const title = asStr(body.title);
        if (tipOf(repo, head) === null || tipOf(repo, base) === null) {
          return sendJson(ctx, 422, { message: 'head or base branch does not exist' });
        }
        const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
        if (dup !== undefined) return sendJson(ctx, 422, { message: 'A pull request already exists for this head and base' });
        const pull: PullRec = {
          id: forge.nextEntId++,
          number: repo.nextNum++,
          title,
          body: asStr(body.body),
          head,
          base,
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeSha: null,
        };
        repo.pulls.push(pull);
        return sendJson(ctx, 201, pullJson(pull, repo));
      }
      return sendJson(ctx, 404, { message: 'Not Found' });
    }
    const num = Number(rest[1]);
    if (!Number.isInteger(num) || num < 1) return sendJson(ctx, 404, { message: 'Not Found' });
    const pull = repo.pulls.find((p) => p.number === num);
    if (pull === undefined) return sendJson(ctx, 404, { message: 'Pull request not found' });
    if (rest.length === 2 && ctx.method === 'GET') return sendJson(ctx, 200, pullJson(pull, repo));
    if (rest.length === 3 && rest[2] === 'files' && ctx.method === 'GET') {
      return sendJson(ctx, 200, diffFiles(repo, pull));
    }
    if (rest.length === 3 && rest[2] === 'merge' && ctx.method === 'PUT') {
      if (pull.merged) return sendJson(ctx, 405, { message: 'Pull request is already merged' });
      if (pull.state === 'closed') return sendJson(ctx, 405, { message: 'Pull request is closed' });
      const done = squashMerge(repo, pull);
      if (!done.ok) return sendJson(ctx, 405, { message: done.reason });
      return sendJson(ctx, 200, { sha: done.sha, merged: true, message: `Merge pull request #${pull.number}` });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (rest.length === 2 && ctx.method === 'POST') {
      const body = asRecord(parseJsonBody(await readBody(ctx.req)));
      const ref = asStr(body.ref);
      const sha = asStr(body.sha);
      if (!ref.startsWith('refs/heads/')) return sendJson(ctx, 422, { message: 'only branch refs are supported' });
      if (!/^[0-9a-f]{40}$/.test(sha)) return sendJson(ctx, 422, { message: 'sha is not a commit id' });
      const target = repo.objects.get(sha);
      if (target === undefined || target.type !== 'commit') return sendJson(ctx, 422, { message: 'sha is not a commit' });
      if (repo.refs.has(ref)) return sendJson(ctx, 422, { message: 'Reference already exists' });
      repo.refs.set(ref, sha);
      repo.rev += 1;
      return sendJson(ctx, 201, { ref, object: { sha } });
    }
    if (rest.length >= 4 && rest[2] === 'heads' && ctx.method === 'GET') {
      const branch = rest.slice(3).map(decodeURIComponent).join('/');
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) return sendJson(ctx, 404, { message: 'Reference not found' });
      return sendJson(ctx, 200, { ref: `refs/heads/${branch}`, object: { sha: tip } });
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  }

  return sendJson(ctx, 404, { message: 'Not Found' });
}

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------

type GqlVal =
  | { k: 'var'; name: string }
  | { k: 'str'; v: string }
  | { k: 'int'; v: number }
  | { k: 'bool'; v: boolean }
  | { k: 'null' }
  | { k: 'enum'; v: string }
  | { k: 'list'; items: GqlVal[] }
  | { k: 'obj'; fields: Record<string, GqlVal> };

interface GqlSel {
  field: string;
  alias: string;
  args: Record<string, GqlVal>;
  sel: GqlSel[];
  frag: string | null;
}

interface GqlOp {
  kind: string;
  name: string;
  vars: Record<string, GqlVal>;
  sel: GqlSel[];
}

function gqlTokens(src: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      out.push('...');
      i += 3;
      continue;
    }
    if ('{}():[]!=$'.includes(c)) {
      out.push(c);
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let text = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1]!;
          text += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          text += src[j]!;
          j += 1;
        }
      }
      out.push(JSON.stringify(text));
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_-]/.test(src[j]!)) j += 1;
    if (j === i) throw new Error(`unexpected character ${JSON.stringify(c)} in query`);
    out.push(src.slice(i, j));
    i = j;
  }
  return out;
}

function gqlParse(src: string): GqlOp {
  const toks = gqlTokens(src);
  let at = 0;
  const peek = (): string => toks[at] ?? '';
  const next = (): string => toks[at++] ?? '';
  const parseValue = (): GqlVal => {
    const t = next();
    if (t === '$') return { k: 'var', name: next() };
    if (t === '[') {
      const items: GqlVal[] = [];
      while (peek() !== ']') items.push(parseValue());
      next();
      return { k: 'list', items };
    }
    if (t === '{') {
      const fields: Record<string, GqlVal> = {};
      while (peek() !== '}') {
        const name = next();
        if (next() !== ':') throw new Error('expected : in input object');
        fields[name] = parseValue();
      }
      next();
      return { k: 'obj', fields };
    }
    if (t.startsWith('"')) return { k: 'str', v: JSON.parse(t) as string };
    if (t === 'true') return { k: 'bool', v: true };
    if (t === 'false') return { k: 'bool', v: false };
    if (t === 'null') return { k: 'null' };
    if (/^-?\d+$/.test(t)) return { k: 'int', v: Number(t) };
    return { k: 'enum', v: t };
  };
  const parseSels = (): GqlSel[] => {
    if (next() !== '{') throw new Error('expected { for selections');
    const out: GqlSel[] = [];
    while (peek() !== '}') {
      if (peek() === '...') {
        next();
        let frag: string | null = null;
        if (peek() === 'on') {
          next();
          frag = next();
        }
        out.push({ field: '', alias: '', args: {}, sel: parseSels(), frag });
        continue;
      }
      let name = next();
      let alias = name;
      if (peek() === ':') {
        next();
        alias = name;
        name = next();
      }
      const args: Record<string, GqlVal> = {};
      if (peek() === '(') {
        next();
        while (peek() !== ')') {
          const argName = next();
          if (next() !== ':') throw new Error('expected : in arguments');
          args[argName] = parseValue();
        }
        next();
      }
      const sel = peek() === '{' ? parseSels() : [];
      out.push({ field: name, alias, args, sel, frag: null });
    }
    next();
    return out;
  };
  const kind = next();
  if (kind !== 'query' && kind !== 'mutation') throw new Error('operation must be query or mutation');
  let name = '';
  if (peek() !== '(' && peek() !== '{') name = next();
  const vars: Record<string, GqlVal> = {};
  if (peek() === '(') {
    next();
    while (peek() !== ')') {
      if (next() !== '$') throw new Error('expected $ in variable definitions');
      const vname = next();
      if (next() !== ':') throw new Error('expected : in variable definitions');
      let type = next();
      if (peek() === '!') {
        next();
        type += '!';
      }
      void type;
      if (peek() === '=') {
        next();
        vars[vname] = parseValue();
      }
      if (peek() === ',') next();
    }
    next();
  }
  return { kind, name, vars, sel: parseSels() };
}

function gqlResolveVal(v: GqlVal, vars: Record<string, unknown>): unknown {
  switch (v.k) {
    case 'var':
      return vars[v.name];
    case 'str':
    case 'int':
    case 'bool':
    case 'enum':
      return v.v;
    case 'null':
      return null;
    case 'list':
      return v.items.map((i) => gqlResolveVal(i, vars));
    case 'obj': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v.fields)) out[k] = gqlResolveVal(val, vars);
      return out;
    }
  }
}

function gqlArg(sel: GqlSel, name: string, vars: Record<string, unknown>): unknown {
  const v = sel.args[name];
  return v === undefined ? undefined : gqlResolveVal(v, vars);
}

const ISSUE_TYPE_FIELDS = ['id', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments'];
const PR_TYPE_FIELDS = ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'url', 'createdAt', 'updatedAt'];
const REPO_TYPE_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'createdAt', 'updatedAt'];

function gqlIssueState(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function gqlIssueOut(repo: Repo, issue: IssueRec, sel: GqlSel[], vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of sel) {
    if (s.frag !== null) continue;
    switch (s.field) {
      case 'id':
        out[s.alias] = globalId('I', repo.owner, repo.name, issue.number);
        break;
      case 'number':
        out[s.alias] = issue.number;
        break;
      case 'title':
        out[s.alias] = issue.title;
        break;
      case 'body':
        out[s.alias] = issue.body;
        break;
      case 'state':
        out[s.alias] = gqlIssueState(issue.state);
        break;
      default:
        throw new Error(`Cannot query field "${s.field}" on type "Issue".`);
    }
  }
  void vars;
  return out;
}

function gqlPrOut(repo: Repo, pull: PullRec, sel: GqlSel[], vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const state = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
  for (const s of sel) {
    if (s.frag !== null) continue;
    switch (s.field) {
      case 'id':
        out[s.alias] = globalId('P', repo.owner, repo.name, pull.number);
        break;
      case 'number':
        out[s.alias] = pull.number;
        break;
      case 'title':
        out[s.alias] = pull.title;
        break;
      case 'body':
        out[s.alias] = pull.body;
        break;
      case 'state':
        out[s.alias] = state;
        break;
      case 'merged':
        out[s.alias] = pull.merged;
        break;
      case 'mergeable':
        out[s.alias] = mergeableOf(repo, pull);
        break;
      case 'headRefName':
        out[s.alias] = pull.head;
        break;
      case 'baseRefName':
        out[s.alias] = pull.base;
        break;
      case 'files': {
        const first = gqlArg(s, 'first', vars);
        const all = diffFiles(repo, pull);
        const page = typeof first === 'number' ? all.slice(0, first) : all;
        out[s.alias] = gqlConn(s.sel, page, (f, sub) => {
          const o: Record<string, unknown> = {};
          for (const leaf of sub) {
            if (leaf.field === 'path') o[leaf.alias] = f.filename;
            else if (leaf.field === 'status') o[leaf.alias] = f.status;
            else if (leaf.field === 'additions') o[leaf.alias] = f.additions;
            else if (leaf.field === 'deletions') o[leaf.alias] = f.deletions;
            else if (leaf.field === 'changes') o[leaf.alias] = f.changes;
          }
          return o;
        });
        break;
      }
      default:
        throw new Error(`Cannot query field "${s.field}" on type "PullRequest".`);
    }
  }
  return out;
}

// A GraphQL connection: the query asks for `nodes { ... }` (and optionally
// `pageInfo { hasNextPage, endCursor }`) under the connection field, so the
// node selections belong to the nodes, not to the connection itself.
function gqlConn<T>(
  sel: GqlSel[],
  items: readonly T[],
  render: (item: T, sub: GqlSel[]) => Record<string, unknown>,
  pageInfo?: { hasNextPage: boolean; endCursor: string | null },
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sub of sel) {
    if (sub.field === 'nodes') out[sub.alias] = items.map((i) => render(i, sub.sel));
    else if (sub.field === 'edges') out[sub.alias] = items.map((i) => ({ node: render(i, sub.sel) }));
    else if (sub.field === 'pageInfo' && pageInfo !== undefined) {
      const info: Record<string, unknown> = {};
      for (const leaf of sub.sel) {
        if (leaf.field === 'hasNextPage') info[leaf.alias] = pageInfo.hasNextPage;
        else if (leaf.field === 'endCursor') info[leaf.alias] = pageInfo.endCursor;
      }
      out[sub.alias] = info;
    } else if (sub.field === 'totalCount') out[sub.alias] = items.length;
  }
  return out;
}

function gqlRepoOut(repo: Repo, sel: GqlSel[], vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of sel) {
    if (s.frag !== null) continue;
    switch (s.field) {
      case 'id':
        out[s.alias] = globalId('R', repo.owner, repo.name);
        break;
      case 'databaseId':
        out[s.alias] = repo.id;
        break;
      case 'name':
        out[s.alias] = repo.name;
        break;
      case 'nameWithOwner':
        out[s.alias] = `${repo.owner}/${repo.name}`;
        break;
      case 'owner':
        out[s.alias] = { login: repo.owner };
        break;
      case 'defaultBranchRef': {
        const tip = tipOf(repo, BRANCH_MAIN);
        out[s.alias] = tip === null ? null : { name: BRANCH_MAIN };
        break;
      }
      case 'viewerPermission':
        out[s.alias] = 'ADMIN';
        break;
      case 'hasIssuesEnabled':
        out[s.alias] = true;
        break;
      case 'issue': {
        const num = gqlArg(s, 'number', vars);
        const found = typeof num === 'number' ? repo.issues.find((i) => i.number === num) : undefined;
        out[s.alias] = found === undefined ? null : gqlIssueOut(repo, found, s.sel, vars);
        break;
      }
      case 'issues': {
        const first = gqlArg(s, 'first', vars);
        const states = gqlArg(s, 'states', vars) as string[] | undefined;
        const orderBy = gqlArg(s, 'orderBy', vars) as Record<string, string> | undefined;
        const after = gqlArg(s, 'after', vars) as string | null | undefined;
        let list = [...repo.issues];
        if (Array.isArray(states) && states.length > 0) {
          list = list.filter((i) => states.includes(gqlIssueState(i.state)));
        }
        const dir = orderBy?.direction === 'ASC' ? 1 : -1;
        list.sort((a, b) => (a.number - b.number) * dir);
        let start = 0;
        if (typeof after === 'string' && after !== '') {
          const decoded = b64urlDecode(after);
          const m = /^c(\d+)$/.exec(decoded);
          if (m !== null) start = Number(m[1]!) + 1;
        }
        const page = list.slice(start, typeof first === 'number' ? start + first : undefined);
        const endIdx = start + page.length - 1;
        out[s.alias] = gqlConn(s.sel, page, (i, sub) => gqlIssueOut(repo, i, sub, vars), {
          hasNextPage: typeof first === 'number' ? start + page.length < list.length : false,
          endCursor: page.length > 0 ? b64urlEncode(`c${endIdx}`) : null,
        });
        break;
      }
      case 'pullRequests': {
        const first = gqlArg(s, 'first', vars);
        const list = repo.pulls.filter((p) => p.state === 'open');
        const page = typeof first === 'number' ? list.slice(0, first) : list;
        out[s.alias] = gqlConn(s.sel, page, (p, sub) => gqlPrOut(repo, p, sub, vars));
        break;
      }
      case 'pullRequest': {
        const num = gqlArg(s, 'number', vars);
        const found = typeof num === 'number' ? repo.pulls.find((p) => p.number === num) : undefined;
        out[s.alias] = found === undefined ? null : gqlPrOut(repo, found, s.sel, vars);
        break;
      }
      default:
        throw new Error(`Cannot query field "${s.field}" on type "Repository".`);
    }
  }
  return out;
}

function gqlTypeOut(name: string): Record<string, unknown> {
  const fieldsFor: Record<string, string[]> = {
    Issue: ISSUE_TYPE_FIELDS,
    PullRequest: PR_TYPE_FIELDS,
    Repository: REPO_TYPE_FIELDS,
    User: ['id', 'login', 'name', 'email'],
  };
  const enumsFor: Record<string, string[]> = {
    SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'COMMIT', 'DISCUSSION', 'MILESTONE'],
    IssueState: ['OPEN', 'CLOSED'],
    PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
    MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
    PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
    RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
    IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
    OrderDirection: ['ASC', 'DESC'],
  };
  return {
    name,
    fields: (fieldsFor[name] ?? []).map((f) => ({ name: f })),
    enumValues: (enumsFor[name] ?? []).map((f) => ({ name: f })),
  };
}

function gqlRunOne(op: GqlOp, vars: Record<string, unknown>): { data: unknown; errors: { message: string }[] } {
  try {
    if (op.kind === 'mutation') return { data: gqlMutate(op, vars), errors: [] };
    const data: Record<string, unknown> = {};
    for (const s of op.sel) {
      if (s.frag !== null) continue;
      if (s.field === 'viewer') {
        const out: Record<string, unknown> = {};
        for (const sub of s.sel) {
          if (sub.field === 'login') out[sub.alias] = VIEWER;
          else throw new Error(`Cannot query field "${sub.field}" on type "User".`);
        }
        data[s.alias] = out;
        continue;
      }
      if (s.field === 'repository') {
        const owner = gqlArg(s, 'owner', vars);
        const name = gqlArg(s, 'name', vars);
        const repo = typeof owner === 'string' && typeof name === 'string' ? forge.getRepo(owner, name) : undefined;
        data[s.alias] = repo === undefined ? null : gqlRepoOut(repo, s.sel, vars);
        continue;
      }
      if (s.field === 'node') {
        const id = gqlArg(s, 'id', vars);
        const parsed = typeof id === 'string' ? parseGlobalId(id) : null;
        if (parsed === null) {
          data[s.alias] = null;
          continue;
        }
        const repo = forge.getRepo(parsed.owner, parsed.name);
        if (repo === undefined) {
          data[s.alias] = null;
          continue;
        }
        if (parsed.kind === 'R') {
          const out: Record<string, unknown> = {};
          for (const sub of s.sel) {
            if (sub.frag !== null) {
              if (sub.frag === 'Repository') {
                for (const inner of sub.sel) {
                  if (inner.field === 'name') out[inner.alias] = repo.name;
                  else if (inner.field === 'nameWithOwner') out[inner.alias] = `${repo.owner}/${repo.name}`;
                  else throw new Error(`Cannot query field "${inner.field}" on type "Repository".`);
                }
              }
              continue;
            }
            if (sub.field === 'id') out[sub.alias] = id;
            else if (sub.field === 'name') out[sub.alias] = repo.name;
            else if (sub.field === 'nameWithOwner') out[sub.alias] = `${repo.owner}/${repo.name}`;
            else throw new Error(`Cannot query field "${sub.field}" on type "Repository".`);
          }
          data[s.alias] = out;
          continue;
        }
        if (parsed.kind === 'I') {
          const issue = repo.issues.find((i) => i.number === parsed.num);
          data[s.alias] = issue === undefined ? null : gqlIssueOut(repo, issue, s.sel, vars);
          continue;
        }
        if (parsed.kind === 'P') {
          const pull = repo.pulls.find((p) => p.number === parsed.num);
          data[s.alias] = pull === undefined ? null : gqlPrOut(repo, pull, s.sel, vars);
          continue;
        }
        data[s.alias] = null;
        continue;
      }
      if (s.field === '__type') {
        const name = gqlArg(s, 'name', vars);
        data[s.alias] = typeof name === 'string' ? gqlTypeOut(name) : null;
        continue;
      }
      throw new Error(`Cannot query field "${s.field}" on type "Query".`);
    }
    return { data, errors: [] };
  } catch (err) {
    return { data: null, errors: [{ message: (err as Error).message }] };
  }
}

function gqlMutate(op: GqlOp, vars: Record<string, unknown>): Record<string, unknown> {
  const data: Record<string, unknown> = {};
  for (const s of op.sel) {
    if (s.frag !== null) continue;
    const input = gqlArg(s, 'input', vars) as Record<string, unknown> | undefined;
    if (input === undefined) throw new Error('mutation input is required');
    if (s.field === 'createIssue') {
      const repoId = String(input.repositoryId ?? '');
      const parsed = parseGlobalId(repoId);
      const repo = parsed !== null ? forge.getRepo(parsed.owner, parsed.name) : undefined;
      if (repo === undefined) throw new Error('repository not found');
      const number = repo.nextNum++;
      const issue: IssueRec = {
        id: forge.nextEntId++,
        number,
        title: String(input.title ?? ''),
        body: String(input.body ?? ''),
        state: 'open',
        labels: [],
        comments: [],
        cache: null,
      };
      repo.issues.push(issue);
      const out: Record<string, unknown> = {};
      for (const sub of s.sel) {
        if (sub.field === 'issue') {
          const issueOut: Record<string, unknown> = {};
          for (const inner of sub.sel) {
            if (inner.field === 'number') issueOut[inner.alias] = number;
            else if (inner.field === 'id') issueOut[inner.alias] = globalId('I', repo.owner, repo.name, number);
            else throw new Error(`Cannot query field "${inner.field}" on type "Issue".`);
          }
          out[sub.alias] = issueOut;
        }
      }
      data[s.alias] = out;
      continue;
    }
    if (s.field === 'closeIssue') {
      const parsed = parseGlobalId(String(input.issueId ?? ''));
      const repo = parsed !== null ? forge.getRepo(parsed.owner, parsed.name) : undefined;
      const issue = repo?.issues.find((i) => i.number === parsed?.num);
      if (issue === undefined) throw new Error('issue not found');
      issue.state = 'closed';
      issue.cache = null;
      const out: Record<string, unknown> = {};
      for (const sub of s.sel) {
        if (sub.field === 'issue') {
          const issueOut: Record<string, unknown> = {};
          for (const inner of sub.sel) {
            if (inner.field === 'number') issueOut[inner.alias] = issue.number;
            else if (inner.field === 'id') issueOut[inner.alias] = globalId('I', repo.owner, repo.name, issue.number);
            else if (inner.field === 'state') issueOut[inner.alias] = 'CLOSED';
            else throw new Error(`Cannot query field "${inner.field}" on type "Issue".`);
          }
          out[sub.alias] = issueOut;
        }
      }
      data[s.alias] = out;
      continue;
    }
    if (s.field === 'createPullRequest') {
      const parsed = parseGlobalId(String(input.repositoryId ?? ''));
      const repo = parsed !== null ? forge.getRepo(parsed.owner, parsed.name) : undefined;
      if (repo === undefined) throw new Error('repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      if (tipOf(repo, head) === null || tipOf(repo, base) === null) throw new Error('head or base branch does not exist');
      const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
      if (dup !== undefined) throw new Error('A pull request already exists for this head and base');
      const pull: PullRec = {
        id: forge.nextEntId++,
        number: repo.nextNum++,
        title: String(input.title ?? ''),
        body: '',
        head,
        base,
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeSha: null,
      };
      repo.pulls.push(pull);
      const out: Record<string, unknown> = {};
      for (const sub of s.sel) {
        if (sub.field === 'pullRequest') {
          const prOut: Record<string, unknown> = {};
          for (const inner of sub.sel) {
            if (inner.field === 'number') prOut[inner.alias] = pull.number;
            else if (inner.field === 'id') prOut[inner.alias] = globalId('P', repo.owner, repo.name, pull.number);
            else if (inner.field === 'state') prOut[inner.alias] = 'OPEN';
            else if (inner.field === 'headRefName') prOut[inner.alias] = head;
            else if (inner.field === 'baseRefName') prOut[inner.alias] = base;
            else throw new Error(`Cannot query field "${inner.field}" on type "PullRequest".`);
          }
          out[sub.alias] = prOut;
        }
      }
      data[s.alias] = out;
      continue;
    }
    if (s.field === 'mergePullRequest') {
      const parsed = parseGlobalId(String(input.pullRequestId ?? ''));
      const repo = parsed !== null ? forge.getRepo(parsed.owner, parsed.name) : undefined;
      const pull = repo?.pulls.find((p) => p.number === parsed?.num);
      if (pull === undefined) throw new Error('pull request not found');
      if (pull.merged) throw new Error('pull request is already merged');
      const done = squashMerge(repo, pull);
      if (!done.ok) throw new Error(done.reason);
      const out: Record<string, unknown> = {};
      for (const sub of s.sel) {
        if (sub.field === 'pullRequest') {
          const prOut: Record<string, unknown> = {};
          for (const inner of sub.sel) {
            if (inner.field === 'number') prOut[inner.alias] = pull.number;
            else if (inner.field === 'merged') prOut[inner.alias] = true;
            else if (inner.field === 'state') prOut[inner.alias] = 'MERGED';
            else throw new Error(`Cannot query field "${inner.field}" on type "PullRequest".`);
          }
          out[sub.alias] = prOut;
        }
      }
      data[s.alias] = out;
      continue;
    }
    if (s.field === 'addComment') {
      const parsed = parseGlobalId(String(input.subjectId ?? ''));
      const repo = parsed !== null ? forge.getRepo(parsed.owner, parsed.name) : undefined;
      const issue = repo?.issues.find((i) => i.number === parsed?.num);
      if (issue === undefined) throw new Error('issue not found');
      const comment = { id: repo.nextComment++, body: String(input.body ?? '') };
      issue.comments.push(comment);
      const out: Record<string, unknown> = {};
      for (const sub of s.sel) {
        if (sub.field === 'commentEdge') {
          const edgeOut: Record<string, unknown> = {};
          for (const inner of sub.sel) {
            if (inner.field === 'node') {
              const nodeOut: Record<string, unknown> = {};
              for (const leaf of inner.sel) {
                if (leaf.field === 'id') nodeOut[leaf.alias] = globalId('C', repo.owner, repo.name, issue.number, comment.id);
                else if (leaf.field === 'body') nodeOut[leaf.alias] = comment.body;
                else throw new Error(`Cannot query field "${leaf.field}" on type "IssueComment".`);
              }
              edgeOut[inner.alias] = nodeOut;
            }
          }
          out[sub.alias] = edgeOut;
        }
      }
      data[s.alias] = out;
      continue;
    }
    throw new Error(`Cannot query field "${s.field}" on type "Mutation".`);
  }
  return data;
}

async function graphql(ctx: Ctx): Promise<void> {
  const raw = await readBody(ctx.req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    return sendJson(ctx, 400, { message: 'request body is not JSON' });
  }
  const run = (doc: Record<string, unknown>): { data: unknown; errors: { message: string }[] } => {
    const query = typeof doc.query === 'string' ? doc.query : '';
    const vars = asRecord(doc.variables);
    try {
      const op = gqlParse(query);
      return gqlRunOne(op, vars);
    } catch (err) {
      return { data: null, errors: [{ message: (err as Error).message }] };
    }
  };
  if (Array.isArray(parsed)) return sendJson(ctx, 200, parsed.map((d) => run(asRecord(d))));
  return sendJson(ctx, 200, run(asRecord(parsed)));
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

const MCP_TOOLS: { name: string; description: string; inputSchema: Record<string, unknown> }[] = [
  {
    name: 'create_repo',
    description: 'Create a repository for the token owner.',
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
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
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
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
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
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter: open, closed or all' },
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
        owner: { type: 'string', description: 'Repository owner login' },
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
    description: 'Squash-merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function mcpToolOk(payload: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload, isError: false };
}

function mcpToolErr(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCall(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const need = (key: string): unknown => args[key];
  switch (name) {
    case 'create_repo': {
      const repoName = asStr(need('name'));
      if (repoName === '') return mcpToolErr('missing required argument: name');
      if (forge.getRepo(VIEWER, repoName) !== undefined) return mcpToolErr('Repository already exists');
      const repo = forge.newRepo(VIEWER, repoName, asBool(need('private'), false), asStr(need('description')));
      return mcpToolOk(repoJson(repo));
    }
    case 'get_repo': {
      const owner = asStr(need('owner'));
      const repoName = asStr(need('repo')) || asStr(need('full_name')).split('/')[1] || '';
      const repo = forge.getRepo(owner, repoName);
      if (repo === undefined) return mcpToolErr(`Repository ${owner}/${repoName} not found`);
      return mcpToolOk(repoJson(repo));
    }
    case 'create_issue': {
      const owner = asStr(need('owner'));
      const repoName = asStr(need('repo'));
      const title = asStr(need('title'));
      if (owner === '' || repoName === '' || title === '') return mcpToolErr('missing required argument: owner, repo or title');
      const repo = forge.getRepo(owner, repoName);
      if (repo === undefined) return mcpToolErr(`Repository ${owner}/${repoName} not found`);
      const number = repo.nextNum++;
      const issue: IssueRec = {
        id: forge.nextEntId++,
        number,
        title,
        body: asStr(need('body')),
        state: 'open',
        labels: [],
        comments: [],
        cache: null,
      };
      repo.issues.push(issue);
      return mcpToolOk(JSON.parse(issueJsonText(issue)) as unknown);
    }
    case 'list_issues': {
      const owner = asStr(need('owner'));
      const repoName = asStr(need('repo'));
      if (owner === '' || repoName === '') return mcpToolErr('missing required argument: owner or repo');
      const repo = forge.getRepo(owner, repoName);
      if (repo === undefined) return mcpToolErr(`Repository ${owner}/${repoName} not found`);
      const state = asStr(need('state'), 'open');
      const list = state === 'all' ? repo.issues : repo.issues.filter((i) => i.state === state);
      return mcpToolOk(list.map((i) => JSON.parse(issueJsonText(i)) as unknown));
    }
    case 'create_pull_request': {
      const owner = asStr(need('owner'));
      const repoName = asStr(need('repo'));
      const title = asStr(need('title'));
      const head = asStr(need('head'));
      const base = asStr(need('base'));
      if (owner === '' || repoName === '' || title === '' || head === '' || base === '') {
        return mcpToolErr('missing required argument: owner, repo, title, head or base');
      }
      const repo = forge.getRepo(owner, repoName);
      if (repo === undefined) return mcpToolErr(`Repository ${owner}/${repoName} not found`);
      if (tipOf(repo, head) === null || tipOf(repo, base) === null) return mcpToolErr('head or base branch does not exist');
      const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head && p.base === base);
      if (dup !== undefined) return mcpToolErr('A pull request already exists for this head and base');
      const pull: PullRec = {
        id: forge.nextEntId++,
        number: repo.nextNum++,
        title,
        body: asStr(need('body')),
        head,
        base,
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeSha: null,
      };
      repo.pulls.push(pull);
      return mcpToolOk(pullJson(pull, repo));
    }
    case 'merge_pull_request': {
      const owner = asStr(need('owner'));
      const repoName = asStr(need('repo'));
      const num = Number(need('pull_number'));
      if (owner === '' || repoName === '' || !Number.isInteger(num)) return mcpToolErr('missing required argument: owner, repo or pull_number');
      const repo = forge.getRepo(owner, repoName);
      if (repo === undefined) return mcpToolErr(`Repository ${owner}/${repoName} not found`);
      const pull = repo.pulls.find((p) => p.number === num);
      if (pull === undefined) return mcpToolErr('Pull request not found');
      if (pull.merged) return mcpToolErr('Pull request is already merged');
      const done = squashMerge(repo, pull);
      if (!done.ok) return mcpToolErr(done.reason);
      return mcpToolOk({ merged: true, sha: done.sha, number: pull.number });
    }
    default:
      return mcpToolErr(`unknown tool: ${name}`);
  }
}

async function mcp(ctx: Ctx): Promise<void> {
  const raw = await readBody(ctx.req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    return sendJson(ctx, 400, mcpError(null, -32700, 'Parse error'));
  }
  const doc = asRecord(parsed);
  const id = doc.id ?? null;
  const method = asStr(doc.method);
  const params = asRecord(doc.params);
  if (method === '' || typeof doc.jsonrpc !== 'string') {
    return sendJson(ctx, 200, mcpError(id, -32600, 'Invalid Request'));
  }
  if (method.startsWith('notifications/')) {
    return sendEmpty(ctx, 202);
  }
  if (method === 'server/discover') {
    const info = { name: 'forge-mcp', version: '1.0.0' };
    return sendJson(ctx, 200, mcpResult(id, {
      supportedVersions: ['2026-07-28', '2025-11-25'],
      capabilities: { tools: {} },
      serverInfo: info,
      _meta: { 'io.modelcontextprotocol/serverInfo': info },
    }));
  }
  if (method === 'initialize') {
    const offered = asStr(params.protocolVersion, '2025-11-25');
    const known = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    return sendJson(ctx, 200, mcpResult(id, {
      protocolVersion: known.includes(offered) ? offered : '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: { name: 'forge-mcp', version: '1.0.0' },
    }));
  }
  if (method === 'tools/list') {
    return sendJson(ctx, 200, mcpResult(id, { tools: MCP_TOOLS }));
  }
  if (method === 'tools/call') {
    const toolName = asStr(params.name);
    const args = asRecord(params.arguments);
    const tool = MCP_TOOLS.find((t) => t.name === toolName);
    if (tool === undefined) return sendJson(ctx, 200, mcpError(id, -32602, `unknown tool: ${toolName}`));
    const required = (tool.inputSchema.required as string[] | undefined) ?? [];
    const missing = required.filter((k) => args[k] === undefined || args[k] === null || args[k] === '');
    if (missing.length > 0) {
      return sendJson(ctx, 200, mcpResult(id, mcpToolErr(`missing required argument: ${missing.join(', ')}`)));
    }
    return sendJson(ctx, 200, mcpResult(id, mcpCall(toolName, args)));
  }
  return sendJson(ctx, 200, mcpError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------------------
// Git HTTP
// ---------------------------------------------------------------------------

async function gitHttp(ctx: Ctx): Promise<void> {
  const s = ctx.segs;
  if (s.length < 2 || !s[1]!.endsWith('.git')) return sendJson(ctx, 404, { message: 'Not Found' });
  const owner = decodeURIComponent(s[0]!);
  const repoName = decodeURIComponent(s[1]!.slice(0, -4));
  const tail = s.slice(2);
  const wantsV2 = ctx.req.headers['git-protocol'] === 'version=2';
  if (ctx.method === 'GET' && tail[0] === 'info' && tail[1] === 'refs') {
    const service = ctx.query.get('service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      return sendJson(ctx, 404, { message: 'Not Found' });
    }
    const repo = forge.getRepo(owner, repoName);
    if (repo === undefined) return sendJson(ctx, 404, { message: 'Repository not found' });
    if (service === 'git-upload-pack' && wantsV2) {
      return sendBuf(ctx, 200, advV2(), 'application/x-git-upload-pack-advertisement');
    }
    return sendBuf(ctx, 200, advV0(repo, service as 'git-upload-pack' | 'git-receive-pack'), `application/x-${service}-advertisement`);
  }
  if (ctx.method === 'POST' && tail[0] === 'git-upload-pack') {
    const repo = forge.getRepo(owner, repoName);
    if (repo === undefined) return sendJson(ctx, 404, { message: 'Repository not found' });
    let packets: Pkt[];
    try {
      packets = splitPktLines(await readBody(ctx.req));
    } catch {
      return sendJson(ctx, 400, { message: 'malformed pkt-line stream' });
    }
    const first = packets.find((p) => p.kind === 'data')?.text ?? '';
    if (first.startsWith('command=ls-refs')) {
      const ask = parseLsRefsAsk(packets);
      return sendBuf(ctx, 200, lsRefsBytes(repo, ask.peel, ask.symrefs, ask.unborn, ask.prefixes), 'application/x-git-upload-pack-result');
    }
    if (first.startsWith('command=fetch')) {
      const ask = parseFetchAsk(packets);
      if (ask.wants.length === 0) {
        return sendBuf(ctx, 200, Buffer.concat([pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_FLUSH, pktLine('packfile\n'), ...sidebandPack(packUp([])), PKT_FLUSH]), 'application/x-git-upload-pack-result');
      }
      if (wantsV2) return sendBuf(ctx, 200, fetchReply(repo, ask), 'application/x-git-upload-pack-result');
      return sendBuf(ctx, 200, fetchReplyV0(repo, ask), 'application/x-git-upload-pack-result');
    }
    return sendJson(ctx, 400, { message: 'unknown upload-pack command' });
  }
  if (ctx.method === 'POST' && tail[0] === 'git-receive-pack') {
    const repo = forge.getRepo(owner, repoName);
    if (repo === undefined) return sendJson(ctx, 404, { message: 'Repository not found' });
    const body = await readBody(ctx.req);
    let out: Buffer;
    try {
      out = doPush(repo, body);
    } catch {
      return sendJson(ctx, 400, { message: 'malformed push' });
    }
    return sendBuf(ctx, 200, out, 'application/x-git-receive-pack-result');
  }
  return sendJson(ctx, 404, { message: 'Not Found' });
}

// ---------------------------------------------------------------------------
// Server + lifecycle
// ---------------------------------------------------------------------------

async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const rawUrl = req.url ?? '/';
  const qAt = rawUrl.indexOf('?');
  const path = qAt < 0 ? rawUrl : rawUrl.slice(0, qAt);
  const query = parseQuery(qAt < 0 ? '' : rawUrl.slice(qAt + 1));
  const segs = path.split('/').filter((p) => p !== '');
  const ctx: Ctx = { req, res, method: req.method ?? 'GET', path, query, segs };
  try {
    if (ctx.path === '/healthz') {
      if (ctx.method !== 'GET') return sendJson(ctx, 404, { message: 'Not Found' });
      return sendJson(ctx, 200, { ok: true });
    }
    if (TOKEN !== '' && req.headers.authorization !== `Bearer ${TOKEN}`) {
      return sendJson(ctx, 401, { message: 'Requires authentication' });
    }
    // Await each handler inside the try: returning its promise un-awaited
    // would let a rejection escape this catch and kill the process.
    if (segs.length >= 2 && segs[1]!.endsWith('.git')) {
      await gitHttp(ctx);
      return;
    }
    if (ctx.path === '/api/graphql' && ctx.method === 'POST') {
      await graphql(ctx);
      return;
    }
    if (ctx.path === '/mcp' && ctx.method === 'POST') {
      await mcp(ctx);
      return;
    }
    if (segs[0] === 'api' && segs[1] === 'v3') {
      const sub: Ctx = { ...ctx, segs: segs.slice(2) };
      await rest(sub);
      return;
    }
    return sendJson(ctx, 404, { message: 'Not Found' });
  } catch (err) {
    const withStatus = err as { status?: number };
    if (typeof withStatus.status === 'number') return sendJson(ctx, withStatus.status, { message: (err as Error).message });
    console.error(err);
    if (!res.headersSent) return sendJson(ctx, 500, { message: 'Internal Server Error' });
  }
}

function fetchJson(url: string, init?: { method?: string; body?: string }): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const request = http.request(
      {
        host: u.hostname,
        port: Number(u.port),
        path: `${u.pathname}${u.search}`,
        method: init?.method ?? 'GET',
        headers: { 'content-type': 'application/json', ...(init?.body !== undefined ? { 'content-length': String(Buffer.byteLength(init.body)) } : {}) },
      },
      (resp) => {
        const chunks: Buffer[] = [];
        resp.on('data', (c: Buffer) => chunks.push(c));
        resp.on('end', () => resolve({ status: resp.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    request.on('error', reject);
    if (init?.body !== undefined) request.write(init.body);
    request.end();
  });
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<void> {
  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"message":"Internal Server Error"}');
      }
    });
  });
  server.keepAliveTimeout = 30000;
  server.on('connection', (socket) => {
    socket.setNoDelay(true);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  if (ENV_URL === '') {
    console.log(`forge listening on 127.0.0.1:${port} (no MAKEFUN_ENV_URL; serving standalone)`);
    return;
  }
  let registered = false;
  for (let attempt = 0; attempt < 30 && !registered; attempt += 1) {
    try {
      const answer = await fetchJson(`${ENV_URL}/register`, { method: 'POST', body: JSON.stringify({ port }) });
      if (answer.status === 200 || answer.status === 409) registered = true;
      else await sleep(500);
    } catch {
      await sleep(500);
    }
  }
  if (!registered) {
    console.error('could not register with the environment');
    process.exit(1);
  }
  const deadline = Date.now() + 850_000;
  for (;;) {
    try {
      const answer = await fetchJson(`${ENV_URL}/done`);
      if (answer.status === 200) {
        const parsed = JSON.parse(answer.text) as { done?: boolean };
        if (parsed.done === true) {
          server.close();
          process.exit(0);
        }
      }
    } catch {
      // The environment is briefly unreachable; keep polling.
    }
    if (Date.now() > deadline) {
      server.close();
      process.exit(0);
    }
    await sleep(500);
  }
}

void main();
