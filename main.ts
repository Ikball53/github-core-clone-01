// Forge — one-process GitHub-compatible git forge.
//
// Serves git smart HTTP (upload-pack v2, receive-pack v0), the REST v3 API,
// GraphQL v4 and MCP from a single in-memory store. Node 22 standard library
// only: no git binary, no network beyond the suite, no UI.
//
// Determinism: every timestamp the forge emits is a fixed constant, ids come
// from counters, and ordering is insertion order. Nothing here reads a wall
// clock or an unseeded random source for state or responses.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { createServer, get as getHttp, request as requestHttp } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';

// ---------------------------------------------------------------- constants

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_ID = 1000;
const ZERO_OID = '0'.repeat(40);
const FIXED_EPOCH = 1700000000;
const FIXED_ISO = '2025-01-01T00:00:00Z';
const FORGE_NAME = 'forge';
const FORGE_VERSION = '1.0.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const TRIAL_NOW = process.env.MAKEFUN_TRIAL_NOW ?? '';

// ---------------------------------------------------------------- small utils

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function jsonText(value: unknown): string {
  return JSON.stringify(value);
}

// ---------------------------------------------------------------- pkt-line framing

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

function pktLines(items: ReadonlyArray<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'end';
  payload: Buffer;
}

/** Decode pkt-lines from the front of `buf`; stops at the first flush/delim/end. */
function decodePktPrefix(buf: Buffer): { packets: PktPacket[]; consumed: number } {
  const packets: PktPacket[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = Number.parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      offset += 4;
      break;
    }
    if (len < 4 || offset + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return { packets, consumed: offset };
}

/** Decode every pkt-line in `buf` (for fully framed bodies). */
function decodeAllPkt(buf: Buffer): PktPacket[] {
  const out: PktPacket[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = Number.parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'end', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len < 4 || offset + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return out;
}

// ---------------------------------------------------------------- git objects

type GitType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObj {
  type: GitType;
  data: Buffer;
}

const TYPE_CODE: Record<GitType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function storeObject(objects: Map<string, GitObj>, type: GitType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeEntries);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
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

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(fields: {
  tree: string;
  parents?: readonly string[];
  message: string;
  author: string;
  committer: string;
  timestamp?: number;
}): Buffer {
  const ts = fields.timestamp ?? FIXED_EPOCH;
  const lines = [`tree ${fields.tree}`];
  for (const parent of fields.parents ?? []) lines.push(`parent ${parent}`);
  lines.push(`author ${fields.author} ${ts} +0000`, `committer ${fields.committer} ${ts} +0000`, '');
  return Buffer.from(`${lines.join('\n')}\n${fields.message}`, 'utf8');
}

interface TagView {
  object: string;
  type: GitType;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space >= 0) headers.set(line.slice(0, space), line.slice(space + 1));
  }
  const type = headers.get('type') ?? 'commit';
  return {
    object: headers.get('object') ?? '',
    type: (type === 'commit' || type === 'tree' || type === 'blob' || type === 'tag' ? type : 'commit') as GitType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

/** Peel a tag object to its target commit (following tag chains). */
function peelToCommit(objects: Map<string, GitObj>, oid: string): string {
  let current = oid;
  const seen = new Set<string>();
  for (;;) {
    const obj = objects.get(current);
    if (!obj || obj.type !== 'tag' || seen.has(current)) return current;
    seen.add(current);
    current = parseTag(obj.data).object;
  }
}

// ---------------------------------------------------------------- packfiles

function packObjectHeader(type: GitType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: readonly GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const obj of objects) {
    parts.push(packObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buf.subarray(offset), { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('delta size varint is truncated');
      const byte = delta[offset++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta expects a different base size');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error('delta produced the wrong size');
  return out;
}

interface PackEntryRaw {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

/** Read a packfile, resolving OFS/REF deltas against the pack and `lookup`. */
function readPack(pack: Buffer, lookup?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('pack does not start with PACK');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declared = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const raw: PackEntryRaw[] = [];
  const byOffset = new Map<number, PackEntryRaw>();
  let offset = 12;
  for (let i = 0; i < declared; i += 1) {
    const entryOffset = offset;
    let byte = pack[offset];
    const first = byte;
    let size = byte & 0x0f;
    let shift = 4;
    offset += 1;
    while (byte & 0x80) {
      byte = pack[offset++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const typeCode = (first >> 4) & 0x07;
    const entry: PackEntryRaw = { offset: entryOffset, typeCode, size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      byte = pack[offset];
      offset += 1;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[offset++];
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack entry ${i} has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch after inflate');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack has stray bytes before its trailer');
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (trailer !== sha1Hex(pack.subarray(0, trailerStart))) throw new Error('pack trailer checksum mismatch');

  const objects = new Map<string, GitObj>();
  const resolvedByOid = new Map<string, PackEntryRaw>();
  const resolved = new Map<number, { type: GitType; data: Buffer; oid: string }>();
  const resolving = new Set<number>();
  const resolve = (entry: PackEntryRaw): { type: GitType; data: Buffer; oid: string } => {
    const cached = resolved.get(entry.offset);
    if (cached) return cached;
    if (resolving.has(entry.offset)) throw new Error('delta cycle in pack');
    resolving.add(entry.offset);
    let type: GitType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset ?? -1);
      if (!baseEntry) throw new Error('ofs-delta base is not in the pack');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid ?? '';
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = lookup?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} is not available`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const out = { type, data, oid };
    resolved.set(entry.offset, out);
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return out;
  };
  for (const entry of raw) {
    const done = resolve(entry);
    if (!objects.has(done.oid)) objects.set(done.oid, { type: done.type, data: done.data });
  }
  return objects;
}

// ---------------------------------------------------------------- reachability

/** Full closure of `roots` over commits, tags, trees and blobs. */
function collectClosure(objects: Map<string, GitObj>, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root)) queue.push(root);
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) if (entry.mode !== '160000') queue.push(entry.oid);
    }
  }
  return seen;
}

function includeTreeClosure(objects: Map<string, GitObj>, into: Map<string, GitObj>, treeOid: string): void {
  const stack = [treeOid];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (into.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    into.set(oid, obj);
    if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    }
  }
}

interface PackPlan {
  send: GitObj[];
  shallow: string[];
  unshallow: string[];
}

/**
 * Plan the objects a fetch sends: the closure of `wants` (commit generations
 * limited by `depth` when set) minus what `haves` already hold, plus the
 * shallow boundary that results.
 */
function planPack(
  objects: Map<string, GitObj>,
  wants: readonly string[],
  haves: readonly string[],
  depth: number | null,
  shallowIn: readonly string[],
): PackPlan {
  // Commits the client already holds. A shallow boundary is held as-is but
  // its parents are NOT held: the client has the boundary commit only, and a
  // deepen fetch must deliver those parents. A plain have, by contrast, holds
  // its whole ancestry.
  const shallowSet = new Set<string>(shallowIn);
  const held = new Set<string>();
  const heldQueue = [...haves];
  // Add every tree/blob reachable from a tree oid to `held`.
  const holdTree = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length) {
      const oid = stack.pop() as string;
      if (held.has(oid)) continue;
      held.add(oid);
      const obj = objects.get(oid);
      if (!obj || obj.type !== 'tree') continue;
      for (const entry of parseTree(obj.data)) {
        if (entry.mode === '40000') stack.push(entry.oid);
        else held.add(entry.oid);
      }
    }
  };
  while (heldQueue.length) {
    const oid = heldQueue.pop() as string;
    if (held.has(oid)) continue;
    held.add(oid);
    const obj = objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'commit') {
      // The boundary's own tree is held (the client has the commit); only
      // the parents are missing, so only parent traversal stops here.
      holdTree(parseCommit(obj.data).tree);
      if (!shallowSet.has(oid)) for (const parent of parseCommit(obj.data).parents) heldQueue.push(parent);
    } else if (obj.type === 'tag') heldQueue.push(parseTag(obj.data).object);
  }
  const included = new Map<string, GitObj>();
  const commitDist = new Map<string, number>();
  const queue: Array<{ oid: string; dist: number }> = wants.map((oid) => ({ oid, dist: 0 }));
  while (queue.length) {
    const item = queue.shift() as { oid: string; dist: number };
    const obj = objects.get(item.oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      if (!included.has(item.oid)) included.set(item.oid, obj);
      queue.push({ oid: parseTag(obj.data).object, dist: item.dist });
      continue;
    }
    if (obj.type !== 'commit') continue;
    if (depth !== null && item.dist >= depth) continue;
    const known = commitDist.get(item.oid);
    if (known !== undefined && known <= item.dist) continue;
    commitDist.set(item.oid, item.dist);
    included.set(item.oid, obj);
    const commit = parseCommit(obj.data);
    includeTreeClosure(objects, included, commit.tree);
    for (const parent of commit.parents) queue.push({ oid: parent, dist: item.dist + 1 });
  }
  const send: GitObj[] = [];
  for (const [oid, obj] of included) if (!held.has(oid)) send.push(obj);
  const shallow: string[] = [];
  if (depth !== null) {
    for (const [oid, dist] of commitDist) if (dist === depth - 1) shallow.push(oid);
  }
  const unshallow: string[] = [];
  for (const boundary of shallowIn) {
    if (!commitDist.has(boundary)) continue;
    const obj = objects.get(boundary);
    if (!obj || obj.type !== 'commit') continue;
    const parents = parseCommit(obj.data).parents;
    if (parents.every((parent) => commitDist.has(parent) || held.has(parent))) unshallow.push(boundary);
  }
  return { send, shallow, unshallow };
}

/** True when `ancestor` is reachable from `descendant` through commit parents. */
function isAncestor(objects: Map<string, GitObj>, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue = [peelToCommit(objects, descendant)];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queue.push(parent);
  }
  return false;
}

// ---------------------------------------------------------------- the store

interface LabelRec {
  name: string;
  color: string;
}

interface CommentRec {
  id: number;
  body: string;
}

interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: LabelRec[];
  comments: CommentRec[];
}

interface PullRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
}

interface RepoRec {
  id: number;
  name: string;
  owner: string;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  labels: Map<string, LabelRec>;
  issues: IssueRec[];
  nextIssue: number;
  pulls: PullRec[];
  nextPull: number;
  nextComment: number;
}

const repos = new Map<string, RepoRec>();
let nextRepoId = 1;
let nextObjectId = 10000;
let nextRequestId = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(owner: string, name: string): RepoRec | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRec(name: string, isPrivate: boolean, description: string): RepoRec {
  const repo: RepoRec = {
    id: nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    isPrivate,
    description,
    defaultBranch: 'main',
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    nextIssue: 1,
    pulls: [],
    nextPull: 1,
    nextComment: 1,
  };
  nextRepoId += 1;
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function globalId(kind: string, ...parts: Array<string | number>): string {
  return b64encode(`${kind}:${parts.join('/')}`);
}

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), parts: text.slice(colon + 1).split('/') };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- repo views (REST shapes)

function repoView(repo: RepoRec): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId('repo', repo.owner, repo.name),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/repos/${repo.owner}/${repo.name}`,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    has_issues: true,
    has_projects: false,
    has_wiki: false,
  };
}

function issueView(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('issue', repo.owner, repo.name, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((label) => ({ id: nextObjectId + label.name.length, name: label.name, color: label.color, description: '' })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    assignee: null,
    comments: issue.comments.length,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullView(repo: RepoRec, pull: PullRec): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: globalId('pr', repo.owner, repo.name, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function commentView(repo: RepoRec, issue: IssueRec, comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('comment', repo.owner, repo.name, issue.number, comment.id),
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
  };
}

// ---------------------------------------------------------------- trees, commits, merges

interface PathEntry {
  oid: string;
  mode: string;
}

/** Flatten a tree object into path -> entry, recursively. */
function flattenTree(repo: RepoRec, treeOid: string): Map<string, PathEntry> {
  const out = new Map<string, PathEntry>();
  const walk = (oid: string, prefix: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const entry of parseTree(obj.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  return out;
}

/** Build tree objects from a flat path map; returns the root tree oid. */
function buildTreeFromPaths(repo: RepoRec, entries: Map<string, PathEntry>): string {
  interface Node {
    files: Map<string, PathEntry>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of entries) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i] as string;
      if (!node.dirs.has(name)) node.dirs.set(name, makeNode());
      node = node.dirs.get(name) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry);
  }
  const build = (node: Node): string => {
    const list: TreeEntry[] = [];
    for (const [name, entry] of node.files) list.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) list.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo.objects, 'tree', buildTree(list));
  };
  return build(root);
}

function refTip(repo: RepoRec, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

function commitTreeOf(repo: RepoRec, commitOid: string): string {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return '';
  return parseCommit(obj.data).tree;
}

/**
 * Commit a set of file changes on `branch` (null content deletes the path).
 * Creates the branch from the default branch tip when it does not exist yet.
 */
function commitFiles(
  repo: RepoRec,
  branch: string,
  changes: Map<string, Buffer | null>,
  message: string,
): { commitSha: string; blobSha: string | null } {
  let tip = refTip(repo, branch);
  if (tip === undefined && branch !== repo.defaultBranch) {
    tip = refTip(repo, repo.defaultBranch);
    if (tip !== undefined) repo.refs.set(`refs/heads/${branch}`, tip);
  }
  const flat = tip === undefined ? new Map<string, PathEntry>() : flattenTree(repo, commitTreeOf(repo, tip));
  let blobSha: string | null = null;
  for (const [path, content] of changes) {
    if (content === null) {
      flat.delete(path);
    } else {
      const oid = storeObject(repo.objects, 'blob', content);
      flat.set(path, { oid, mode: '100644' });
      blobSha = oid;
    }
  }
  const tree = buildTreeFromPaths(repo, flat);
  const commitData = buildCommit({
    tree,
    parents: tip === undefined ? [] : [tip],
    // Keep the message byte-for-byte as the caller gave it: the REST checks
    // compare the parsed message to the exact string they sent.
    message,
    author: `${VIEWER_NAME} <${VIEWER_EMAIL}>`,
    committer: `${VIEWER_NAME} <${VIEWER_EMAIL}>`,
  });
  const commitSha = storeObject(repo.objects, 'commit', commitData);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, blobSha };
}

/** All commits reachable from `tip`, newest first (parents in order). */
function listCommits(repo: RepoRec, tip: string): Array<{ sha: string; message: string }> {
  const out: Array<{ sha: string; message: string }> = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const commit = parseCommit(obj.data);
    out.push({ sha: oid, message: commit.message });
    for (let i = commit.parents.length - 1; i >= 0; i -= 1) stack.push(commit.parents[i] as string);
  }
  return out;
}

interface DiffEntry {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
  oldOid: string | null;
  newOid: string | null;
}

function lineCounts(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  const oldLines = oldBuf === null ? [] : oldBuf.toString('utf8').split('\n');
  const newLines = newBuf === null ? [] : newBuf.toString('utf8').split('\n');
  const oldCount = new Map<string, number>();
  for (const line of oldLines) oldCount.set(line, (oldCount.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of newLines) {
    const left = oldCount.get(line) ?? 0;
    if (left > 0) oldCount.set(line, left - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const left of oldCount.values()) deletions += left;
  return { additions, deletions };
}

function diffTrees(repo: RepoRec, baseTreeOid: string, headTreeOid: string): DiffEntry[] {
  const base = baseTreeOid === '' ? new Map<string, PathEntry>() : flattenTree(repo, baseTreeOid);
  const head = headTreeOid === '' ? new Map<string, PathEntry>() : flattenTree(repo, headTreeOid);
  const paths = new Set<string>([...base.keys(), ...head.keys()]);
  const out: DiffEntry[] = [];
  for (const path of [...paths].sort()) {
    const from = base.get(path);
    const to = head.get(path);
    if (from !== undefined && to === undefined) {
      const oldBuf = repo.objects.get(from.oid)?.data ?? null;
      const counts = lineCounts(oldBuf, null);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: counts.deletions, changes: counts.deletions, oldOid: from.oid, newOid: null });
    } else if (from === undefined && to !== undefined) {
      const newBuf = repo.objects.get(to.oid)?.data ?? null;
      const counts = lineCounts(null, newBuf);
      out.push({ filename: path, status: 'added', additions: counts.additions, deletions: 0, changes: counts.additions, oldOid: null, newOid: to.oid });
    } else if (from !== undefined && to !== undefined && from.oid !== to.oid) {
      const oldBuf = repo.objects.get(from.oid)?.data ?? null;
      const newBuf = repo.objects.get(to.oid)?.data ?? null;
      const counts = lineCounts(oldBuf, newBuf);
      out.push({
        filename: path,
        status: 'modified',
        additions: Math.max(counts.additions, 1),
        deletions: counts.deletions,
        changes: Math.max(counts.additions, 1) + counts.deletions,
        oldOid: from.oid,
        newOid: to.oid,
      });
    }
  }
  return out;
}

/** Three-way conflict test: head vs base0 changes overlapping baseTip vs base0 changes. */
function mergeConflicts(repo: RepoRec, pull: PullRec): boolean {
  const baseTip = refTip(repo, pull.baseRef);
  if (baseTip === undefined) return true;
  const headTip = refTip(repo, pull.headRef) ?? pull.headSha;
  const base0Tree = commitTreeOf(repo, pull.baseSha);
  const headTree = commitTreeOf(repo, headTip);
  const baseTipTree = commitTreeOf(repo, baseTip);
  const headChanges = diffTrees(repo, base0Tree, headTree);
  const baseChanges = diffTrees(repo, base0Tree, baseTipTree);
  const baseChanged = new Map<string, DiffEntry>();
  for (const entry of baseChanges) baseChanged.set(entry.filename, entry);
  for (const entry of headChanges) {
    const other = baseChanged.get(entry.filename);
    if (other === undefined) continue;
    if (entry.newOid !== other.newOid) return true;
  }
  return false;
}

function mergeableState(repo: RepoRec, pull: PullRec): string {
  if (pull.state !== 'open') return 'UNKNOWN';
  return mergeConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
}

/** Squash-merge an open pull request onto its base branch. Null when conflicted. */
function doMerge(repo: RepoRec, pull: PullRec): string | null {
  if (pull.state !== 'open') return null;
  if (mergeConflicts(repo, pull)) return null;
  const baseTip = refTip(repo, pull.baseRef) as string;
  const headTip = refTip(repo, pull.headRef) ?? pull.headSha;
  const base0Tree = commitTreeOf(repo, pull.baseSha);
  const headTree = commitTreeOf(repo, headTip);
  const baseTipTree = commitTreeOf(repo, baseTip);
  const merged = flattenTree(repo, baseTipTree);
  const headChanges = diffTrees(repo, base0Tree, headTree);
  for (const entry of headChanges) {
    if (entry.newOid === null) merged.delete(entry.filename);
    else merged.set(entry.filename, { oid: entry.newOid, mode: '100644' });
  }
  const tree = buildTreeFromPaths(repo, merged);
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}\n\n${pull.title}\n`;
  const commitData = buildCommit({
    tree,
    parents: [baseTip],
    message,
    author: `${VIEWER_NAME} <${VIEWER_EMAIL}>`,
    committer: `${VIEWER_NAME} <${VIEWER_EMAIL}>`,
  });
  const mergeSha = storeObject(repo.objects, 'commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = TRIAL_NOW !== '' ? TRIAL_NOW : FIXED_ISO;
  pull.mergeSha = mergeSha;
  return mergeSha;
}

function createIssueRec(repo: RepoRec, title: string, body: string, labels: LabelRec[]): IssueRec {
  const issue: IssueRec = {
    id: nextObjectId,
    number: repo.nextIssue,
    title,
    body,
    state: 'open',
    labels,
    comments: [],
  };
  nextObjectId += 1;
  repo.nextIssue += 1;
  repo.issues.push(issue);
  return issue;
}

function createPullRec(
  repo: RepoRec,
  title: string,
  body: string,
  headRef: string,
  baseRef: string,
  headSha: string,
  baseSha: string,
): PullRec {
  const pull: PullRec = {
    id: nextObjectId,
    number: repo.nextPull,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeSha: null,
    headRef,
    baseRef,
    headSha,
    baseSha,
  };
  nextObjectId += 1;
  repo.nextPull += 1;
  repo.pulls.push(pull);
  return pull;
}

// ---------------------------------------------------------------- HTTP plumbing

function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  if (token === '') return false;
  if (TOKEN !== '') return token === TOKEN;
  return true;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendBuffer(res: ServerResponse, status: number, body: Buffer, contentType: string, extra?: Record<string, string>): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    ...(extra ?? {}),
  });
  res.end(body);
}

let requestCounter = 1;

function sendJson(res: ServerResponse, status: number, value: unknown, extra?: Record<string, string>): void {
  const body = Buffer.from(jsonText(value), 'utf8');
  sendBuffer(res, status, body, 'application/json; charset=utf-8', {
    'x-github-request-id': `forge-${requestCounter}`,
    ...(extra ?? {}),
  });
  requestCounter += 1;
}

function sendJsonError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

interface RouteContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  body: Buffer;
  json: Record<string, unknown> | null;
  jsonError: boolean;
}

async function parseJsonBody(ctx: RouteContext): Promise<boolean> {
  if (ctx.body.length === 0) {
    ctx.json = {};
    return true;
  }
  try {
    const parsed: unknown = JSON.parse(ctx.body.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      ctx.json = parsed as Record<string, unknown>;
      return true;
    }
    ctx.json = {};
    return true;
  } catch {
    ctx.jsonError = true;
    return false;
  }
}

function stringField(body: Record<string, unknown> | null, key: string): string {
  if (body === null) return '';
  const value = body[key];
  return typeof value === 'string' ? value : '';
}

function boolField(body: Record<string, unknown> | null, key: string, fallback: boolean): boolean {
  if (body === null) return fallback;
  const value = body[key];
  return typeof value === 'boolean' ? value : fallback;
}

function pageParams(url: URL): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
  const perPageRaw = Number.parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30;
  const perPage = Math.min(100, Math.max(1, perPageRaw));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): { slice: T[]; hasNext: boolean } {
  const start = (page - 1) * perPage;
  return { slice: items.slice(start, start + perPage), hasNext: start + perPage < items.length };
}

function linkHeader(req: IncomingMessage, url: URL, page: number, perPage: number, hasNext: boolean, hasPrev: boolean): string {
  const origin = `http://${req.headers.host ?? '127.0.0.1'}`;
  const parts: string[] = [];
  const build = (p: number): string => {
    const next = new URL(url.toString());
    next.searchParams.set('page', String(p));
    next.searchParams.set('per_page', String(perPage));
    return `${origin}${next.pathname}${next.search}`;
  };
  if (hasNext) parts.push(`<${build(page + 1)}>; rel="next"`);
  if (hasPrev) parts.push(`<${build(page - 1)}>; rel="prev"`);
  parts.push(`<${build(1)}>; rel="first"`);
  return parts.join(', ');
}

// ---------------------------------------------------------------- git smart HTTP

function gitRepoPath(url: URL): { owner: string; repo: string; rest: string } | null {
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(url.pathname);
  if (!match) return null;
  return { owner: decodeURIComponent(match[1] as string), repo: decodeURIComponent(match[2] as string), rest: match[3] ?? '' };
}

function sortedRefNames(repo: RepoRec): string[] {
  return [...repo.refs.keys()].sort();
}

function tagPeeled(repo: RepoRec, oid: string): string | undefined {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tag') return undefined;
  return peelToCommit(repo.objects, oid);
}

function v0Advertisement(repo: RepoRec, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps =
    service === 'git-upload-pack'
      ? 'symref=HEAD:refs/heads/main side-band-64k ofs-delta thin-pack shallow multi_ack agent=forge/1.0 object-format=sha1'
      : 'symref=HEAD:refs/heads/main report-status side-band-64k delete-refs ofs-delta thin-pack agent=forge/1.0';
  const lines: Array<string | 'flush'> = [`# service=${service}\n`, 'flush'];
  const names = sortedRefNames(repo);
  const headTip = repo.refs.get('refs/heads/main');
  if (names.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    let first = true;
    if (headTip !== undefined) {
      lines.push(`${headTip} HEAD${first ? `\0${caps}` : ''}\n`);
      first = false;
    }
    for (const name of names) {
      const oid = repo.refs.get(name) as string;
      lines.push(`${oid} ${name}${first ? `\0${caps}` : ''}\n`);
      first = false;
      const peeled = tagPeeled(repo, oid);
      if (peeled !== undefined) lines.push(`${peeled} ${name}^{}\n`);
    }
  }
  lines.push('flush');
  return pktLines(lines);
}

function v2Advertisement(): Buffer {
  return pktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow\n',
    'object-format=sha1\n',
    'agent=forge/1.0\n',
    'flush',
  ]);
}

interface LsRefsArg {
  prefixes: string[];
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
}

function handleLsRefs(repo: RepoRec, args: LsRefsArg): Buffer {
  const out: Array<string | 'flush'> = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((prefix) => name.startsWith(prefix));
  const headTip = repo.refs.get('refs/heads/main');
  if (keep('HEAD')) {
    if (headTip !== undefined) {
      out.push(`${headTip} HEAD${args.symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    } else if (args.unborn) {
      out.push(`unborn HEAD${args.symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    }
  }
  for (const name of sortedRefNames(repo)) {
    if (!keep(name)) continue;
    const oid = repo.refs.get(name) as string;
    let line = `${oid} ${name}`;
    if (args.peel) {
      const peeled = tagPeeled(repo, oid);
      if (peeled !== undefined) line += ` peeled:${peeled}`;
    }
    out.push(`${line}\n`);
  }
  out.push('flush');
  return pktLines(out);
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const maxData = 65515;
  for (let offset = 0; offset < pack.length; offset += maxData) {
    const chunk = pack.subarray(offset, Math.min(pack.length, offset + maxData));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function handleFetchV2(repo: RepoRec, body: Buffer): Buffer {
  const packets = decodeAllPkt(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let depth: number | null = null;
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7).trim(), 10) || null;
  }
  const plan = planPack(repo.objects, wants, haves, depth, shallowIn);
  const pack = writePack(plan.send);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), pktFlush());
  if (depth !== null) {
    const info: Array<string | 'flush'> = ['shallow-info\n'];
    for (const oid of plan.shallow) info.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) info.push(`unshallow ${oid}\n`);
    info.push('flush');
    parts.push(pktLines(info));
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}

function handleFetchV0(repo: RepoRec, body: Buffer): Buffer {
  // Two sections: wants (with shallow/deepen) + flush, then haves + done + flush.
  const { packets } = decodePktPrefix(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7).trim(), 10) || null;
  }
  void section;
  const plan = planPack(repo.objects, wants, haves, depth, shallowIn);
  const pack = writePack(plan.send);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}

function handleUploadPack(repo: RepoRec, body: Buffer, useV2: boolean): Buffer {
  if (useV2) {
    const packets = decodeAllPkt(body);
    let command = '';
    for (const packet of packets) {
      if (packet.kind !== 'data') continue;
      const line = packet.payload.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('command=')) command = line.slice(8).trim();
    }
    if (command === 'ls-refs') {
      const args: LsRefsArg = { prefixes: [], peel: false, symrefs: false, unborn: false };
      for (const packet of packets) {
        if (packet.kind !== 'data') continue;
        const line = packet.payload.toString('utf8').replace(/\n$/, '');
        if (line === 'peel') args.peel = true;
        else if (line === 'symrefs') args.symrefs = true;
        else if (line === 'unborn') args.unborn = true;
        else if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice(11).trim());
      }
      return handleLsRefs(repo, args);
    }
    if (command === 'fetch') return handleFetchV2(repo, body);
    return pktLines(['flush']);
  }
  return handleFetchV0(repo, body);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: RepoRec, body: Buffer): Buffer {
  const { packets, consumed } = decodePktPrefix(body);
  const commands: PushCommand[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    let line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    const parts = line.split(' ');
    if (parts.length >= 3) {
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
    }
  }
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = body.subarray(consumed);
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    } catch (err) {
      unpackOk = false;
      unpackDetail = `unpack error: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  for (const command of commands) {
    const current = repo.refs.get(command.ref);
    let ok = false;
    let reason = '';
    if (!unpackOk) {
      reason = 'unpack error';
    } else if (command.newOid === ZERO_OID) {
      if (current === undefined) {
        reason = 'no such ref';
      } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
        reason = 'stale info';
      } else {
        repo.refs.delete(command.ref);
        ok = true;
      }
    } else if (!repo.objects.has(command.newOid)) {
      reason = 'object not found';
    } else if (command.oldOid === ZERO_OID) {
      if (current !== undefined) {
        reason = 'already exists';
      } else {
        repo.refs.set(command.ref, command.newOid);
        ok = true;
      }
    } else if (current === undefined) {
      reason = 'no such ref';
    } else if (command.oldOid !== current) {
      reason = 'stale info';
    } else {
      const newObj = repo.objects.get(command.newOid) as GitObj;
      if (newObj.type !== 'commit' && newObj.type !== 'tag') {
        reason = 'invalid object type';
      } else if (newObj.type === 'tag') {
        repo.refs.set(command.ref, command.newOid);
        ok = true;
      } else if (isAncestor(repo.objects, command.oldOid, command.newOid)) {
        repo.refs.set(command.ref, command.newOid);
        ok = true;
      } else {
        reason = 'non-fast-forward';
      }
    }
    reportLines.push(ok ? `ok ${command.ref}\n` : `ng ${command.ref} ${reason}\n`);
  }
  const reportStream = pktLines(reportLines);
  const band = Buffer.concat([Buffer.from([1]), reportStream]);
  return Buffer.concat([pktLine(band), pktFlush()]);
}

// ---------------------------------------------------------------- REST v3

function restRepoOr404(ctx: RouteContext, owner: string, name: string): RepoRec | null {
  if (owner !== VIEWER_LOGIN) return null;
  return findRepo(owner, name) ?? null;
}

function restCreateRepo(ctx: RouteContext): void {
  const { res } = ctx;
  if (!ctx.json) {
    sendJsonError(res, 400, 'malformed JSON body');
    return;
  }
  const name = stringField(ctx.json, 'name');
  if (name === '') {
    sendJsonError(res, 422, 'name is required');
    return;
  }
  const existing = findRepo(VIEWER_LOGIN, name);
  if (existing) {
    sendJsonError(res, 422, 'Repository already exists');
    return;
  }
  const repo = createRepoRec(name, boolField(ctx.json, 'private', false), stringField(ctx.json, 'description'));
  sendJson(res, 201, repoView(repo));
}

function restListUserRepos(ctx: RouteContext): void {
  const { req, res, url } = ctx;
  const owned = [...repos.values()].filter((repo) => repo.owner === VIEWER_LOGIN);
  const { page, perPage } = pageParams(url);
  const { slice, hasNext } = paginate(owned, page, perPage);
  sendJson(res, 200, slice.map(repoView), {
    link: linkHeader(req, url, page, perPage, hasNext, page > 1),
  });
}

function restContentsGet(ctx: RouteContext, repo: RepoRec, path: string): void {
  const { res, url } = ctx;
  const ref = url.searchParams.get('ref') ?? undefined;
  let tip: string | undefined;
  if (ref !== undefined) {
    if (isOid(ref)) tip = ref;
    else tip = refTip(repo, ref);
    if (tip === undefined || !repo.objects.has(tip)) {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
  } else {
    tip = refTip(repo, repo.defaultBranch);
    if (tip === undefined) {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
  }
  const treeOid = commitTreeOf(repo, tip);
  if (treeOid === '') {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const flat = flattenTree(repo, treeOid);
  if (path === '') {
    const entries: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const key of flat.keys()) {
      const top = key.split('/')[0] as string;
      if (seen.has(top)) continue;
      seen.add(top);
      const isDir = [...flat.keys()].some((other) => other.startsWith(`${top}/`));
      if (isDir) {
        const sub = new Map<string, PathEntry>();
        for (const [p, entry] of flat) if (p.startsWith(`${top}/`)) sub.set(p.slice(top.length + 1), entry);
        entries.push({ type: 'dir', name: top, path: top, sha: buildTreeFromPaths(repo, sub) });
      } else {
        const entry = flat.get(top) as PathEntry;
        entries.push({ type: 'file', name: top, path: top, sha: entry.oid, size: repo.objects.get(entry.oid)?.data.length ?? 0 });
      }
    }
    sendJson(res, 200, entries);
    return;
  }
  const entry = flat.get(path);
  if (entry !== undefined) {
    const data = repo.objects.get(entry.oid)?.data ?? Buffer.alloc(0);
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: data.length,
      name: path.split('/').pop() ?? path,
      path,
      content: data.toString('base64'),
      sha: entry.oid,
    });
    return;
  }
  const prefix = `${path}/`;
  const children = [...flat.keys()].filter((key) => key.startsWith(prefix));
  if (children.length === 0) {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const entries: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (const key of children) {
    const rest = key.slice(prefix.length);
    const top = rest.split('/')[0] as string;
    if (seen.has(top)) continue;
    seen.add(top);
    const isDir = rest.includes('/');
    if (isDir) {
      const sub = new Map<string, PathEntry>();
      for (const [p, e] of flat) if (p.startsWith(`${prefix}${top}/`)) sub.set(p.slice(prefix.length + top.length + 1), e);
      entries.push({ type: 'dir', name: top, path: `${path}/${top}`, sha: buildTreeFromPaths(repo, sub) });
    } else {
      const e = flat.get(key) as PathEntry;
      entries.push({ type: 'file', name: top, path: key, sha: e.oid, size: repo.objects.get(e.oid)?.data.length ?? 0 });
    }
  }
  sendJson(res, 200, entries);
}

function restContentsPut(ctx: RouteContext, repo: RepoRec, path: string): void {
  const { res } = ctx;
  if (!ctx.json) {
    sendJsonError(res, 400, 'malformed JSON body');
    return;
  }
  const message = stringField(ctx.json, 'message') || 'update file';
  const contentB64 = stringField(ctx.json, 'content');
  if (contentB64 === '') {
    sendJsonError(res, 422, 'content is required');
    return;
  }
  const content = b64decode(contentB64);
  const branch = stringField(ctx.json, 'branch') || repo.defaultBranch;
  const sha = stringField(ctx.json, 'sha');
  const tip = refTip(repo, branch) ?? refTip(repo, repo.defaultBranch);
  const existed = tip !== undefined && flattenTree(repo, commitTreeOf(repo, tip)).has(path);
  if (existed && sha !== '') {
    const current = flattenTree(repo, commitTreeOf(repo, tip as string)).get(path) as PathEntry;
    if (current.oid.toLowerCase() !== sha.toLowerCase()) {
      sendJsonError(res, 409, 'sha does not match the current blob');
      return;
    }
  }
  const changes = new Map<string, Buffer | null>([[path, content]]);
  const { commitSha, blobSha } = commitFiles(repo, branch, changes, message);
  sendJson(res, existed ? 200 : 201, {
    content: { name: path.split('/').pop() ?? path, path, sha: blobSha, size: content.length, encoding: 'base64', type: 'file' },
    commit: { sha: commitSha, message },
  });
}

function restContentsDelete(ctx: RouteContext, repo: RepoRec, path: string): void {
  const { res } = ctx;
  if (!ctx.json) {
    sendJsonError(res, 400, 'malformed JSON body');
    return;
  }
  const message = stringField(ctx.json, 'message') || 'delete file';
  const tip = refTip(repo, repo.defaultBranch);
  if (tip === undefined) {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const flat = flattenTree(repo, commitTreeOf(repo, tip));
  if (!flat.has(path)) {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const { commitSha } = commitFiles(repo, repo.defaultBranch, new Map([[path, null]]), message);
  sendJson(res, 200, { commit: { sha: commitSha, message } });
}

function restIssuesList(ctx: RouteContext, repo: RepoRec): void {
  const { res, url } = ctx;
  const state = url.searchParams.get('state') ?? 'open';
  const sort = url.searchParams.get('sort') ?? 'created';
  const direction = url.searchParams.get('direction') ?? 'desc';
  let list = [...repo.issues];
  if (state !== 'all') list = list.filter((issue) => issue.state === state);
  list.sort((a, b) => {
    if (sort === 'created' && direction === 'asc') return a.number - b.number;
    return b.number - a.number;
  });
  const { page, perPage } = pageParams(url);
  const { slice, hasNext } = paginate(list, page, perPage);
  sendJson(res, 200, slice.map((issue) => issueView(repo, issue)), {
    link: linkHeader(ctx.req, url, page, perPage, hasNext, page > 1),
  });
}

function restPullsList(ctx: RouteContext, repo: RepoRec): void {
  const { res, url } = ctx;
  const state = url.searchParams.get('state') ?? 'open';
  let list = [...repo.pulls];
  if (state !== 'all') list = list.filter((pull) => pull.state === state);
  list.sort((a, b) => b.number - a.number);
  const { page, perPage } = pageParams(url);
  const { slice, hasNext } = paginate(list, page, perPage);
  sendJson(res, 200, slice.map((pull) => pullView(repo, pull)), {
    link: linkHeader(ctx.req, url, page, perPage, hasNext, page > 1),
  });
}

function restHandle(ctx: RouteContext): boolean {
  const { req, res, url } = ctx;
  const method = req.method ?? 'GET';
  const segments = url.pathname.split('/').filter((part) => part !== '');
  if (segments[0] !== 'api' || segments[1] !== 'v3') return false;
  const tail = segments.slice(2);

  if (tail.length === 0 && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/user', repository_url: '/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, user' });
    return true;
  }
  if (tail.length === 1 && tail[0] === 'meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0', git_server_url: 'https://example.invalid' });
    return true;
  }
  if (tail.length === 1 && tail[0] === 'user' && method === 'GET') {
    sendJson(res, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: globalId('user', VIEWER_LOGIN),
      name: VIEWER_NAME,
      email: VIEWER_EMAIL,
      type: 'User',
      avatar_url: 'https://example.invalid/avatar.png',
      html_url: `https://example.invalid/${VIEWER_LOGIN}`,
    });
    return true;
  }
  if (tail.length === 2 && tail[0] === 'user' && tail[1] === 'repos' && method === 'GET') {
    restListUserRepos(ctx);
    return true;
  }
  if (tail.length === 2 && tail[0] === 'user' && tail[1] === 'repos' && method === 'POST') {
    if (!parseJsonBody(ctx)) {
      sendJsonError(res, 400, 'malformed JSON body');
      return true;
    }
    restCreateRepo(ctx);
    return true;
  }
  if (tail.length >= 3 && tail[0] === 'repos') {
    const owner = decodeURIComponent(tail[1] as string);
    const name = decodeURIComponent(tail[2] as string);
    const repo = restRepoOr404(ctx, owner, name);
    if (repo === null) {
      sendJsonError(res, 404, 'Not Found');
      return true;
    }
    const rest = tail.slice(3);
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoView(repo));
      } else if (method === 'PATCH') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        const desc = stringField(ctx.json, 'description');
        if (desc !== '') repo.description = desc;
        sendJson(res, 200, repoView(repo));
      } else if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'x-github-request-id': `forge-${requestCounter}` });
        requestCounter += 1;
        res.end();
      } else {
        sendJsonError(res, 404, 'Not Found');
      }
      return true;
    }
    if (rest[0] === 'git' && rest[1] === 'refs' && method === 'POST') {
      if (!parseJsonBody(ctx)) {
        sendJsonError(res, 400, 'malformed JSON body');
        return true;
      }
      const ref = stringField(ctx.json, 'ref');
      const sha = stringField(ctx.json, 'sha');
      if (ref === '' || sha === '') {
        sendJsonError(res, 422, 'ref and sha are required');
        return true;
      }
      if (!isOid(sha) || !repo.objects.has(sha)) {
        sendJsonError(res, 422, 'sha does not reference a known object');
        return true;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: 'commit' }, node_id: globalId('ref', owner, name, ref) });
      return true;
    }
    if (rest[0] === 'git' && rest[1] === 'refs' && method === 'GET') {
      const ref = rest.slice(2).join('/');
      const oid = repo.refs.get(ref);
      if (oid === undefined) {
        sendJsonError(res, 404, 'Not Found');
      } else {
        sendJson(res, 200, { ref, object: { sha: oid, type: 'commit' } });
      }
      return true;
    }
    if (rest[0] === 'branches' && method === 'GET' && rest.length === 1) {
      const list = sortedRefNames(repo)
        .filter((ref) => ref.startsWith('refs/heads/'))
        .map((ref) => ({
          name: ref.slice('refs/heads/'.length),
          commit: { sha: repo.refs.get(ref) as string },
          protected: false,
        }));
      sendJson(res, 200, list);
      return true;
    }
    if (rest[0] === 'branches' && method === 'GET' && rest.length === 2) {
      const branch = decodeURIComponent(rest[1] as string);
      const tip = refTip(repo, branch);
      if (tip === undefined) {
        sendJsonError(res, 404, 'Not Found');
      } else {
        sendJson(res, 200, { name: branch, commit: { sha: tip }, protected: false });
      }
      return true;
    }
    if (rest[0] === 'commits' && method === 'GET') {
      const shaParam = url.searchParams.get('sha');
      const tip = shaParam !== null ? (isOid(shaParam) ? shaParam : refTip(repo, shaParam)) : refTip(repo, repo.defaultBranch);
      if (tip === undefined || !repo.objects.has(tip)) {
        sendJson(res, 200, []);
        return true;
      }
      const commits = listCommits(repo, tip);
      const { page, perPage } = pageParams(url);
      const { slice, hasNext } = paginate(commits, page, perPage);
      sendJson(
        res,
        200,
        slice.map((commit) => ({ sha: commit.sha, commit: { message: commit.message }, url: `/repos/${owner}/${name}/commits/${commit.sha}` })),
        { link: linkHeader(req, url, page, perPage, hasNext, page > 1) },
      );
      return true;
    }
    if (rest[0] === 'contents' && rest.length >= 2) {
      const path = rest.slice(1).map((part) => decodeURIComponent(part)).join('/');
      if (method === 'GET') restContentsGet(ctx, repo, path);
      else if (method === 'PUT') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        restContentsPut(ctx, repo, path);
      } else if (method === 'DELETE') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        restContentsDelete(ctx, repo, path);
      } else {
        sendJsonError(res, 404, 'Not Found');
      }
      return true;
    }
    if (rest[0] === 'labels' && method === 'POST') {
      if (!parseJsonBody(ctx)) {
        sendJsonError(res, 400, 'malformed JSON body');
        return true;
      }
      const labelName = stringField(ctx.json, 'name');
      const color = stringField(ctx.json, 'color') || 'ededed';
      if (labelName === '') {
        sendJsonError(res, 422, 'name is required');
        return true;
      }
      const label: LabelRec = { name: labelName, color };
      repo.labels.set(labelName, label);
      sendJson(res, 201, { id: nextObjectId + labelName.length, name: labelName, color, description: '' });
      return true;
    }
    if (rest[0] === 'labels' && method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map((label) => ({ id: nextObjectId + label.name.length, name: label.name, color: label.color, description: '' })));
      return true;
    }
    if (rest[0] === 'issues' && method === 'POST' && rest.length === 1) {
      if (!parseJsonBody(ctx)) {
        sendJsonError(res, 400, 'malformed JSON body');
        return true;
      }
      const title = stringField(ctx.json, 'title');
      const body = stringField(ctx.json, 'body');
      const wanted: LabelRec[] = [];
      const labelNames = ctx.json?.labels;
      if (Array.isArray(labelNames)) {
        for (const raw of labelNames) {
          if (typeof raw !== 'string') continue;
          const label = repo.labels.get(raw);
          if (!label) {
            sendJsonError(res, 422, `label "${raw}" does not exist`);
            return true;
          }
          wanted.push(label);
        }
      }
      if (title === '') {
        sendJsonError(res, 422, 'title is required');
        return true;
      }
      const issue = createIssueRec(repo, title, body, wanted);
      sendJson(res, 201, issueView(repo, issue));
      return true;
    }
    if (rest[0] === 'issues' && method === 'GET' && rest.length === 1) {
      restIssuesList(ctx, repo);
      return true;
    }
    if (rest[0] === 'issues' && rest.length >= 2) {
      const number = Number.parseInt(rest[1] as string, 10);
      const issue = repo.issues.find((item) => item.number === number);
      if (issue === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        sendJson(res, 200, issueView(repo, issue));
        return true;
      }
      if (rest.length === 2 && method === 'PATCH') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        const title = stringField(ctx.json, 'title');
        if (title !== '') issue.title = title;
        const body = stringField(ctx.json, 'body');
        if (body !== '') issue.body = body;
        const state = stringField(ctx.json, 'state');
        if (state === 'open' || state === 'closed') issue.state = state;
        sendJson(res, 200, issueView(repo, issue));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'comments' && method === 'POST') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        const body = stringField(ctx.json, 'body');
        if (body === '') {
          sendJsonError(res, 422, 'body is required');
          return true;
        }
        const comment: CommentRec = { id: repo.nextComment, body };
        repo.nextComment += 1;
        issue.comments.push(comment);
        sendJson(res, 201, commentView(repo, issue, comment));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'comments' && method === 'GET') {
        sendJson(res, 200, issue.comments.map((comment) => commentView(repo, issue, comment)));
        return true;
      }
      sendJsonError(res, 404, 'Not Found');
      return true;
    }
    if (rest[0] === 'pulls' && method === 'POST') {
      if (!parseJsonBody(ctx)) {
        sendJsonError(res, 400, 'malformed JSON body');
        return true;
      }
      const title = stringField(ctx.json, 'title');
      const body = stringField(ctx.json, 'body');
      const head = stringField(ctx.json, 'head');
      const base = stringField(ctx.json, 'base') || repo.defaultBranch;
      if (title === '' || head === '') {
        sendJsonError(res, 422, 'title and head are required');
        return true;
      }
      const headTip = refTip(repo, head);
      if (headTip === undefined) {
        sendJsonError(res, 422, `head branch "${head}" does not exist`);
        return true;
      }
      const baseTip = refTip(repo, base) ?? refTip(repo, repo.defaultBranch);
      if (baseTip === undefined) {
        sendJsonError(res, 422, `base branch "${base}" does not exist`);
        return true;
      }
      const duplicate = repo.pulls.find((pull) => pull.headRef === head && pull.state === 'open');
      if (duplicate !== undefined) {
        sendJsonError(res, 422, 'a pull request already exists for this head branch');
        return true;
      }
      const pull = createPullRec(repo, title, body, head, base, headTip, baseTip);
      sendJson(res, 201, pullView(repo, pull));
      return true;
    }
    if (rest[0] === 'pulls' && method === 'GET' && rest.length === 1) {
      restPullsList(ctx, repo);
      return true;
    }
    if (rest[0] === 'pulls' && rest.length >= 2) {
      const number = Number.parseInt(rest[1] as string, 10);
      const pull = repo.pulls.find((item) => item.number === number);
      if (pull === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        sendJson(res, 200, pullView(repo, pull));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        const baseTree = commitTreeOf(repo, pull.baseSha);
        const headTip = refTip(repo, pull.headRef) ?? pull.headSha;
        const headTree = commitTreeOf(repo, headTip);
        const files = diffTrees(repo, baseTree, headTree);
        sendJson(
          res,
          200,
          files.map((file) => ({
            filename: file.filename,
            status: file.status,
            additions: file.additions,
            deletions: file.deletions,
            changes: file.changes,
            sha: file.newOid ?? file.oldOid,
          })),
        );
        return true;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (!parseJsonBody(ctx)) {
          sendJsonError(res, 400, 'malformed JSON body');
          return true;
        }
        if (pull.state !== 'open') {
          sendJsonError(res, 405, 'pull request is not open');
          return true;
        }
        const mergeSha = doMerge(repo, pull);
        if (mergeSha === null) {
          sendJsonError(res, 405, 'merge conflict');
          return true;
        }
        sendJson(res, 200, { sha: mergeSha, merged: true, message: `Pull Request successfully merged` });
        return true;
      }
      sendJsonError(res, 404, 'Not Found');
      return true;
    }
    sendJsonError(res, 404, 'Not Found');
    return true;
  }
  return false;
}

// ---------------------------------------------------------------- GraphQL

interface GqlArg {
  name: string;
  value: unknown;
}

interface GqlField {
  alias: string;
  name: string;
  args: GqlArg[];
  selections: GqlField[];
  fragmentName: string | null;
  inlineType: string | null;
}

interface GqlVarDef {
  name: string;
  typeName: string;
  defaultValue: unknown;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  fragments: Map<string, GqlField[]>;
  selections: GqlField[];
  variables: Map<string, unknown>;
  varDefs: GqlVarDef[];
}

interface GqlToken {
  kind: 'name' | 'punct' | 'string' | 'number';
  value: string;
}

function gqlLex(input: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < input.length && input[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.') {
      if (input.slice(i, i + 3) === '...') {
        tokens.push({ kind: 'punct', value: '...' });
        i += 3;
        continue;
      }
      i += 1;
      continue;
    }
    if ('!$():=@[]{ }|'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let value = '';
      i += 1;
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          const escaped = input[i + 1] as string;
          if (escaped === 'n') value += '\n';
          else if (escaped === 't') value += '\t';
          else if (escaped === 'r') value += '\r';
          else value += escaped;
          i += 2;
          continue;
        }
        value += input[i] as string;
        i += 1;
      }
      i += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let value = '';
      while (i < input.length && /[0-9.eE+-]/.test(input[i] as string)) {
        value += input[i] as string;
        i += 1;
      }
      tokens.push({ kind: 'number', value });
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let value = '';
      while (i < input.length && /[A-Za-z0-9_]/.test(input[i] as string)) {
        value += input[i] as string;
        i += 1;
      }
      tokens.push({ kind: 'name', value });
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;
  private variables: Map<string, unknown>;

  constructor(tokens: GqlToken[], variables: Map<string, unknown>) {
    this.tokens = tokens;
    this.variables = variables;
  }

  peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  next(): GqlToken | undefined {
    return this.tokens[this.pos++];
  }

  expect(value: string): GqlToken {
    const token = this.next();
    if (token === undefined || token.value !== value) throw new Error(`expected ${value}`);
    return token;
  }

  expectName(): string {
    const token = this.next();
    if (token === undefined || token.kind !== 'name') throw new Error('expected name');
    return token.value;
  }

  parseValue(): unknown {
    const token = this.next();
    if (token === undefined) throw new Error('unexpected end of document');
    if (token.value === '$') {
      const name = this.expectName();
      return this.variables.get(name) ?? null;
    }
    if (token.kind === 'string') return token.value;
    if (token.kind === 'number') return Number(token.value);
    if (token.kind === 'name') {
      if (token.value === 'true') return true;
      if (token.value === 'false') return false;
      if (token.value === 'null') return null;
      return token.value;
    }
    if (token.value === '[') {
      const list: unknown[] = [];
      while (this.peek() !== undefined && this.peek()?.value !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (token.value === '{') {
      const obj: Record<string, unknown> = {};
      while (this.peek() !== undefined && this.peek()?.value !== '}') {
        const key = this.expectName();
        this.expect(':');
        obj[key] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    throw new Error(`unexpected token ${token.value}`);
  }

  parseArguments(): GqlArg[] {
    const args: GqlArg[] = [];
    if (this.peek()?.value !== '(') return args;
    this.next();
    while (this.peek() !== undefined && this.peek()?.value !== ')') {
      const name = this.expectName();
      this.expect(':');
      const value = this.parseValue();
      args.push({ name, value });
    }
    this.expect(')');
    return args;
  }

  parseTypeName(): string {
    const token = this.next();
    if (token === undefined) return 'String';
    if (token.value === '[') {
      const inner = this.parseTypeName();
      this.expect(']');
      return `[${inner}]`;
    }
    return token.value;
  }

  parseVariableDefinitions(): GqlVarDef[] {
    const defs: GqlVarDef[] = [];
    if (this.peek()?.value !== '(') return defs;
    this.next();
    while (this.peek() !== undefined && this.peek()?.value !== ')') {
      this.expect('$');
      const name = this.expectName();
      this.expect(':');
      const typeName = this.parseTypeName();
      if (this.peek()?.value === '!') this.next();
      let defaultValue: unknown = undefined;
      if (this.peek()?.value === '=') {
        this.next();
        defaultValue = this.parseValue();
      }
      defs.push({ name, typeName, defaultValue });
    }
    this.expect(')');
    return defs;
  }

  parseSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== undefined && this.peek()?.value !== '}') {
      fields.push(this.parseField());
    }
    this.expect('}');
    return fields;
  }

  parseField(): GqlField {
    const token = this.peek();
    if (token !== undefined && token.value === '...') {
      this.next();
      const next = this.peek();
      if (next !== undefined && next.value === 'on') {
        this.next();
        const typeName = this.expectName();
        const selections = this.parseSelectionSet();
        return { alias: '', name: '', args: [], selections, fragmentName: null, inlineType: typeName };
      }
      const name = this.expectName();
      return { alias: '', name: '', args: [], selections: [], fragmentName: name, inlineType: null };
    }
    let alias = '';
    let name = this.expectName();
    if (this.peek()?.value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArguments();
    while (this.peek() !== undefined && this.peek()?.value === '@') {
      this.next();
      this.expectName();
      this.parseArguments();
    }
    let selections: GqlField[] = [];
    if (this.peek()?.value === '{') selections = this.parseSelectionSet();
    return { alias: alias === '' ? name : alias, name, args, selections, fragmentName: null, inlineType: null };
  }
}

function parseGqlDocument(query: string, variables: Map<string, unknown>): GqlOperation {
  const parser = new GqlParser(gqlLex(query), variables);
  let kind: 'query' | 'mutation' = 'query';
  const fragments = new Map<string, GqlField[]>();
  let selections: GqlField[] = [];
  const varDefs: GqlVarDef[] = [];
  let sawOperation = false;
  while (parser.peek() !== undefined) {
    const token = parser.peek();
    if (token !== undefined && token.kind === 'name' && (token.value === 'query' || token.value === 'mutation')) {
      kind = token.value as 'query' | 'mutation';
      parser.next();
      const next = parser.peek();
      if (next !== undefined && next.kind === 'name') parser.next();
      if (parser.peek()?.value === '(') varDefs.push(...parser.parseVariableDefinitions());
      selections = parser.parseSelectionSet();
      sawOperation = true;
      continue;
    }
    if (token !== undefined && token.kind === 'name' && token.value === 'fragment') {
      parser.next();
      const name = parser.expectName();
      parser.expect('on');
      parser.expectName();
      const fields = parser.parseSelectionSet();
      fragments.set(name, fields);
      continue;
    }
    if (token !== undefined && token.value === '{') {
      selections = parser.parseSelectionSet();
      sawOperation = true;
      continue;
    }
    parser.next();
  }
  if (!sawOperation) throw new Error('no operation found');
  for (const def of varDefs) {
    if (!variables.has(def.name) && def.defaultValue !== undefined) variables.set(def.name, def.defaultValue);
  }
  return { kind, fragments, selections, variables, varDefs };
}

function argValue(field: GqlField, name: string): unknown {
  const found = field.args.find((arg) => arg.name === name);
  return found === undefined ? undefined : found.value;
}

function stringArg(field: GqlField, name: string, fallback = ''): string {
  const value = argValue(field, name);
  return typeof value === 'string' ? value : fallback;
}

function intArg(field: GqlField, name: string, fallback = 0): number {
  const value = argValue(field, name);
  return typeof value === 'number' ? value : fallback;
}

// ---------------------------------------------------------------- GraphQL execution

const TYPE_FIELDS: Record<string, string[]> = {
  Viewer: ['login', 'id'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'title', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files'],
  IssueConnection: ['nodes', 'pageInfo'],
  PullRequestConnection: ['nodes', 'pageInfo'],
  IssueEdge: ['node'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
};

interface GqlCtx {
  repoById: (id: string) => RepoRec | null;
  errors: Array<{ message: string }>;
  isMutation: boolean;
}

function encodeCursor(number: number): string {
  return b64encode(`cursor:${number}`);
}

function decodeCursor(cursor: string): number {
  const text = Buffer.from(cursor, 'base64').toString('utf8');
  const match = /^cursor:(\d+)$/.exec(text);
  return match ? Number.parseInt(match[1] as string, 10) : 0;
}

function checkField(typeName: string, field: GqlField, ctx: GqlCtx): boolean {
  if (typeName === 'Query' || typeName === 'Mutation') return true;
  const known = TYPE_FIELDS[typeName];
  if (known === undefined) return true;
  if (known.includes(field.name)) return true;
  ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
  return false;
}

type AnyObj = Record<string, unknown>;

function resolveIssueFields(repo: RepoRec, issue: IssueRec, fields: GqlField[], ctx: GqlCtx): AnyObj {
  const out: AnyObj = {};
  for (const field of fields) {
    if (field.fragmentName !== null) continue;
    if (field.inlineType !== null) {
      if (field.inlineType === 'Issue') Object.assign(out, resolveIssueFields(repo, issue, field.selections, ctx));
      continue;
    }
    if (!checkField('Issue', field, ctx)) continue;
    if (field.name === 'id') out[field.alias] = globalId('issue', repo.owner, repo.name, issue.number);
    else if (field.name === 'number') out[field.alias] = issue.number;
    else if (field.name === 'title') out[field.alias] = issue.title;
    else if (field.name === 'state') out[field.alias] = issue.state === 'open' ? 'OPEN' : 'CLOSED';
    else if (field.name === 'body') out[field.alias] = issue.body;
  }
  return out;
}

function resolvePullFields(repo: RepoRec, pull: PullRec, fields: GqlField[], ctx: GqlCtx): AnyObj {
  const out: AnyObj = {};
  for (const field of fields) {
    if (field.fragmentName !== null) continue;
    if (field.inlineType !== null) {
      if (field.inlineType === 'PullRequest') Object.assign(out, resolvePullFields(repo, pull, field.selections, ctx));
      continue;
    }
    if (!checkField('PullRequest', field, ctx)) continue;
    if (field.name === 'id') out[field.alias] = globalId('pr', repo.owner, repo.name, pull.number);
    else if (field.name === 'number') out[field.alias] = pull.number;
    else if (field.name === 'title') out[field.alias] = pull.title;
    else if (field.name === 'state') out[field.alias] = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
    else if (field.name === 'merged') out[field.alias] = pull.merged;
    else if (field.name === 'headRefName') out[field.alias] = pull.headRef;
    else if (field.name === 'baseRefName') out[field.alias] = pull.baseRef;
    else if (field.name === 'mergeable') out[field.alias] = mergeableState(repo, pull);
    else if (field.name === 'files') {
      const first = intArg(field, 'first', 100);
      const headTip = refTip(repo, pull.headRef) ?? pull.headSha;
      const files = diffTrees(repo, commitTreeOf(repo, pull.baseSha), commitTreeOf(repo, headTip));
      // The suite asks files { nodes { path ... } }: the node fields live
      // under the nested `nodes` selection, not directly on `files`.
      const nodesField = field.selections.find((sel) => sel.name === 'nodes');
      const nodeSelections = nodesField !== undefined ? nodesField.selections : field.selections;
      const nodes = files.slice(0, first).map((file) => {
        const node: AnyObj = {};
        for (const sub of nodeSelections) {
          if (sub.name === 'path') node[sub.alias] = file.filename;
          if (sub.name === 'additions') node[sub.alias] = file.additions;
          if (sub.name === 'deletions') node[sub.alias] = file.deletions;
          if (sub.name === 'changeType') node[sub.alias] = file.status;
        }
        return node;
      });
      out[field.alias] = { nodes, pageInfo: { hasNextPage: files.length > first, endCursor: files.length > 0 ? encodeCursor(files.length) : null } };
    }
  }
  return out;
}

function resolveRepoFields(repo: RepoRec, fields: GqlField[], ctx: GqlCtx, op: GqlOperation): AnyObj {
  const out: AnyObj = {};
  for (const field of fields) {
    if (field.fragmentName !== null) {
      const frag = op.fragments.get(field.fragmentName);
      if (frag !== undefined) Object.assign(out, resolveRepoFields(repo, frag, ctx, op));
      continue;
    }
    if (field.inlineType !== null) {
      // `... on Repository { ... }`: the fragment itself has no name; resolve
      // its selections as Repository fields.
      if (field.inlineType === 'Repository') Object.assign(out, resolveRepoFields(repo, field.selections, ctx, op));
      continue;
    }
    if (!checkField('Repository', field, ctx)) continue;
    if (field.name === 'id') out[field.alias] = globalId('repo', repo.owner, repo.name);
    else if (field.name === 'databaseId') out[field.alias] = repo.id;
    else if (field.name === 'name') out[field.alias] = repo.name;
    else if (field.name === 'nameWithOwner') out[field.alias] = `${repo.owner}/${repo.name}`;
    else if (field.name === 'owner') {
      const ownerOut: AnyObj = {};
      for (const sub of field.selections) {
        if (sub.name === 'login') ownerOut[sub.alias] = repo.owner;
        else if (sub.name === 'id') ownerOut[sub.alias] = globalId('user', repo.owner);
      }
      out[field.alias] = ownerOut;
    } else if (field.name === 'defaultBranchRef') {
      const branchOut: AnyObj = {};
      for (const sub of field.selections) {
        if (sub.name === 'name') branchOut[sub.alias] = repo.defaultBranch;
      }
      out[field.alias] = branchOut;
    } else if (field.name === 'viewerPermission') out[field.alias] = 'ADMIN';
    else if (field.name === 'hasIssuesEnabled') out[field.alias] = true;
    else if (field.name === 'issue') {
      const number = intArg(field, 'number', 0);
      const issue = repo.issues.find((item) => item.number === number);
      out[field.alias] = issue === undefined ? null : resolveIssueFields(repo, issue, field.selections, ctx);
    } else if (field.name === 'issues') {
      const first = intArg(field, 'first', 100);
      const after = stringArg(field, 'after', '');
      const statesRaw = argValue(field, 'states');
      const states = Array.isArray(statesRaw) ? (statesRaw as unknown[]).map(String) : undefined;
      const orderBy = argValue(field, 'orderBy');
      let list = [...repo.issues];
      if (states !== undefined) list = list.filter((issue) => states.includes(issue.state === 'open' ? 'OPEN' : 'CLOSED'));
      if (orderBy !== null && typeof orderBy === 'object') {
        const direction = String((orderBy as Record<string, unknown>).direction ?? 'DESC');
        list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
      } else {
        list.sort((a, b) => b.number - a.number);
      }
      let startIndex = 0;
      if (after !== '') {
        const afterNumber = decodeCursor(after);
        const idx = list.findIndex((issue) => issue.number === afterNumber);
        if (idx >= 0) startIndex = idx + 1;
      }
      const page = list.slice(startIndex, startIndex + first);
      const nodesField = field.selections.find((sel) => sel.name === 'nodes');
      const nodeSelections = nodesField !== undefined ? nodesField.selections : [];
      out[field.alias] = {
        nodes: page.map((issue) => resolveIssueFields(repo, issue, nodeSelections, ctx)),
        pageInfo: {
          hasNextPage: startIndex + first < list.length,
          endCursor: page.length > 0 ? encodeCursor(page[page.length - 1]?.number ?? 0) : null,
        },
      };
      // Preserve nested pageInfo selections if requested on the connection itself.
      const pageInfoField = field.selections.find((sel) => sel.name === 'pageInfo');
      if (pageInfoField !== undefined) {
        const connection = out[field.alias] as AnyObj;
        const pageInfo: AnyObj = {};
        for (const sub of pageInfoField.selections) {
          if (sub.name === 'hasNextPage') pageInfo[sub.alias] = startIndex + first < list.length;
          else if (sub.name === 'endCursor') pageInfo[sub.alias] = page.length > 0 ? encodeCursor(page[page.length - 1]?.number ?? 0) : null;
        }
        connection.pageInfo = pageInfo;
      }
    } else if (field.name === 'pullRequests') {
      const first = intArg(field, 'first', 100);
      const list = [...repo.pulls].sort((a, b) => b.number - a.number);
      const page = list.slice(0, first);
      const nodesField = field.selections.find((sel) => sel.name === 'nodes');
      const nodeSelections = nodesField !== undefined ? nodesField.selections : [];
      out[field.alias] = {
        nodes: page.map((pull) => resolvePullFields(repo, pull, nodeSelections, ctx)),
        pageInfo: { hasNextPage: first < list.length, endCursor: page.length > 0 ? encodeCursor(page[page.length - 1]?.number ?? 0) : null },
      };
    } else if (field.name === 'pullRequest') {
      const number = intArg(field, 'number', 0);
      const pull = repo.pulls.find((item) => item.number === number);
      out[field.alias] = pull === undefined ? null : resolvePullFields(repo, pull, field.selections, ctx);
    }
  }
  return out;
}

function introspectionType(name: string): AnyObj | null {
  if (name === 'Issue') {
    return {
      name: 'Issue',
      kind: 'OBJECT',
      fields: ['id', 'number', 'title', 'state', 'body'].map((field) => ({ name: field, type: { name: field === 'number' ? 'Int' : 'String', kind: 'SCALAR' } })),
    };
  }
  if (name === 'PullRequest') {
    return {
      name: 'PullRequest',
      kind: 'OBJECT',
      fields: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'].map((field) => ({ name: field, type: { name: 'String', kind: 'SCALAR' } })),
    };
  }
  if (name === 'Repository') {
    return {
      name: 'Repository',
      kind: 'OBJECT',
      fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'].map((field) => ({
        name: field,
        type: { name: 'String', kind: 'SCALAR' },
      })),
    };
  }
  if (name === 'SearchType') {
    return { name: 'SearchType', kind: 'ENUM', enumValues: [{ name: 'ISSUE' }, { name: 'REPOSITORY' }, { name: 'USER' }] };
  }
  return null;
}

function executeQuery(op: GqlOperation, ctx: GqlCtx): AnyObj {
  const out: AnyObj = {};
  for (const field of op.selections) {
    if (field.fragmentName !== null) continue;
    if (field.name === 'viewer') {
      const viewerOut: AnyObj = {};
      for (const sub of field.selections) {
        if (sub.name === 'login') viewerOut[sub.alias] = VIEWER_LOGIN;
        else if (sub.name === 'id') viewerOut[sub.alias] = globalId('user', VIEWER_LOGIN);
        else ctx.errors.push({ message: `Cannot query field "${sub.name}" on type "Viewer".` });
      }
      out[field.alias] = viewerOut;
    } else if (field.name === 'repository') {
      const owner = stringArg(field, 'owner');
      const name = stringArg(field, 'name');
      const repo = findRepo(owner, name) ?? null;
      out[field.alias] = repo === null ? null : resolveRepoFields(repo, field.selections, ctx, op);
    } else if (field.name === 'node') {
      const id = stringArg(field, 'id');
      const decoded = decodeGlobalId(id);
      if (decoded === null) {
        out[field.alias] = null;
      } else if (decoded.kind === 'repo') {
        const repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        out[field.alias] = repo === null ? null : resolveRepoFields(repo, field.selections, ctx, op);
      } else if (decoded.kind === 'issue') {
        const repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        const issue = repo?.issues.find((item) => item.number === Number(decoded.parts[2]));
        out[field.alias] = issue === undefined || repo === null ? null : resolveIssueFields(repo, issue, field.selections, ctx);
      } else if (decoded.kind === 'pr') {
        const repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        const pull = repo?.pulls.find((item) => item.number === Number(decoded.parts[2]));
        out[field.alias] = pull === undefined || repo === null ? null : resolvePullFields(repo, pull, field.selections, ctx);
      } else {
        out[field.alias] = null;
      }
    } else if (field.name === '__type') {
      const name = stringArg(field, 'name');
      const type = introspectionType(name);
      const typeOut: AnyObj = {};
      for (const sub of field.selections) {
        if (sub.name === 'name') typeOut[sub.alias] = type?.name ?? null;
        else if (sub.name === 'kind') typeOut[sub.alias] = type?.kind ?? null;
        else if (sub.name === 'fields') {
          const all = (type?.fields as Array<Record<string, unknown>> | undefined) ?? [];
          typeOut[sub.alias] = all.map((entry) => {
            const fieldOut: AnyObj = {};
            for (const inner of sub.selections) {
              if (inner.name === 'name') fieldOut[inner.alias] = entry.name;
              else if (inner.name === 'type') {
                const typeOut2: AnyObj = {};
                for (const deeper of inner.selections) {
                  if (deeper.name === 'name') typeOut2[deeper.alias] = (entry.type as Record<string, unknown>).name;
                  else if (deeper.name === 'kind') typeOut2[deeper.alias] = (entry.type as Record<string, unknown>).kind;
                }
                fieldOut[inner.alias] = typeOut2;
              }
            }
            return fieldOut;
          });
        } else if (sub.name === 'enumValues') {
          const all = (type?.enumValues as Array<Record<string, unknown>> | undefined) ?? [];
          typeOut[sub.alias] = all.map((entry) => {
            const valueOut: AnyObj = {};
            for (const inner of sub.selections) {
              if (inner.name === 'name') valueOut[inner.alias] = entry.name;
            }
            return valueOut;
          });
        }
      }
      out[field.alias] = type;
    } else if (field.name === '__schema') {
      out[field.alias] = { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' } };
    } else {
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Query".` });
    }
  }
  return out;
}

function executeMutation(op: GqlOperation, ctx: GqlCtx): AnyObj {
  const out: AnyObj = {};
  for (const field of op.selections) {
    if (field.fragmentName !== null) continue;
    if (field.name === 'createIssue') {
      const input = (argValue(field, 'input') ?? {}) as Record<string, unknown>;
      const repoId = String(input.repositoryId ?? '');
      const repo = ctx.repoById(repoId);
      const result: AnyObj = {};
      if (repo === null) {
        result.issue = null;
      } else {
        const issue = createIssueRec(repo, String(input.title ?? ''), String(input.body ?? ''), []);
        result.issue = resolveIssueFields(repo, issue, field.selections.flatMap((sel) => (sel.name === 'issue' ? sel.selections : [])), ctx);
      }
      out[field.alias] = result;
    } else if (field.name === 'closeIssue') {
      const input = (argValue(field, 'input') ?? {}) as Record<string, unknown>;
      const issueId = String(input.issueId ?? '');
      const decoded = decodeGlobalId(issueId);
      let issue: IssueRec | undefined;
      let repo: RepoRec | null = null;
      if (decoded !== null && decoded.kind === 'issue') {
        repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        issue = repo?.issues.find((item) => item.number === Number(decoded.parts[2]));
      }
      if (issue !== undefined) issue.state = 'closed';
      const result: AnyObj = {};
      for (const sel of field.selections) {
        if (sel.name === 'issue' && issue !== undefined && repo !== null) result.issue = resolveIssueFields(repo, issue, sel.selections, ctx);
      }
      out[field.alias] = result;
    } else if (field.name === 'createPullRequest') {
      const input = (argValue(field, 'input') ?? {}) as Record<string, unknown>;
      const repoId = String(input.repositoryId ?? '');
      const repo = ctx.repoById(repoId);
      const headRef = String(input.headRefName ?? '');
      const baseRef = String(input.baseRefName ?? repo?.defaultBranch ?? 'main');
      const result: AnyObj = {};
      if (repo === null) {
        result.pullRequest = null;
      } else {
        const headTip = refTip(repo, headRef);
        const baseTip = refTip(repo, baseRef) ?? refTip(repo, repo.defaultBranch);
        if (headTip === undefined || baseTip === undefined) {
          result.pullRequest = null;
        } else {
          const pull = createPullRec(repo, String(input.title ?? ''), String(input.body ?? ''), headRef, baseRef, headTip, baseTip);
          result.pullRequest = resolvePullFields(repo, pull, field.selections.flatMap((sel) => (sel.name === 'pullRequest' ? sel.selections : [])), ctx);
        }
      }
      out[field.alias] = result;
    } else if (field.name === 'mergePullRequest') {
      const input = (argValue(field, 'input') ?? {}) as Record<string, unknown>;
      const prId = String(input.pullRequestId ?? '');
      const decoded = decodeGlobalId(prId);
      let pull: PullRec | undefined;
      let repo: RepoRec | null = null;
      if (decoded !== null && decoded.kind === 'pr') {
        repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        pull = repo?.pulls.find((item) => item.number === Number(decoded.parts[2]));
      }
      const result: AnyObj = {};
      if (pull !== undefined && repo !== null) {
        const mergeSha = doMerge(repo, pull);
        for (const sel of field.selections) {
          if (sel.name === 'pullRequest') result.pullRequest = resolvePullFields(repo, pull, sel.selections, ctx);
        }
        void mergeSha;
      }
      out[field.alias] = result;
    } else if (field.name === 'addComment') {
      const input = (argValue(field, 'input') ?? {}) as Record<string, unknown>;
      const subjectId = String(input.subjectId ?? '');
      const decoded = decodeGlobalId(subjectId);
      let comment: CommentRec | null = null;
      let repo: RepoRec | null = null;
      let issue: IssueRec | undefined;
      if (decoded !== null && decoded.kind === 'issue') {
        repo = findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
        issue = repo?.issues.find((item) => item.number === Number(decoded.parts[2]));
        if (issue !== undefined) {
          comment = { id: repo?.nextComment ?? 1, body: String(input.body ?? '') };
          if (repo !== null) repo.nextComment += 1;
          issue.comments.push(comment);
        }
      }
      const result: AnyObj = {};
      for (const sel of field.selections) {
        if (sel.name === 'commentEdge') {
          const edge: AnyObj = {};
          for (const inner of sel.selections) {
            if (inner.name === 'node' && comment !== null) {
              const node: AnyObj = {};
              for (const deeper of inner.selections) {
                if (deeper.name === 'id') node[deeper.alias] = globalId('comment', repo?.owner ?? '', repo?.name ?? '', issue?.number ?? 0, comment.id);
                else if (deeper.name === 'body') node[deeper.alias] = comment.body;
              }
              edge.node = node;
            }
          }
          result.commentEdge = edge;
        }
      }
      out[field.alias] = result;
    } else {
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Mutation".` });
    }
  }
  return out;
}

function repoByGlobalId(id: string): RepoRec | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'repo') return null;
  return findRepo(decoded.parts[0] as string, decoded.parts[1] as string) ?? null;
}

function runGraphqlOperation(bodyText: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return { errors: [{ message: 'malformed JSON body' }] };
  }
  const documents = Array.isArray(parsed) ? parsed : [parsed];
  const results: Record<string, unknown>[] = [];
  for (const document of documents) {
    const doc = document as Record<string, unknown>;
    const query = typeof doc.query === 'string' ? doc.query : '';
    const variablesRaw = doc.variables ?? {};
    const variables = new Map<string, unknown>();
    if (variablesRaw !== null && typeof variablesRaw === 'object') {
      for (const [key, value] of Object.entries(variablesRaw as Record<string, unknown>)) variables.set(key, value);
    }
    const ctx: GqlCtx = { repoById: repoByGlobalId, errors: [], isMutation: false };
    let data: AnyObj = {};
    try {
      const op = parseGqlDocument(query, variables);
      ctx.isMutation = op.kind === 'mutation';
      data = op.kind === 'mutation' ? executeMutation(op, ctx) : executeQuery(op, ctx);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
    }
    const result: Record<string, unknown> = { data };
    if (ctx.errors.length > 0) result.errors = ctx.errors;
    results.push(result);
  }
  return Array.isArray(parsed) ? { __batch: results } : results[0] as Record<string, unknown>;
}

// ---------------------------------------------------------------- MCP

interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required: string[];
  };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
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
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
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
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
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

function toolCanonicalName(name: string): string {
  const parts = name.split('__');
  return (parts[parts.length - 1] as string).toLowerCase();
}

function mcpResult(id: unknown, value: unknown, isError: boolean): Record<string, unknown> {
  const text = jsonText(value);
  return {
    jsonrpc: '2.0',
    id: id === undefined ? null : id,
    result: {
      content: [{ type: 'text', text }],
      structuredContent: value,
      isError,
    },
  };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error: { code, message } };
}

function mcpCallTool(toolName: string, args: Record<string, unknown>): { value: unknown; isError: boolean } | { rpcError: { code: number; message: string } } {
  const canonical = toolCanonicalName(toolName);
  const tool = MCP_TOOLS.find((candidate) => candidate.name === canonical);
  if (tool === undefined) return { rpcError: { code: -32602, message: `unknown tool: ${toolName}` } };
  for (const required of tool.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return { rpcError: { code: -32602, message: `missing required argument: ${required}` } };
    }
  }
  const owner = String(args.owner ?? '');
  const repoName = String(args.repo ?? args.repository ?? '');
  if (canonical === 'create_repo') {
    const name = String(args.name ?? '');
    if (name === '') return { rpcError: { code: -32602, message: 'missing required argument: name' } };
    if (findRepo(VIEWER_LOGIN, name) !== undefined) return { value: { error: 'Repository already exists' }, isError: true };
    const repo = createRepoRec(name, args.private === true, String(args.description ?? ''));
    return { value: repoView(repo), isError: false };
  }
  if (canonical === 'get_repo') {
    const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
    if (repo === undefined) return { value: { error: 'Not Found' }, isError: true };
    return { value: repoView(repo), isError: false };
  }
  if (canonical === 'create_issue') {
    const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
    if (repo === undefined) return { value: { error: 'Not Found' }, isError: true };
    const issue = createIssueRec(repo, String(args.title ?? ''), String(args.body ?? ''), []);
    return { value: issueView(repo, issue), isError: false };
  }
  if (canonical === 'list_issues') {
    const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
    if (repo === undefined) return { value: { error: 'Not Found' }, isError: true };
    const state = String(args.state ?? 'open');
    let list = [...repo.issues];
    if (state !== 'all') list = list.filter((issue) => issue.state === state);
    list.sort((a, b) => b.number - a.number);
    return { value: list.map((issue) => issueView(repo, issue)), isError: false };
  }
  if (canonical === 'create_pull_request') {
    const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
    if (repo === undefined) return { value: { error: 'Not Found' }, isError: true };
    const head = String(args.head ?? '');
    const base = String(args.base ?? repo.defaultBranch);
    const headTip = refTip(repo, head);
    const baseTip = refTip(repo, base) ?? refTip(repo, repo.defaultBranch);
    if (headTip === undefined || baseTip === undefined) return { value: { error: 'head or base branch does not exist' }, isError: true };
    const duplicate = repo.pulls.find((pull) => pull.headRef === head && pull.state === 'open');
    if (duplicate !== undefined) return { value: { error: 'a pull request already exists for this head branch' }, isError: true };
    const pull = createPullRec(repo, String(args.title ?? ''), String(args.body ?? ''), head, base, headTip, baseTip);
    return { value: pullView(repo, pull), isError: false };
  }
  if (canonical === 'merge_pull_request') {
    const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
    if (repo === undefined) return { value: { error: 'Not Found' }, isError: true };
    const number = Number(args.pull_number ?? args.pullNumber ?? 0);
    const pull = repo.pulls.find((item) => item.number === number);
    if (pull === undefined) return { value: { error: 'Not Found' }, isError: true };
    if (pull.state !== 'open') return { value: { error: 'pull request is not open' }, isError: true };
    const mergeSha = doMerge(repo, pull);
    if (mergeSha === null) return { value: { error: 'merge conflict' }, isError: true };
    return { value: { sha: mergeSha, merged: true, message: 'Pull Request successfully merged' }, isError: false };
  }
  return { rpcError: { code: -32602, message: `unknown tool: ${toolName}` } };
}

function handleMcp(ctx: RouteContext): void {
  const { req, res } = ctx;
  const method = req.method ?? 'POST';
  if (method === 'DELETE') {
    sendJson(res, 200, {});
    return;
  }
  if (method === 'GET') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(jsonText({ message: 'Method Not Allowed' }));
    return;
  }
  if (!authed(req)) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(jsonText({ error: { code: -32001, message: 'unauthorized' } }));
    return;
  }
  const text = ctx.body.toString('utf8');
  let request: unknown;
  try {
    request = JSON.parse(text);
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (request === null || typeof request !== 'object' || Array.isArray(request)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const message = request as Record<string, unknown>;
  const id = message.id === undefined ? null : message.id;
  const methodName = String(message.method ?? '');
  if (methodName === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
      },
    });
    return;
  }
  if (methodName === 'initialize') {
    const params = (message.params ?? {}) as Record<string, unknown>;
    const protocolVersion = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      },
    });
    return;
  }
  if (methodName === 'notifications/initialized' || methodName.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }
  if (methodName === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (methodName === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (methodName === 'tools/call') {
    const params = (message.params ?? {}) as Record<string, unknown>;
    const toolName = String(params.name ?? '');
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const outcome = mcpCallTool(toolName, args);
    if ('rpcError' in outcome) {
      sendJson(res, 200, mcpError(id, outcome.rpcError.code, outcome.rpcError.message));
      return;
    }
    sendJson(res, 200, mcpResult(id, outcome.value, outcome.isError));
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `method not found: ${methodName}`));
}

// ---------------------------------------------------------------- request routing

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
  const method = req.method ?? 'GET';
  try {
    if (url.pathname === '/healthz' && method === 'GET') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (url.pathname === '/api/graphql') {
      if (method !== 'POST') {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      if (!authed(req)) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(jsonText({ message: 'Requires authentication' }));
        return;
      }
      const body = await readBody(req);
      const result = runGraphqlOperation(body.toString('utf8'));
      if ((result as Record<string, unknown>).__batch !== undefined) {
        const batch = (result as Record<string, unknown>).__batch as Record<string, unknown>[];
        sendJson(res, 200, batch);
        return;
      }
      sendJson(res, 200, result);
      return;
    }
    if (url.pathname === '/mcp') {
      const body = await readBody(req);
      handleMcp({ req, res, url, body, json: null, jsonError: false });
      return;
    }
    const gitPath = gitRepoPath(url);
    if (gitPath !== null) {
      const repo = gitPath.owner === VIEWER_LOGIN ? findRepo(gitPath.owner, gitPath.repo) : undefined;
      if (repo === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET' && gitPath.rest === '/info/refs') {
        const service = url.searchParams.get('service') ?? '';
        const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2' && service === 'git-upload-pack';
        const body = wantsV2 ? v2Advertisement() : v0Advertisement(repo, service === 'git-receive-pack' ? 'git-receive-pack' : 'git-upload-pack');
        const contentType = service === 'git-receive-pack' ? 'application/x-git-receive-pack-advertisement' : 'application/x-git-upload-pack-advertisement';
        sendBuffer(res, 200, body, contentType);
        return;
      }
      if (method === 'POST' && gitPath.rest === '/git-upload-pack') {
        const body = await readBody(req);
        const useV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
        const out = handleUploadPack(repo, body, useV2);
        sendBuffer(res, 200, out, 'application/x-git-upload-pack-result');
        return;
      }
      if (method === 'POST' && gitPath.rest === '/git-receive-pack') {
        const body = await readBody(req);
        const out = handleReceivePack(repo, body);
        sendBuffer(res, 200, out, 'application/x-git-receive-pack-result');
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    if (url.pathname.startsWith('/api/v3')) {
      if (!authed(req)) {
        res.writeHead(401, { 'content-type': 'application/json', 'x-github-request-id': `forge-${requestCounter}` });
        requestCounter += 1;
        res.end(jsonText({ message: 'Requires authentication' }));
        return;
      }
      const body = await readBody(req);
      const ctx: RouteContext = { req, res, url, body, json: null, jsonError: false };
      const handled = restHandle(ctx);
      if (!handled) sendJsonError(res, 404, 'Not Found');
      return;
    }
    sendJsonError(res, 404, 'Not Found');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    try {
      if (!res.headersSent) sendJsonError(res, 500, message);
    } catch {
      // Response already in flight; nothing further to do.
    }
  }
}

// ---------------------------------------------------------------- startup

const server = createServer((req, res) => {
  void handleRequest(req, res);
});

function postJson(target: string, payload: unknown): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const targetUrl = new URL(target);
    const payloadText = jsonText(payload);
    const request = requestHttp(
      {
        hostname: targetUrl.hostname,
        port: targetUrl.port,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payloadText) },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      },
    );
    request.on('error', reject);
    request.end(payloadText);
  });
}

function fetchText(target: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const targetUrl = new URL(target);
    const request = getHttp(targetUrl, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    request.on('error', reject);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollDone(envUrl: string): Promise<void> {
  for (;;) {
    try {
      const text = await fetchText(`${envUrl}/done`);
      const parsed: unknown = JSON.parse(text);
      if (parsed !== null && typeof parsed === 'object' && (parsed as Record<string, unknown>).done === true) return;
    } catch {
      // Transient fetch failure: keep polling.
    }
    await sleep(500);
  }
}

const portEnv = process.env.PORT;
const listenPort = portEnv !== undefined && portEnv !== '' ? Number.parseInt(portEnv, 10) : 0;

server.listen(listenPort, '127.0.0.1', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : listenPort;
  console.log(`forge listening on 127.0.0.1:${port}`);
  const envUrl = process.env.MAKEFUN_ENV_URL;
  if (envUrl !== undefined && envUrl !== '') {
    void (async () => {
      try {
        await postJson(`${envUrl}/register`, { port });
        await pollDone(envUrl);
        server.close(() => process.exit(0));
      } catch (err) {
        console.error(`register failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    })();
  }
});
