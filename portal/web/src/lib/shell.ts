// A mongosh-compatible command parser for the portal shell.
//
// Commands are parsed in the browser into structured operations that the
// portal API validates and executes as the user's MongoDB identity. No
// JavaScript is evaluated anywhere: only a fixed grammar of mongosh-style
// statements is recognised.

import { shellToExtJSON } from './ejson';

export type ShellCommand =
  | { kind: 'help' }
  | { kind: 'showDbs' }
  | { kind: 'showCollections' }
  | { kind: 'use'; db: string }
  | { kind: 'currentDb' }
  | { kind: 'dbStats' }
  | { kind: 'clear' }
  | { kind: 'find'; coll: string; filter: string; projection: string; sort: string; limit?: number; skip?: number; one: boolean }
  | { kind: 'count'; coll: string; filter: string }
  | { kind: 'estimatedCount'; coll: string }
  | { kind: 'aggregate'; coll: string; pipeline: string }
  | { kind: 'getIndexes'; coll: string }
  | { kind: 'collStats'; coll: string }
  | { kind: 'insertOne'; coll: string; document: string }
  | { kind: 'deleteOne'; coll: string; id: unknown }
  | { kind: 'replaceOne'; coll: string; id: unknown; document: string }
  | { kind: 'createIndex'; coll: string; keys: string; options: string }
  | { kind: 'dropIndex'; coll: string; name: string }
  | { kind: 'drop'; coll: string }
  | { kind: 'createCollection'; name: string };

export class ShellSyntaxError extends Error {}

const COLLECTION_METHODS = new Set([
  'find', 'findOne', 'countDocuments', 'count', 'estimatedDocumentCount', 'aggregate', 'getIndexes', 'stats',
  'insertOne', 'deleteOne', 'replaceOne', 'createIndex', 'dropIndex', 'drop',
]);

const UNSUPPORTED: Record<string, string> = {
  updateOne: 'use replaceOne({_id: …}, document) or the document editor',
  updateMany: 'bulk updates are not available in the portal shell',
  deleteMany: 'bulk deletes are not available in the portal shell',
  insertMany: 'insert documents one at a time with insertOne',
  findOneAndUpdate: 'not available in the portal shell',
  findOneAndDelete: 'not available in the portal shell',
  bulkWrite: 'not available in the portal shell',
  mapReduce: 'server-side JavaScript is not permitted',
  eval: 'server-side JavaScript is not permitted',
  runCommand: 'arbitrary commands are not permitted; use the dedicated operations',
  adminCommand: 'arbitrary commands are not permitted',
  dropDatabase: 'not available in the portal shell',
  createUser: 'user administration is not available in the portal',
  dropUser: 'user administration is not available in the portal',
};

export const SHELL_HELP = `Portal shell — mongosh-style commands executed through the portal API as your MongoDB user.

  show dbs | show databases          list databases
  show collections                   list collections in the current database
  use <db>                           switch database
  db                                 print the current database
  db.stats()                         database statistics
  db.createCollection("name")        create a collection (SRE)
  db.<coll>.find(filter, projection).sort({...}).skip(n).limit(n)
  db.<coll>.findOne(filter, projection)
  db.<coll>.countDocuments(filter)   db.<coll>.estimatedDocumentCount()
  db.<coll>.aggregate([ ...stages ])
  db.<coll>.getIndexes()             db.<coll>.stats()
  db.<coll>.insertOne(doc)           (SRE)
  db.<coll>.replaceOne({_id: …}, doc) (SRE)
  db.<coll>.deleteOne({_id: …})      (SRE, confirmation required)
  db.<coll>.createIndex(keys, opts)  (SRE)
  db.<coll>.dropIndex("name")        (SRE, confirmation required)
  db.<coll>.drop()                   (SRE, confirmation required)
  db.getCollection("name").<method>(…) for names that are not identifiers
  cls                                clear the screen

Values may use shell helpers: ObjectId("…"), ISODate("…"), NumberLong(…), NumberDecimal("…"), UUID("…").
Server-side JavaScript ($where, $function, $accumulator), and $out/$merge for developers, are rejected.`;

/** Parses one shell statement. */
export function parseShell(input: string): ShellCommand {
  const src = input.trim().replace(/;\s*$/, '');
  if (!src) throw new ShellSyntaxError('Empty command');
  if (src === 'help' || src === 'help()') return { kind: 'help' };
  if (src === 'cls' || src === 'clear') return { kind: 'clear' };
  if (src === 'db') return { kind: 'currentDb' };
  if (/^show\s+(dbs|databases)$/.test(src)) return { kind: 'showDbs' };
  if (/^show\s+(collections|tables)$/.test(src)) return { kind: 'showCollections' };
  const use = /^use\s+([^\s/\\. "$*<>:|?]+)$/.exec(src);
  if (use) return { kind: 'use', db: use[1] };

  if (!src.startsWith('db.')) throw new ShellSyntaxError('Commands must start with "db.", "show", or "use". Type help for the list.');
  let rest = src.slice(3);

  // db-level methods
  const dbCall = /^(stats|getCollectionNames|createCollection|getName)\s*\(/.exec(rest);
  if (dbCall) {
    const { args, end } = readCall(rest, dbCall[0].length - 1);
    if (rest.slice(end).trim()) throw new ShellSyntaxError('Unexpected text after ' + dbCall[1] + '()');
    switch (dbCall[1]) {
      case 'stats':
        return { kind: 'dbStats' };
      case 'getCollectionNames':
        return { kind: 'showCollections' };
      case 'getName':
        return { kind: 'currentDb' };
      case 'createCollection': {
        const [name] = parseArgs(args);
        if (typeof name !== 'string') throw new ShellSyntaxError('createCollection expects a collection name string');
        return { kind: 'createCollection', name };
      }
    }
  }

  // Collection reference: db.getCollection("x") or db.a.b.c
  let coll: string;
  const gc = /^getCollection\s*\(/.exec(rest);
  if (gc) {
    const { args, end } = readCall(rest, gc[0].length - 1);
    const [name] = parseArgs(args);
    if (typeof name !== 'string') throw new ShellSyntaxError('getCollection expects a collection name string');
    coll = name;
    rest = rest.slice(end);
    if (!rest.startsWith('.')) throw new ShellSyntaxError('Expected a method call after getCollection(…)');
    rest = rest.slice(1);
  } else {
    // Collection names may contain dots; the method is the first segment
    // that is a known method name followed by "(".
    const parts: string[] = [];
    for (;;) {
      const m = /^([A-Za-z_$][\w$-]*)/.exec(rest);
      if (!m) throw new ShellSyntaxError('Expected a collection name after "db."');
      const after = rest.slice(m[0].length).trimStart();
      if (after.startsWith('(') && parts.length === 0) {
        if (UNSUPPORTED[m[1]]) throw new ShellSyntaxError(`db.${m[1]}() is not supported: ${UNSUPPORTED[m[1]]}`);
        throw new ShellSyntaxError(`Unknown database method db.${m[1]}(). Type help for supported commands.`);
      }
      if (after.startsWith('(')) {
        if (UNSUPPORTED[m[1]]) throw new ShellSyntaxError(`${m[1]}() is not supported: ${UNSUPPORTED[m[1]]}`);
        if (COLLECTION_METHODS.has(m[1])) break;
        throw new ShellSyntaxError(`Unknown method ${m[1]}(). Type help for supported commands.`);
      }
      parts.push(m[1]);
      rest = rest.slice(m[0].length);
      if (!rest.startsWith('.')) throw new ShellSyntaxError('Expected a method call such as .find()');
      rest = rest.slice(1);
    }
    coll = parts.join('.');
  }

  const mm = /^([A-Za-z]+)\s*\(/.exec(rest);
  if (!mm) throw new ShellSyntaxError('Expected a method call');
  const method = mm[1];
  if (UNSUPPORTED[method]) throw new ShellSyntaxError(`${method}() is not supported: ${UNSUPPORTED[method]}`);
  if (!COLLECTION_METHODS.has(method)) throw new ShellSyntaxError(`Unknown method ${method}(). Type help for supported commands.`);
  const call = readCall(rest, mm[0].length - 1);
  const args = parseArgs(call.args);
  const chain = parseChain(rest.slice(call.end));

  const doc = (v: unknown, what: string): string => {
    if (v === undefined) return '';
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new ShellSyntaxError(`${what} must be a document`);
    return JSON.stringify(v);
  };
  const noChain = () => {
    if (chain.length) throw new ShellSyntaxError(`.${chain[0].name}() cannot be chained after ${method}()`);
  };

  switch (method) {
    case 'find':
    case 'findOne': {
      const cmd: ShellCommand = { kind: 'find', coll, filter: doc(args[0], 'filter'), projection: doc(args[1], 'projection'), sort: '', one: method === 'findOne' };
      for (const c of chain) {
        if (method === 'findOne') throw new ShellSyntaxError('findOne() does not support chained methods');
        switch (c.name) {
          case 'sort':
            cmd.sort = doc(c.args[0], 'sort');
            break;
          case 'limit':
            cmd.limit = int(c.args[0], 'limit');
            break;
          case 'skip':
            cmd.skip = int(c.args[0], 'skip');
            break;
          case 'projection':
            cmd.projection = doc(c.args[0], 'projection');
            break;
          case 'pretty':
          case 'toArray':
            break;
          case 'count':
            return { kind: 'count', coll, filter: cmd.filter };
          default:
            throw new ShellSyntaxError(`.${c.name}() is not supported on find()`);
        }
      }
      return cmd;
    }
    case 'countDocuments':
    case 'count':
      noChain();
      return { kind: 'count', coll, filter: doc(args[0], 'filter') };
    case 'estimatedDocumentCount':
      noChain();
      return { kind: 'estimatedCount', coll };
    case 'aggregate': {
      for (const c of chain) if (c.name !== 'toArray' && c.name !== 'pretty') throw new ShellSyntaxError(`.${c.name}() is not supported on aggregate()`);
      const p = args[0];
      if (!Array.isArray(p)) throw new ShellSyntaxError('aggregate expects an array of stages');
      return { kind: 'aggregate', coll, pipeline: JSON.stringify(p) };
    }
    case 'getIndexes':
      noChain();
      return { kind: 'getIndexes', coll };
    case 'stats':
      noChain();
      return { kind: 'collStats', coll };
    case 'insertOne':
      noChain();
      return { kind: 'insertOne', coll, document: doc(args[0], 'document') || bad('insertOne expects a document') };
    case 'deleteOne':
      noChain();
      return { kind: 'deleteOne', coll, id: idFilter(args[0], 'deleteOne') };
    case 'replaceOne':
      noChain();
      return { kind: 'replaceOne', coll, id: idFilter(args[0], 'replaceOne'), document: doc(args[1], 'replacement') || bad('replaceOne expects a replacement document') };
    case 'createIndex':
      noChain();
      return { kind: 'createIndex', coll, keys: doc(args[0], 'keys') || bad('createIndex expects a key document'), options: doc(args[1], 'options') };
    case 'dropIndex': {
      noChain();
      if (typeof args[0] !== 'string') throw new ShellSyntaxError('dropIndex expects the index name as a string');
      return { kind: 'dropIndex', coll, name: args[0] };
    }
    case 'drop':
      noChain();
      return { kind: 'drop', coll };
  }
  throw new ShellSyntaxError(`Unknown method ${method}()`);
}

function bad(msg: string): never {
  throw new ShellSyntaxError(msg);
}

function int(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) throw new ShellSyntaxError(`${what} expects a non-negative integer`);
  return v;
}

/** Single-document writes are addressed by _id only, as in the document editor. */
function idFilter(v: unknown, method: string): unknown {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new ShellSyntaxError(`${method} expects a filter of the form {_id: …}`);
  const keys = Object.keys(v);
  if (keys.length !== 1 || keys[0] !== '_id') throw new ShellSyntaxError(`${method} in the portal shell only accepts a filter on _id`);
  return (v as Record<string, unknown>)._id;
}

/** Reads a balanced (...) call starting at the "(" index; returns inner text and end index. */
function readCall(s: string, open: number): { args: string; end: number } {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'") {
      i = skipString(s, i);
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) {
        if (c !== ')') throw new ShellSyntaxError('Unbalanced brackets');
        return { args: s.slice(open + 1, i), end: i + 1 };
      }
    }
  }
  throw new ShellSyntaxError('Missing closing parenthesis');
}

function skipString(s: string, i: number): number {
  const q = s[i];
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') j++;
    else if (s[j] === q) return j;
  }
  throw new ShellSyntaxError('Unterminated string');
}

function parseChain(s: string): { name: string; args: unknown[] }[] {
  const out: { name: string; args: unknown[] }[] = [];
  let rest = s.trim();
  while (rest) {
    const m = /^\.\s*([A-Za-z]+)\s*\(/.exec(rest);
    if (!m) throw new ShellSyntaxError(`Unexpected text: ${rest.slice(0, 30)}`);
    const call = readCall(rest, m[0].length - 1);
    out.push({ name: m[1], args: parseArgs(call.args) });
    rest = rest.slice(call.end).trim();
  }
  return out;
}

/** Parses comma-separated shell arguments (relaxed JSON with shell helpers). */
export function parseArgs(text: string): unknown[] {
  const t = text.trim();
  if (!t) return [];
  const converted = shellToExtJSON(`[${t}]`);
  try {
    const v: unknown = JSON.parse(converted);
    if (!Array.isArray(v)) throw new Error('not an array');
    return v;
  } catch {
    throw new ShellSyntaxError('Arguments must be JSON values (documents, arrays, strings or numbers); JavaScript expressions are not evaluated');
  }
}
