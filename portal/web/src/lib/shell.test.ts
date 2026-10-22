import { describe, expect, it } from 'vitest';
import { parseShell, ShellSyntaxError } from './shell';

describe('parseShell', () => {
  it('parses navigation commands', () => {
    expect(parseShell('show dbs')).toEqual({ kind: 'showDbs' });
    expect(parseShell('show collections;')).toEqual({ kind: 'showCollections' });
    expect(parseShell('use app')).toEqual({ kind: 'use', db: 'app' });
    expect(parseShell('db')).toEqual({ kind: 'currentDb' });
    expect(parseShell('db.stats()')).toEqual({ kind: 'dbStats' });
  });

  it('parses find with chained cursor methods and shell helpers', () => {
    const c = parseShell('db.orders.find({status: "A", _id: ObjectId("507f1f77bcf86cd799439011")}, {total: 1}).sort({_id: -1}).skip(5).limit(10).pretty()');
    expect(c).toEqual({
      kind: 'find',
      coll: 'orders',
      filter: '{"status":"A","_id":{"$oid":"507f1f77bcf86cd799439011"}}',
      projection: '{"total":1}',
      sort: '{"_id":-1}',
      skip: 5,
      limit: 10,
      one: false,
    });
  });

  it('supports dotted collection names and getCollection', () => {
    expect(parseShell('db.orders.archive.countDocuments({})')).toEqual({ kind: 'count', coll: 'orders.archive', filter: '{}' });
    expect(parseShell('db.getCollection("my-coll").findOne()')).toMatchObject({ kind: 'find', coll: 'my-coll', one: true });
  });

  it('parses aggregate and index commands', () => {
    expect(parseShell('db.o.aggregate([{$match: {a: 1}}, {$count: "n"}])')).toEqual({
      kind: 'aggregate', coll: 'o', pipeline: '[{"$match":{"a":1}},{"$count":"n"}]',
    });
    expect(parseShell('db.o.createIndex({a: 1}, {unique: true})')).toEqual({ kind: 'createIndex', coll: 'o', keys: '{"a":1}', options: '{"unique":true}' });
    expect(parseShell("db.o.dropIndex('a_1')")).toEqual({ kind: 'dropIndex', coll: 'o', name: 'a_1' });
    expect(parseShell('db.o.getIndexes()')).toEqual({ kind: 'getIndexes', coll: 'o' });
  });

  it('restricts single-document writes to _id filters', () => {
    expect(parseShell('db.o.deleteOne({_id: 5})')).toEqual({ kind: 'deleteOne', coll: 'o', id: 5 });
    expect(() => parseShell('db.o.deleteOne({status: "x"})')).toThrow(ShellSyntaxError);
    expect(parseShell('db.o.insertOne({a: 1})')).toEqual({ kind: 'insertOne', coll: 'o', document: '{"a":1}' });
  });

  it('never evaluates JavaScript and rejects unsupported operations', () => {
    for (const bad of [
      'db.o.find({a: 1 + 1})',
      'db.o.find(function(){ return true })',
      'db.o.updateMany({}, {$set: {a: 1}})',
      'db.o.deleteMany({})',
      'db.runCommand({dropDatabase: 1})',
      'db.dropDatabase()',
      'db.o.mapReduce()',
      'while(true){}',
      'db.o.find().forEach(printjson)',
      'db.o.find({}).limit(-1)',
    ]) {
      expect(() => parseShell(bad), bad).toThrow(ShellSyntaxError);
    }
  });
});
