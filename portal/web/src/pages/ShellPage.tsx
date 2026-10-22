import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { Alert, Button, Content, PageSection, TextInput, Title } from '@patternfly/react-core';
import { api, ApiError, errorMessage, nsPath, enc } from '../api/client';
import { useSession } from '../api/hooks';
import type { CollectionInfo, DatabaseInfo, DocPage, EJSONDocument, QueryResponse } from '../api/types';
import { ConfirmDialog } from '../components/Dialogs';
import { DocumentView } from '../components/DocumentView';
import { formatBytes } from '../lib/ejson';
import { parseShell, SHELL_HELP, ShellSyntaxError, type ShellCommand } from '../lib/shell';

interface Entry {
  id: number;
  prompt: string;
  input: string;
  output?: ReactNode;
  error?: string;
}

interface PendingConfirm {
  title: string;
  body: ReactNode;
  typeToConfirm?: string;
  run: () => Promise<ReactNode>;
  entryId: number;
}

const DEFAULT_LIMIT = 20;

function idToken(id: unknown): string {
  const json = JSON.stringify({ _id: id });
  const bytes = new TextEncoder().encode(json);
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function Docs({ docs }: { docs: EJSONDocument[] }) {
  if (docs.length === 0) return <span className="portal-shell-muted">(no documents)</span>;
  return (
    <>
      {docs.map((d, i) => (
        <div key={i} className="portal-shell-doc">
          <DocumentView doc={d} expandDepth={2} />
        </div>
      ))}
    </>
  );
}

function pageOutput(page: DocPage): ReactNode {
  return (
    <>
      <Docs docs={page.documents} />
      <div className="portal-shell-muted">
        {page.documents.length} document{page.documents.length === 1 ? '' : 's'} · {page.elapsedMs} ms
        {page.hasMore && ' · more results available: add .skip()/.limit() or refine the filter'}
        {page.truncated && ' · truncated by response size limit'}
      </div>
    </>
  );
}

const json = (v: unknown) => <pre className="portal-shell-pre">{JSON.stringify(v, null, 2)}</pre>;

export function ShellPage() {
  const [params] = useSearchParams();
  const session = useSession();
  const [db, setDb] = useState(params.get('db') || 'test');
  const [input, setInput] = useState('');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [history, setHistory] = useState<string[]>([]);
  const [histPos, setHistPos] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<PendingConfirm>();
  const nextId = useRef(1);
  const confirmed = useRef(false);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const canWrite = session.data?.canWrite ?? false;

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: 'end' });
  }, [entries]);

  const update = (id: number, patch: Partial<Entry>) => setEntries((es) => es.map((e) => (e.id === id ? { ...e, ...patch } : e)));

  const query = (coll: string, body: object) => api<QueryResponse>(`${nsPath(db, coll)}/query`, { method: 'POST', body });

  const requireWrite = () => {
    if (!canWrite) throw new ApiError(403, 'portal_role_forbidden', 'Your portal role is read-only; this command requires SRE access');
  };

  const execute = async (cmd: ShellCommand, entryId: number): Promise<ReactNode | null> => {
    switch (cmd.kind) {
      case 'help':
        return <pre className="portal-shell-pre">{SHELL_HELP}</pre>;
      case 'clear':
        setEntries([]);
        return null;
      case 'currentDb':
        return db;
      case 'use':
        setDb(cmd.db);
        return `switched to db ${cmd.db}`;
      case 'showDbs': {
        const r = await api<{ databases: DatabaseInfo[]; source: string }>('/databases');
        return (
          <pre className="portal-shell-pre">
            {r.databases.map((d) => `${d.name.padEnd(28)} ${r.source === 'privileges' ? '' : formatBytes(d.sizeOnDisk)}`).join('\n') || '(none)'}
          </pre>
        );
      }
      case 'showCollections': {
        const r = await api<{ collections: CollectionInfo[] }>(`${nsPath(db)}/collections`);
        return <pre className="portal-shell-pre">{r.collections.map((c) => c.name).join('\n') || '(none)'}</pre>;
      }
      case 'dbStats': {
        const r = await api<{ stats: unknown }>(`${nsPath(db)}/stats`);
        return json(r.stats);
      }
      case 'collStats': {
        const r = await api<{ stats: unknown }>(`${nsPath(db, cmd.coll)}/stats`);
        return json(r.stats);
      }
      case 'estimatedCount': {
        const r = await api<{ stats: { count?: unknown } }>(`${nsPath(db, cmd.coll)}/stats`);
        return json(r.stats.count);
      }
      case 'find': {
        const r = await query(cmd.coll, {
          operation: cmd.one ? 'findOne' : 'find',
          filter: cmd.filter,
          projection: cmd.projection,
          sort: cmd.sort,
          limit: cmd.one ? 1 : cmd.limit || DEFAULT_LIMIT,
          skip: cmd.skip,
        });
        if (cmd.one) return r.page?.documents[0] ? <Docs docs={[r.page.documents[0]]} /> : 'null';
        return r.page ? pageOutput(r.page) : null;
      }
      case 'count': {
        const r = await query(cmd.coll, { operation: 'countDocuments', filter: cmd.filter });
        return `${r.count}${r.countCapped ? '+' : ''}`;
      }
      case 'aggregate': {
        const r = await query(cmd.coll, { operation: 'aggregate', pipeline: cmd.pipeline, limit: DEFAULT_LIMIT });
        return r.page ? pageOutput(r.page) : null;
      }
      case 'getIndexes': {
        const r = await api<{ indexes: unknown[] }>(`${nsPath(db, cmd.coll)}/indexes`);
        return json(r.indexes);
      }
      case 'insertOne': {
        requireWrite();
        const r = await api<{ insertedId: unknown }>(`${nsPath(db, cmd.coll)}/documents`, { method: 'POST', body: { document: cmd.document } });
        return json({ acknowledged: true, insertedId: r.insertedId });
      }
      case 'replaceOne': {
        requireWrite();
        const r = await api(`${nsPath(db, cmd.coll)}/documents/${enc(idToken(cmd.id))}`, { method: 'PUT', body: { document: cmd.document } });
        return json(r);
      }
      case 'createIndex': {
        requireWrite();
        const r = await api<{ name: string }>(`${nsPath(db, cmd.coll)}/indexes`, { method: 'POST', body: { keys: cmd.keys, options: cmd.options } });
        return JSON.stringify(r.name);
      }
      case 'createCollection': {
        requireWrite();
        await api(`${nsPath(db)}/collections`, { method: 'POST', body: { name: cmd.name } });
        return json({ ok: 1 });
      }
      case 'deleteOne':
        requireWrite();
        setConfirm({
          entryId,
          title: 'Delete document',
          body: `Delete the document with _id ${JSON.stringify(cmd.id)} from ${db}.${cmd.coll}?`,
          run: async () => json(await api(`${nsPath(db, cmd.coll)}/documents/${enc(idToken(cmd.id))}`, { method: 'DELETE', headers: { 'X-Confirm': 'delete' } })),
        });
        return <span className="portal-shell-muted">awaiting confirmation…</span>;
      case 'dropIndex':
        requireWrite();
        setConfirm({
          entryId,
          title: 'Drop index',
          body: `Drop index ${cmd.name} on ${db}.${cmd.coll}?`,
          typeToConfirm: cmd.name,
          run: async () => json(await api(`${nsPath(db, cmd.coll)}/indexes/${enc(cmd.name)}`, { method: 'DELETE', headers: { 'X-Confirm': cmd.name } })),
        });
        return <span className="portal-shell-muted">awaiting confirmation…</span>;
      case 'drop':
        requireWrite();
        setConfirm({
          entryId,
          title: 'Drop collection',
          body: `Permanently drop ${db}.${cmd.coll} with all documents and indexes?`,
          typeToConfirm: cmd.coll,
          run: async () => {
            await api(nsPath(db, cmd.coll), { method: 'DELETE', headers: { 'X-Confirm': cmd.coll } });
            return 'true';
          },
        });
        return <span className="portal-shell-muted">awaiting confirmation…</span>;
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = input.trim();
    if (!text || busy) return;
    setInput('');
    setHistory((h) => (h[h.length - 1] === text ? h : [...h.slice(-99), text]));
    setHistPos(-1);
    const id = nextId.current++;
    setEntries((es) => [...es, { id, prompt: `${db}>`, input: text }]);
    setBusy(true);
    try {
      const cmd = parseShell(text);
      const out = await execute(cmd, id);
      if (out !== null) update(id, { output: out });
    } catch (err) {
      update(id, { error: err instanceof ShellSyntaxError ? `SyntaxError: ${err.message}` : errorMessage(err) });
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp' && history.length) {
      e.preventDefault();
      const pos = histPos < 0 ? history.length - 1 : Math.max(0, histPos - 1);
      setHistPos(pos);
      setInput(history[pos]);
    } else if (e.key === 'ArrowDown' && histPos >= 0) {
      e.preventDefault();
      const pos = histPos + 1;
      if (pos >= history.length) {
        setHistPos(-1);
        setInput('');
      } else {
        setHistPos(pos);
        setInput(history[pos]);
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setEntries([]);
    }
  };

  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-sm">
        Shell
      </Title>
      <Content component="p" className="pf-v6-u-mb-md">
        mongosh-style commands, executed through the portal as <strong>{session.data?.mongoUser}</strong>. Type <code>help</code> for the
        supported commands. JavaScript is not evaluated.
      </Content>
      {!canWrite && <Alert variant="info" isInline isPlain className="pf-v6-u-mb-sm" title="Your portal role is read-only: write commands are rejected." />}
      <div className="portal-shell" onClick={() => inputRef.current?.focus()}>
        <div role="log" aria-live="polite" aria-label="Shell output">
          {entries.map((en) => (
            <div key={en.id} className="portal-shell-entry">
              <div>
                <span className="portal-shell-prompt">{en.prompt}</span> {en.input}
              </div>
              {en.output !== undefined && <div className="portal-shell-out">{en.output}</div>}
              {en.error && <div className="portal-shell-error">{en.error}</div>}
            </div>
          ))}
        </div>
        <form onSubmit={(e) => void submit(e)} className="portal-shell-input" aria-label="Shell command">
          <label htmlFor="shell-input" className="portal-shell-prompt">
            {db}&gt;
          </label>
          <TextInput
            id="shell-input"
            ref={inputRef}
            value={input}
            onChange={(_e, v) => setInput(v)}
            onKeyDown={onKeyDown}
            autoComplete="off"
            spellCheck={false}
            aria-label="Command"
            placeholder='db.collection.find({ field: "value" })'
            isDisabled={busy}
            autoFocus
          />
          <Button type="submit" variant="primary" isDisabled={busy || !input.trim()} isLoading={busy}>
            Run
          </Button>
        </form>
        <div ref={endRef} />
      </div>
      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          body={confirm.body}
          typeToConfirm={confirm.typeToConfirm}
          confirmLabel={confirm.title}
          onConfirm={async () => {
            confirmed.current = true;
            try {
              const out = await confirm.run();
              update(confirm.entryId, { output: out });
            } catch (err) {
              update(confirm.entryId, { output: undefined, error: errorMessage(err) });
            }
          }}
          onClose={() => {
            if (!confirmed.current) update(confirm.entryId, { output: <span className="portal-shell-muted">cancelled</span> });
            confirmed.current = false;
            setConfirm(undefined);
          }}
        />
      )}
    </PageSection>
  );
}
