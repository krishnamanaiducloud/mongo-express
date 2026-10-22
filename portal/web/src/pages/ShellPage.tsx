import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import {
  Alert,
  Button,
  Checkbox,
  Content,
  Flex,
  Form,
  FormGroup,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  Spinner,
  TextArea,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { useSession } from '../api/hooks';
import type { DisplayError, DisplayValue } from '../sandbox/display';
import { ShellBroker, type ConfirmDecision, type ConfirmRequest } from '../shell/broker';
import { ShellError, ShellValue } from '../shell/ShellOutput';

interface Entry {
  id: number;
  prompt: string;
  code: string;
  outputs: DisplayValue[];
  error?: DisplayError;
  running: boolean;
}

type Status = 'starting' | 'ready' | 'failed';

export function ShellPage() {
  const [params] = useSearchParams();
  const session = useSession();
  // UI hint: whether RBAC allows any change anywhere. Each operation is
  // checked by the portal against its namespace and by MongoDB.
  const perms = session.data?.permissions ?? {};
  const canWrite = ['documents:create', 'documents:update', 'documents:delete', 'indexes:create', 'indexes:delete', 'collections:create', 'collections:delete', 'databases:delete'].some((k) => perms[k]);
  const profile = session.data?.profile ?? 'portal';
  const initialDb = params.get('db') || 'test';
  const hasSession = !!session.data;

  const frameHost = useRef<HTMLDivElement>(null);
  const broker = useRef<ShellBroker | null>(null);
  const current = useRef<number | null>(null);
  const nextId = useRef(1);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const [generation, setGeneration] = useState(0);
  const [status, setStatus] = useState<Status>('starting');
  const [startError, setStartError] = useState<string>();
  const [prompt, setPrompt] = useState('>');
  const [version, setVersion] = useState('');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [histPos, setHistPos] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [completions, setCompletions] = useState<string[]>([]);
  const [completing, setCompleting] = useState(false);
  const [confirmReq, setConfirmReq] = useState<{ req: ConfirmRequest; resolve: (d: ConfirmDecision) => void } | null>(null);

  const patch = useCallback((id: number, f: (e: Entry) => Entry) => {
    setEntries((es) => es.map((e) => (e.id === id ? f(e) : e)));
  }, []);

  // Start (or restart) the sandbox.
  useEffect(() => {
    const host = frameHost.current;
    if (!host || !hasSession) return;
    const b = new ShellBroker({
      canWrite,
      confirm: (req) => new Promise<ConfirmDecision>((resolve) => setConfirmReq({ req, resolve })),
      onPrint: (values) => {
        const id = current.current;
        if (id !== null) patch(id, (e) => ({ ...e, outputs: [...e.outputs, ...values].slice(-2000) }));
      },
      onClear: () => setEntries([]),
      onExit: () => setGeneration((g) => g + 1),
    });
    broker.current = b;
    setStatus('starting');
    setStartError(undefined);
    b.start(host, initialDb, `mongodb://${profile}.portal/`).then(
      (r) => {
        setPrompt(r.prompt);
        setVersion(r.version);
        setStatus('ready');
      },
      (e: unknown) => {
        setStatus('failed');
        setStartError(e instanceof Error ? e.message : 'The shell failed to start');
      },
    );
    return () => {
      b.destroy();
      broker.current = null;
    };
  }, [generation, hasSession, canWrite, initialDb, profile, patch]);

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: 'end' });
  }, [entries]);

  const run = async () => {
    const code = input.trim();
    if (!code || busy || status !== 'ready' || !broker.current) return;
    setInput('');
    setCompletions([]);
    setHistory((h) => (h[h.length - 1] === code ? h : [...h.slice(-199), code]));
    setHistPos(-1);
    const id = nextId.current++;
    current.current = id;
    setEntries((es) => [...es, { id, prompt, code, outputs: [], running: true }].slice(-300));
    setBusy(true);
    const r = await broker.current.evaluate(code);
    current.current = null;
    setBusy(false);
    setPrompt(r.prompt || prompt);
    patch(id, (e) => ({
      ...e,
      running: false,
      outputs: r.ok && r.value && !(r.value.type === null && r.value.value === 'undefined') ? [...e.outputs, r.value] : e.outputs,
      error: r.ok ? undefined : r.error,
    }));
    inputRef.current?.focus();
  };

  const complete = async () => {
    if (!broker.current || status !== 'ready' || completing) return;
    setCompleting(true);
    const list = await broker.current.complete(input).finally(() => setCompleting(false));
    if (list.length === 1) {
      setInput(list[0]);
      setCompletions([]);
      return;
    }
    // Extend to the longest common prefix, then offer the choices.
    let prefix = list[0] ?? '';
    for (const c of list) while (!c.startsWith(prefix)) prefix = prefix.slice(0, -1);
    if (prefix.length > input.length) setInput(prefix);
    setCompletions(list);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void run();
    } else if (e.key === 'Tab') {
      e.preventDefault();
      void complete();
    } else if (e.key === 'Escape') {
      setCompletions([]);
    } else if (e.key === 'ArrowUp' && el.selectionStart === 0 && history.length) {
      e.preventDefault();
      const pos = histPos < 0 ? history.length - 1 : Math.max(0, histPos - 1);
      setHistPos(pos);
      setInput(history[pos]);
    } else if (e.key === 'ArrowDown' && histPos >= 0 && el.selectionEnd === el.value.length) {
      e.preventDefault();
      const pos = histPos + 1;
      setHistPos(pos >= history.length ? -1 : pos);
      setInput(pos >= history.length ? '' : history[pos]);
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setEntries([]);
    }
  };

  const reset = () => {
    setEntries((es) => es.map((x) => (x.running ? { ...x, running: false, error: { name: 'Interrupted', message: 'Execution was interrupted and the shell was restarted' } } : x)));
    setBusy(false);
    current.current = null;
    setGeneration((g) => g + 1);
  };

  return (
    <PageSection>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-sm">
        <Title headingLevel="h1">Shell</Title>
        {version && <Label isCompact>mongosh {version}</Label>}
        <Flex className="pf-v6-u-ml-auto" gap={{ default: 'gapSm' }}>
          <Button variant="secondary" onClick={() => setEntries([])}>
            Clear
          </Button>
          <Button variant={busy ? 'warning' : 'secondary'} onClick={reset}>
            {busy ? 'Interrupt' : 'Restart shell'}
          </Button>
        </Flex>
      </Flex>
      <Content component="p" className="pf-v6-u-mb-sm">
        The real mongosh runtime, running isolated in your browser as <strong>{session.data?.mongoUser}</strong>. JavaScript,
        variables, loops, <code>printjson</code> and Tab completion work as in mongosh; every database operation goes through the portal
        and is checked against your role and MongoDB privileges.
      </Content>
      {!canWrite && (
        <Alert variant="info" isInline isPlain className="pf-v6-u-mb-sm" title="Your portal role is read-only: write operations are rejected." />
      )}
      {status === 'failed' && (
        <Alert variant="danger" isInline className="pf-v6-u-mb-sm" title={startError ?? 'The shell failed to start'}>
          <Button variant="link" isInline onClick={() => setGeneration((g) => g + 1)}>
            Try again
          </Button>
        </Alert>
      )}
      <div ref={frameHost} />
      <div className="portal-shell" onClick={(e) => { if (e.target === e.currentTarget) inputRef.current?.focus(); }}>
        {status === 'starting' && (
          <div className="portal-shell-muted">
            <Spinner size="sm" aria-label="Starting" /> Starting mongoshÃ¢â‚¬Â¦
          </div>
        )}
        <div role="log" aria-live="polite" aria-label="Shell output">
          {entries.map((en) => (
            <div key={en.id} className="portal-shell-entry">
              <div>
                <span className="portal-shell-prompt">{en.prompt}</span> <span className="portal-shell-code">{en.code}</span>
              </div>
              {en.outputs.map((o, i) => (
                <div key={i} className="portal-shell-out">
                  <ShellValue d={o} />
                </div>
              ))}
              {en.error && (
                <div className="portal-shell-out">
                  <ShellError e={en.error} />
                </div>
              )}
              {en.running && <Spinner size="sm" aria-label="Running" />}
            </div>
          ))}
        </div>
        <div className="portal-shell-input">
          <label htmlFor="shell-input" className="portal-shell-prompt">
            {prompt}
          </label>
          <TextArea
            id="shell-input"
            ref={inputRef}
            value={input}
            onChange={(_e, v) => {
              setInput(v);
              if (completions.length) setCompletions([]);
            }}
            onKeyDown={onKeyDown}
            autoResize
            rows={1}
            resizeOrientation="vertical"
            spellCheck={false}
            autoComplete="off"
            aria-label="mongosh command. Enter runs, Shift+Enter inserts a new line, Tab completes."
            placeholder={status === 'ready' ? 'db.collection.find({})' : ''}
            isDisabled={status !== 'ready'}
            className="portal-mono"
          />
          <Button onClick={() => void run()} isDisabled={busy || status !== 'ready' || !input.trim()} isLoading={busy}>
            Run
          </Button>
        </div>
        {completing && <div className="portal-shell-muted">completing…</div>}
        {completions.length > 1 && (
          <div className="portal-shell-completions" role="listbox" aria-label="Completions">
            {completions.map((c) => (
              <button
                key={c}
                type="button"
                role="option"
                aria-selected={false}
                className="portal-shell-completion"
                onClick={() => {
                  setInput(c);
                  setCompletions([]);
                  inputRef.current?.focus();
                }}
              >
                {c}
              </button>
            ))}
          </div>
        )}
        <div ref={endRef} />
      </div>
      {confirmReq && (
        <ShellConfirm
          req={confirmReq.req}
          onDone={(d) => {
            confirmReq.resolve(d);
            setConfirmReq(null);
          }}
        />
      )}
    </PageSection>
  );
}

function ShellConfirm({ req, onDone }: { req: ConfirmRequest; onDone: (d: ConfirmDecision) => void }) {
  const [typed, setTyped] = useState('');
  const [remember, setRemember] = useState(false);
  const ready = !req.typeToConfirm || typed === req.typeToConfirm;
  return (
    <Modal variant={ModalVariant.small} isOpen onClose={() => onDone({ confirmed: false })} aria-labelledby="shell-confirm-title">
      <ModalHeader title={req.title} labelId="shell-confirm-title" titleIconVariant="warning" />
      <ModalBody>
        <Content component="p">{req.summary}</Content>
        <Content component="small">Requested by a command running in the shell.</Content>
        {req.typeToConfirm && (
          <Form onSubmit={(e) => { e.preventDefault(); if (ready) onDone({ confirmed: true }); }} className="pf-v6-u-mt-md">
            <FormGroup label={`Type "${req.typeToConfirm}" to confirm`} fieldId="shell-confirm-input">
              <TextInput id="shell-confirm-input" value={typed} onChange={(_e, v) => setTyped(v)} autoComplete="off" autoFocus />
            </FormGroup>
          </Form>
        )}
        {req.allowRemember && (
          <Checkbox
            id="shell-confirm-remember"
            className="pf-v6-u-mt-md"
            label={`Don't ask again for ${req.op} in this shell session`}
            isChecked={remember}
            onChange={(_e, v) => setRemember(v)}
          />
        )}
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" isDisabled={!ready} onClick={() => onDone({ confirmed: true, remember })}>
          Run {req.op}
        </Button>
        <Button variant="link" onClick={() => onDone({ confirmed: false })}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
