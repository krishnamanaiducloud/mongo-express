import {
  Alert,
  Bullseye,
  Button,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  PageSection,
} from '@patternfly/react-core';
import { BanIcon, ExclamationCircleIcon, LockIcon, SearchIcon } from '@patternfly/react-icons';
import { NavLink } from 'react-router';
import { ApiError, errorMessage } from '../api/client';

export function SsoRequiredPage() {
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <EmptyState titleText="Corporate sign-in required" headingLevel="h1" icon={LockIcon}>
        <EmptyStateBody>
          This portal is available to authorized users through corporate single sign-on. Your SSO session is missing or has
          expired.
        </EmptyStateBody>
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="primary" onClick={() => window.location.assign('/')}>
              Sign in with corporate SSO
            </Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      </EmptyState>
    </Bullseye>
  );
}

export function AccessDeniedPage({ message }: { message: string }) {
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <EmptyState titleText="Access denied" headingLevel="h1" icon={BanIcon} status="danger">
        <EmptyStateBody>
          {message}. Request membership in the developer or SRE portal group through your access management process.
        </EmptyStateBody>
      </EmptyState>
    </Bullseye>
  );
}

export function ErrorPage({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <ErrorState error={error} onRetry={onRetry} />
    </Bullseye>
  );
}

/** Inline error panel. Never shows stack traces; includes the request id for support. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <EmptyState
      titleText={forbidden ? 'Not authorized' : 'Something went wrong'}
      headingLevel="h2"
      icon={forbidden ? BanIcon : ExclamationCircleIcon}
      status={forbidden ? 'warning' : 'danger'}
    >
      <EmptyStateBody>
        {errorMessage(error)}
        {error instanceof ApiError && error.requestId && (
          <div className="pf-v6-u-font-size-sm pf-v6-u-mt-sm">Request ID: {error.requestId}</div>
        )}
      </EmptyStateBody>
      {onRetry && (
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="secondary" onClick={onRetry}>
              Try again
            </Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      )}
    </EmptyState>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  const rid = error instanceof ApiError ? error.requestId : undefined;
  return (
    <Alert variant="danger" isInline title={errorMessage(error)}>
      {rid && <span className="pf-v6-u-font-size-sm">Request ID: {rid}</span>}
    </Alert>
  );
}

export function NotFoundPage() {
  return (
    <PageSection>
      <EmptyState titleText="Page not found" headingLevel="h1" icon={SearchIcon}>
        <EmptyStateBody>The page you requested does not exist.</EmptyStateBody>
        <EmptyStateFooter>
          <NavLink to="/">Back to databases</NavLink>
        </EmptyStateFooter>
      </EmptyState>
    </PageSection>
  );
}
