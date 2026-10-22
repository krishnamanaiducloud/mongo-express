import { useEffect } from 'react';
import { Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router';
import { Bullseye, Spinner } from '@patternfly/react-core';
import { useQueryClient } from '@tanstack/react-query';
import { ApiError, SESSION_LOST_EVENT, SSO_LOST_EVENT } from './api/client';
import { keys, useMe, useSession } from './api/hooks';
import { AppLayout } from './components/AppLayout';
import { AccessDeniedPage, ErrorPage, NotFoundPage, SsoRequiredPage } from './pages/StatusPages';
import { LoginPage } from './pages/LoginPage';
import { DatabasesPage } from './pages/DatabasesPage';
import { DatabasePage } from './pages/DatabasePage';
import { CollectionPage } from './pages/CollectionPage';
import { SessionPage } from './pages/SessionPage';
import { AuditPage } from './pages/AuditPage';
import { ServerPage } from './pages/ServerPage';
import { ShellPage } from './pages/ShellPage';

function Loading() {
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <Spinner aria-label="Loading" />
    </Bullseye>
  );
}

export function App() {
  const me = useMe();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const lost = (e: Event) => {
      qc.removeQueries({ queryKey: keys.session });
      const reason = (e as CustomEvent<string>).detail === 'mongo_session_expired' ? 'expired' : 'required';
      if (!location.pathname.startsWith('/login')) {
        navigate(`/login?reason=${reason}`, { replace: true, state: { from: location.pathname } });
      }
    };
    const ssoLost = () => void qc.invalidateQueries({ queryKey: keys.me });
    window.addEventListener(SESSION_LOST_EVENT, lost);
    window.addEventListener(SSO_LOST_EVENT, ssoLost);
    return () => {
      window.removeEventListener(SESSION_LOST_EVENT, lost);
      window.removeEventListener(SSO_LOST_EVENT, ssoLost);
    };
  }, [qc, navigate, location.pathname]);

  if (me.isPending) return <Loading />;
  if (me.isError) {
    const e = me.error;
    if (e instanceof ApiError && e.code === 'portal_access_denied') return <AccessDeniedPage message={e.message} />;
    if (e instanceof ApiError && (e.code === 'sso_required' || e.status === 401)) return <SsoRequiredPage />;
    return <ErrorPage error={e} onRetry={() => void me.refetch()} />;
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage me={me.data} />} />
      <Route element={<RequireSession />}>
        <Route element={<AppLayout me={me.data} />}>
          <Route index element={<DatabasesPage />} />
          <Route path="db/:db" element={<DatabasePage />} />
          <Route path="db/:db/:coll" element={<CollectionPage />} />
          <Route path="session" element={<SessionPage me={me.data} />} />
          <Route path="audit" element={<AuditPage me={me.data} />} />
          <Route path="server" element={<ServerPage />} />
          <Route path="shell" element={<ShellPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}

function RequireSession() {
  const session = useSession();
  const location = useLocation();
  if (session.isPending) return <Loading />;
  if (session.isError) {
    const e = session.error;
    if (e instanceof ApiError && e.status === 401) {
      return <Navigate to="/login" replace state={{ from: location.pathname }} />;
    }
    return <ErrorPage error={e} onRetry={() => void session.refetch()} />;
  }
  return <Outlet />;
}
