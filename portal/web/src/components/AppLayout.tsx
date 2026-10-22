import { useMemo, useState } from 'react';
import { NavLink, Outlet, useNavigate, useParams } from 'react-router';
import {
  Button,
  Divider,
  Dropdown,
  DropdownItem,
  DropdownList,
  Label,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  Nav,
  NavGroup,
  NavItem,
  NavList,
  Page,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
  SearchInput,
  Spinner,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
  Tooltip,
} from '@patternfly/react-core';
import {
  BarsIcon,
  CubeIcon,
  DatabaseIcon,
  LockIcon,
  MoonIcon,
  ServerIcon,
  SunIcon,
  TerminalIcon,
  UnlockIcon,
  UserIcon,
} from '@patternfly/react-icons';
import type { Me } from '../api/types';
import { useCollections, useDatabases, useLogout, useSession } from '../api/hooks';
import { applyTheme, currentTheme, type Theme } from '../lib/theme';
import { RoleLabel } from './Permission';

export function AppLayout({ me }: { me: Me }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [theme, setTheme] = useState<Theme>(currentTheme());
  const [userOpen, setUserOpen] = useState(false);
  const session = useSession();
  const logout = useLogout();
  const navigate = useNavigate();

  const toggleTheme = () => {
    const t = theme === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    setTheme(t);
  };

  const doLogout = async () => {
    setUserOpen(false);
    try {
      await logout.mutateAsync();
    } finally {
      navigate('/login?reason=logout', { replace: true });
    }
  };

  const s = session.data;
  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton
            variant="plain"
            aria-label="Toggle navigation"
            isSidebarOpen={sidebarOpen}
            onSidebarToggle={() => setSidebarOpen((o) => !o)}
          >
            <BarsIcon />
          </PageToggleButton>
        </MastheadToggle>
        <MastheadBrand>
          <MastheadLogo component={(p) => <NavLink to="/" {...p} />}>
            <span className="portal-brand">
              <DatabaseIcon /> MongoDB Portal
            </span>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarGroup align={{ default: 'alignEnd' }} gap={{ default: 'gapMd' }}>
              {me.environment && (
                <ToolbarItem visibility={{ default: 'hidden', md: 'visible' }}>
                  <Label color="grey">{me.environment}</Label>
                </ToolbarItem>
              )}
              {s && (
                <ToolbarItem visibility={{ default: 'hidden', md: 'visible' }}>
                  <Tooltip content={s.tls ? 'Connection to MongoDB is encrypted with TLS' : 'Connection to MongoDB is NOT encrypted'}>
                    <Label color={s.tls ? 'green' : 'red'} icon={s.tls ? <LockIcon /> : <UnlockIcon />}>
                      {s.profileInfo?.displayName ?? s.profile}
                    </Label>
                  </Tooltip>
                </ToolbarItem>
              )}
              <ToolbarItem>
                <RoleLabel role={me.role} />
              </ToolbarItem>
              <ToolbarItem>
                <Button
                  variant="plain"
                  aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                  onClick={toggleTheme}
                  icon={theme === 'dark' ? <SunIcon /> : <MoonIcon />}
                />
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown
                  isOpen={userOpen}
                  onOpenChange={setUserOpen}
                  popperProps={{ position: 'right' }}
                  toggle={(ref) => (
                    <MenuToggle ref={ref} variant="plainText" icon={<UserIcon />} onClick={() => setUserOpen((o) => !o)} isExpanded={userOpen}>
                      {s ? `${s.mongoUser} (${me.user})` : me.user}
                    </MenuToggle>
                  )}
                >
                  <DropdownList>
                    <DropdownItem key="session" onClick={() => { setUserOpen(false); navigate('/session'); }}>
                      Session &amp; security
                    </DropdownItem>
                    <DropdownItem key="logout" onClick={() => void doLogout()}>
                      Disconnect from MongoDB
                    </DropdownItem>
                    {me.ssoLogoutURL && (
                      <DropdownItem key="sso" to={me.ssoLogoutURL}>
                        Sign out of corporate SSO
                      </DropdownItem>
                    )}
                  </DropdownList>
                </Dropdown>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );

  const sidebar = (
    <PageSidebar isSidebarOpen={sidebarOpen}>
      <PageSidebarBody>
        <Sidebar />
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <Page masthead={masthead} sidebar={sidebar} isContentFilled>
      {s && !s.tls && (
        <div className="portal-banner" role="alert">
          <UnlockIcon /> MongoDB traffic for this connection profile is not encrypted. Credentials and data travel in plaintext between the portal and MongoDB.
        </div>
      )}
      <Outlet />
    </Page>
  );
}

function Sidebar() {
  const [filter, setFilter] = useState('');
  const { db: activeDb, coll: activeColl } = useParams();
  const dbs = useDatabases();
  const colls = useCollections(activeDb);
  const f = filter.trim().toLowerCase();

  const dbList = useMemo(() => (dbs.data?.databases ?? []).filter((d) => !f || d.name.toLowerCase().includes(f) || d.name === activeDb), [dbs.data, f, activeDb]);
  const collList = useMemo(() => (colls.data?.collections ?? []).filter((c) => !f || c.name.toLowerCase().includes(f)), [colls.data, f]);

  return (
    <>
      <div className="pf-v6-u-p-md">
        <SearchInput
          aria-label="Filter databases and collections"
          placeholder="Filter databases & collections"
          value={filter}
          onChange={(_e, v) => setFilter(v)}
          onClear={() => setFilter('')}
        />
      </div>
      <Nav aria-label="Database navigation">
        <NavGroup title="Databases">
          {dbs.isPending && <Spinner size="md" className="pf-v6-u-ml-md" aria-label="Loading databases" />}
          <NavList>
            {dbList.map((d) => (
              <NavItem key={d.name} isActive={d.name === activeDb && !activeColl} icon={<DatabaseIcon />}>
                <NavLink to={`/db/${encodeURIComponent(d.name)}`}>{d.name}</NavLink>
              </NavItem>
            ))}
          </NavList>
        </NavGroup>
        {activeDb && (
          <NavGroup title={`Collections in ${activeDb}`}>
            {colls.isPending && <Spinner size="md" className="pf-v6-u-ml-md" aria-label="Loading collections" />}
            <NavList>
              {collList.map((c) => (
                <NavItem key={c.name} isActive={c.name === activeColl} icon={<CubeIcon />}>
                  <NavLink to={`/db/${encodeURIComponent(activeDb)}/${encodeURIComponent(c.name)}`}>{c.name}</NavLink>
                </NavItem>
              ))}
            </NavList>
          </NavGroup>
        )}
        <Divider />
        <NavList>
          <NavItem icon={<TerminalIcon />}>
            <NavLink to={activeDb ? `/shell?db=${encodeURIComponent(activeDb)}` : '/shell'}>Shell</NavLink>
          </NavItem>
          <NavItem icon={<ServerIcon />}>
            <NavLink to="/server">Server</NavLink>
          </NavItem>
          <NavItem icon={<LockIcon />}>
            <NavLink to="/session">Session &amp; security</NavLink>
          </NavItem>
          <NavItem>
            <NavLink to="/audit">Audit activity</NavLink>
          </NavItem>
        </NavList>
      </Nav>
    </>
  );
}
