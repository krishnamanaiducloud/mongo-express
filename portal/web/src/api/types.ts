/** How the current user signed in. "" means anonymous (no SSO, no MongoDB session). */
export type IdentitySource = '' | 'openshift' | 'header' | 'dev' | 'mongodb';

export interface OpenShiftStatus {
  state: 'available' | 'unavailable' | 'disabled';
  reason?: string;
  checkedAt?: string;
  issuer?: string;
}

/** Sign-in methods available right now. SSO sources are optional and passive. */
export interface AuthOptions {
  openshift: OpenShiftStatus;
  openshiftURL: string;
  header: boolean;
  dev: boolean;
  requireSSO: boolean;
  mongodbLogin: boolean;
}

/** UI permission hints keyed "resource:action" (and "audit:all"). */
export type GlobalPermissions = Record<string, boolean>;

export interface Me {
  authenticated: boolean;
  user: string;
  source: IdentitySource;
  sso: boolean;
  groups: string[];
  roles: string[];
  permissions: GlobalPermissions;
  csrfToken: string;
  hasSession: boolean;
  ssoLogoutURL: string;
  environment: string;
  build: { version: string; commit: string };
  auth: AuthOptions;
}

export type HealthState = 'unknown' | 'online' | 'degraded' | 'offline' | 'misconfigured' | 'disabled';

export interface ProfileHealth {
  state: HealthState;
  reason?: string;
  latencyMs?: number;
  setName?: string;
  checkedAt?: string;
}

export interface Profile {
  name: string;
  displayName: string;
  description?: string;
  defaultAuthSource: string;
  authMechanisms: string[];
  tlsMode: 'enabled' | 'disabled';
  clientCertificate: boolean;
  plaintextWarning: boolean;
  replicaSet?: string;
  health?: ProfileHealth;
}

export interface RoleRef {
  role: string;
  db: string;
}

export interface Principal {
  user: string;
  groups: string[] | null;
  source: IdentitySource;
}

export interface SessionInfo {
  handle: string;
  profile: string;
  profileInfo?: Profile;
  mongoUser: string;
  authSource: string;
  mechanism: string;
  tls: boolean;
  identity: Principal | null;
  portalRoles: string[] | null;
  permissions: GlobalPermissions;
  mongoRoles: RoleRef[] | null;
  createdAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  idleTimeoutSeconds: number;
  csrfToken: string;
}

export interface Capabilities {
  find: boolean;
  insert: boolean;
  update: boolean;
  remove: boolean;
  createIndex: boolean;
  dropIndex: boolean;
  createCollection: boolean;
  dropCollection: boolean;
  listCollections: boolean;
  listIndexes: boolean;
  dbStats: boolean;
  collStats: boolean;
}

/** Portal RBAC decisions for one namespace. */
export interface PortalAccess {
  find: boolean;
  insert: boolean;
  update: boolean;
  remove: boolean;
  createIndex: boolean;
  dropIndex: boolean;
  createCollection: boolean;
  dropCollection: boolean;
  dropDatabase: boolean;
}

export interface Access {
  /** Any document write allowed by RBAC (legacy summary). */
  portalWrite: boolean;
  portal?: PortalAccess;
  mongo: Capabilities;
}

export interface DatabaseInfo {
  name: string;
  sizeOnDisk: number;
  empty: boolean;
}

export interface CollectionInfo {
  name: string;
  type: string;
  readOnly: boolean;
  options?: Record<string, unknown>;
  access: Access;
}

export type EJSONDocument = Record<string, unknown>;

export interface DocPage {
  documents: EJSONDocument[];
  ids: string[];
  hasMore: boolean;
  truncated: boolean;
  skip: number;
  limit: number;
  elapsedMs: number;
}

export interface DocumentsResponse {
  page: DocPage;
  access?: Access;
  count?: number;
  countCapped?: boolean;
}

export interface SessionSummary {
  handle: string;
  profile: string;
  mongoUser: string;
  authSource: string;
  createdAt: string;
  lastSeen: string;
  expiresAt: string;
  userAgent: string;
  current: boolean;
  tls: boolean;
}

export interface AuditEvent {
  time: string;
  requestId?: string;
  ssoUser: string;
  identity?: IdentitySource;
  portalRole?: string;
  mongoUser?: string;
  profile?: string;
  action: string;
  database?: string;
  collection?: string;
  target?: string;
  outcome: 'success' | 'denied' | 'failure';
  reason?: string;
}

export interface QueryRequest {
  operation: 'find' | 'findOne' | 'countDocuments' | 'aggregate';
  filter?: string;
  projection?: string;
  sort?: string;
  pipeline?: string;
  limit?: number;
  skip?: number;
  maxTimeMS?: number;
}

export interface QueryResponse {
  page?: DocPage;
  count?: number;
  countCapped?: boolean;
}

export interface PolicyStatus {
  source: 'file' | 'config' | 'built-in';
  defaultRole: string;
  loadedAt: string;
  error?: string;
}

export interface RbacRule {
  role: string;
  resource: string;
  action: string;
  object: string;
  effect: 'allow' | 'deny';
}

export interface PermissionsInfo {
  user: string;
  source: IdentitySource;
  subjects: string[];
  roles: string[];
  directRoles: string[];
  defaultRole: string;
  rules: RbacRule[];
  policy: PolicyStatus;
  check?: { resource: string; action: string; object: string; allowed: boolean };
}

export interface StatusInfo {
  auth: AuthOptions;
  profiles: { name: string; displayName: string; health: ProfileHealth }[];
  build: { version: string; commit: string };
  rbac?: PolicyStatus;
  tracing?: boolean;
  shell?: boolean;
  sessions?: { active: number; max: number };
}
