export type Role = 'developer' | 'sre';

export interface Me {
  user: string;
  groups: string[];
  role: Role;
  canWrite: boolean;
  csrfToken: string;
  hasSession: boolean;
  ssoLogoutURL: string;
  environment: string;
  build: { version: string; commit: string };
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
}

export interface RoleRef {
  role: string;
  db: string;
}

export interface SessionInfo {
  handle: string;
  profile: string;
  profileInfo?: Profile;
  mongoUser: string;
  authSource: string;
  mechanism: string;
  tls: boolean;
  portalRole: Role;
  canWrite: boolean;
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

export interface Access {
  portalWrite: boolean;
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
