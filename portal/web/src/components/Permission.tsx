import type { ReactNode } from 'react';
import { Label, Tooltip } from '@patternfly/react-core';
import { EyeIcon, PencilAltIcon, UserShieldIcon } from '@patternfly/react-icons';
import type { Access, Capabilities, Role } from '../api/types';

export function RoleLabel({ role }: { role: Role }) {
  return role === 'sre' ? (
    <Tooltip content="SRE portal role: operations are permitted up to your MongoDB privileges">
      <Label color="purple" icon={<UserShieldIcon />}>
        SRE
      </Label>
    </Tooltip>
  ) : (
    <Tooltip content="Developer portal role: read-only access regardless of MongoDB privileges">
      <Label color="blue" icon={<EyeIcon />}>
        Developer · read-only
      </Label>
    </Tooltip>
  );
}

export type WriteAction = keyof Pick<
  Capabilities,
  'insert' | 'update' | 'remove' | 'createIndex' | 'dropIndex' | 'createCollection' | 'dropCollection'
>;

/**
 * UI hint only: whether to offer an action. The backend enforces the portal
 * role on every request and MongoDB enforces the user's privileges.
 */
export function canDo(access: Access | undefined, action: WriteAction): boolean {
  if (!access?.portalWrite) return false;
  return access.mongo[action];
}

export function IfAllowed({ access, action, children }: { access?: Access; action: WriteAction; children: ReactNode }) {
  return canDo(access, action) ? <>{children}</> : null;
}

export function AccessLabel({ access }: { access?: Access }) {
  if (!access) return null;
  const m = access.mongo;
  const mongoWrite = m.insert || m.update || m.remove;
  if (access.portalWrite && mongoWrite) {
    return (
      <Tooltip content="Your portal role and MongoDB privileges allow modifying data here">
        <Label color="orange" icon={<PencilAltIcon />}>
          Read / write
        </Label>
      </Tooltip>
    );
  }
  const why = !access.portalWrite ? 'Your portal role is read-only' : 'Your MongoDB user has no write privileges here';
  return (
    <Tooltip content={why}>
      <Label color="blue" icon={<EyeIcon />}>
        {m.find ? 'Read only' : 'Limited'}
      </Label>
    </Tooltip>
  );
}
