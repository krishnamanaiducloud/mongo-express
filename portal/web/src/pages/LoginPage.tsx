import { useState } from 'react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router';
import {
  ActionGroup,
  Alert,
  Bullseye,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Gallery,
  Label,
  LabelGroup,
  Spinner,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { DatabaseIcon, LockIcon, UnlockIcon } from '@patternfly/react-icons';
import { ApiError, errorMessage } from '../api/client';
import { useLogin, useProfiles } from '../api/hooks';
import type { Me, Profile } from '../api/types';
import { RoleLabel } from '../components/Permission';
import { ErrorState } from './StatusPages';

const reasons: Record<string, string> = {
  expired: 'Your MongoDB session expired. Sign in again to continue.',
  required: 'Sign in to MongoDB to continue. Sessions do not survive portal restarts or moves between portal instances.',
  logout: 'You have been disconnected from MongoDB.',
};

export function LoginPage({ me }: { me: Me }) {
  const profiles = useProfiles();
  const login = useLogin();
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string>();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authSourceEdit, setAuthSource] = useState<string>();
  const [mechanism, setMechanism] = useState('');

  const profile: Profile | undefined = profiles.data?.find((p) => p.name === selected) ?? profiles.data?.[0];
  const authSource = authSourceEdit ?? profile?.defaultAuthSource ?? '';

  const select = (p: Profile) => {
    setSelected(p.name);
    setAuthSource(undefined);
    setMechanism('');
  };

  if (me.hasSession && !params.get('reason') && !login.isPending) {
    return <Navigate to="/" replace />;
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profile) return;
    try {
      await login.mutateAsync({ profile: profile.name, username, password, authSource, mechanism });
      setPassword('');
      const from = (location.state as { from?: string } | null)?.from;
      navigate(from && from !== '/login' ? from : '/', { replace: true });
    } catch {
      setPassword('');
    }
  };

  const reason = params.get('reason');
  const err = login.error;
  const retryAfter = err instanceof ApiError && err.code === 'rate_limited';

  return (
    <Bullseye className="portal-login">
      <Card className="portal-login-card" isLarge>
        <CardHeader>
          <CardTitle>
            <Title headingLevel="h1" size="2xl">
              <DatabaseIcon /> Connect to MongoDB
            </Title>
          </CardTitle>
        </CardHeader>
        <CardBody>
          <Content component="p">
            Signed in via corporate SSO as <strong>{me.user}</strong> <RoleLabel role={me.role} />
          </Content>
          <Content component="small">
            Enter your own MongoDB credentials. Your password is sent once to MongoDB for verification and is never stored by the
            portal.
          </Content>
          {reason && reasons[reason] && <Alert className="pf-v6-u-mt-md" variant="info" isInline isPlain title={reasons[reason]} />}

          <Title headingLevel="h2" size="md" className="pf-v6-u-mt-lg pf-v6-u-mb-sm">
            Connection profile
          </Title>
          {profiles.isPending && <Spinner size="lg" aria-label="Loading profiles" />}
          {profiles.isError && <ErrorState error={profiles.error} onRetry={() => void profiles.refetch()} />}
          <Gallery hasGutter minWidths={{ default: '220px' }} role="radiogroup" aria-label="Connection profiles">
            {profiles.data?.map((p) => (
              <Card
                key={p.name}
                isCompact
                isSelectable
                isSelected={profile?.name === p.name}
                id={`profile-${p.name}`}
              >
                <CardHeader
                  selectableActions={{
                    selectableActionId: `profile-input-${p.name}`,
                    selectableActionAriaLabelledby: `profile-${p.name}`,
                    name: 'profile',
                    variant: 'single',
                    onChange: () => select(p),
                    isChecked: profile?.name === p.name,
                  }}
                >
                  <CardTitle>{p.displayName}</CardTitle>
                </CardHeader>
                <CardBody>
                  {p.description && <Content component="small">{p.description}</Content>}
                  <LabelGroup className="pf-v6-u-mt-sm">
                    {p.tlsMode === 'enabled' ? (
                      <Label color="green" icon={<LockIcon />} isCompact>
                        TLS{p.clientCertificate ? ' + client cert' : ''}
                      </Label>
                    ) : (
                      <Label color="red" icon={<UnlockIcon />} isCompact>
                        Unencrypted
                      </Label>
                    )}
                    {p.replicaSet && <Label isCompact>rs: {p.replicaSet}</Label>}
                  </LabelGroup>
                </CardBody>
              </Card>
            ))}
          </Gallery>

          {profile?.plaintextWarning && (
            <Alert className="pf-v6-u-mt-md" variant="warning" isInline title="This connection is not encrypted">
              MongoDB TLS is disabled for this profile. Your username, password and all data travel between the portal and MongoDB
              without transport encryption. Use this profile only where an approved security exception exists.
            </Alert>
          )}

          <Form className="pf-v6-u-mt-lg" onSubmit={(e) => void submit(e)} aria-label="MongoDB login">
            <FormGroup label="MongoDB username" isRequired fieldId="username">
              <TextInput id="username" value={username} onChange={(_e, v) => setUsername(v)} isRequired autoComplete="username" autoFocus />
            </FormGroup>
            <FormGroup label="Password" isRequired fieldId="password">
              <TextInput
                id="password"
                type="password"
                value={password}
                onChange={(_e, v) => setPassword(v)}
                isRequired
                autoComplete="current-password"
              />
            </FormGroup>
            <FormGroup label="Authentication database" isRequired fieldId="authSource">
              <TextInput id="authSource" value={authSource} onChange={(_e, v) => setAuthSource(v)} isRequired />
            </FormGroup>
            <FormGroup label="Authentication mechanism" fieldId="mechanism">
              <FormSelect id="mechanism" value={mechanism} onChange={(_e, v) => setMechanism(v)}>
                <FormSelectOption value="" label="Negotiate (recommended)" />
                {profile?.authMechanisms.map((m) => <FormSelectOption key={m} value={m} label={m} />)}
              </FormSelect>
            </FormGroup>
            {err && (
              <Alert variant={retryAfter ? 'warning' : 'danger'} isInline title={errorMessage(err)}>
                {err instanceof ApiError && err.code === 'tls_verification_failed' &&
                  'The MongoDB server certificate could not be verified against the configured CA. Contact the platform team.'}
                {err instanceof ApiError && err.code === 'mongo_unavailable' && 'MongoDB did not respond. It may be down or unreachable from the portal.'}
              </Alert>
            )}
            <ActionGroup>
              <Button type="submit" variant="primary" isDisabled={!profile || !username || !password || login.isPending} isLoading={login.isPending}>
                Connect
              </Button>
            </ActionGroup>
          </Form>
        </CardBody>
      </Card>
    </Bullseye>
  );
}
