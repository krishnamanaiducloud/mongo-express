import {
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Label,
  LabelGroup,
  PageSection,
  Spinner,
  Title,
} from '@patternfly/react-core';
import { useServerInfo } from '../api/hooks';
import { ErrorState } from './StatusPages';

type Info = {
  build?: { version?: string; gitVersion?: string };
  hello?: { setName?: string; hosts?: string[]; primary?: string; me?: string; isWritablePrimary?: boolean; msg?: string };
};

export function ServerPage() {
  const q = useServerInfo();
  if (q.isPending) return <PageSection><Spinner aria-label="Loading server information" /></PageSection>;
  if (q.isError) return <PageSection><ErrorState error={q.error} onRetry={() => void q.refetch()} /></PageSection>;
  const info = q.data.server as Info;
  const h = info.hello ?? {};
  const rows: [string, React.ReactNode][] = [
    ['MongoDB version', info.build?.version ?? '—'],
    ['Topology', h.setName ? `Replica set ${h.setName}` : h.msg === 'isdbgrid' ? 'Sharded cluster (mongos)' : 'Standalone'],
    ['Primary', h.primary ?? '—'],
    ['Connected member', h.me ?? '—'],
    [
      'Members',
      <LabelGroup key="m" numLabels={10}>
        {(h.hosts ?? []).map((x) => (
          <Label key={x} isCompact color={x === h.primary ? 'green' : 'grey'}>
            {x}
          </Label>
        ))}
      </LabelGroup>,
    ],
    ['Transport', q.data.tls ? 'TLS' : 'Plaintext (not encrypted)'],
  ];
  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        Server
      </Title>
      <Card>
        <CardTitle>Profile {q.data.profile}</CardTitle>
        <CardBody>
          <DescriptionList isHorizontal>
            {rows.map(([k, v]) => (
              <DescriptionListGroup key={k}>
                <DescriptionListTerm>{k}</DescriptionListTerm>
                <DescriptionListDescription>{v}</DescriptionListDescription>
              </DescriptionListGroup>
            ))}
          </DescriptionList>
        </CardBody>
      </Card>
    </PageSection>
  );
}
