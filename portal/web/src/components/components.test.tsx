import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DocumentView } from './DocumentView';
import { canDo } from './Permission';
import { DocumentCard } from '../pages/collection/DocumentCard';
import type { Access, Capabilities } from '../api/types';

const allCaps: Capabilities = {
  find: true, insert: true, update: true, remove: true, createIndex: true, dropIndex: true,
  createCollection: true, dropCollection: true, listCollections: true, listIndexes: true, dbStats: true, collStats: true,
};

describe('DocumentView', () => {
  it('renders BSON types and escapes HTML', () => {
    render(
      <DocumentView
        doc={{
          _id: { $oid: '507f1f77bcf86cd799439011' },
          price: { $numberDecimal: '9.99' },
          html: '<img src=x onerror=alert(1)>',
          nested: { a: { $date: { $numberLong: '0' } } },
        }}
      />,
    );
    expect(screen.getByText('ObjectId("507f1f77bcf86cd799439011")')).toBeTruthy();
    expect(screen.getByText('NumberDecimal("9.99")')).toBeTruthy();
    expect(screen.getByText('"<img src=x onerror=alert(1)>"')).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText('ISODate("1970-01-01T00:00:00.000Z")')).toBeTruthy();
  });
});

describe('permission gating (UI hints only)', () => {
  const dev: Access = { portalWrite: false, mongo: allCaps };
  const sre: Access = { portalWrite: true, mongo: { ...allCaps, remove: false } };

  it('never offers writes to the developer role, even with MongoDB write privileges', () => {
    expect(canDo(dev, 'insert')).toBe(false);
    expect(canDo(dev, 'dropCollection')).toBe(false);
  });

  it('offers SRE writes only where MongoDB grants them', () => {
    expect(canDo(sre, 'insert')).toBe(true);
    expect(canDo(sre, 'remove')).toBe(false);
  });

  it('hides edit and delete buttons for developers', () => {
    render(<DocumentCard doc={{ _id: { $numberInt: '1' } }} id="x" access={dev} raw={false} onEdit={() => {}} onDelete={() => {}} />);
    expect(screen.queryByLabelText('Edit document')).toBeNull();
    expect(screen.queryByLabelText('Delete document')).toBeNull();
    expect(screen.getByLabelText('Copy document JSON')).toBeTruthy();
  });
});
