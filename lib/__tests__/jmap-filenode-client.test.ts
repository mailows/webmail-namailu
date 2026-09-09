import { describe, it, expect, vi, beforeEach } from 'vitest';
import { JMAPClient } from '../jmap/client';

function createClient(): JMAPClient {
  const client = new JMAPClient('https://jmap.example.com', 'user', 'pass');
  Object.assign(client, {
    apiUrl: 'https://jmap.example.com/api',
    accountId: 'account-1',
    accounts: { 'account-1': { name: 'user', isPersonal: true, isReadOnly: false, accountCapabilities: { 'urn:ietf:params:jmap:filenode': {} } } },
    capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:ietf:params:jmap:filenode': {} },
  });
  return client;
}

function mockFetch(response: object) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: true,
    status: 200,
    text: () => Promise.resolve(JSON.stringify(response)),
    json: () => Promise.resolve(response),
  } as Response);
}

// What Stalwart hands back for nodes created over WebDAV: the raw
// percent-encoded href segment as the name (#869).
const webdavFolder = { id: 'f1', parentId: null, name: 'Spares%20Catalog%20%D8%B9%D8%B1%D8%A8%D9%8A', type: '', blobId: null, size: 0, created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' };
const jmapFile = { id: 'f2', parentId: 'f1', name: '100% done.txt', type: 'text/plain', blobId: 'b2', size: 3, created: '2026-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' };

describe('JMAPClient FileNode name decoding (#869)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('listAllFileNodes decodes WebDAV-created names and keeps JMAP-created ones', async () => {
    const client = createClient();
    mockFetch({ methodResponses: [['FileNode/get', { list: [webdavFolder, jmapFile] }, 'fng0']] });

    const nodes = await client.listAllFileNodes();
    expect(nodes.map(n => n.name)).toEqual(['Spares Catalog عربي', '100% done.txt']);
    // Other properties pass through untouched.
    expect(nodes[0]).toMatchObject({ id: 'f1', parentId: null, blobId: null });
  });

  it('getFileNodes decodes names', async () => {
    const client = createClient();
    mockFetch({ methodResponses: [['FileNode/get', { list: [webdavFolder] }, 'fn0']] });

    const nodes = await client.getFileNodes(['f1']);
    expect(nodes[0].name).toBe('Spares Catalog عربي');
  });

  it('listAllFileNodesAcrossAccounts decodes names', async () => {
    const client = createClient();
    mockFetch({ methodResponses: [['FileNode/get', { list: [webdavFolder, jmapFile] }, 'fng0']] });

    const nodes = await client.listAllFileNodesAcrossAccounts();
    expect(nodes.map(n => n.name)).toEqual(['Spares Catalog عربي', '100% done.txt']);
    expect(nodes[0]).toMatchObject({ id: 'f1', accountId: 'account-1', isShared: false });
  });
});
