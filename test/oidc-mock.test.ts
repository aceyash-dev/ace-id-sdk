import { describe, expect, it } from 'vitest';
import { createMockOIDCIssuer } from '../src/testing/oidc-mock.js';

describe('OIDC test issuer fetch compatibility', () => {
  it('normalizes Request URL, method, and body before routing', async () => {
    const issuer = createMockOIDCIssuer();
    const request = new Request(issuer.issuer + '/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&code=fixture',
    });
    const response = await issuer.fetch(request);
    expect(response.status).toBe(200);
    expect(issuer.requests[0]).toMatchObject({
      url: issuer.issuer + '/token',
      method: 'POST',
      body: 'grant_type=authorization_code&code=fixture',
    });
  });

  it('honors an already-aborted signal before recording a request', async () => {
    const issuer = createMockOIDCIssuer();
    const controller = new AbortController();
    controller.abort(new DOMException('Cancelled', 'AbortError'));
    await expect(issuer.fetch(issuer.issuer + '/token', {
      method: 'POST', body: 'grant_type=authorization_code', signal: controller.signal,
    })).rejects.toMatchObject({ name: 'AbortError' });
    expect(issuer.requests).toHaveLength(0);
  });

  it('applies init header overrides to a Request input', async () => {
    const issuer = createMockOIDCIssuer();
    const request = new Request(issuer.issuer + '/userinfo', {
      headers: { authorization: 'Bearer original' },
    });
    const response = await issuer.fetch(request, { headers: { authorization: 'Bearer override' } });
    expect(response.status).toBe(200);
    expect(issuer.requests[0]?.url).toBe(issuer.issuer + '/userinfo');
  });
});
