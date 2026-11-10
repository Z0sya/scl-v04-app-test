// Independent synthetic shop fixture. Never reads security contracts or runner code.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { argument, body, isMain, json, ROOT } from './shared.ts';

export function createShop(version: 'baseline' | 'candidate') {
  if (!['baseline', 'candidate'].includes(version)) throw new Error('Unknown version');
  const credentials = JSON.parse(readFileSync(resolve(ROOT, 'config/demo-credentials.local.json'), 'utf8'));
  const sessions = new Map([
    [credentials['shop.ava'], { customer: 'customer-ava', role: 'buyer' }],
    [credentials['shop.noah'], { customer: 'customer-noah', role: 'buyer' }],
    [credentials['shop.admin'], { customer: null, role: 'admin' }]
  ]);
  const orders = new Map([
    ['order-101', { number: 'order-101', customer: 'customer-ava', delivery: { city: 'Synthetic North', instructions: 'Leave at synthetic desk' }, stage: 'created', totalCents: 2400 }],
    ['order-202', { number: 'order-202', customer: 'customer-noah', delivery: { city: 'Synthetic South', instructions: 'Call synthetic bell' }, stage: 'created', totalCents: 5100 }]
  ]);
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      const match = /^\/v1\/orders\/([a-z0-9-]+)(\/delivery|\/stage)?$/.exec(url.pathname);
      if (!match || !(req.method === 'GET' && !match[2] || req.method === 'PUT' && match[2] === '/delivery' || req.method === 'POST' && match[2] === '/stage')) return json(res, 404, { code: 'NOT_FOUND' });
      const session = sessions.get(req.headers['x-demo-session'] as string);
      if (!session) return json(res, 401, { code: 'AUTH_REQUIRED' });
      const order = orders.get(match[1]);
      if (!order) return json(res, 404, { code: 'NOT_FOUND' });
      if (req.method === 'POST') {
        // Admin role boundary remains intact in both versions.
        if (session.role !== 'admin') return json(res, 403, { code: 'ADMIN_REQUIRED' });
        const input = await body(req);
        if (input.stage !== 'shipped' || Object.keys(input).length !== 1) return json(res, 400, { code: 'INVALID_INPUT' });
        order.stage = input.stage;
      } else {
        // Controlled regression: buyer ownership check omitted in candidate.
        if (version === 'baseline' && session.role !== 'admin' && order.customer !== session.customer) return json(res, 403, { code: 'ORDER_PRIVATE' });
        if (req.method === 'PUT') {
          const input = await body(req);
          if (typeof input.instructions !== 'string' || input.instructions.length > 160 || Object.keys(input).length !== 1) return json(res, 400, { code: 'INVALID_INPUT' });
          order.delivery.instructions = input.instructions;
        }
      }
      json(res, 200, { order });
    } catch { json(res, 400, { code: 'INVALID_INPUT' }); }
  });
}
if (isMain(import.meta.url)) {
  const version = argument('--version', 'baseline');
  if (version !== 'baseline' && version !== 'candidate') throw new Error('Invalid version');
  const port = Number(argument('--port', '0'));
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid port');
  const server = createShop(version);
  server.listen(port, '127.0.0.1', () => {
    const address = server.address() as { port: number };
    console.log(JSON.stringify({ ready: true, version, url: `http://127.0.0.1:${address.port}` }));
  });
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => server.close(() => process.exit(0)));
}
