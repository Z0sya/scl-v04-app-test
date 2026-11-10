import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const CONTRACT = resolve(ROOT, 'contracts/security.json');
export type Note = { id: string; ownerId: string; title: string };
export type Check = { id: string; actor: string | null; method: 'GET' | 'PATCH'; objectId: string; title?: string; expected: 'ALLOW' | 'DENY'; status: number };
export type Contract = { schemaVersion: 1; id: string; name: string; users: Record<string, { credential: string }>; objects: Note[]; checks: Check[] };

export async function readContract(path: string, source?: string): Promise<Contract> {
  const c = JSON.parse(source ?? await readFile(path, 'utf8'));
  const fail = () => { throw new Error('Invalid security contract'); };
  if (c.schemaVersion !== 1 || typeof c.id !== 'string' || !c.users || typeof c.users !== 'object' || Array.isArray(c.users) || !Array.isArray(c.objects) || !c.objects.length || !Array.isArray(c.checks) || !c.checks.length) fail();
  const tokens = Object.values(c.users).map((u: any) => u?.credential);
  if (tokens.some(t => typeof t !== 'string' || !t) || new Set(tokens).size !== tokens.length) fail();
  const objectIds = new Set();
  for (const o of c.objects) {
    if (!o || typeof o.id !== 'string' || !/^[a-z0-9-]+$/.test(o.id) || objectIds.has(o.id) || !Object.hasOwn(c.users, o.ownerId) || typeof o.title !== 'string') fail();
    objectIds.add(o.id);
  }
  const ids = new Set();
  for (const k of c.checks) {
    if (!k || typeof k.id !== 'string' || ids.has(k.id) || !['GET', 'PATCH'].includes(k.method) || !['ALLOW', 'DENY'].includes(k.expected) || (k.actor !== null && !Object.hasOwn(c.users, k.actor)) || typeof k.objectId !== 'string' || !/^[a-z0-9-]+$/.test(k.objectId) || !Number.isInteger(k.status) || k.status < 100 || k.status > 599 || (k.method === 'PATCH' && typeof k.title !== 'string') || (k.expected === 'ALLOW' && (!objectIds.has(k.objectId) || k.status !== 200)) || (k.expected === 'DENY' && ![401, 403, 404].includes(k.status))) fail();
    ids.add(k.id);
  }
  return c;
}
export function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
export async function body(req: IncomingMessage): Promise<any> {
  let data = '';
  for await (const chunk of req) {
    data += chunk;
    if (Buffer.byteLength(data) > 4096) throw new Error('Body too large');
  }
  return JSON.parse(data || '{}');
}
export function isMain(url: string) { return !!process.argv[1] && resolve(process.argv[1]) === fileURLToPath(url); }
export function argument(name: string, fallback: string) {
  const i = process.argv.indexOf(name);
  if (i === -1) return fallback;
  if (!process.argv[i + 1] || process.argv[i + 1].startsWith('--')) throw new Error(`Missing value for ${name}`);
  return process.argv[i + 1];
}
export function loopbackTarget(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || !u.port || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('Only http://127.0.0.1:<port> loopback targets are permitted');
  return u.origin;
}
