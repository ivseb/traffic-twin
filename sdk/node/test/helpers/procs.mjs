// Child-process and local-server helpers for integration tests and benchmarks.

import { spawn } from 'node:child_process';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, '..', '..');
export const REGISTER = join(ROOT, 'dist', 'esm', 'register.js');
export const HMAC_KEY = 'k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

export function tempDir(prefix = 'tt-sdk-') {
  const d = mkdtempSync(join(tmpdir(), prefix));
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) };
}

/** Spawns a fixture app; resolves with its port once it prints {"port": N}. */
export function spawnApp(script, { register = false, env = {}, nodeArgs = [] } = {}) {
  return new Promise((resolve, reject) => {
    const args = [...nodeArgs, ...(register ? ['--import', REGISTER] : []), script];
    const child = spawn(process.execPath, args, {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => reject(new Error('app did not start: ' + err)), 15_000);
    child.stderr.on('data', (d) => (err += d));
    child.stdout.on('data', (d) => {
      out += d;
      const line = out.split('\n').find((l) => l.startsWith('{"port"'));
      if (line && !child.port) {
        child.port = JSON.parse(line).port;
        clearTimeout(timer);
        resolve({
          child,
          port: child.port,
          stderr: () => err,
          stdout: () => out,
          stop: () => new Promise((r) => {
            if (child.exitCode !== null) return r();
            child.once('exit', () => r());
            child.kill('SIGTERM');
          }),
        });
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (!child.port) reject(new Error(`app exited ${code}: ${err}`));
    });
  });
}

/** A fake carrier (invented API) recording the headers it receives. */
export async function startCarrier() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, port: req.socket.remotePort, body: Buffer.concat(chunks).toString('utf8') });
      if (req.method === 'POST' && req.url === '/v1/shipments') {
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ shipmentId: 'SHP-5521-0098', status: 'BOOKED', eta: '2026-10-25T09:00:00Z' }));
        return;
      }
      if (req.method === 'GET' && req.url.startsWith('/v1/shipments')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ items: [{ shipmentId: 'SHP-5521-0098', status: 'BOOKED' }] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  server.keepAliveTimeout = 30_000;
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    seen,
    close: () => {
      server.closeAllConnections?.();
      return new Promise((r) => server.close(() => r()));
    },
  };
}

/** HTTP request to the app with a keep-alive agent; resolves with status, headers and body. */
export function call(port, { method = 'GET', path = '/', headers = {}, body, agent } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
