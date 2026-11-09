import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./watchdog.sh', import.meta.url));

test('restarts a session named in a death log line, using its own key', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'watchdog-'));
  const stub = (name, body) => {
    writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(dir, name), 0o755);
  };
  stub('docker', `echo '{"sessionId":"abc-1","message":"Target closed"}'`);
  stub('sleep', 'exec /bin/sleep 0.05');

  const calls = [];
  const server = createServer((req, res) => {
    calls.push({ route: `${req.method} ${req.url}`, key: req.headers['x-api-key'] });
    res.setHeader('content-type', 'application/json');
    res.end(req.method === 'GET' ? '[{"id":"abc-1","status":"ready"}]' : '{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

  const child = spawn('sh', [script], {
    stdio: 'ignore',
    env: {
      PATH: `${dir}:${process.env.PATH}`,
      WATCHDOG_API_KEY: 'test-key',
      WATCHDOG_API_URL: `http://127.0.0.1:${server.address().port}`,
      WATCHDOG_STATE_DIR: join(dir, 'state'),
      WATCHDOG_BACKSTOP_SECONDS: '0',
      WATCHDOG_DEBOUNCE_SECONDS: '0',
    },
  });

  try {
    const posts = () => calls.filter(c => c.route.startsWith('POST')).map(c => c.route);
    for (let i = 0; i < 200 && posts().length < 2; i++) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.deepEqual(posts().slice(0, 2), ['POST /api/sessions/abc-1/stop', 'POST /api/sessions/abc-1/start']);
    assert.ok(calls.every(c => c.key === 'test-key'));
  } finally {
    child.kill('SIGKILL');
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
