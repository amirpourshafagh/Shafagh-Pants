import { spawn } from 'node:child_process';
import http from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const listenPort = Number(process.env.PORT || 3000);
const innerPort = listenPort < 64000 ? listenPort + 101 : listenPort - 101;
const child = spawn(process.execPath, ['--experimental-sqlite', resolve(root, 'server.js')], {
  env: { ...process.env, PORT: String(innerPort), LISTEN_HOST: '127.0.0.1' },
  stdio: ['ignore', 'inherit', 'inherit']
});
child.on('exit', code => {
  console.error('Shafagh inner process exited', code);
  process.exit(code ?? 1);
});

function proxy(req, res) {
  const upstream = http.request({
    hostname: '127.0.0.1',
    port: innerPort,
    path: req.url,
    method: req.method,
    headers: req.headers
  }, incoming => {
    res.writeHead(incoming.statusCode, incoming.headers);
    incoming.pipe(res);
  });
  upstream.on('error', () => {
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'فروشگاه در حال راه‌اندازی است. چند ثانیه بعد دوباره تلاش کنید.' }));
  });
  req.pipe(upstream);
}

function ready(tries = 0) {
  const probe = http.get({ hostname: '127.0.0.1', port: innerPort, path: '/api/products' }, () => {
    probe.destroy();
    http.createServer(proxy).listen(listenPort, '0.0.0.0', () => {
      console.log(`Shafagh proxy ${listenPort} -> ${innerPort}`);
    });
  });
  probe.on('error', () => {
    if (tries > 50) {
      console.error('Inner server did not start. Set Node 22+ and NODE_OPTIONS=--experimental-sqlite');
      process.exit(1);
    }
    setTimeout(() => ready(tries + 1), 100);
  });
}

ready();
