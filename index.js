import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const server = resolve(dirname(fileURLToPath(import.meta.url)), 'server.js');
const child = spawn(process.execPath, ['--experimental-sqlite', server], {
  stdio: 'inherit',
  env: process.env
});
child.on('error', error => {
  console.error(error.message);
  process.exit(1);
});
child.on('exit', code => process.exit(code ?? 1));
