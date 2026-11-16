import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { setAdmin } from '../lib/security.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const path = process.env.DB_PATH || resolve(root, 'data/store.db');
mkdirSync(dirname(path), { recursive: true });

async function save(username, password) {
  const db = new DatabaseSync(path); db.exec('PRAGMA busy_timeout=5000');
  try { await setAdmin(db, username, password); }
  finally { db.close(); }
  console.log('Administrator saved at', path);
  console.log('Sign in at /admin');
}

const [usernameArg, passwordArg] = process.argv.slice(2);
if (usernameArg && passwordArg) {
  try { await save(usernameArg, passwordArg); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
  process.exit();
}

if (!process.stdin.isTTY) {
  console.error('Usage: node --experimental-sqlite scripts/admin-setup.js USERNAME PASSWORD');
  process.exit(1);
}

let muted = false;
const output = new Writable({ write(chunk, encoding, callback) { if (!muted) process.stdout.write(chunk, encoding); callback(); } });
const rl = createInterface({ input: process.stdin, output, terminal: true });
try {
  console.log('Create administrator. No default username exists.');
  const username = (await rl.question('Username: ')).trim();
  process.stdout.write('Password (8–128 characters, hidden): '); muted = true;
  const password = await rl.question('');
  muted = false; process.stdout.write('\nConfirm password (hidden): '); muted = true;
  const confirm = await rl.question(''); muted = false; process.stdout.write('\n');
  if (password !== confirm) throw Error('Passwords do not match. Nothing changed.');
  await save(username, password);
} catch (error) { muted = false; console.error(error.message); process.exitCode = 1; }
finally { rl.close(); }
