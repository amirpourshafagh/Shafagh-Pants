import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { setAdmin } from '../lib/security.js';

// Only the local terminal can provision/reset the single administrator.
if (!process.stdin.isTTY) { console.error('Run this command in an interactive terminal.'); process.exit(1); }
let muted = false;
const output = new Writable({ write(chunk, encoding, callback) { if (!muted) process.stdout.write(chunk, encoding); callback(); } });
const rl = createInterface({ input: process.stdin, output, terminal: true });
try {
  console.log('Create/reset administrator. Existing sessions will be signed out.');
  const username = (await rl.question('Username [admin]: ')).trim() || 'admin';
  process.stdout.write('New password (12–128 characters, hidden): '); muted = true;
  const password = await rl.question('');
  muted = false; process.stdout.write('\nConfirm password (hidden): '); muted = true;
  const confirm = await rl.question(''); muted = false; process.stdout.write('\n');
  if (password !== confirm) throw Error('Passwords do not match. Nothing changed.');
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const path = process.env.DB_PATH || resolve(root, 'data/store.db');
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path); db.exec('PRAGMA busy_timeout=5000');
  try { await setAdmin(db, username, password); } finally { db.close(); }
  console.log('Administrator saved. Sign in at /admin. ADMIN_KEY is no longer used.');
} catch (error) { muted = false; console.error(error.message); process.exitCode = 1; }
finally { rl.close(); }
