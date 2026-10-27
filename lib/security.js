import { scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const derive = promisify(scrypt);
export const digest = value => createHash('sha256').update(value).digest('hex');
export const token = () => randomBytes(32).toString('hex');
export function equal(a, b) {
  return typeof a === 'string' && typeof b === 'string' && timingSafeEqual(Buffer.from(digest(a)), Buffer.from(digest(b)));
}
export async function passwordHash(password, salt = randomBytes(16).toString('hex')) {
  const hash = await derive(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
  return { salt, hash: hash.toString('hex') };
}
export function authSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS admin_credentials(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,salt TEXT NOT NULL,hash TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,username TEXT NOT NULL,expires INTEGER NOT NULL,last_seen INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS login_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until_time INTEGER NOT NULL);`);
}
export async function setAdmin(db, username, password) {
  if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) throw Error('Username: 3–40 letters, numbers, dot, dash or underscore.');
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) throw Error('Password must contain 12–128 characters.');
  const { salt, hash } = await passwordHash(password);
  authSchema(db);
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO admin_credentials VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,salt=excluded.salt,hash=excluded.hash').run(username, salt, hash);
    db.exec('DELETE FROM admin_sessions; DELETE FROM login_limits; COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}
