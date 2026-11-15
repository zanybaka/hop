/* ADR/003-exchange-write-access.md */
import { randomUUID } from 'node:crypto';

export function openExchangeAccess(db, path) {
  db.prepare('ATTACH DATABASE ? AS exchange_access').run(path);
  // A rollback journal lets SQLite coordinate commits spanning both files.
  db.exec(`PRAGMA exchange_access.journal_mode=DELETE;
    PRAGMA exchange_access.synchronous=FULL;
    CREATE TABLE IF NOT EXISTS exchange_access.modes (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS exchange_access.grants (
      id TEXT NOT NULL, member TEXT NOT NULL, fingerprint TEXT NOT NULL, seenAt INTEGER,
      PRIMARY KEY(id, member), UNIQUE(id, fingerprint)
    );
    CREATE TABLE IF NOT EXISTS exchange_access.invitations (id TEXT NOT NULL, fingerprint TEXT NOT NULL, PRIMARY KEY(id, fingerprint))`);
  const mode = db.prepare('SELECT enabled FROM exchange_access.modes WHERE id = ?');
  const update = db.prepare('INSERT INTO exchange_access.modes VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled');
  const find = db.prepare('SELECT member FROM exchange_access.grants WHERE id = ? AND fingerprint = ?');
  const list = db.prepare('SELECT member AS id, seenAt FROM exchange_access.grants WHERE id = ? ORDER BY rowid');
  const add = db.prepare('INSERT INTO exchange_access.grants VALUES (?, ?, ?, NULL)');
  const seen = db.prepare('UPDATE exchange_access.grants SET seenAt = ? WHERE id = ? AND member = ?');
  const invite = db.prepare('INSERT OR IGNORE INTO exchange_access.invitations VALUES (?, ?)');
  const pending = db.prepare('SELECT COUNT(*) AS count FROM exchange_access.invitations WHERE id = ?');
  const consume = db.prepare('DELETE FROM exchange_access.invitations WHERE id = ? AND fingerprint = ?');
  const eraseInvitations = db.prepare('DELETE FROM exchange_access.invitations WHERE id = ?');
  const eraseMode = db.prepare('DELETE FROM exchange_access.modes WHERE id = ?');
  const eraseGrants = db.prepare('DELETE FROM exchange_access.grants WHERE id = ?');
  const revoke = db.prepare('DELETE FROM exchange_access.grants WHERE id = ? AND member = ?');
  return {
    enabled: id => Boolean(mode.get(id)?.enabled),
    update: (id, enabled) => update.run(id, Number(enabled)),
    find: (id, fingerprint) => find.get(id, fingerprint),
    list: id => list.all(id),
    add: (id, fingerprint) => add.run(id, randomUUID(), fingerprint),
    seen: (id, member, time) => seen.run(time, id, member),
    invite: (id, fingerprint) => invite.run(id, fingerprint),
    pending: id => pending.get(id).count,
    revoke: (id, member) => revoke.run(id, member).changes !== 0,
    claim(id, invitation, device) {
      const existing = find.get(id, device);
      if (existing) return existing.member;
      if (!consume.run(id, invitation).changes) return null;
      const member = randomUUID();
      add.run(id, member, device);
      return member;
    },
    clearInvitations: id => eraseInvitations.run(id),
    clear(id) { eraseMode.run(id); eraseGrants.run(id); eraseInvitations.run(id); },
  };
}
