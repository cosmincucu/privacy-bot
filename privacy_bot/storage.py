"""Encrypted JSON records in SQLite; browser profiles have their own protected directory."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.fernet import Fernet


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.root / 'privacy.sqlite3'
        key = os.environ.get('PRIVACY_BOT_KEY')
        key_path = self.root / 'encryption.key'
        if not key:
            if not key_path.exists():
                if self.path.exists():
                    raise RuntimeError('Encryption key missing for existing database')
                with key_path.open('xb') as f:
                    os.chmod(key_path, 0o600)
                    f.write(Fernet.generate_key())
            key = key_path.read_text(encoding='utf-8').strip()
        self.cipher = Fernet(key.encode())
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        os.chmod(self.path, 0o600)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('CREATE TABLE IF NOT EXISTS records (collection TEXT, id TEXT, payload BLOB NOT NULL, PRIMARY KEY(collection,id))')
        self.conn.commit()
        # Decrypt immediately: a wrong key must stop startup rather than hide state.
        for row in self.conn.execute('SELECT payload FROM records LIMIT 1'):
            self.cipher.decrypt(row[0])

    def all(self, collection):
        with self.lock:
            return [json.loads(self.cipher.decrypt(r[0])) for r in self.conn.execute(
                'SELECT payload FROM records WHERE collection=? ORDER BY rowid DESC', (collection,))]

    def get(self, collection, key, default=None):
        with self.lock:
            row = self.conn.execute('SELECT payload FROM records WHERE collection=? AND id=?', (collection, key)).fetchone()
            return json.loads(self.cipher.decrypt(row[0])) if row else default

    def put(self, collection, value, key=None):
        value = dict(value)
        value['id'] = key or value.get('id') or uuid4().hex
        payload = self.cipher.encrypt(json.dumps(value, ensure_ascii=False).encode())
        with self.lock, self.conn:
            self.conn.execute('INSERT INTO records VALUES (?,?,?) ON CONFLICT(collection,id) DO UPDATE SET payload=excluded.payload',
                              (collection, value['id'], payload))
        return value

    def snapshot(self):
        """Read-verified daily online backup; preserve previous snapshots."""
        dest = self.root / 'backups'
        dest.mkdir(exist_ok=True, mode=0o700)
        path = dest / (datetime.now(timezone.utc).strftime('%Y-%m-%d') + '.sqlite3')
        if path.exists():
            return
        temporary = path.with_suffix('.partial')
        with self.lock, sqlite3.connect(temporary) as backup:
            self.conn.backup(backup)
            if backup.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Backup verification failed')
        os.chmod(temporary, 0o600)
        temporary.rename(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        path.with_suffix('.sha256').write_text(digest + '\n', encoding='utf-8')

    def close(self):
        self.conn.close()
