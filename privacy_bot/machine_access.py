"""Named machine readers cannot inherit browser or private-network privileges."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat


class JobReaders:
    def __init__(self, document=None):
        self.readers = ()
        if document is None:
            return
        if (not isinstance(document, dict) or set(document) != {'schema_version', 'readers'}
                or type(document['schema_version']) is not int or document['schema_version'] != 1
                or not isinstance(document['readers'], list) or len(document['readers']) > 32):
            raise ValueError('Invalid job reader configuration')
        readers, identifiers, digests = [], set(), set()
        for row in document['readers']:
            if (not isinstance(row, dict) or set(row) != {'id', 'sha256'}
                    or not isinstance(row['id'], str)
                    or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', row['id'])
                    or not isinstance(row['sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
                    or row['id'] in identifiers or row['sha256'] in digests):
                raise ValueError('Invalid job reader configuration')
            identifiers.add(row['id'])
            digests.add(row['sha256'])
            readers.append((row['id'], row['sha256']))
        self.readers = tuple(readers)

    @classmethod
    def from_file(cls, filename):
        if not filename:
            return cls()
        try:
            with os.fdopen(os.open(Path(filename), os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 32768:
                    raise ValueError
                document = json.loads(stream.read(32769).decode('utf-8'))
            return cls(document)
        except (OSError, ValueError, UnicodeError):
            raise ValueError('Invalid job reader file') from None

    def authenticate(self, headers):
        if len(headers) != 1:
            return None
        scheme, separator, token = headers[0].partition(' ')
        if scheme.lower() != 'bearer' or not separator or not 32 <= len(token) <= 512:
            return None
        digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
        principal = None
        for identifier, expected in self.readers:
            if hmac.compare_digest(digest, expected):
                principal = identifier
        return principal


def _fields(row, names):
    result = {}
    for name in names:
        value = row.get(name)
        if value is not None and not isinstance(value, (str, bool, int, float)):
            raise ValueError('Invalid job metadata')
        result[name] = value
    return result


def job_metadata(store):
    """Preserve the operational dashboard shape without reading profile/credit data."""
    return {
        'sources': [_fields(row, ('id', 'name', 'kind', 'region', 'mode', 'enabled',
                                'status', 'last_checked')) for row in store.all('sources')],
        'settings': _fields(store.get('meta', 'settings') or {}, ('enabled', 'interval_hours', 'notify_soft')),
        'runs': [_fields(row, ('source_id', 'status', 'no_match', 'created_at'))
                 for row in store.all('runs')[:20]],
        'findings': [_fields(row, ('source_id', 'status')) for row in store.all('findings')],
        'removals': [_fields(row, ('status',)) for row in store.all('removals')],
        'alerts': [_fields(row, ('read',)) for row in store.all('alerts')[:500]],
        'notification_status': _fields(store.get('meta', 'notification_status') or {}, ('status',)),
    }
