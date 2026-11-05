"""Consistent SQLite backup; run inside the container with python backup.py /data/backups."""
import os, sqlite3, sys, datetime
from pathlib import Path
source=Path(os.environ.get('DATABASE','/data/inventory.db'))
target=Path(sys.argv[1] if len(sys.argv)>1 else '/data/backups')
target.mkdir(parents=True,exist_ok=True)
filename=target / ('inventory-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.db')
with sqlite3.connect(source) as src, sqlite3.connect(filename) as dst: src.backup(dst)
filename.chmod(0o600)
print(filename)
