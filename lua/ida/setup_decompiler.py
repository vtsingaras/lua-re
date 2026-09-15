#!/usr/bin/env python3
"""Fetch the pinned MIT-licensed unluac JAR from its official distribution."""
import hashlib
from pathlib import Path
import urllib.request
import zipfile
from lua_re_ida.decompiler import UNLUAC_URL, UNLUAC_SHA256

root = Path(__file__).resolve().parent / 'vendor'
root.mkdir(exist_ok=True)
data = urllib.request.urlopen(UNLUAC_URL, timeout=60).read()
if hashlib.sha256(data).hexdigest() != UNLUAC_SHA256:
    raise SystemExit('Downloaded JAR checksum mismatch; nothing installed.')
jar = root / 'unluac.jar'
jar.write_bytes(data)
with zipfile.ZipFile(jar) as z:
    (root / 'unluac-LICENSE.txt').write_text(z.read('license.txt').decode('utf-8').replace('\r\n', '\n'))
print(jar)
