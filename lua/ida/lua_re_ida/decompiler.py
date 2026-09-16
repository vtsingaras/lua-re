"""Pinned unluac integration, with no execution of Lua code. AGPL-3.0."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

UNLUAC_URL = 'https://downloads.sourceforge.net/project/unluac/Unstable/unluac_2025_12_23.jar'
UNLUAC_SHA256 = '98be0fa84ac73ca66dce2842a2e4512226f4c611b6500dc96415571fc5538fcc'

def standard_bytes(chunk):
    """Build a temporary stock-format chunk without changing analysis offsets."""
    if chunk.variant == 'standard':
        return chunk.data
    if chunk.variant == 'glinet-compact':
        return chunk.data[:15] + struct.pack('<qd', 0x5678, 370.5) + chunk.data[16:]
    if chunk.variant == 'lnum':
        # Stock 5.1/5.2 has only one numeric type. Widen floats to double
        # and translate signed integer constants without rounding their value.
        # Counts, instructions, strings and debug records need no rewriting.
        parts = [chunk.data[:10], bytes([8, 0]), chunk.data[12:chunk.header_size]]
        cursor = chunk.header_size
        for p in chunk.prototypes:
            for k in p.constants:
                if k.tag not in (3, 19):
                    continue
                value = float(k.value)
                if k.tag == 3 and value != k.value:
                    raise ValueError(
                        f'LNUM integer {k.value} at file offset {k.offset:#x} cannot '
                        f'be represented exactly by stock Lua {chunk.version_string}/unluac; '
                        'disassembly and integer constants remain available')
                parts.extend((chunk.data[cursor:k.offset], b'\x03',
                              struct.pack(chunk.endian + 'd', value)))
                cursor = k.end
        parts.append(chunk.data[cursor:])
        return b''.join(parts)
    raise ValueError(f'Unsupported bytecode variant: {chunk.variant}')

def find_java():
    from .runtime import selected_java
    return selected_java().path

def configuration():
    from .runtime import load_config, selected_java
    config = load_config()
    java = selected_java().path
    override = os.environ.get('LUA_RE_UNLUAC_JAR') or os.environ.get('LUA54_UNLUAC_JAR')
    jar = override or config.get('jar')
    if not jar:
        jar = Path(__file__).parent.parent / 'vendor/unluac.jar'
        if not jar.is_file():
            jar = Path(__file__).parent.parent.parent / 'lua-re-tools/unluac.jar'
    jar = Path(jar)
    if not jar.is_file():
        raise RuntimeError('unluac is missing; run setup_decompiler.py, then install.py.')
    if not override and hashlib.sha256(jar.read_bytes()).hexdigest() != UNLUAC_SHA256:
        raise RuntimeError('unluac checksum mismatch; reinstall the pinned binary.')
    return java, str(jar)

def decompile(chunk, cancel=None, timeout=120):
    java, jar = configuration()
    with tempfile.TemporaryDirectory(prefix='lua-re-decompile-') as directory:
        root = Path(directory)
        source = root / 'input.luac'
        source.write_bytes(standard_bytes(chunk))
        args = [java, '-Xmx512m', '-jar', jar]
        if not chunk.root.lines:
            args.append('--nodebug')
        args.append(str(source))
        with (root / 'stdout').open('wb') as out, (root / 'stderr').open('wb') as err:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            deadline = time.monotonic() + timeout
            try:
                while proc.poll() is None:
                    if cancel is not None and cancel.is_set():
                        raise RuntimeError('Decompilation cancelled')
                    if time.monotonic() > deadline:
                        raise RuntimeError(f'Decompilation exceeded {timeout} seconds')
                    if (root / 'stdout').stat().st_size > 64 * 1024 * 1024 or (root / 'stderr').stat().st_size > 4 * 1024 * 1024:
                        raise RuntimeError('Decompiler output exceeded the size limit')
                    time.sleep(0.05)
                if proc.returncode:
                    detail = (root / 'stderr').read_text(errors='replace')[:4000]
                    raise RuntimeError(f'unluac exited with {proc.returncode}:\n{detail}')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        output = root / 'stdout'
        if output.stat().st_size > 64 * 1024 * 1024:
            raise RuntimeError('Decompiled source exceeds the 64 MiB view limit')
        # unluac defaults to escaped binary strings. Preserve any non-UTF8 bytes.
        return output.read_text(encoding='utf-8', errors='backslashreplace')
