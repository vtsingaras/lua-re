"""Discover and select a local Java runtime. No downloads or installation."""
from dataclasses import dataclass
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

INSTALL_URL = 'https://adoptium.net/temurin/releases/'
INSTALL_HELP = ('Lua source recovery needs Java 8 or later. Install a JRE or JDK from '
                + INSTALL_URL + ', then run python3 install.py --configure-java '
                'in the Lua RE lua/ida directory, or set LUA_RE_JAVA to the java executable. '
                'In IDA use Edit > Plugins > Lua RE: Configure Java runtime. '
                'Loading, disassembly and analysis remain available without Java.')

class JavaRuntimeError(RuntimeError):
    pass

@dataclass(frozen=True)
class JavaRuntime:
    path: str
    version: str
    major: int


def config_path():
    return Path(__file__).with_name('decompiler.json')


def load_config():
    path = config_path()
    if not path.exists():
        return {}
    try:
        result = json.loads(path.read_text())
        if not isinstance(result, dict) or any(not isinstance(v, str) for v in result.values()):
            raise ValueError('expected an object with string values')
        return result
    except (OSError, ValueError) as exc:
        raise JavaRuntimeError(f'Invalid Lua RE runtime configuration at {path}: {exc}. '
                               'Use Configure Java runtime to select a runtime again.') from exc


@lru_cache(maxsize=128)
def _probe(path, modified, size):
    try:
        result = subprocess.run([path, '-version'], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=5,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise JavaRuntimeError(f'Cannot start Java at {path}: {exc}') from exc
    output = result.stderr + result.stdout
    match = re.search(r'(?:java|openjdk) version "([^"]+)"', output, re.I)
    if result.returncode or match is None:
        raise JavaRuntimeError(f'Not a usable Java runtime: {path}')
    version = match.group(1)
    numbers = re.findall(r'\d+', version)
    if not numbers:
        raise JavaRuntimeError(f'Unrecognized Java version: {version}')
    major = int(numbers[1] if numbers[0] == '1' and len(numbers) > 1 else numbers[0])
    if major < 8:
        raise JavaRuntimeError(f'Java {version} is too old; unluac requires Java 8 or later.')
    return JavaRuntime(path, version, major)


def probe_java(path):
    path = Path(path).expanduser()
    if path.is_dir():
        mac = path / 'Contents/Home'
        if mac.is_dir():
            path = mac
        path = path / 'bin' / ('java.exe' if sys.platform == 'win32' else 'java')
    try:
        path = path.resolve(strict=True)
        stat = path.stat()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise OSError('not an executable file')
    except OSError as exc:
        raise JavaRuntimeError(f'Java executable is unavailable: {path}. {INSTALL_HELP}') from exc
    return _probe(str(path), stat.st_mtime_ns, stat.st_size)


def candidate_paths():
    yield os.environ.get('LUA_RE_JAVA') or os.environ.get('LUA54_JAVA')
    try:
        yield load_config().get('java')
    except JavaRuntimeError:
        pass
    exe = 'java.exe' if sys.platform == 'win32' else 'java'
    for key in ('JAVA_HOME', 'JRE_HOME'):
        if os.environ.get(key):
            yield str(Path(os.environ[key]) / 'bin' / exe)
    yield shutil.which('java')
    patterns = []
    if sys.platform == 'darwin':
        patterns = ['/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java',
                    str(Path.home() / 'Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java'),
                    '/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java',
                    '/Applications/IntelliJ IDEA*.app/Contents/jbr/Contents/Home/bin/java',
                    '/opt/homebrew/opt/openjdk*/bin/java', '/usr/local/opt/openjdk*/bin/java']
    elif sys.platform == 'win32':
        for root in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'),
                     os.environ.get('LOCALAPPDATA')):
            if root:
                patterns.extend(str(Path(root)/p) for p in ('Java/*/bin/java.exe',
                    'Eclipse Adoptium/*/bin/java.exe','Microsoft/jdk*/bin/java.exe',
                    'Programs/Eclipse Adoptium/*/bin/java.exe','Android/Android Studio/jbr/bin/java.exe'))
    else:
        patterns = ['/usr/lib/jvm/*/bin/java', '/usr/java/*/bin/java', '/opt/java/*/bin/java']
    patterns.append(str(Path.home() / '.sdkman/candidates/java/*/bin' / exe))
    import glob
    for pattern in patterns:
        yield from sorted(glob.glob(pattern))


def discover_java():
    found, seen = [], set()
    for candidate in candidate_paths():
        if not candidate:
            continue
        path = str(Path(candidate).expanduser().resolve())
        if path in seen:
            continue
        seen.add(path)
        try:
            found.append(probe_java(path))
        except JavaRuntimeError:
            continue
        if len(found) >= 32:
            break
    return found


def selected_java():
    override = os.environ.get('LUA_RE_JAVA') or os.environ.get('LUA54_JAVA')
    selected = override or load_config().get('java')
    if selected:
        return probe_java(selected)
    found = discover_java()
    if found:
        return found[0]
    raise JavaRuntimeError('No compatible Java runtime was found. ' + INSTALL_HELP)


def select_java(path=None, destination=None):
    runtime = probe_java(path) if path else None
    target = Path(destination) if destination else config_path()
    try:
        config = json.loads(target.read_text()) if target.exists() else {}
        if not isinstance(config, dict):
            config = {}
    except (OSError, ValueError):
        config = {}
    if runtime:
        config['java'] = runtime.path
    else:
        config.pop('java', None)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(config, indent=2)+'\n')
    temporary.replace(target)
    return runtime


def choose_java_cli():
    """Interactive only when explicitly requested; never called by the provider."""
    if not sys.stdin.isatty():
        raise JavaRuntimeError('Interactive Java selection needs a terminal. Use --java PATH or --java auto instead.')
    found = discover_java()
    print('Java runtime for Lua RE source recovery')
    print('  0. Automatic discovery')
    for index, item in enumerate(found, 1):
        print(f'  {index}. Java {item.version}: {item.path}')
    if not found:
        print(INSTALL_HELP)
    print('Enter a number, an executable/JRE path, or q to cancel.')
    while True:
        answer = input('Java [0]: ').strip()
        if answer.lower() == 'q':
            return False
        if not answer or answer == '0':
            return 'auto'
        if answer.isdigit() and 1 <= int(answer) <= len(found):
            return found[int(answer)-1].path
        try:
            return probe_java(answer).path
        except JavaRuntimeError as exc:
            print(exc)
