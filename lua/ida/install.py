#!/usr/bin/env python3
"""Install Lua RE for IDA 9.4 and configure optional Java source recovery."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from lua_re_ida.runtime import (
    discover_java, probe_java, choose_java_cli, JavaRuntimeError, INSTALL_HELP,
)

def install(destination, java=None):
    root = Path(__file__).resolve().parent
    destination = Path(destination).expanduser().resolve()
    config_path = destination / 'python/lua_re_ida/decompiler.json'
    try:
        previous_config = json.loads(config_path.read_text()) if config_path.exists() else {}
        if not isinstance(previous_config, dict):
            previous_config = {}
    except (OSError, ValueError):
        previous_config = {}
    if java and java != 'auto':
        java = probe_java(java).path
    elif java is None:
        java = previous_config.get('java')
    if java == 'auto':
        java = None

    sources = [(root / 'loaders/lua_re_loader.py', Path('loaders/lua_re_loader.py')),
               (root / 'procs/luare.py', Path('procs/luare.py')),
               (root / 'plugins/lua_re_plugin.py', Path('plugins/lua_re_plugin.py'))]
    sources += [(p, Path('python/lua_re_ida') / p.name)
                for p in sorted((root / 'lua_re_ida').glob('*.py'))]
    sources += [(p, Path('python') / p.parent.name / p.name)
                for p in sorted((root / 'lua_re_ida-1.0.0.dist-info').glob('*'))]
    sources.append((root.parents[1] / 'LICENSE', Path('python/lua_re_ida/LICENSE')))
    jar = root / 'vendor/unluac.jar'
    config = {}
    if jar.exists():
        from lua_re_ida.decompiler import UNLUAC_SHA256
        if hashlib.sha256(jar.read_bytes()).hexdigest() != UNLUAC_SHA256:
            raise RuntimeError('unluac JAR checksum mismatch')
        sources += [(jar, Path('lua-re-tools/unluac.jar')),
                    (root / 'vendor/unluac-LICENSE.txt', Path('lua-re-tools/unluac-LICENSE.txt'))]
        config['jar'] = str(destination / 'lua-re-tools/unluac.jar')
    if java:
        config['java'] = java
    backup = destination / 'lua-re-backups' / datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    manifest = {}
    manifest_path = destination / 'lua-re-install.json'
    old_path = manifest_path if manifest_path.exists() else destination / 'lua54-install.json'
    old_manifest = json.loads(old_path.read_text()) if old_path.exists() else {}
    for source, relative in sources:
        target = destination / relative
        content = source.read_bytes()
        if target.exists() and target.read_bytes() != content:
            old = backup / relative
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, old)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != content:
            temporary = target.with_suffix(target.suffix + '.lua-re-tmp')
            temporary.write_bytes(content)
            temporary.replace(target)
        manifest[str(relative)] = hashlib.sha256(content).hexdigest()

    for relative, digest in old_manifest.get('files', {}).items():
        if relative in manifest:
            continue
        previous = destination / relative
        if not previous.resolve().is_relative_to(destination):
            raise RuntimeError('Invalid path in previous installation manifest')
        if previous.is_file() and hashlib.sha256(previous.read_bytes()).hexdigest() == digest:
            old = backup / relative
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(previous, old)
            previous.unlink()
    if config_path.exists() and config_path.read_text() != json.dumps(config, indent=2)+'\n':
        old = backup / 'python/lua_re_ida/decompiler.json'
        old.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(config_path, old)
    config_path.write_text(json.dumps(config, indent=2)+'\n')
    manifest_path.write_text(json.dumps(
        {'version': 1, 'source': str(root), 'files': manifest}, indent=2) + '\n')
    print(f'Installed Lua RE for IDA 9.4 at {destination}')
    try:
        found = [probe_java(java)] if java else discover_java()
        if not found:
            raise JavaRuntimeError('No compatible Java runtime was found. ' + INSTALL_HELP)
        print(f'Java {found[0].version}: {found[0].path}')
        print('Selection: ' + ('saved path' if java else 'automatic discovery'))
    except JavaRuntimeError as exc:
        print(str(exc))
    print('Configure later: python3 install.py --configure-java')
    print('Headless setup: python3 install.py --java /path/to/java')
    if backup.exists():
        print('Previous files saved at', backup)
    print('Restart IDA or reconnect the MCP worker to load updated modules.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ida-user', default=os.environ.get('IDAUSR', str(Path.home() / '.idapro')).split(os.pathsep)[0])
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--java', help='Java executable or JRE/JDK directory; use auto for discovery')
    choice.add_argument('--configure-java', action='store_true', help='Interactively select Java in a terminal')
    choice.add_argument('--list-java', action='store_true', help='List detected compatible runtimes without installing')
    parser.add_argument('--json', action='store_true', help='Machine-readable output for --list-java')
    args = parser.parse_args()
    if args.json and not args.list_java:
        parser.error('--json requires --list-java')
    try:
        if args.list_java:
            runtimes = discover_java()
            if args.json:
                print(json.dumps({'runtimes': [vars(x) for x in runtimes],
                                  'setup_hint': None if runtimes else INSTALL_HELP}, indent=2))
            else:
                for item in runtimes:
                    print(f'Java {item.version}\t{item.path}')
                if not runtimes:
                    print(INSTALL_HELP)
            return
        java = choose_java_cli() if args.configure_java else args.java
        if java is False:
            print('Java selection cancelled; no changes made.')
            return
        install(args.ida_user, java)
    except (JavaRuntimeError, OSError, ValueError, RuntimeError) as exc:
        parser.exit(2, str(exc) + '\n')

if __name__ == '__main__':
    main()
