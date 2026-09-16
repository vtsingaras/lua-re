# Lua RE for IDA 9.4

One loader, processor and analysis plugin for **Lua 5.1, 5.2, 5.3 and 5.4**.
The version is detected automatically. This is the modern IDA extension in
[vtsingaras/lua-re](https://github.com/vtsingaras/lua-re), forked from the
Lua reverse-engineering work originally published at `feicong/lua_re`
(now `feicong/re-docs`).

## Install

Requirements: **IDA Professional 9.4 with IDAPython**, Python 3.11 or later for
headless tooling, and optionally Java 8 or later for source recovery.
The loader and analysis do not need Java or Hex-Rays.

```sh
git clone https://github.com/vtsingaras/lua-re.git
cd lua-re/lua/ida
python3 install.py
```

Restart IDA, then open a compiled Lua chunk. The installer uses IDA's user
directory (`~/.idapro`, or the first directory in `IDAUSR`); override it with
`--ida-user PATH`. Changed files are backed up under `lua-re-backups`. Re-run
the installer to update. The runtime choice is preserved across updates.

### Java setup, including headless MCP

The bundled unluac JAR is pinned and verified. No Java runtime is bundled and
nothing is downloaded or installed automatically. Discovery checks the saved
choice, `JAVA_HOME`/`JRE_HOME`, `PATH`, and common macOS, Windows and Linux
installation locations. Java launchers are checked with `-version`; Java 8+
is required.

```sh
# Inspect detected runtimes without modifying anything.
python3 install.py --list-java
python3 install.py --list-java --json

# Explicit terminal onboarding.
python3 install.py --configure-java

# Unattended installation/configuration.
python3 install.py --java /path/to/java
python3 install.py --java /path/to/jdk
python3 install.py --java auto
```

`--configure-java` asks only in an interactive terminal. In scripts, use
`--java PATH` or `--java auto`. `LUA_RE_JAVA` overrides the saved selection;
`JAVA_HOME` and `JRE_HOME` participate in discovery.

In IDA, **Edit → Plugins → Lua RE: Configure Java runtime…** lets you choose
a detected runtime or browse to an executable. If Java is absent, F5 provides
setup guidance and a link to [Eclipse Temurin](https://adoptium.net/temurin/releases/).
Core analysis remains available. Saved configuration lives in
`<IDA user directory>/python/lua_re_ida/decompiler.json`.

MCP workers never open dialogs or read terminal input. Their health response
reports missing Java and supplies the setup command. Configure it outside the
MCP connection, then retry; runtime settings are read on each request.

## Work in IDA

| Action | Shortcut |
| --- | --- |
| Recover the current function's Lua source | **F5** |
| Browse functions | **Ctrl-Alt-L** |
| Inspect instructions, locals, constants and upvalues | **Ctrl-Alt-I** |
| Browse inferred call sites | **Ctrl-Alt-C** |
| Browse constants and strings | **Ctrl-Alt-S** |
| Browse required modules, export JSON or DOT, configure Java | **Edit → Plugins** |

All versions share the same UI and original-file-offset address model.
The loader creates functions and control-flow graphs, constant/string references,
debug-local annotations and closure references. Lua 5.1 closure-binding words
and later `EXTRAARG` payloads are folded into their owning instructions.
Static dataflow produces call and dependency indexes. Inferred names are
hypotheses; only agreed closure targets become direct code-call references.

F5 runs unluac in a cancellable subprocess with a timeout and memory limit.
Function-level recovery builds a temporary parent closure so captured variables
and stripped functions have context. The returned source includes that wrapper;
debug information retains original names when present. No target Lua code runs.

The IDB stores the original chunk, so it can be reopened without the input file.
Current IDB bytes are used for recovery and analysis after patches. Structural
changes that move metadata or prototype boundaries require re-importing the
modified chunk. Existing generated comments and open viewers are snapshots;
reopen a viewer after edits to refresh its contents.

## MCP and scripts

Install the [maintained IDA Pro MCP fork](https://github.com/vtsingaras/ida-pro-mcp)
through [the Codex marketplace](https://github.com/vtsingaras/codex-marketplace).
**Lua RE itself is not a Codex marketplace plugin**; it installs into IDA.

The MCP fork discovers the installed Lua RE provider through Python entry-point
metadata. Call the normal `decompile` tool with a function name or address.
Use `server_health.decompiler_ready`, `decompiler_backend` and `decompiler_hint`
to check effective availability. `hexrays_ready: false` is normal for Lua.
The provider works with headless idalib and the GUI MCP package.

```python
# Run on IDA's main thread, like other IDAPython database operations.
from lua_re_ida.pseudocode import decompile
source = decompile(ea)
print(source.render())
```

This returns recovered **Lua source**, not a Hex-Rays `cfunc_t`, ctree or
microcode implementation. Native Hex-Rays APIs are not replaced. Only the
function-entry address is attached to source; statement/address correspondence
is not fabricated. Ctree-specific tools remain native-code-only.

## Offline use

From `lua/ida`, without IDA:

```sh
python3 -m lua_re_ida sample.luac
python3 -m lua_re_ida sample.luac --json -o analysis.json
python3 -m lua_re_ida sample.luac --callgraph -o calls.dot
python3 -m lua_re_ida sample.luac --decompile -o recovered.lua
python3 -m lua_re_ida sample.luac --standard -o normalized.luac
```

## Supported formats and limits

- Standard format-0 Lua 5.1–5.4 chunks, little or big endian, supported 4/8-byte
  scalar widths, debug and stripped functions.
- LNUM/OpenWrt dual-number chunks: the shared Lua 5.1/5.2 reader recognizes
  2-, 4- and 8-byte signed integer payloads (constant tags `9` and `254`)
  alongside 4- or 8-byte floating-point numbers. The header must explicitly
  declare LNUM; unknown tags in stock chunks are still rejected. Lua 5.1 is
  validated against OpenWrt bytecode; the same legacy layout under Lua 5.2 is
  covered by synthetic fixtures. Lua 5.3/5.4 use their native integer/float
  encodings and preserve full 64-bit integer precision.
- The observed GL.iNet Lua 5.4 compact header, whose numeric sentinels are
  replaced by a zero byte. Only that specific variant is recognized.
- Four-byte Lua instructions; bounded counts, offsets, nesting and chunk size.
- LuaJIT, Lua 5.5, encrypted chunks and custom opcode permutations are not supported.
- unluac may fail on nonstandard or obfuscated control flow. Errors are returned
  explicitly; disassembly remains available. Decompiled output requires review.
- LNUM source recovery converts a temporary copy to stock Lua 5.1/5.2 numbers.
  Original bytes, integer values and IDA addresses remain unchanged. Integers
  that cannot be represented exactly as doubles cause an explicit recovery
  error instead of silent rounding; disassembly remains available. LNUM
  complex numbers and extended-precision floating-point formats are unsupported.
- Native operation is validated on macOS ARM64 with IDA 9.4. Python code and Java
  discovery include Windows/Linux support; those platforms need their own IDA
  runtime validation. No compatibility claim is made for IDA 9.2.

## Verification

```sh
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'
PYTHONPATH=. python3 tests/check_compilers.py \
  --compiler 5.1=/path/to/lua-5.1.5/src/luac \
  --compiler 5.2=/path/to/lua-5.2.4/src/luac \
  --compiler 5.3=/path/to/lua-5.3.6/src/luac \
  --compiler 5.4=/path/to/lua-5.4.8/src/luac
```

The compiler check compares every opcode, operand, debug line and branch target
with each official `luac`, compiles every recovered function, and checks exact
instruction/constant recovery for the debug fixture's whole chunk.
The numeric regression suite covers both legacy LNUM headers, all supported
integer widths, both integer tags, endianness, debug/stripped nested closures,
truncation, exact normalization and full-width native Lua 5.3/5.4 integers.

With an IDA-enabled Python, run `tests/ida_smoke.py` on a **disposable copy**.
It creates/saves an IDB and verifies functions, instruction sizes, CFG edges,
rendering, explorer initialization and source recovery. The MCP fork's
`tests/ida_provider_smoke.py` checks standard tool dispatch, JSON schemas,
readiness, error handling, patches and native fallback.

The development corpus included 38 Lua 5.4 chunks: 496 prototypes,
30,506 instruction words and 7,162 constants matched stock `luac 5.4.8`.
The primary 62-prototype sample's recovered whole source recompiles to identical
instruction arrays and constant pools. Proprietary samples and derived artifacts
are excluded from this repository.

## Provenance and licensing

The extension follows the repository's **AGPL-3.0** license. The earlier Lua
reverse-engineering articles and scripts retain their upstream authorship.
The format is implemented against official Lua `lundump.c`, `lopcodes.h`,
`lvm.c` and `ldebug.c` for each supported release. `XUCharles/lua5.4_parser`
was reviewed as a reference; its code was not copied.
The LNUM layout follows OpenWrt's
[numeric-format patch](https://github.com/openwrt/openwrt/blob/main/package/utils/lua/patches/010-lua-5.1.3-lnum-full-260308.patch)
and [architecture-independent bytecode patch](https://github.com/openwrt/openwrt/blob/main/package/utils/lua/patches/030-archindependent-bytecode.patch).

The included **unluac v1.2.3.569** is MIT-licensed; see
[vendor/unluac-LICENSE.txt](vendor/unluac-LICENSE.txt). Its official download is
`unluac_2025_12_23.jar`, with SHA-256
`98be0fa84ac73ca66dce2842a2e4512226f4c611b6500dc96415571fc5538fcc`.
`setup_decompiler.py` downloads and verifies that exact artifact.
An explicit `LUA_RE_UNLUAC_JAR` override supports testing another build; the
bundled binary always requires its pinned checksum.
