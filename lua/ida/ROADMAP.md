# Lua RE milestones

## Milestone 1 — installed end-to-end edition

One IDA 9.4 loader/processor/plugin detects Lua 5.1–5.4. The separate, generic
MCP fork exposes Lua source through its existing decompile tool. Java can be
discovered or selected through CLI onboarding, a saved path, or IDA settings.
The user's Codex installation uses their maintained MCP fork and fresh marketplace.

The current backend launches Java with the pinned unluac JAR and a temporary
bytecode file. Standard input is disabled. Standard output supplies recovered
source, while standard error supplies diagnostics. Process lifetime, memory and
output size are bounded. Only source parsing and recovery occur; the target
program is never executed.

Acceptance: all four Lua versions load in IDA 9.4; native Hex-Rays still works;
headless MCP recovery, missing-Java errors, saved databases and the real target
are verified against the installed packages.

## Milestone 2 — structured and persistent unluac integration

This is a plan, not implemented functionality.

1. **Measure the current backend.** Record cold/warm latency, memory, cancellation,
   output stability and recovery success for debug, stripped and malformed chunks.
   Use a publishable regression corpus and local private samples separately.
2. **Inspect unluac's internal Java API.** Design a small versioned facade returning
   source, structured diagnostics, prototype identities, and any available
   instruction/source relationships. Validate every mapping; never infer exact
   addresses merely from emitted line numbers.
3. **Prototype two backends.** Compare a persistent Java worker using a framed
   request/response protocol with an in-process JVM through JNI or a supported
   Python/Java bridge. Keep the existing subprocess backend as a fallback.
4. **Evaluate lifecycle and isolation.** JNI permits programmatic JVM creation and
   method calls, but does not support multiple JVMs in one process. Test IDA
   startup/shutdown, multiple IDBs, threading, timeout/cancellation and recovery
   after failures. Any native component targets **IDA SDK 9.4** and must be built
   separately for each supported OS/CPU.
5. **Improve recovery context deliberately.** Preserve parent captures, symbols,
   source metadata and cross-prototype identity. These changes, or decompiler
   algorithm fixes, may improve recovered source quality. Merely changing the
   process transport does not improve unluac's decompilation algorithms.
6. **Choose using evidence.** Favor a persistent worker if it provides the required
   structured API and performance with better crash isolation. Embed the JVM only
   if measured benefits justify the native dependencies and lifecycle constraints.
7. **Ship compatibility tests and explicit capabilities.** Keep the normal MCP
   decompile endpoint, version the structured result additions, and document
   which source mappings are exact. No claim of Hex-Rays ctree/microcode support
   without implementing and testing those interfaces.

Reference: [Java 21 JNI Invocation API](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/invocation.html).
