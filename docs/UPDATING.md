# Updating Orisis

This document is a maintainer-focused guide for updating the project after upstream changes (for example: game/client updates that change code generation, symbol layouts, or instruction sequences).

You will usually update one or both of:

1. Byte patterns (signature scanning)
2. Struct/class field names + offsets (schema / SDK changes)

This repo treats patterns and offsets as code-reviewed artifacts: update the header definitions, then validate against current binaries.

## Repo Map (Where Things Live)

Patterns:

- Linux patterns: `Source/MemoryPatterns/Linux/*.h`
- Windows patterns: `Source/MemoryPatterns/Windows/*.h`
- Pattern composition / module mapping: `Source/MemoryPatterns/MemoryPatterns.h`

Pattern result types (this is what `.read()` reads into, and what the caller expects):

- `Source/MemoryPatterns/PatternTypes/*PatternTypes.h`

CS2 types and field definitions (used by many strong types / offsets):

- `Source/CS2/Classes/**`
- `Source/CS2/Panorama/**`
- `Source/CS2/Constants/**`

## Terminology

- Pattern: A hex byte signature string used to locate code/data references in a module.
- Wildcard: `?` in the pattern string; matches any byte.
- Unique match: The pattern matches exactly one location in the target module's code section.
- Missing: The pattern matches zero locations.
- Multi-match: The pattern matches more than one location (ambiguous; must be fixed).

## How CodePattern Works (Important)

Most pattern definitions look like:

```cpp
.template addPattern<SomeType, CodePattern{"48 8B ? ? ? ? 89"}.add(2).read()>()
```

Key pieces:

- `CodePattern{"..."}` is the byte signature.
- `.add(N)` shifts the cursor inside the matched byte span by `N` bytes.
- `.read()` reads a typed value from the matched byte span at the current cursor.
- `.abs()` reads a 4-byte signed displacement (little-endian) at the cursor and converts it to an absolute pointer.

The semantics are implemented in `Source/MemorySearch/PatternSearchResult.h`.

### Why Wildcards Are Safe With .abs() / .read()

Wildcards affect matching, not reading.

The pattern engine stores the real bytes it matched from memory; even if the pattern string uses `?`, the `PatternSearchResult` still contains the actual bytes at that location, so `.abs()` and `.read()` read the real displacement/offset bytes.

## Linux Pattern Update Workflow (Repeatable)

### 1) Prepare Current Binaries Locally

You need the current Linux shared objects for the modules that are signature-scanned.

Place them in:

- `UP-To-DatePatterns/`

Expected filenames:

- `libclient.so`
- `libscenesystem.so`
- `libtier0.so`
- `libfilesystem_stdio.so`
- `libsoundsystem.so`
- `libpanorama.so`
- `libSDL3.so.0` (used for SDL hook validation)

This folder is intentionally git-ignored (see `.gitignore`) because these binaries are large and environment-specific.

### 2) Run The Linux Pattern Checker

From repo root:

```powershell
python tools/patterns/check_linux_patterns.py
```

This script validates:

- Every Linux `CodePattern` matches exactly once in the module's `.text`.
- `.abs(...)` patterns compute an absolute target that lands in a mapped ELF section (not unmapped nonsense).
- `.read()` patterns have enough bytes after `.add(N)` to read the expected width (based on `PatternTypes`).
- Direct patterns used by hooks still resolve correctly:
  - Panorama `BytePatternLiteral` patterns (in `libpanorama.so`)
  - SDL `matchPatternAtAddress` patterns (at `SDL_PeepEvents` in `libSDL3.so.0`)

If it prints `OK`, the Linux patterns are internally consistent against the binaries in `UP-To-DatePatterns/`.

### 3) Fix Anything That Fails

The checker reports failures like:

- `matches=0` (missing)
- `matches=2` (multi-match)
- `abs_target_unmapped`
- `read_oob`
- `pattern_mismatch` / `missing_symbol=...` (SDL direct checks)

Fix patterns by editing the corresponding header in:

- `Source/MemoryPatterns/Linux/*.h`

Rules of thumb:

- Prefer 12-24 bytes for stable uniqueness; short patterns multi-match over time.
- Wildcard RIP displacements (`disp32`) unless you need them fixed for uniqueness.
- Keep opcodes and ModRM bytes fixed.
- If you shift the pattern start, re-check `.add(N)` so the cursor still points to the intended bytes.

### 4) Re-run The Checker Until Clean

After each change:

```powershell
python tools/patterns/check_linux_patterns.py
```

Isolate issues and keep diffs reviewable.

## Updating Offsets / CS2 Classes

Patterns are only half the maintenance story. If upstream updates change type layouts or field names:

- A pattern can still match and still read a value, but the code may be referring to an old field name or using an offset for a member that moved.

Where offsets come from:

- Strong types in `Source/MemoryPatterns/PatternTypes/*` refer to `cs2::` types and members.
- Those members are declared under `Source/CS2/**`.

High-level update strategy:

1. Update `Source/CS2/**` to match the new upstream schema/SDK.
2. Rebuild and fix compilation errors (member names/types may have changed).
3. Re-run the Linux pattern checker.

