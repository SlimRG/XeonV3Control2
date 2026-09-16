# TurboBoost foreign Unlock cleanup

## Current executable path: `RemoveInjectedFfs`

Current catalog policy: `retainedFamilies` is empty. `ser8989-turbohack` is **Foreign** and follows the same cleanup rules as every other verified third-party family.

A clean baseline BIOS is **not required** to remove an unambiguously verified Foreign module. Direct removal is authorized from the current source image only when the detector has strong verified family evidence, resolves exactly one known non-retained family, localizes the finding to one exact active FFS, and the source analysis is complete. GUID, module name, a single string, `NearKnownFamilySemantics`, `GenericUnlockSemantics`, ambiguous-family matches, or `Unclassified` findings never authorize mutation.

`RemoveInjectedFfs` is the existing operation identifier for this exact in-place FFS removal primitive. Its executor does not need to prove historical ancestry from a stock image and does not copy stock bytes. Immediately before mutation it re-reads the source file, verifies the source SHA-256, re-runs the full managed TurboBoost/UEFI analysis, re-confirms the exact verified Foreign module, and performs the authorization-agnostic low-level FFS preflight against exact GUID + FV offset + FFS offset + size + type + FFS SHA-256. The preflight also requires an active `DataValid` PI FFS in a parsed standard firmware volume, valid scanner state/checksums, supported erase polarity, and rejects `FFS_ATTRIB_FIXED`.

Physical removal follows the PI FFS state model: only `EFI_FILE_DELETED` is added to the active `DataValid` state, encoded according to FV erase polarity. The FFS body, header identity, size, placement, following files, FV geometry, and every unrelated byte remain untouched. No FFS is repacked, moved, erased as a range, or replaced.

Postconditions are fail-closed:

- exactly the authorized target FFS becomes `Deleted` at the same location;
- the output differs from the source by exactly the FFS state byte;
- the target Foreign Unlock disappears from the repeated TurboBoost and UEFI-driver analysis;
- all other TurboBoost modules remain equivalent;
- all Intel microcodes remain identical, and the presence/absence of CPU Patch `6F 06F2` is unchanged;
- FV/region layout remains compatible and a full managed analysis succeeds;
- file output is side-by-side, write-through, hash-verified and never overwrites an existing destination.

The TurboBoost page exposes only an **individual** remove action for a `Ready/RemoveInjectedFfs` Foreign module; clicking it starts the operation immediately without a second confirmation dialog. No clean-BIOS picker is part of this path. There is no bulk "remove all foreign Unlocks" action: after each mutation the source SHA-256 changes, so the new BIOS is analyzed again and any next module must be independently re-authorized.

A clean baseline remains useful only for the separate future `RestoreBaselineFfs` investigation: it may provide topology evidence that a Foreign Unlock modified/replaced a stock FFS. That topology is not byte authorization and cannot make restore executable.

## `RestoreBaselineFfs`: intentionally blocked

`RestoreBaselineFfs` remains `RequiresBaselineByteAuthorization`. Topology alone is not permission to copy
bytes from another BIOS. Before this state can ever become executable, all gates below must be implemented
and proven together.

1. **Exact platform / firmware lineage**
   - exact image kind and Intel flash-region geometry;
   - board/platform identity from stable firmware metadata where it can be parsed unambiguously;
   - BIOS identity/version/revision compatibility where available;
   - absence of contradictions between source and baseline identity data.

2. **Exact firmware-volume identity**
   - same FV base, length, filesystem GUID, attributes, erase polarity and block geometry;
   - same FV extended-header Name GUID when present;
   - valid FV header checksums on both images.

3. **Unambiguous surrounding FFS topology**
   - a unique source/baseline change window;
   - stable preceding/following FFS anchors with compatible GUID/type/attributes/alignment;
   - no unknown, ordinary or unclassified FFS inside a candidate cleanup group;
   - no known family is excluded implicitly; `ser8989-turbohack` is Foreign, and any future retained family must be explicitly authorized by the data catalog.

4. **Stock FFS identity and semantics**
   - the baseline candidate is the unique expected stock FFS for the change window;
   - GUID/type/header size/attributes/data alignment are compatible with the source slot;
   - DEPEX identity/dependencies are compatible;
   - executable format, machine architecture, subsystem and section topology are compatible;
   - UI name, vendor/version/build metadata agree where present;
   - the baseline FFS itself contains no verified or ambiguous TurboBoost Unlock evidence.

5. **Byte-range authorization**
   - the replacement fits without moving unrelated FFS or changing the FV layout;
   - every byte allowed to differ is explicitly covered by the authorized target range and required checksum/state bytes;
   - no baseline data may restore CPU Patch 6F/06F2, reintroduce a removed Foreign Unlock, or alter any unrelated FFS;
   - if exact counterpart compatibility cannot be proven, authorization fails rather than repacking.

6. **Result proof**
   - full managed re-analysis of the candidate output;
   - expected stock FFS present at the exact authorized location;
   - Foreign target absent, all non-target Unlock modules unchanged, CPU Patch state unchanged;
   - unrelated FFS identities and bytes unchanged;
   - source file never overwritten and output hash verified after atomic commit.

### Known blocker

The current generic `BiosImage` model does not expose enough vendor-independent board/BIOS-lineage metadata or
FV extended-header identity to satisfy all gates above. Therefore topology planning may classify a modified or
replaced FFS, but it **must not** authorize baseline bytes. `RequiresBaselineByteAuthorization` is the intended
production state until those proofs exist.

## Nalex/UPT regression pair

`tests/8DPV11.bin` and `tests/TurboUnlock/ForeignCleanup/8DPV11_nalex_upt.bin` pin a real Nalex/UPT insertion. The modified image contains exact Foreign FFS `9C81BC4D-A8F5-4D3D-BB75-5AA2E934A034` at `0x8C9AE8`, size `2347`, SHA-256 `9068ED21C0BE8524D5B554307D49EA4D44F647CC700FF0D706F477D8BF784D5A`. Direct cleanup is intentionally only the PI state transition at `0x8C9AFF`, `F8 -> E8`; it does not reconstruct the complete stock image or undo unrelated UPT changes. The resulting image SHA-256 is `E81AD0CE6B83E7413048D3AF9D1349382E91A4BBD16476D0961BC3DE7D35DE57`. CPU Patch `6F 06F2` and all microcodes remain unchanged.
