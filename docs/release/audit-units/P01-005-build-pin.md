# P01-005: Pin the 7.14.2 CI toolchain

Status: static contract reviewed; rebuilt assembly validation pending.

The local release script and emulator Dockerfile named an immutable image,
but CI overrode that default with mutable Docker Hub/GHCR v15 tags. The host
Dockerfile also defaulted to v15. A tag change could therefore alter the build
without changing the audited firmware revision.

CI now pulls the existing release digest directly; emulator and both buildx
host-image steps consume that same reference. Both Dockerfile defaults and the
local release entrypoint agree. Remove the unused mirror authentication/resolution
steps. This matches the digest policy already used by 7.14.3 and 7.15.

Validation: parsed workflow bindings and compared all five entrypoint references;
no remaining RESOLVED_BASE/BASE_IMAGE_MIRROR inputs. Actionlint syntax/expression
validation and git diff --check pass. Full actionlint retains the same five
pre-existing shellcheck diagnostics in unrelated steps; no claim of clean full
workflow lint. New CI artifacts must be generated at phase integration; older
mutable-tag artifacts do not prove this revised build contract.
