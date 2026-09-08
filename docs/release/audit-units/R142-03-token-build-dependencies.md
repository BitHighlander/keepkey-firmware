# R142-03: generated token tables reach the same build

Base: R142-01 `20c1f07bb`, on product source `cdde6888c`.
Scope: declare both generated token tables as CMake custom-target byproducts.
No token selection, transaction handling or dependency pin changes.

The generator target runs every build but omitted its outputs from the dependency
graph. With Ninja, regeneration of an existing empty table was observed without
recompiling its consumer until a second invocation. Acceptance requires a single
build to regenerate the table, rebuild the consumer and pass the relevant tests.

Local review: both paths match the actual generator destinations; consumers
already depend on this target. BYPRODUCTS supplies the missing file-producing
edges and preserves the generators' existing no-change timestamp behavior.

Validation on the R142-01 source and exact dependency pins with this one-line
CMake delta: deliberately replaced the generated Ethereum table with `#undef X`,
then ran one firmware-unit build. It regenerated the table and all 80 firmware
tests passed, including the three token-resolution tests that failed with the
empty table. Logs: `/private/tmp/7142-byproducts-{configure,build,tests}.log`.
Native build accommodations are recorded in R142-01; ARM/product checks remain
assembly gates. No test expectations were relaxed and no Copilot was requested.

Applicability to 7.14.3 and 7.15 must be checked against their generation rules;
do not blindly replay this change where table-budget logic differs.
