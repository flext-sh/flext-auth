# FLEXT Auth tests

The suite verifies authentication behavior through the public `flext_auth`
facades. Tests use `flext-tests` matchers and typed helpers exposed by the local
`tests` facets.

## Contract

- Exercise `FlextAuth`, `FlextAuthSettings`, and the package `c/t/p/m/u`
  surfaces; do not import or construct private implementations.
- Use `tm` for result and value assertions and shared typed fixtures from the
  unified `conftest.py`.
- Use `tests.u.Tests.env_vars_context` when observable settings behavior needs
  a temporary real environment. Values expected from settings or configuration
  come from the same public typed owner as production.
- Mocks, patching, monkeypatching, copied setup, compatibility fixtures, and
  hardcoded project-owned defaults are prohibited.
- Preserve the first failure and its cause. A warning, skip, empty collection,
  disabled Testmon cache, or normalized failure is red.

## Layout

- `conftest.py` owns suite-wide lifecycle fixtures.
- `fixtures/` owns reusable typed fixture data.
- `unit/` contains public behavioral contracts for the API, settings, constants,
  typings, and real token flows.
- Generated test facets are regenerated from their owner and are never edited
  directly.

## Execution

Run the suite only from the workspace root through the canonical Testmon-backed
dispatcher:

```bash
make test APPLY=Y
```

The same command owns impacted and explicitly requested complete execution; do
not invoke pytest or its underlying plugins directly.

## Review checklist

- The assertion observes public behavior rather than implementation structure.
- Configurable expectations come from the typed settings/configuration owner.
- Fixtures are shared, typed, deterministic, and leave no process or filesystem
  residue.
- Success and causal failure paths are both covered where the public contract
  exposes them.
- The root test verb completes with Testmon enabled and without warnings or
  skips.
