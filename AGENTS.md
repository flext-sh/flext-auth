# AGENTS.md — flext-auth

> **Parent workspace law** lives in [`../AGENTS.md`](../AGENTS.md) — read it first.
> Universal engineering core: `~/.agents/UNIVERSAL_CORE.md`. Composition: global skills + parent/root `AGENTS.md` + this scope delta. Do not re-embed universal law.
>
> **Standalone / independent mode:** when `../AGENTS.md` does not resolve, pin the parent raw `AGENTS.md` URL to the same branch/release as this package (never `main`).

<!-- AIHUB-AGENTS-SCOPE-LOCAL-BEGIN -->
**Package:** `flext_auth` · deps: `flext-api`, `flext-core`

## Overview

Enterprise authentication & authorization service. Provider-based, registry-driven extensibility.

## Structure

```text
src/flext_auth/
├── api.py            # FlextAuth (inherits FlextAuthApplicationService)
├── base.py
├── providers/        # api-key, basic, certificate, jwt, ldap, oauth2/oidc, saml, kerberos, rfc
├── services/         # auth_service, provider_service (lifecycle/session/token)
├── _registry/        # lookup.py, plugins.py, metadata.py (provider registry)
├── constants.py typings.py protocols.py models.py utilities.py   # AUTO-GENERATED facets
└── _config.py _settings.py _constants/ _models/ _protocols/ _utilities/
```

## Code Map

| Symbol | Kind | Location | Role |
|--------|------|----------|------|
| `FlextAuth` | class | `api.py` | facade (inherits `FlextAuthApplicationService`) |
| `AuthService` | class | `services/auth_service.py` | auth lifecycle |
| `ProviderService` | class | `services/provider_service.py` | provider orchestration |
| registry | modules | `_registry/{lookup,plugins,metadata}.py` | provider selection |

## Conventions (specific to this package)

- Provider selection/extensibility is **registry-driven**; authentication lifecycle/session/token services are separate from provider implementations.
- Canonical reference for pure-declaration `_settings.py`: `@field_validator` normalization + `@computed_field @property` derived secret, nothing else.

## Commands

```bash
make check PROJECT=flext-auth
make test  PROJECT=flext-auth       # tests/{unit,fixtures}
```
<!-- AIHUB-AGENTS-SCOPE-LOCAL-END -->
