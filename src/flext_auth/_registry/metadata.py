"""Auth registry metadata helpers."""

from __future__ import annotations

from flext_auth import c, m, p, u
from flext_auth._registry.mutation import FlextAuthRegistryMutation


class FlextAuthRegistryMetadata(FlextAuthRegistryMutation):
    def _build_metadata(
        self,
        name: str,
        service: p.Auth.FlextAuthBaseProvider,
        provided: p.Auth.Providers.Metadata | None,
    ) -> p.Auth.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(c for c in service.supports())
        except c.EXC_ATTR_TYPE as exc:
            u.fetch_logger(__name__).warning(
                f"Provider {name} does not support capabilities introspection: {exc}",
            )
            caps = ()
        base = m.Auth.Providers.Metadata(
            name=name,
            version="1.0.0",
            capabilities=caps,
            extras={},
        )
        if provided:
            return provided
        get_metadata_fn = getattr(service, "get_metadata", None)
        if callable(get_metadata_fn):
            try:
                raw = get_metadata_fn()
                return m.Auth.Providers.Metadata.model_validate(raw)
            except c.EXC_BASIC_TYPE as exc:
                u.fetch_logger(__name__).debug(
                    f"Provider {name} metadata extraction failed, using base: {exc}",
                )
                return base
        return base


__all__: list[str] = ["FlextAuthRegistryMetadata"]
