"""Auth registry metadata helpers."""

from __future__ import annotations

from flext_auth import c, m, p, u

from .mutation import FlextAuthRegistryMutation


class FlextAuthRegistryMetadata(FlextAuthRegistryMutation):
    def _build_metadata(
        self,
        name: str,
        service: p.Auth.FlextAuthBaseProvider,
        provided: m.Auth.Providers.Metadata | None,
    ) -> m.Auth.Providers.Metadata:
        """Build metadata from provider and provided data."""
        try:
            caps = tuple(c for c in service.supports())
        except c.EXC_ATTR_TYPE as exc:
            u.fetch_logger(__name__).warning(
                f"Provider {name} does not support capabilities introspection: {exc}"
            )
            caps = ()
        base = m.Auth.Providers.Metadata(
            name=name, version=c.Auth.PROVIDER_VERSION, capabilities=caps, extras={}
        )
        if provided:
            return provided
        sentinel = object()
        raw = getattr(service, "metadata", sentinel)
        if raw is sentinel:
            return base
        try:
            metadata: m.Auth.Providers.Metadata = (
                m.Auth.Providers.Metadata.model_validate(raw)
            )
        except c.EXC_BASIC_TYPE as exc:
            u.fetch_logger(__name__).debug(
                f"Provider {name} metadata extraction failed, using base: {exc}"
            )
            return base
        else:
            return metadata


__all__: list[str] = ["FlextAuthRegistryMetadata"]
