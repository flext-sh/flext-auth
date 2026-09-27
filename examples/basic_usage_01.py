"""FLEXT Auth - Basic usage examples."""

from __future__ import annotations

from flext_auth import u

from .basic_usage_flows import FlextAuthBasicUsageFlows
from .basic_usage_workflow import FlextAuthBasicUsageWorkflow


class FlextAuthBasicUsageExample(FlextAuthBasicUsageFlows, FlextAuthBasicUsageWorkflow):
    """Single owner for the basic usage example flow."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def main(cls) -> None:
        """Run every basic usage example; the first failure escapes with its cause."""
        for example in (
            cls.example_basic_authentication,
            cls.example_user_lifecycle,
            cls.example_direct_auth,
            cls.example_advanced_registration,
            cls.example_complete_workflow,
        ):
            example().unwrap()
        cls.logger.info("All basic usage examples completed")


if __name__ == "__main__":
    FlextAuthBasicUsageExample.main()
