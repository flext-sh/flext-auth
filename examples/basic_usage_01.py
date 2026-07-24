"""FLEXT Auth - Basic usage examples."""

from __future__ import annotations

from examples.basic_usage_flows import FlextAuthBasicUsageFlows
from examples.basic_usage_workflow import FlextAuthBasicUsageWorkflow
from flext_auth import u


class FlextAuthBasicUsageExample(FlextAuthBasicUsageFlows, FlextAuthBasicUsageWorkflow):
    """Single owner for the basic usage example flow."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def _run_examples(cls) -> None:
        """Run each basic usage example in order."""
        for example in (
            cls.example_basic_authentication,
            cls.example_password_operations,
            cls.example_email_validation,
            cls.example_user_lifecycle,
            cls.example_direct_auth,
            cls.example_advanced_registration,
            cls.example_complete_workflow,
        ):
            example()

    @classmethod
    def main(cls) -> None:
        """Run all examples."""
        cls.logger.info("Starting FLEXT Auth comprehensive examples")
        try:
            cls._run_examples()
            cls.logger.info(
                "All examples completed successfully - FLEXT Auth is working correctly"
            )
        except Exception as exc:
            cls.logger.exception("Example execution failed", error=str(exc))
            raise


if __name__ == "__main__":
    FlextAuthBasicUsageExample.main()
