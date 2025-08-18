from collections.abc import Awaitable, Callable as Callable

from _typeshed import Incomplete

def run_example_suite(
    title: str,
    sync_examples: list[Callable[[], None]],
    async_examples: list[Callable[[], Awaitable[None]]] | None = None,
    success_message: str | None = None,
) -> None: ...
def create_example_runner(
    title: str, success_message: str | None = None
) -> Callable[
    [list[Callable[[], None]], list[Callable[[], Awaitable[None]]] | None], None
]: ...

basic_example_runner: Incomplete
advanced_example_runner: Incomplete
