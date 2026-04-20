from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)
from datetime import UTC, datetime, timedelta

from flext_api import r, u

from flext_auth import FlextAuthSettings, p, t
from flext_core import FlextContext


class FlextAuthRateLimiterManagers:
    class FlextAuthRateLimiter:
        def __init__(
            self, settings: FlextAuthSettings, dispatcher: p.Dispatcher
        ) -> None:
            super().__init__()
            self._config = settings
            self._dispatcher = dispatcher
            self.logger = u.fetch_logger(__name__)
            self._context = FlextContext()
            self._attempts: MutableMapping[str, t.Auth.Managers.AttemptData] = {}
            self._max_attempts = 5
            self._window_minutes = 15

        def check_rate_limit(self, username: str) -> p.Result[bool]:
            now = datetime.now(UTC)
            if username not in self._attempts:
                return r[bool].ok(value=True)
            recent_attempts = self._cleanup_window(username, now)
            if username not in self._attempts:
                self._attempts[username] = {"attempts": recent_attempts}

            if len(recent_attempts) >= self._max_attempts:
                return r[bool].fail("Too many failed attempts. Please try again later.")
            return r[bool].ok(value=True)

        def get_total_failed_attempts(self) -> int:
            return sum(len(attempts) for attempts in self._attempts.values())

        def record_failed_attempt(self, username: str) -> None:
            now = datetime.now(UTC)
            if username not in self._attempts:
                self._attempts[username] = {"attempts": []}
            attempts_raw = self._attempts[username].get("attempts")
            attempts_list: MutableSequence[t.ContainerValue]
            if isinstance(attempts_raw, list):
                attempts_list = [
                    attempt for attempt in attempts_raw if isinstance(attempt, datetime)
                ]
            else:
                attempts_list = list[t.ContainerValue]()
                self._attempts[username]["attempts"] = attempts_list
            attempts_list.append(now)
            recent_attempts = self._cleanup_window(username, now)
            self._attempts[username]["attempts"] = recent_attempts

        def _cleanup_window(
            self,
            username: str,
            now: datetime,
        ) -> Sequence[t.ContainerValue]:
            window_start = now - timedelta(minutes=self._window_minutes)
            attempt_data = self._attempts.get(username)
            if not isinstance(attempt_data, Mapping):
                return []
            attempts_value = attempt_data.get("attempts")
            if not isinstance(attempts_value, list):
                return []
            recent_attempts: Sequence[t.ContainerValue] = [
                attempt
                for attempt in attempts_value
                if isinstance(attempt, datetime) and attempt > window_start
            ]
            return recent_attempts
