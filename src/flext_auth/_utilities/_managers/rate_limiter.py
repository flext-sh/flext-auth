from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from datetime import datetime, timedelta
from typing import ClassVar

from flext_api import r, u

from flext_auth import p, t
from flext_core import FlextContext


class FlextAuthRateLimiterManagers:
    _context_type: ClassVar[p.ContextType] = FlextContext

    class FlextAuthRateLimiter:
        def __init__(
            self,
            dispatcher: p.Dispatcher,
        ) -> None:
            super().__init__()
            self._dispatcher = dispatcher
            self.logger = u.fetch_logger(__name__)
            self.context = FlextAuthRateLimiterManagers._context_type.create()
            self._attempts: MutableMapping[str, t.Auth.ManagersAttemptData] = {}
            self._max_attempts = 5
            self._window_minutes = 15

        def check_rate_limit(self, username: str) -> p.Result[bool]:
            now = u.now()
            if username not in self._attempts:
                ok_result: p.Result[bool] = r[bool].ok(value=True)
                return ok_result
            recent_attempts = self._cleanup_window(username, now)
            if username not in self._attempts:
                self._attempts[username] = {"attempts": recent_attempts}

            if len(recent_attempts) >= self._max_attempts:
                fail_result: p.Result[bool] = r[bool].fail(
                    "Too many failed attempts. Please try again later.",
                )
                return fail_result
            allowed_result: p.Result[bool] = r[bool].ok(value=True)
            return allowed_result

        def get_total_failed_attempts(self) -> int:
            return sum(len(attempts) for attempts in self._attempts.values())

        def record_failed_attempt(self, username: str) -> None:
            now = u.now()
            if username not in self._attempts:
                self._attempts[username] = {"attempts": []}
            attempts_raw = self._attempts[username].get("attempts")
            attempts_list: t.MutableSequenceOf[datetime] = (
                [] if attempts_raw is None else list(attempts_raw)
            )
            if attempts_raw is None:
                self._attempts[username]["attempts"] = attempts_list
            attempts_list.append(now)
            recent_attempts = self._cleanup_window(username, now)
            self._attempts[username]["attempts"] = recent_attempts

        def _cleanup_window(
            self,
            username: str,
            now: datetime,
        ) -> t.Auth.ManagersAttemptEvents:
            window_start = now - timedelta(minutes=self._window_minutes)
            attempt_data = self._attempts.get(username)
            if attempt_data is None:
                return []
            attempts_value = attempt_data.get("attempts")
            if attempts_value is None:
                return []
            recent_attempts: t.Auth.ManagersAttemptEvents = [
                attempt for attempt in attempts_value if attempt > window_start
            ]
            return recent_attempts
