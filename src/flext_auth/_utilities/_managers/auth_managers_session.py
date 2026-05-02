from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
    Sequence,
)
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import uuid4

from flext_api import r, u

from flext_auth import e, m, t
from flext_core import FlextContainer, FlextContext, p

if TYPE_CHECKING:
    from flext_auth.settings import FlextAuthSettings


class FlextAuthSessionManagers:
    class FlextAuthSessionManager:
        def __init__(self, settings: FlextAuthSettings) -> None:
            super().__init__()
            self.config = settings
            self.logger = u.fetch_logger(__name__)
            self.context = FlextContext.create()
            self._dispatcher: p.Dispatcher = (
                FlextContainer.shared().dispatcher().unwrap()
            )
            self._sessions: MutableMapping[str, t.Auth.ManagersSessionData] = {}

        def cleanup_expired_sessions(self) -> p.Result[int]:
            cleaned_count = 0
            sessions_to_check = list(self._sessions.keys())
            for session_id in sessions_to_check:
                session_data = self._sessions[session_id]
                if not self._is_session_active(session_data):
                    end_result = self.end_session_by_id(session_id)
                    if end_result.success:
                        cleaned_count += 1
            return r[int].ok(cleaned_count)

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = 60,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> p.Result[m.Auth.Session]:
            session_id = str(uuid4())
            expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
            session_data: t.Auth.ManagersSessionData = {
                "id": session_id,
                "unique_id": session_id,
                "identity_id": user_id,
                "session_token": token,
                "expires_at": expires_at,
                "is_active": True,
                "last_accessed": datetime.now(UTC),
                "ip_address": ip_address or "",
                "user_agent": user_agent or "",
            }
            self._sessions[session_id] = session_data
            session = m.Auth.Session(
                identity_id=str(session_data["identity_id"]),
                session_token=str(session_data["session_token"]),
                expires_at=session_data["expires_at"]
                if isinstance(session_data["expires_at"], datetime)
                else datetime.fromisoformat(str(session_data["expires_at"])),
                is_active=bool(session_data.get("is_active", True)),
                ip_address=str(session_data.get("ip_address", "")),
                user_agent=str(session_data.get("user_agent", "")),
                last_accessed=session_data["last_accessed"]
                if "last_accessed" in session_data
                and isinstance(session_data["last_accessed"], datetime)
                else datetime.now(UTC),
            )
            return r[m.Auth.Session].ok(session)

        def end_session(self, user_id: str) -> p.Result[bool]:
            found = False
            for session_data in self._sessions.values():
                identity_id_value = session_data.get("identity_id")
                match identity_id_value:
                    case str() as identity_id_value_str if (
                        identity_id_value_str == user_id
                    ):
                        session_data["is_active"] = False
                        found = True
                    case _:
                        continue
            if found:
                return r[bool].ok(value=True)
            return r[bool].fail("No sessions found for user")

        def end_session_by_id(self, session_id: str) -> p.Result[bool]:
            if session_id in self._sessions:
                self._sessions[session_id]["is_active"] = False
                return r[bool].ok(value=True)
            return e.fail_not_found("Session", "", result_type=r[bool])

        def get_active_sessions(
            self, user_id: str
        ) -> p.Result[Sequence[m.Auth.Session]]:
            sessions: MutableSequence[m.Auth.Session] = []
            for session_id, session_data in self._sessions.items():
                identity_id_value = session_data.get("identity_id")
                match identity_id_value:
                    case str() as identity_id_value_str if (
                        identity_id_value_str == user_id
                        and self._is_session_active(session_data)
                    ):
                        session = m.Auth.Session(
                            identity_id=str(session_data["identity_id"]),
                            session_token=str(session_data["session_token"]),
                            expires_at=session_data["expires_at"]
                            if isinstance(session_data["expires_at"], datetime)
                            else datetime.fromisoformat(
                                str(session_data["expires_at"]),
                            ),
                            is_active=bool(session_data.get("is_active", True)),
                            ip_address=str(session_data.get("ip_address", "")),
                            user_agent=str(session_data.get("user_agent", "")),
                            last_accessed=session_data["last_accessed"]
                            if "last_accessed" in session_data
                            and isinstance(session_data["last_accessed"], datetime)
                            else datetime.now(UTC),
                        )
                        session.unique_id = session_id
                        sessions.append(session)
                    case _:
                        continue
            return r[Sequence[m.Auth.Session]].ok(sessions)

        def get_total_active_sessions(self) -> int:
            return sum(
                1
                for session in self._sessions.values()
                if self._is_session_active(session)
            )

        def _is_session_active(
            self,
            session_data: t.Auth.ManagersSessionData,
        ) -> bool:
            expires_at_value = session_data.get("expires_at")
            if not isinstance(expires_at_value, datetime):
                return False
            expires_at = expires_at_value
            is_active_value = session_data.get("is_active")
            match is_active_value:
                case bool() as active:
                    is_active = active
                case _:
                    return False
            return is_active and expires_at > datetime.now(UTC)
