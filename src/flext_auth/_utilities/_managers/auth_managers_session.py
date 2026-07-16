from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
    Sequence,
)
from datetime import datetime, timedelta
from typing import ClassVar
from uuid import uuid4

from flext_api import r, u

from flext_auth import e, m, p, t
from flext_core import FlextContainer, FlextContext


class FlextAuthSessionManagers:
    _container_type: ClassVar[p.ContainerType] = FlextContainer
    _context_type: ClassVar[p.ContextType] = FlextContext

    class FlextAuthSessionManager:
        def __init__(self) -> None:
            super().__init__()
            self.logger = u.fetch_logger(__name__)
            self.context = FlextAuthSessionManagers._context_type.create()
            self._dispatcher: p.Dispatcher = (
                FlextAuthSessionManagers._container_type.shared().dispatcher().unwrap()
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
            result: p.Result[int] = r[int].ok(cleaned_count)
            return result

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = 60,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> p.Result[p.Auth.Session]:
            session_id = str(uuid4())
            expires_at = u.now() + timedelta(minutes=expires_in_minutes)
            session_data: t.Auth.ManagersSessionData = {
                "id": session_id,
                "unique_id": session_id,
                "identity_id": user_id,
                "session_token": token,
                "expires_at": expires_at,
                "is_active": True,
                "last_accessed": u.now(),
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
                else u.now(),
            )
            result: p.Result[p.Auth.Session] = r[p.Auth.Session].ok(session)
            return result

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
                ok_result: p.Result[bool] = r[bool].ok(value=True)
                return ok_result
            fail_result: p.Result[bool] = r[bool].fail("No sessions found for user")
            return fail_result

        def end_session_by_id(self, session_id: str) -> p.Result[bool]:
            if session_id in self._sessions:
                self._sessions[session_id]["is_active"] = False
                ok_result: p.Result[bool] = r[bool].ok(value=True)
                return ok_result
            fail_result: p.Result[bool] = e.fail_not_found(
                "Session",
                session_id,
                result_type=r[bool],
            )
            return fail_result

        def get_active_sessions(
            self,
            user_id: str,
        ) -> p.Result[Sequence[p.Auth.Session]]:
            sessions: MutableSequence[p.Auth.Session] = []
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
                            else u.now(),
                        )
                        session.unique_id = session_id
                        sessions.append(session)
                    case _:
                        continue
            result: p.Result[Sequence[p.Auth.Session]] = r[Sequence[p.Auth.Session]].ok(
                sessions,
            )
            return result

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
            current_time: datetime = u.now()
            return is_active and expires_at > current_time
