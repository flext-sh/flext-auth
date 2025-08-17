import pytest

from flext_auth import (
    FlextSession,
    FlextUser,
    InMemorySessionRepository,
    InMemoryUserRepository,
)

EXPECTED_BULK_SIZE: int
EXPECTED_DATA_COUNT: int

@pytest.fixture
def user_repository() -> InMemoryUserRepository: ...
@pytest.fixture
def session_repository() -> InMemorySessionRepository: ...
@pytest.fixture
def sample_user() -> FlextUser: ...
@pytest.fixture
def sample_session() -> FlextSession: ...

class TestUserRepository:
    async def test_save_user_success(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_save_user_duplicate_username(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_save_user_duplicate_email(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_save_user_update_existing(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_id_success(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_id_not_found(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_get_user_by_username_success(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_username_case_insensitive(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_username_not_found(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_get_user_by_email_success(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_email_case_insensitive(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_user_by_email_not_found(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_delete_user_success(
        self, user_repository: InMemoryUserRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_delete_user_not_found(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_list_users_no_filter(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_list_users_with_status_filter(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_list_users_pagination(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_count_users_no_filter(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...
    async def test_count_users_with_status_filter(
        self, user_repository: InMemoryUserRepository
    ) -> None: ...

class TestSessionRepository:
    async def test_save_session_success(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_save_session_preserves_data(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_save_session_update_existing(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_get_session_by_id_success(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_get_session_by_id_not_found(
        self, session_repository: InMemorySessionRepository
    ) -> None: ...
    async def test_get_sessions_by_user_id(
        self, session_repository: InMemorySessionRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_get_sessions_by_user_id_not_found(
        self, session_repository: InMemorySessionRepository
    ) -> None: ...
    async def test_get_active_sessions(
        self, session_repository: InMemorySessionRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_revoke_session(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_revoke_session_not_found(
        self, session_repository: InMemorySessionRepository
    ) -> None: ...
    async def test_revoke_all_user_sessions(
        self, session_repository: InMemorySessionRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_cleanup_expired_sessions(
        self, session_repository: InMemorySessionRepository, sample_user: FlextUser
    ) -> None: ...
    async def test_delete_session(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None: ...
    async def test_delete_session_not_found(
        self, session_repository: InMemorySessionRepository
    ) -> None: ...
    async def test_session_user_index_consistency(
        self, session_repository: InMemorySessionRepository, sample_user: FlextUser
    ) -> None: ...

class TestRepositoryIntegration:
    async def test_user_session_relationship(
        self,
        user_repository: InMemoryUserRepository,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None: ...
    async def test_repository_error_handling(
        self,
        user_repository: InMemoryUserRepository,
        session_repository: InMemorySessionRepository,
    ) -> None: ...
