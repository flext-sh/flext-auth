"""REAL Production PostgreSQL Tests - NO MOCKS, REAL DATABASE.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Tests REAL production functionality with actual PostgreSQL database.
Validates complete authentication workflows with REAL persistence.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from flext_core import FlextEntityId

# Import everything from public API only - no internal module imports
from flext_auth import (
    AsyncPGPool,
    FlextAuth,
    FlextAuthConfig,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
    SimplePostgreSQLSessionRepository,
    SimplePostgreSQLUserRepository,
    create_postgresql_pool,
    initialize_database_schema,
)


class TestRealProductionPostgreSQL:
    """Test REAL production PostgreSQL functionality - NO MOCKS."""

    @pytest.fixture
    async def production_database_url(self) -> str:
        """Get REAL production database URL."""
        # Use environment variable or default to test database
        return os.getenv(
            "FLEXT_AUTH_TEST_DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5433/flext_auth_test",
        )

    @pytest.fixture
    async def production_pool(
        self, production_database_url: str
    ) -> AsyncGenerator[AsyncPGPool]:
        """Create REAL production PostgreSQL pool."""
        # Fix URL format - asyncpg expects postgresql:// not postgresql+asyncpg://
        db_url = production_database_url.replace(
            "postgresql+asyncpg://", "postgresql://"
        )
        pool = await create_postgresql_pool(db_url)

        # Initialize database schema
        init_result = await initialize_database_schema(pool)
        assert init_result.success, (
            f"Database initialization failed: {init_result.error}"
        )

        yield pool

        # Cleanup after test
        await pool.close()

    @pytest.fixture
    async def production_user_repo(
        self, production_pool: AsyncPGPool
    ) -> SimplePostgreSQLUserRepository:
        """Create REAL production user repository."""
        return SimplePostgreSQLUserRepository(production_pool)

    @pytest.fixture
    async def production_session_repo(
        self, production_pool: AsyncPGPool
    ) -> SimplePostgreSQLSessionRepository:
        """Create REAL production session repository."""
        return SimplePostgreSQLSessionRepository(production_pool)

    @pytest.fixture
    async def production_auth(
        self,
        production_user_repo: SimplePostgreSQLUserRepository,
        production_session_repo: SimplePostgreSQLSessionRepository,
    ) -> FlextAuth:
        """Create REAL production FlextAuth instance."""
        config = FlextAuthConfig(
            app_name="RealProductionTest",
            version="1.0.0",
            environment="production",
            password_min_length=8,
            password_max_length=128,
            bcrypt_rounds=4,  # Lower for test speed, but still real bcrypt
            max_login_attempts=3,
            lockout_duration_minutes=30,
            session_timeout_hours=24,
            jwt_secret_key="real-production-test-secret-32-characters-minimum",
        )

        return FlextAuth(
            config=config,
            user_repository=production_user_repo,
            session_repository=production_session_repo,
        )

    async def test_real_postgresql_user_persistence(
        self, production_user_repo: SimplePostgreSQLUserRepository
    ) -> None:
        """Test REAL PostgreSQL user persistence - actual database operations."""
        # Create REAL user entity
        user = FlextUser(
            id=FlextEntityId("prod_user_001"),
            username="realproductionuser",
            email="real@production.com",
            password_hash="$2b$12$RealBcryptHashFromActualProduction",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        # Save to REAL PostgreSQL
        save_result = await production_user_repo.save(user)
        assert save_result.success, f"Real PostgreSQL save failed: {save_result.error}"
        assert save_result.value is not None
        saved_user = save_result.value
        assert saved_user.username == "realproductionuser"
        assert saved_user.email == "real@production.com"

        # Retrieve from REAL PostgreSQL by username
        get_result = await production_user_repo.get_by_username("realproductionuser")
        assert get_result.success, f"Real PostgreSQL get failed: {get_result.error}"
        assert get_result.value is not None
        retrieved_user = get_result.value
        assert retrieved_user.email == "real@production.com"
        assert (
            retrieved_user.password_hash == "$2b$12$RealBcryptHashFromActualProduction"
        )

        # Retrieve from REAL PostgreSQL by email
        email_result = await production_user_repo.get_by_email("real@production.com")
        assert email_result.success, (
            f"Real PostgreSQL email get failed: {email_result.error}"
        )
        assert email_result.value is not None
        assert email_result.value.username == "realproductionuser"

        # Count users in REAL PostgreSQL
        count_result = await production_user_repo.count_users()
        assert count_result.success, (
            f"Real PostgreSQL count failed: {count_result.error}"
        )
        assert count_result.value >= 1  # At least our user

        # List users from REAL PostgreSQL
        list_result = await production_user_repo.list_users(limit=10)
        assert list_result.success, f"Real PostgreSQL list failed: {list_result.error}"
        assert len(list_result.value) >= 1
        assert any(u.username == "realproductionuser" for u in list_result.value)

    async def test_real_postgresql_session_persistence(
        self, production_session_repo: SimplePostgreSQLSessionRepository
    ) -> None:
        """Test REAL PostgreSQL session persistence - actual database operations."""
        # Create REAL session entity
        session = FlextSession(
            id=FlextEntityId("prod_session_001"),
            user_id="prod_user_001",
            access_token="real.jwt.token.from.production.service",
            refresh_token="real.refresh.token.from.production",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.100",
            user_agent="RealProductionBrowser/1.0",
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )

        # Save to REAL PostgreSQL
        save_result = await production_session_repo.save(session)
        assert save_result.success, (
            f"Real PostgreSQL session save failed: {save_result.error}"
        )
        assert save_result.value is not None
        saved_session = save_result.value
        assert saved_session.user_id == "prod_user_001"
        assert saved_session.access_token == "real.jwt.token.from.production.service"

        # Retrieve from REAL PostgreSQL
        get_result = await production_session_repo.get_by_id("prod_session_001")
        assert get_result.success, (
            f"Real PostgreSQL session get failed: {get_result.error}"
        )
        assert get_result.value is not None
        retrieved_session = get_result.value
        assert retrieved_session.user_id == "prod_user_001"
        assert retrieved_session.ip_address == "192.168.1.100"

        # Get sessions by user from REAL PostgreSQL
        user_sessions_result = await production_session_repo.get_by_user_id(
            "prod_user_001"
        )
        assert user_sessions_result.success, (
            f"Real PostgreSQL user sessions failed: {user_sessions_result.error}"
        )
        assert len(user_sessions_result.value) >= 1
        assert any(s.id == session.id for s in user_sessions_result.value)

    async def test_real_complete_authentication_workflow_postgresql(
        self, production_auth: FlextAuth
    ) -> None:
        """Test complete REAL authentication workflow with PostgreSQL persistence."""
        # Step 1: Create user with REAL PostgreSQL persistence
        username = "completeproduser"
        email = "complete@production.com"
        password = "RealProductionPassword123!@#"

        create_result = await production_auth.create_user(username, email, password)
        assert create_result.success, (
            f"Real production user creation failed: {create_result.error}"
        )
        assert create_result.value is not None
        user_data = create_result.value
        assert user_data["user_created"] is True
        assert user_data["username"] == username
        assert user_data["email"] == email

        # Step 2: Authenticate with REAL PostgreSQL lookup and bcrypt verification
        auth_result = await production_auth.authenticate(username, password)
        assert auth_result.success, (
            f"Real production authentication failed: {auth_result.error}"
        )
        assert auth_result.value is not None
        auth_data = auth_result.value
        assert auth_data["authenticated"] is True
        assert "access_token" in auth_data
        assert "user" in auth_data
        assert auth_data["user"]["username"] == username

        # Step 3: Validate JWT token is REAL and properly signed
        access_token = str(auth_data["access_token"])
        assert isinstance(access_token, str)
        assert len(access_token) > 100  # Real JWT length
        assert access_token.count(".") == 2  # Real JWT format

        # Step 4: Verify token with REAL JWT service
        jwt_service = production_auth.jwt_service
        token_verify = jwt_service.verify_token(access_token)
        assert token_verify.success, (
            f"Real JWT verification failed: {token_verify.error}"
        )
        claims = token_verify.value
        assert claims.username == username
        assert claims.sub == user_data["id"]

        # Step 5: Verify user persisted in REAL PostgreSQL
        user_repo = production_auth.user_repository
        persisted_user_result = await user_repo.get_by_username(username)
        assert persisted_user_result.success, "User should be persisted in PostgreSQL"
        assert persisted_user_result.value is not None
        persisted_user = persisted_user_result.value
        assert persisted_user.email == email
        assert persisted_user.role == FlextUserRole.USER
        assert persisted_user.status == FlextUserStatus.ACTIVE

        # Step 6: Test authentication failure with wrong password
        wrong_auth = await production_auth.authenticate(username, "WrongPassword")
        assert not wrong_auth.success, "Wrong password should fail authentication"

    async def test_real_postgresql_user_uniqueness_constraints(
        self, production_user_repo: SimplePostgreSQLUserRepository
    ) -> None:
        """Test REAL PostgreSQL uniqueness constraints - actual database validation."""
        # Create first user
        user1 = FlextUser(
            id=FlextEntityId("unique_user_001"),
            username="uniqueuser",
            email="unique@test.com",
            password_hash="$2b$12$RealHashOne",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        save1_result = await production_user_repo.save(user1)
        assert save1_result.success, "First user should save successfully"

        # Try to create user with same username (should fail)
        user2 = FlextUser(
            id=FlextEntityId("unique_user_002"),
            username="uniqueuser",  # Same username
            email="different@test.com",
            password_hash="$2b$12$RealHashTwo",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        save2_result = await production_user_repo.save(user2)
        assert not save2_result.success, "Duplicate username should fail"
        assert "already exists" in save2_result.error

        # Try to create user with same email (should fail)
        user3 = FlextUser(
            id=FlextEntityId("unique_user_003"),
            username="differentuser",
            email="unique@test.com",  # Same email
            password_hash="$2b$12$RealHashThree",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        save3_result = await production_user_repo.save(user3)
        assert not save3_result.success, "Duplicate email should fail"
        assert "already exists" in save3_result.error

    async def test_real_postgresql_session_cleanup(
        self, production_session_repo: SimplePostgreSQLSessionRepository
    ) -> None:
        """Test REAL PostgreSQL session cleanup - actual database operations."""
        # Create expired session
        expired_session = FlextSession(
            id=FlextEntityId("expired_session_001"),
            user_id="test_user_001",
            access_token="expired.jwt.token",
            refresh_token="expired.refresh.token",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.101",
            user_agent="TestBrowser/1.0",
            expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
        )

        # Save expired session
        save_result = await production_session_repo.save(expired_session)
        assert save_result.success, "Expired session should save"

        # Create active session
        active_session = FlextSession(
            id=FlextEntityId("active_session_001"),
            user_id="test_user_001",
            access_token="active.jwt.token",
            refresh_token="active.refresh.token",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.102",
            user_agent="TestBrowser/1.0",
            expires_at=datetime.now(UTC) + timedelta(hours=1),  # Active
        )

        # Save active session
        save_active_result = await production_session_repo.save(active_session)
        assert save_active_result.success, "Active session should save"

        # Run cleanup
        cleanup_result = await production_session_repo.cleanup_expired()
        assert cleanup_result.success, f"Session cleanup failed: {cleanup_result.error}"
        assert cleanup_result.value >= 1, (
            "Should have cleaned at least 1 expired session"
        )

        # Verify expired session is gone
        expired_get = await production_session_repo.get_by_id("expired_session_001")
        assert expired_get.success, "Get operation should succeed"
        assert expired_get.value is None, "Expired session should be deleted"

        # Verify active session still exists
        active_get = await production_session_repo.get_by_id("active_session_001")
        assert active_get.success, "Get operation should succeed"
        assert active_get.value is not None, "Active session should still exist"

    async def test_real_postgresql_factory_method(
        self, production_database_url: str
    ) -> None:
        """Test REAL PostgreSQL factory method creates working FlextAuth."""
        # Create FlextAuth using factory method with REAL PostgreSQL
        auth = await FlextAuth.create_with_postgresql(
            database_url=production_database_url,
            config=FlextAuthConfig(
                app_name="FactoryTest",
                version="1.0.0",
                environment="production",
                password_min_length=8,
                password_max_length=128,
                bcrypt_rounds=4,
                jwt_secret_key="factory-test-secret-32-characters-minimum",
            ),
        )

        # Test that it works with REAL operations
        username = "factoryuser"
        email = "factory@test.com"
        password = "FactoryTestPassword123!"

        # Create user
        create_result = await auth.create_user(username, email, password)
        assert create_result.success, (
            f"Factory auth user creation failed: {create_result.error}"
        )

        # Authenticate user
        auth_result = await auth.authenticate(username, password)
        assert auth_result.success, (
            f"Factory auth authentication failed: {auth_result.error}"
        )

        # Verify repositories are REAL PostgreSQL instances
        assert isinstance(auth.user_repository, SimplePostgreSQLUserRepository)
        assert isinstance(auth.session_repository, SimplePostgreSQLSessionRepository)
