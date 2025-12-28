"""
Subscription and access request service (Postgres + SQLAlchemy).
"""

from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.subscription import (
    Subscription,
    SubscriptionRequestedScope,
    SubscriptionGrantedScope,
)
from app.models.app_client import AppClient
from app.models.api_management import APIVersion, APIProduct, Scope
from app.schemas.subscription import SubscriptionStatus
from app.middleware.rate_limiter import rate_limiter


class SubscriptionService:
    def __init__(self, db: Session):
        self.db = db

    # --------------------------------------------------
    # Create subscription request
    # --------------------------------------------------

    def create_subscription_request(
        self,
        app_client_id: UUID,
        api_version_id: UUID,
        requested_scope_names: List[str],
        justification: Optional[str],
        requested_by_user_id: UUID,
    ) -> Subscription:
        """Create a PENDING subscription request."""

        client = self.db.get(AppClient, app_client_id)
        if not client:
            raise ValueError("App client not found")
        if not client.is_active:
            raise ValueError("App client is inactive")

        version = self.db.get(APIVersion, api_version_id)
        if not version:
            raise ValueError("API version not found")
        if version.status != "published":
            raise ValueError("API version is not published")

        # Prevent duplicate active subscription
        existing = (
            self.db.query(Subscription)
            .filter(
                Subscription.app_client_id == app_client_id,
                Subscription.api_version_id == api_version_id,
                Subscription.status.in_(
                    [SubscriptionStatus.PENDING, SubscriptionStatus.APPROVED]
                ),
            )
            .first()
        )
        if existing:
            raise ValueError("Active subscription already exists")

        # Validate requested scopes belong to product
        scopes = (
            self.db.query(Scope)
            .filter(
                Scope.product_id == version.product_id,
                Scope.name.in_(requested_scope_names),
            )
            .all()
        )

        if len(scopes) != len(set(requested_scope_names)):
            valid = {s.name for s in scopes}
            invalid = set(requested_scope_names) - valid
            raise ValueError(f"Invalid scopes: {invalid}")

        sub = Subscription(
            app_client_id=app_client_id,
            api_version_id=api_version_id,
            status=SubscriptionStatus.PENDING,
            justification=justification,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.db.add(sub)
        self.db.flush()  # get subscription.id

        for scope in scopes:
            self.db.add(
                SubscriptionRequestedScope(
                    subscription_id=sub.id,
                    scope_id=scope.id,
                )
            )

        self.db.commit()
        self.db.refresh(sub)
        return sub

    # --------------------------------------------------
    # Read
    # --------------------------------------------------

    def get_subscription(self, subscription_id: UUID) -> Optional[Subscription]:
        return self.db.get(Subscription, subscription_id)

    def list_subscriptions(
        self,
        org_id: Optional[UUID] = None,
        status: Optional[SubscriptionStatus] = None,
        api_version_id: Optional[UUID] = None,
        app_client_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Subscription]:
        q = self.db.query(Subscription)

        if status:
            q = q.filter(Subscription.status == status)
        if api_version_id:
            q = q.filter(Subscription.api_version_id == api_version_id)
        if app_client_id:
            q = q.filter(Subscription.app_client_id == app_client_id)
        if org_id:
            q = (
                q.join(AppClient)
                .filter(AppClient.org_id == org_id)
            )

        return q.offset(offset).limit(limit).all()

    # --------------------------------------------------
    # Approval / Denial / Revocation
    # --------------------------------------------------

    def approve_subscription(
        self,
        subscription_id: UUID,
        granted_scope_names: List[str],
        rate_limit_per_minute: int,
        approved_by_user_id: UUID,
    ) -> Optional[Subscription]:
        sub = self.db.get(Subscription, subscription_id)
        if not sub:
            return None

        if sub.status != SubscriptionStatus.PENDING:
            raise ValueError("Subscription is not pending")

        requested = {
            rs.scope.name for rs in sub.requested_scopes
        }
        invalid = set(granted_scope_names) - requested
        if invalid:
            raise ValueError(f"Cannot grant unrequested scopes: {invalid}")

        scopes = (
            self.db.query(Scope)
            .filter(Scope.name.in_(granted_scope_names))
            .all()
        )

        sub.status = SubscriptionStatus.APPROVED
        sub.rate_limit_per_minute = rate_limit_per_minute
        sub.approved_by = approved_by_user_id
        sub.approved_at = datetime.now(timezone.utc)
        sub.updated_at = datetime.now(timezone.utc)

        for scope in scopes:
            self.db.add(
                SubscriptionGrantedScope(
                    subscription_id=sub.id,
                    scope_id=scope.id,
                )
            )

        self.db.commit()

        rate_limiter.set_limit(
            f"sub:{sub.id}",
            per_minute=rate_limit_per_minute,
            per_hour=rate_limit_per_minute * 60,
        )

        self.db.refresh(sub)
        return sub

    def deny_subscription(
        self,
        subscription_id: UUID,
        denial_reason: str,
        decided_by_user_id: UUID,
    ) -> Optional[Subscription]:
        sub = self.db.get(Subscription, subscription_id)
        if not sub:
            return None

        if sub.status != SubscriptionStatus.PENDING:
            raise ValueError("Subscription is not pending")

        sub.status = SubscriptionStatus.DENIED
        sub.denial_reason = denial_reason
        sub.updated_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(sub)
        return sub

    def revoke_subscription(
        self,
        subscription_id: UUID,
        revoked_by_user_id: UUID,
    ) -> Optional[Subscription]:
        sub = self.db.get(Subscription, subscription_id)
        if not sub:
            return None

        if sub.status != SubscriptionStatus.APPROVED:
            raise ValueError("Subscription is not approved")

        sub.status = SubscriptionStatus.REVOKED
        sub.updated_at = datetime.now(timezone.utc)

        self.db.commit()

        rate_limiter.reset(f"sub:{sub.id}")

        self.db.refresh(sub)
        return sub

    # --------------------------------------------------
    # OAuth helpers
    # --------------------------------------------------

    def get_client_scopes(self, app_client_id: UUID) -> List[str]:
        """Return distinct granted scope names for approved subscriptions."""
        rows = (
            self.db.query(Scope.name)
            .join(SubscriptionGrantedScope)
            .join(Subscription)
            .filter(
                Subscription.app_client_id == app_client_id,
                Subscription.status == SubscriptionStatus.APPROVED,
            )
            .distinct()
            .all()
        )
        return [r[0] for r in rows]

    def check_scope_access(self, app_client_id: UUID, required_scopes: List[str]) -> bool:
        granted = set(self.get_client_scopes(app_client_id))
        return all(scope in granted for scope in required_scopes)
