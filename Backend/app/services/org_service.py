
"""Organization management service (Postgres/SQLAlchemy)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional, List, Dict, Any

import logging
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.organization import (
    OrganizationCreate, OrganizationUpdate,
    OrganizationResponse
)
from app.schemas.auth import UserResponse, UserRole  # if you want typed users

# TODO: replace with your actual ORM imports
from app.models.organization import Organization  # <- adjust
from app.models.auth import User  # <- adjust

logger = logging.getLogger(__name__)


class OrganizationService:
    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def _org_to_response(o: Organization) -> OrganizationResponse:
        return OrganizationResponse(
            id=str(o.id),
            name=o.name,
            description=o.description,
            is_active=o.is_active,
            created_at=o.created_at,
            updated_at=o.updated_at,
        )

    @staticmethod
    def _user_to_response(u: User) -> UserResponse:
        return UserResponse(
            id=str(u.id),
            email=u.email,
            name=u.name,
            role=u.role if isinstance(u.role, UserRole) else UserRole(u.role),
            org_id=str(u.org_id) if u.org_id is not None else None,
            is_active=u.is_active,
            created_at=u.created_at,
            updated_at=u.updated_at,
        )

    async def create_organization(self, data: OrganizationCreate) -> OrganizationResponse:
        """Create a new organization."""
        o = Organization(name=data.name, description=data.description, is_active=True)
        self.session.add(o)
        try:
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
            # unique(organizations.name)
            raise ValueError("Organization name already exists")

        await self.session.refresh(o)
        return self._org_to_response(o)

    async def get_organization(self, org_id: str) -> Optional[OrganizationResponse]:
        res = await self.session.execute(select(Organization).where(Organization.id == org_id))
        o = res.scalar_one_or_none()
        return self._org_to_response(o) if o else None

    async def list_organizations(
        self,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[OrganizationResponse]:
        stmt = select(Organization)
        if is_active is not None:
            stmt = stmt.where(Organization.is_active == is_active)

        stmt = stmt.order_by(Organization.created_at.desc()).offset(offset).limit(limit)
        res = await self.session.execute(stmt)
        return [self._org_to_response(o) for o in res.scalars().all()]

    async def update_organization(self, org_id: str, data: OrganizationUpdate) -> Optional[OrganizationResponse]:
        values: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if data.name is not None:
            values["name"] = data.name
        if data.description is not None:
            values["description"] = data.description
        if data.is_active is not None:
            values["is_active"] = data.is_active

        stmt = (
            update(Organization)
            .where(Organization.id == org_id)
            .values(**values)
            .returning(Organization)
        )

        try:
            res = await self.session.execute(stmt)
            row = res.fetchone()
            if not row:
                await self.session.rollback()
                return None
            await self.session.commit()
            return self._org_to_response(row[0])
        except IntegrityError:
            await self.session.rollback()
            raise ValueError("Organization name already exists")

    async def delete_organization(self, org_id: str) -> bool:
        """Soft delete organization (set is_active to False)."""
        stmt = (
            update(Organization)
            .where(Organization.id == org_id)
            .values(is_active=False, updated_at=datetime.utcnow())
        )
        res = await self.session.execute(stmt)
        await self.session.commit()
        return res.rowcount > 0

    async def add_user_to_org(self, user_id: str, org_id: str) -> bool:
        """Add user to organization."""
        # ensure org exists & active
        res = await self.session.execute(select(Organization).where(Organization.id == org_id))
        org = res.scalar_one_or_none()
        if not org:
            raise ValueError("Organization not found")
        if not org.is_active:
            raise ValueError("Organization is inactive")

        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(org_id=org_id, updated_at=datetime.utcnow())
        )
        res2 = await self.session.execute(stmt)
        await self.session.commit()
        return res2.rowcount > 0

    async def remove_user_from_org(self, user_id: str) -> bool:
        """Remove user from organization."""
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(org_id=None, updated_at=datetime.utcnow())
        )
        res = await self.session.execute(stmt)
        await self.session.commit()
        return res.rowcount > 0

    async def get_org_users(
        self,
        org_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UserResponse]:
        """Get all users in an organization."""
        stmt = (
            select(User)
            .where(User.org_id == org_id)
            .order_by(User.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        res = await self.session.execute(stmt)
        return [self._user_to_response(u) for u in res.scalars().all()]
