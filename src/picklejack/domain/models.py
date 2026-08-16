"""SQLAlchemy 2.0 models for the fictional multi-tenant workspace domain.

Tenants own users and exactly one reporting workspace. A user belongs to exactly
one tenant; a workspace is owned by one tenant and holds an ordered collection of
dashboard panels and saved filters. All data is fictional and read-only at
runtime.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all domain models."""


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)

    users: Mapped[list[User]] = relationship(back_populates="tenant")
    workspace: Mapped[Workspace] = relationship(back_populates="tenant", uselist=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    username: Mapped[str] = mapped_column(String, unique=True)
    token: Mapped[str] = mapped_column(String, unique=True)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), unique=True)
    name: Mapped[str] = mapped_column(String)

    tenant: Mapped[Tenant] = relationship(back_populates="workspace")
    panels: Mapped[list[Panel]] = relationship(
        back_populates="workspace", order_by="Panel.position"
    )
    filters: Mapped[list[SavedFilter]] = relationship(
        back_populates="workspace", order_by="SavedFilter.position"
    )


class Panel(Base):
    __tablename__ = "panels"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    position: Mapped[int] = mapped_column()
    title: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)

    workspace: Mapped[Workspace] = relationship(back_populates="panels")


class SavedFilter(Base):
    __tablename__ = "filters"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    position: Mapped[int] = mapped_column()
    field: Mapped[str] = mapped_column(String)
    operator: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(String)

    workspace: Mapped[Workspace] = relationship(back_populates="filters")
