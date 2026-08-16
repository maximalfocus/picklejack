"""Deterministic fixtures for the fictional workspace domain.

Seeding produces identical data on every run so exported snapshots, reconstructed
views, counts, and ordering are stable. Nothing here is a real organization,
person, or credential.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from picklejack.domain.models import Base, Panel, SavedFilter, Tenant, User, Workspace

# Demo-only static bearer tokens. Conspicuously fake; they authenticate nothing
# outside this local demonstration.
GLOBEX_TOKEN = "demo-token-globex-mallory"
INITECH_TOKEN = "demo-token-initech-peter"


def seed(session: Session) -> None:
    """Create the schema and insert the deterministic fixture rows."""
    Base.metadata.create_all(session.get_bind())

    tenants = [
        Tenant(id=1, slug="globex", name="Globex Corporation"),
        Tenant(id=2, slug="initech", name="Initech LLC"),
    ]
    users = [
        User(id=1, tenant_id=1, username="mallory", token=GLOBEX_TOKEN),
        User(id=2, tenant_id=2, username="peter", token=INITECH_TOKEN),
    ]
    workspaces = [
        Workspace(id=1, tenant_id=1, name="Globex Ops Overview"),
        Workspace(id=2, tenant_id=2, name="Initech Field Metrics"),
    ]
    panels = [
        Panel(id=1, workspace_id=1, position=1, title="Weekly Revenue", kind="line_chart"),
        Panel(id=2, workspace_id=1, position=2, title="Open Incidents", kind="counter"),
        Panel(id=3, workspace_id=1, position=3, title="Regional Breakdown", kind="bar_chart"),
        Panel(id=4, workspace_id=2, position=1, title="Field Utilization", kind="gauge"),
        Panel(id=5, workspace_id=2, position=2, title="SLA Compliance", kind="counter"),
    ]
    filters = [
        SavedFilter(
            id=1, workspace_id=1, position=1, field="region", operator="in", value="APAC,EMEA"
        ),
        SavedFilter(
            id=2, workspace_id=1, position=2, field="status", operator="eq", value="active"
        ),
        SavedFilter(
            id=3, workspace_id=2, position=1, field="team", operator="eq", value="field-ops"
        ),
    ]

    session.add_all([*tenants, *users, *workspaces, *panels, *filters])
    session.commit()
