from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260717_0008"
down_revision = "20260717_0007"
branch_labels = None
depends_on = None


_ROLE_PERMISSION_ADDITIONS: dict[str, tuple[str, ...]] = {
    "viewer": (
        "dynamic_group.read",
        "saved_view.read",
        "tag.read",
    ),
    "operator": (
        "dynamic_group.manage",
        "dynamic_group.read",
        "saved_view.manage",
        "saved_view.read",
        "tag.manage",
        "tag.read",
    ),
    "responder": (
        "dynamic_group.manage",
        "dynamic_group.read",
        "saved_view.manage",
        "saved_view.read",
        "tag.manage",
        "tag.read",
    ),
    "approver": (
        "dynamic_group.read",
        "saved_view.read",
        "tag.read",
    ),
    "admin": (
        "dynamic_group.manage",
        "dynamic_group.read",
        "saved_view.manage",
        "saved_view.read",
        "tag.manage",
        "tag.read",
    ),
}

_SCOPED_RESOURCE_CHECK = (
    "(scope_type = 'global' AND client_id IS NULL AND location_id IS NULL "
    "AND scope_key = 'global') OR "
    "(scope_type = 'client' AND client_id IS NOT NULL AND location_id IS NULL "
    "AND scope_key = 'client:' || client_id) OR "
    "(scope_type = 'location' AND client_id IS NOT NULL AND location_id IS NOT NULL "
    "AND scope_key = 'location:' || client_id || ':' || location_id)"
)


def _scope_foreign_keys(prefix: str) -> tuple[sa.ForeignKeyConstraint, ...]:
    return (
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["clients.client_id"],
            name=f"fk_{prefix}_client",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["location_id", "client_id"],
            ["locations.location_id", "locations.client_id"],
            name=f"fk_{prefix}_location_client",
            ondelete="RESTRICT",
        ),
    )


def _seed_role_permissions(connection: sa.Connection) -> None:
    for role_key, permissions in _ROLE_PERMISSION_ADDITIONS.items():
        role_id = connection.execute(
            sa.text("SELECT role_id FROM roles WHERE key = :role_key"),
            {"role_key": role_key},
        ).scalar_one()
        for permission in permissions:
            connection.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission) "
                    "VALUES (:role_id, :permission)"
                ),
                {"role_id": role_id, "permission": permission},
            )


def _assert_downgrade_safe(connection: sa.Connection) -> None:
    populated = [
        table_name
        for table_name in (
            "endpoint_tag_assignments",
            "dynamic_groups",
            "saved_view_versions",
            "saved_views",
            "tags",
        )
        if int(
            connection.execute(
                sa.text(f'SELECT COUNT(*) FROM "{table_name}"')
            ).scalar_one()
        )
        > 0
    ]
    missing_seed_rows: list[str] = []
    for role_key, permissions in _ROLE_PERMISSION_ADDITIONS.items():
        for permission in permissions:
            exists = connection.execute(
                sa.text(
                    "SELECT COUNT(*) FROM role_permissions rp "
                    "JOIN roles r ON r.role_id = rp.role_id "
                    "WHERE r.key = :role_key AND rp.permission = :permission"
                ),
                {"role_key": role_key, "permission": permission},
            ).scalar_one()
            if int(exists) != 1:
                missing_seed_rows.append(f"{role_key}:{permission}")
    if populated or missing_seed_rows:
        details: list[str] = []
        if populated:
            details.append("live fleet metadata in " + ", ".join(populated))
        if missing_seed_rows:
            details.append("modified permission seeds: " + ", ".join(missing_seed_rows))
        raise RuntimeError(
            "refusing fleet metadata downgrade because it would destroy data: "
            + "; ".join(details)
        )


def _remove_role_permissions(connection: sa.Connection) -> None:
    for role_key, permissions in _ROLE_PERMISSION_ADDITIONS.items():
        for permission in permissions:
            connection.execute(
                sa.text(
                    "DELETE FROM role_permissions "
                    "WHERE role_id = (SELECT role_id FROM roles WHERE key = :role_key) "
                    "AND permission = :permission"
                ),
                {"role_key": role_key, "permission": permission},
            )


def upgrade() -> None:
    op.create_index(
        "uq_endpoints_id_scope",
        "endpoints",
        ["endpoint_id", "client_id", "location_id"],
        unique=True,
    )

    op.create_table(
        "tags",
        sa.Column("tag_id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("name_normalized", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(208), nullable=False),
        sa.Column("client_id", sa.String(64)),
        sa.Column("location_id", sa.String(64)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        *_scope_foreign_keys("tags"),
        sa.CheckConstraint(_SCOPED_RESOURCE_CHECK, name="ck_tags_scope"),
        sa.UniqueConstraint("scope_key", "name_normalized", name="uq_tags_scope_name"),
        sa.UniqueConstraint("tag_id", "scope_key", name="uq_tags_id_scope"),
    )
    op.create_index("ix_tags_scope", "tags", ["scope_type", "client_id", "location_id"])

    op.create_table(
        "endpoint_tag_assignments",
        sa.Column("endpoint_id", sa.String(64), primary_key=True),
        sa.Column("tag_id", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("location_id", sa.String(64), nullable=False),
        sa.Column("tag_scope_key", sa.String(208), nullable=False),
        sa.Column("assigned_by", sa.String(255), nullable=False),
        sa.Column("assigned_at", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(
            ["endpoint_id", "client_id", "location_id"],
            ["endpoints.endpoint_id", "endpoints.client_id", "endpoints.location_id"],
            name="fk_endpoint_tag_assignments_endpoint_scope",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tag_id", "tag_scope_key"],
            ["tags.tag_id", "tags.scope_key"],
            name="fk_endpoint_tag_assignments_tag_scope",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "tag_scope_key = 'global' OR "
            "tag_scope_key = 'client:' || client_id OR "
            "tag_scope_key = 'location:' || client_id || ':' || location_id",
            name="ck_endpoint_tag_assignments_scope",
        ),
    )
    op.create_index(
        "ix_endpoint_tag_assignments_scope",
        "endpoint_tag_assignments",
        ["client_id", "location_id", "tag_id"],
    )

    op.create_table(
        "saved_views",
        sa.Column("saved_view_id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("name_normalized", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("visibility", sa.String(16), nullable=False),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(208), nullable=False),
        sa.Column("client_id", sa.String(64)),
        sa.Column("location_id", sa.String(64)),
        sa.Column(
            "owner_user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="SET NULL"),
        ),
        sa.Column("owner_actor", sa.String(255), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        *_scope_foreign_keys("saved_views"),
        sa.CheckConstraint(_SCOPED_RESOURCE_CHECK, name="ck_saved_views_scope"),
        sa.CheckConstraint(
            "visibility IN ('private', 'shared')",
            name="ck_saved_views_visibility",
        ),
        sa.CheckConstraint("current_version > 0", name="ck_saved_views_current_version"),
        sa.UniqueConstraint(
            "scope_key", "name_normalized", name="uq_saved_views_scope_name"
        ),
        sa.UniqueConstraint(
            "saved_view_id", "scope_key", name="uq_saved_views_id_scope"
        ),
    )
    op.create_index(
        "ix_saved_views_scope",
        "saved_views",
        ["scope_type", "client_id", "location_id", "visibility"],
    )
    op.create_index("ix_saved_views_owner", "saved_views", ["owner_user_id", "owner_actor"])

    op.create_table(
        "saved_view_versions",
        sa.Column("saved_view_id", sa.String(64), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("filter_json", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(
            ["saved_view_id"],
            ["saved_views.saved_view_id"],
            name="fk_saved_view_versions_view",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("version > 0", name="ck_saved_view_versions_version"),
        sa.UniqueConstraint(
            "saved_view_id", "content_hash", name="uq_saved_view_versions_content"
        ),
    )

    op.create_table(
        "dynamic_groups",
        sa.Column("dynamic_group_id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("name_normalized", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(208), nullable=False),
        sa.Column("client_id", sa.String(64)),
        sa.Column("location_id", sa.String(64)),
        sa.Column("saved_view_id", sa.String(64), nullable=False),
        sa.Column(
            "owner_user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="SET NULL"),
        ),
        sa.Column("owner_actor", sa.String(255), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.String(32), nullable=False),
        *_scope_foreign_keys("dynamic_groups"),
        sa.ForeignKeyConstraint(
            ["saved_view_id", "scope_key"],
            ["saved_views.saved_view_id", "saved_views.scope_key"],
            name="fk_dynamic_groups_saved_view_scope",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(_SCOPED_RESOURCE_CHECK, name="ck_dynamic_groups_scope"),
        sa.UniqueConstraint(
            "scope_key", "name_normalized", name="uq_dynamic_groups_scope_name"
        ),
    )
    op.create_index(
        "ix_dynamic_groups_scope",
        "dynamic_groups",
        ["scope_type", "client_id", "location_id"],
    )
    op.create_index("ix_dynamic_groups_saved_view", "dynamic_groups", ["saved_view_id"])

    _seed_role_permissions(op.get_bind())


def downgrade() -> None:
    connection = op.get_bind()
    _assert_downgrade_safe(connection)
    _remove_role_permissions(connection)
    op.drop_table("dynamic_groups")
    op.drop_table("saved_view_versions")
    op.drop_table("saved_views")
    op.drop_table("endpoint_tag_assignments")
    op.drop_table("tags")
    op.drop_index("uq_endpoints_id_scope", table_name="endpoints")
