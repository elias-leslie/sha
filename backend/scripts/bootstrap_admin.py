from __future__ import annotations

import argparse

from app.bootstrap_admin import bootstrap_global_admin
from app.config import get_settings
from app.db import DatabaseStore


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bind the first global SHA Admin to an exact OIDC issuer and subject."
    )
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--display-name")
    args = parser.parse_args()

    settings = get_settings()
    store = DatabaseStore(
        settings.resolved_database_url(),
        migration_mode=settings.database_migration_mode,
    )
    try:
        store.prepare()
        user, identity, binding = bootstrap_global_admin(
            store,
            issuer=args.issuer,
            subject=args.subject,
            display_name=args.display_name,
        )
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    finally:
        store.dispose()
    print(
        f"bootstrapped user={user.user_id} identity={identity.identity_id} "
        f"binding={binding.binding_id}"
    )


if __name__ == "__main__":
    main()
