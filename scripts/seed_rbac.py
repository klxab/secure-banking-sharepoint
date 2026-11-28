from src.database.session import SessionLocal
from src.security.rbac_seed import seed_rbac


def main() -> None:
    db = SessionLocal()

    try:
        result = seed_rbac(db)
        db.commit()

        print("RBAC seed completed successfully.")
        print(f"Roles created: {result['roles_created']}")
        print(f"Permissions created: {result['permissions_created']}")
        print(f"Role-permission assignments created: {result['assignments_created']}")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
