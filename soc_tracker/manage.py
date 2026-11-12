"""Administrative commands for one-time operator provisioning."""

import argparse
import getpass

from sqlalchemy import select

from .auth import hash_password, validate_password_strength
from .models import SessionLocal, User


def create_admin(username: str) -> None:
    password = getpass.getpass("Admin password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    error = validate_password_strength(password)
    if error:
        raise SystemExit(error)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            raise SystemExit(f"User {username!r} already exists.")
        db.add(User(username=username, password_hash=hash_password(password), role="L3", is_admin=True))
        db.commit()
    print(f"Created administrator {username!r}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="Create the first or another L3 administrator")
    admin.add_argument("username")
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.username.strip())


if __name__ == "__main__":
    main()
