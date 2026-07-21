"""Interactive, local-only bootstrap for Hyrule administrator accounts."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    AdminAuditRow,
    create_db_engine,
    create_session_factory,
    generate_account_id,
    init_db,
)
from hyrule_cloud.services.passwords import (
    generate_recovery_code,
    hash_password,
    hash_recovery_code,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hyrule-admin")
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create", help="create an administrator account")
    create.add_argument(
        "--allow-additional",
        action="store_true",
        help="allow creation when an enabled administrator already exists",
    )
    return parser


def _read_password() -> str:
    password = getpass.getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match")
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must contain between 12 and 256 characters")
    return password


async def _create_admin(*, allow_additional: bool) -> tuple[str, str]:
    password = _read_password()
    recovery_code = generate_recovery_code()
    config = HyruleConfig()
    engine = create_db_engine(config.database_url)
    try:
        await init_db(engine)
        sessions = create_session_factory(engine)
        async with sessions() as session:
            enabled_admins = int(
                await session.scalar(
                    select(func.count())
                    .select_from(AccountRow)
                    .where(
                        AccountRow.is_admin.is_(True),
                        AccountRow.disabled_at.is_(None),
                    )
                )
                or 0
            )
            if enabled_admins and not allow_additional:
                raise RuntimeError(
                    "An enabled Admin already exists; pass --allow-additional intentionally"
                )
            for _ in range(5):
                account_id = generate_account_id()
                account = AccountRow(
                    account_id=account_id,
                    password_hash=hash_password(password),
                    recovery_code_hash=hash_recovery_code(recovery_code),
                    recovery_code_issued_at=datetime.now(UTC),
                    password_changed_at=datetime.now(UTC),
                    is_admin=True,
                )
                session.add(account)
                session.add(
                    AdminAuditRow(
                        audit_id=str(uuid.uuid4()),
                        actor_account_id=account_id,
                        action="admin.bootstrap",
                        target_type="account",
                        target_id=account_id,
                        reason="Created interactively with hyrule-admin",
                        details={"additional_admin": bool(enabled_admins)},
                    )
                )
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    continue
                return account_id, recovery_code
            raise RuntimeError("Could not allocate a unique account ID")
    finally:
        await engine.dispose()


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "create":
            account_id, recovery_code = asyncio.run(
                _create_admin(allow_additional=args.allow_additional)
            )
        else:  # pragma: no cover - argparse rejects this path
            raise RuntimeError("Unsupported command")
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print("Administrator created. These credentials are shown once:")
    print(f"Account ID: {account_id}")
    print(f"Recovery code: {recovery_code}")
    print("Store the recovery code securely before closing this terminal.")


if __name__ == "__main__":
    main()
