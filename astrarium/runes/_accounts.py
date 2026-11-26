"""pyinfra operations shared by astrarium runes: system account and authorized_keys from host data."""

import io

from pyinfra.context import host
from pyinfra.facts.server import Groups, Users
from pyinfra.operations import files, server


def ensure_system_user(user: str, home: str) -> None:
    """System group and user with bash, home and quiet login, matching legacy Deployment-created accounts."""

    if user not in host.get_fact(Groups):
        server.group(
            name=f"Ensure {user} group exists",
            group=user,
            system=True,
            _sudo=True,
        )

    if user not in host.get_fact(Users):
        server.user(  # noqa: S604
            name=f"Ensure {user} system user exists",
            user=user,
            group=user,
            system=True,
            shell="/bin/bash",
            home=home,
            create_home=True,
            _sudo=True,
        )

    files.file(
        name=f"Suppress login banner for {user}",
        path=f"{home}/.hushlogin",
        user=user,
        group=user,
        _sudo=True,
    )


def install_authorized_keys(user: str, home: str, keys: list[str]) -> None:
    """Replace user's authorized_keys with exactly these lines."""

    files.directory(
        name=f"Ensure SSH directory for {user}",
        path=f"{home}/.ssh",
        user=user,
        group=user,
        mode="0700",
        _sudo=True,
    )

    files.put(
        name=f"Install {user} authorized_keys from host data",
        src=io.StringIO("\n".join(keys) + "\n"),
        dest=f"{home}/.ssh/authorized_keys",
        user=user,
        group=user,
        mode="0600",
        _sudo=True,
    )
