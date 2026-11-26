"""CI cast user from host data: NOPASSWD sudo, keys usable only through jump host."""

import io

from pyinfra.api.exceptions import PyinfraError
from pyinfra.context import host
from pyinfra.operations import files

from astrarium.runes._accounts import ensure_system_user, install_authorized_keys
from astrarium.runes._policy import ci_access_action, ci_sudoers_body


def deploy_ci_access() -> None:
    """Create, revoke or leave alone CI cast identity on non-bastion node."""

    access = host.data.get("astrarium")
    if not isinstance(access, dict):
        raise PyinfraError("ci_access needs host data 'astrarium'; cast it through `arium fleet provision`")

    if access["jump_only"]:
        host.noop("no CI cast identity on a jump host")
        return

    user = access["ci_cast_user"]
    action = ci_access_action(user, access["ci_cast_keys"])

    if action == "noop":
        host.noop("no CI cast identity on this host")
        return

    sudoers_path = f"/etc/sudoers.d/{user}"
    home = f"/home/{user}"

    if action == "revoke":
        files.file(
            name=f"Revoke {user} sudoers policy",
            path=sudoers_path,
            present=False,
            _sudo=True,
        )
        files.file(
            name=f"Revoke {user} authorized_keys",
            path=f"{home}/.ssh/authorized_keys",
            present=False,
            _sudo=True,
        )
        return

    ensure_system_user(user, home)
    install_authorized_keys(
        user,
        home,
        access["ci_cast_keys"],
    )

    files.put(
        name=f"Write {user} sudoers policy",
        src=io.StringIO(ci_sudoers_body(user)),
        dest=sudoers_path,
        user="root",
        group="root",
        mode="0440",
        _sudo=True,
    )


deploy_ci_access()
