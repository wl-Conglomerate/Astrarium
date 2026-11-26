"""Deploy user from host data: jump-only hop account on bastions.

Fleet nodes: deploy user injected as role=deploy features.users entry at inventory render,
NullForge users rune owns account, keys, sudoers and feature-dir ACLs there.
"""

import io

from nullforge.smithy.packages import get_pm
from pyinfra.api.exceptions import PyinfraError
from pyinfra.context import host
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from astrarium.runes._accounts import ensure_system_user, install_authorized_keys
from astrarium.runes._policy import HOP_SSHD_DROPIN_PATH, hop_sshd_dropin


def deploy_access() -> None:
    """Provision deploy user from host data 'astrarium'."""

    access = host.data.get("astrarium")
    if not isinstance(access, dict):
        raise PyinfraError("deploy_access needs host data 'astrarium'; cast it through `arium fleet provision`")

    user = access["deploy_user"]
    keys = access["deploy_keys"]
    if not keys:
        raise PyinfraError(f"refusing to install an empty authorized_keys for {user}")
    home = f"/home/{user}"
    sudoers_path = f"/etc/sudoers.d/{user}"

    ensure_system_user(user, home)
    install_authorized_keys(
        user,
        home,
        keys,
    )

    if access["jump_only"]:
        if not access["fleet_endpoints"]:
            raise PyinfraError("jump-only deploy account needs at least one fleet endpoint")
        files.file(
            name=f"Remove {user} sudoers policy on jump host",
            path=sudoers_path,
            present=False,
            _sudo=True,
        )
        _restrict_hop_forwarding([user])
        return


def _restrict_hop_forwarding(users: list[str]) -> None:
    """Hop accounts get local forwarding only, drop-in failing `sshd -t` removed again, sshd reloaded on change."""

    dropin = files.put(
        name="Restrict hop accounts to local forwarding",
        src=io.StringIO(hop_sshd_dropin(users)),
        dest=HOP_SSHD_DROPIN_PATH,
        user="root",
        group="root",
        mode="0644",
        _sudo=True,
    )

    server.shell(
        name="Validate sshd configuration",
        commands=[f"/usr/sbin/sshd -t || {{ rm -f {HOP_SSHD_DROPIN_PATH}; exit 1; }}"],
        _sudo=True,
        _if=any_changed(dropin),
    )

    systemd.service(
        name="Reload sshd for hop policy",
        service="ssh" if get_pm().is_debian_based else "sshd",
        reloaded=True,
        _sudo=True,
        _if=any_changed(dropin),
    )


deploy_access()
