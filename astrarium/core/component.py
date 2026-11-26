"""Component base class: CLI commands plus controller of one domain."""

from typing import ClassVar, Generic

import rich_click as click

from astrarium.core.types import ApplicationType, ControllerType


def command_group(base: click.Group, name: str, help_text: str) -> click.Group:
    """Subgroup `name` of `base`, created empty with `help_text` when missing. Shared by components."""

    found = base.commands.get(name)
    if isinstance(found, click.Group):
        return found
    group = base.group(name)(lambda: None)
    group.help = help_text
    return group


class BaseComponent(Generic[ApplicationType, ControllerType]):  # noqa: UP046
    """CLI commands for one domain, plus controller holding its reusable logic."""

    name: ClassVar[str]
    controller_class: ClassVar[type]
    expose_controller: ClassVar[bool] = True
    """Make controller reachable as `app.<name>` for other components."""

    def __init__(self, app: ApplicationType) -> None:
        self.app = app
        self.controller: ControllerType = self.controller_class(app)

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        """Add click commands to `base`, called before any application exists."""

    def on_register(self) -> None:
        """Called after component is registered with application."""

    def on_deregister(self) -> None:
        """Called after component is removed from application."""
