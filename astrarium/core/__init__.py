"""CLI framework core (copied skeleton shared with HexRift, NullForge and Manticora)."""

from rich.console import Console

from astrarium.core.application import BaseApplication
from astrarium.core.component import BaseComponent, command_group
from astrarium.core.controller import BaseController
from astrarium.core.errors import ComponentAlreadyRegistered, ComponentNotRegistered, RegistryError


__all__ = [
    "BaseApplication",
    "BaseComponent",
    "BaseController",
    "ComponentAlreadyRegistered",
    "ComponentNotRegistered",
    "RegistryError",
    "command_group",
    "console",
    "err",
]

console = Console()

err = Console(stderr=True)
