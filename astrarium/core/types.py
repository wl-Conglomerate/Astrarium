"""Type variables of CLI framework."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar


if TYPE_CHECKING:
    from astrarium.core.application import BaseApplication
    from astrarium.core.controller import BaseController

ApplicationType = TypeVar("ApplicationType", bound="BaseApplication")

ControllerType = TypeVar("ControllerType", bound="BaseController")
