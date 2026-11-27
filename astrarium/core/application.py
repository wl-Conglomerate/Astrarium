"""Application singleton and component registry."""

from __future__ import annotations

from typing import ClassVar, Generic

import rich_click as click

from astrarium.core.component import BaseComponent
from astrarium.core.errors import ComponentAlreadyRegistered, ComponentNotRegistered
from astrarium.core.types import ApplicationType


class BaseApplication(Generic[ApplicationType]):  # noqa: UP046
    """Component registry: instantiates `default_components`, exposes controllers as `app.<name>`."""

    default_components: ClassVar[tuple[type[BaseComponent], ...]] = ()
    _instance: ClassVar[BaseApplication | None] = None

    def __init__(self) -> None:
        self.components: dict[str, BaseComponent] = {}
        type(self)._instance = self
        for component in self.default_components:
            self.register(component)

    @classmethod
    def current(cls) -> ApplicationType:
        if cls._instance is None:
            raise RuntimeError("Application not initialized")
        return cls._instance  # ty:ignore[invalid-explicit-return]

    @classmethod
    def reset(cls) -> None:
        """Clear cached singleton instance, for test isolation."""

        cls._instance = None

    def register(self, component_cls: type[BaseComponent]) -> None:
        if component_cls.name in self.components:
            raise ComponentAlreadyRegistered(component_cls.name)
        component = component_cls(self)
        self.components[component.name] = component
        if component.expose_controller:
            setattr(
                self,
                component.name,
                component.controller,
            )
        component.on_register()

    def deregister(self, component_name: str) -> None:
        if component_name not in self.components:
            raise ComponentNotRegistered(component_name)
        component = self.components.pop(component_name)
        component.on_deregister()
        if component.expose_controller and hasattr(self, component_name):
            delattr(self, component_name)

    @classmethod
    def register_cli(cls, group: click.Group) -> None:
        for component_cls in cls.default_components:
            component_cls.expose_cli(group)
