"""Component registry guards and singleton reset."""

import pytest

from astrarium.core import (
    BaseApplication,
    BaseComponent,
    BaseController,
    ComponentAlreadyRegistered,
    ComponentNotRegistered,
)


pytestmark = pytest.mark.unit


class EchoController(BaseController["DemoApp"]):
    def ping(self) -> str:
        return "pong"


class EchoComponent(BaseComponent["DemoApp", EchoController]):
    name = "echo"
    controller_class = EchoController


class DemoApp(BaseApplication["DemoApp"]):
    default_components = (EchoComponent,)


def test_registered_controller_is_reachable_by_name():
    app = DemoApp()
    assert app.echo.ping() == "pong"  # ty:ignore[missing-attribute]
    assert DemoApp.current() is app


def test_registering_same_component_twice_is_refused():
    app = DemoApp()
    with pytest.raises(ComponentAlreadyRegistered):
        app.register(EchoComponent)


def test_deregister_removes_controller_and_unknown_name_is_refused():
    app = DemoApp()
    app.deregister("echo")
    assert not hasattr(app, "echo")
    with pytest.raises(ComponentNotRegistered):
        app.deregister("echo")


def test_reset_forgets_current_instance():
    DemoApp()
    DemoApp.reset()
    with pytest.raises(RuntimeError):
        DemoApp.current()
