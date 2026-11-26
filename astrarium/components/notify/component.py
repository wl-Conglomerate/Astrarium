"""Notify component: controller only, no commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astrarium.components.notify.controller import NotifyController
from astrarium.core import BaseComponent


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class NotifyComponent(BaseComponent["AstrariumApp", NotifyController]):
    name = "notify"
    controller_class = NotifyController
