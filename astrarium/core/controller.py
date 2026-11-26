"""Controller base class."""

from __future__ import annotations

from typing import Generic

from astrarium.core.types import ApplicationType


class BaseController(Generic[ApplicationType]):  # noqa: UP046
    """Reusable domain logic of one component, reaches others through `self.app.<name>`, never prints."""

    def __init__(self, app: ApplicationType) -> None:
        self.app = app
