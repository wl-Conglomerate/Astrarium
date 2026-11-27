"""Framework errors: registry misuse, programming errors only."""


class RegistryError(Exception):
    """Component registry misuse."""


class ComponentAlreadyRegistered(RegistryError):
    def __init__(self, name: str) -> None:
        super().__init__(f"component {name!r} is already registered")


class ComponentNotRegistered(RegistryError):
    def __init__(self, name: str) -> None:
        super().__init__(f"component {name!r} is not registered")
