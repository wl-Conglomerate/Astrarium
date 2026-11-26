"""Thread-pool map for subprocess-bound loops (subprocess releases GIL)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor


def run_pool[T, R](func: Callable[[T], R], items: Iterable[T], *, workers: int = 8) -> list[R]:
    """Map `func` over `items` on thread pool, result order matches input. First exception propagates."""

    todo = list(items)
    if len(todo) <= 1:
        return [func(item) for item in todo]
    with ThreadPoolExecutor(max_workers=min(workers, len(todo))) as pool:
        return list(pool.map(func, todo))
