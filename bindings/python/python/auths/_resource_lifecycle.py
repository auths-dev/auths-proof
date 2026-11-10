"""Owned async resource lifetimes; no verification, entry, or provider semantics."""
from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Literal, Optional, Protocol, Set, TypeVar, Union, cast

from ._product_errors import AuthsWorkflowError, CauseCategory

T = TypeVar("T")
Retry = Literal["idempotent", "unsafe"]


class CleanupFailure(AuthsWorkflowError):
    """The registry cleanup boundary with a bounded local completion reason."""
    def __init__(self, incomplete: bool = False) -> None:
        self.cause_chain = ("cleanup-incomplete" if incomplete else "cleanup-failed",)
        super().__init__("cleanup-failed", self.cause_chain[0],
                         causes=(CauseCategory.TIMEOUT if incomplete else CauseCategory.UNAVAILABLE,))


def _disposed() -> AuthsWorkflowError:
    return AuthsWorkflowError("disposed", "Auths resource is disposed or not open")


def _timeout(value: Optional[float]) -> Optional[float]:
    if value is not None and (isinstance(value, bool) or not math.isfinite(value) or value <= 0):
        raise ValueError("timeout must be finite and positive")
    return value


def _future() -> asyncio.Future[None]:
    result: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    result.add_done_callback(lambda value: None if value.cancelled() else value.exception())
    return result


class Timer(Protocol):
    def cancel(self) -> None: ...


class LifecycleTiming(Protocol):
    def now(self) -> float: ...
    def schedule(self, callback: Callable[[], None], delay: float) -> Timer: ...


class LoopTiming:
    def now(self) -> float:
        return asyncio.get_running_loop().time()

    def schedule(self, callback: Callable[[], None], delay: float) -> Timer:
        return asyncio.get_running_loop().call_later(delay, callback)


async def _wait(task: Awaitable[T], timeout: Optional[float], timing: LifecycleTiming) -> T:
    # Shield belongs to the waiter, never the owned task. Cancellation and the
    # explicit timer settle only this waiter's forwarding future.
    shielded = asyncio.shield(task)
    if timeout is None:
        return await shielded
    loop = asyncio.get_running_loop()
    result: asyncio.Future[T] = loop.create_future()
    deadline = timing.now() + timeout
    timer: Optional[Timer] = None
    def expired() -> None:
        nonlocal timer
        if result.done():
            return
        remaining = deadline - timing.now()
        if remaining > 0:
            timer = timing.schedule(expired, remaining)
        else:
            result.set_exception(asyncio.TimeoutError())
    def settled(value: asyncio.Future[T]) -> None:
        if result.done():
            return
        if value.cancelled():
            result.cancel()
        else:
            error = value.exception()
            if error is not None:
                result.set_exception(error)
            else:
                result.set_result(value.result())
    shielded.add_done_callback(settled)
    timer = timing.schedule(expired, timeout)
    try:
        return await result
    finally:
        timer.cancel()
        shielded.remove_done_callback(settled)
        if shielded.done() and not shielded.cancelled():
            shielded.exception()
        shielded.cancel()


@dataclass(frozen=True)
class New:
    pass


@dataclass(frozen=True)
class Open:
    pass


@dataclass(frozen=True)
class Opening:
    result: asyncio.Future[None]


@dataclass(frozen=True)
class NormalClose:
    pass


@dataclass(frozen=True)
class OpenFailure:
    error: BaseException


CloseReason = Union[NormalClose, OpenFailure]


@dataclass(frozen=True)
class Generation:
    result: asyncio.Future[None]
    deadline: Optional[float]
    reason: CloseReason


@dataclass(frozen=True)
class Closing:
    generation: Generation


@dataclass(frozen=True)
class ClosingOverdue:
    generation: Generation


@dataclass(frozen=True)
class CleanupFailed:
    failure: CleanupFailure
    reason: CloseReason


@dataclass(frozen=True)
class Closed:
    reason: CloseReason


State = Union[New, Opening, Open, Closing, ClosingOverdue, CleanupFailed, Closed]


@dataclass(frozen=True)
class Obligation:
    run: Callable[[bool], Awaitable[None]]
    retry: Retry
    order: int
    state: Literal["pending", "failed"] = "pending"


class ResourceLifecycle:
    def __init__(self, *, opened: bool = False, timing: Optional[LifecycleTiming] = None) -> None:
        self._timing = timing if timing is not None else LoopTiming()
        self.state: State = Open() if opened else New()
        self._active: Set[asyncio.Task[object]] = set()
        self._obligations: Dict[int, tuple[object, Obligation]] = {}
        self._invalidations: Set[asyncio.Future[None]] = set()
        self._cleanup: Optional[asyncio.Task[None]] = None

    @property
    def is_open(self) -> bool:
        return isinstance(self.state, Open)

    @property
    def is_closed(self) -> bool:
        return isinstance(self.state, (Closing, ClosingOverdue, CleanupFailed, Closed))

    def assert_open(self) -> None:
        if not self.is_open:
            raise _disposed()

    def own(self, resource: object, run: Callable[[bool], Awaitable[None]], *, retry: Retry = "unsafe", order: int = 0) -> None:
        if isinstance(self.state, Closed):
            raise _disposed()
        self._obligations.setdefault(id(resource), (resource, Obligation(run, retry, order)))

    def transfer(self, resource: object) -> None:
        """Synchronous handoff only, after the next owner registered the destructor."""
        self._obligations.pop(id(resource), None)

    async def dispose_owned(self, resource: object) -> None:
        pair = self._obligations.get(id(resource))
        if pair is not None and pair[1].state == "pending":
            await self._attempt(*pair)

    def _work(self, operation: Callable[[], Awaitable[T]]) -> asyncio.Task[T]:
        # Even an eager task factory cannot enter foreign code before this
        # owner retains the task. The gate is released only after registration.
        admitted: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        async def owned() -> T:
            await admitted
            return await operation()
        task = asyncio.create_task(owned())
        retained = cast("asyncio.Task[object]", task)
        self._active.add(retained)
        def settled(value: asyncio.Task[T]) -> None:
            self._active.discard(retained)
            if not value.cancelled():
                value.exception()
        task.add_done_callback(settled)
        admitted.set_result(None)
        return task

    async def open(self, initialize: Callable[[], Awaitable[None]], *, timeout: Optional[float] = None,
                   opened: Optional[Callable[[], None]] = None) -> None:
        timeout = _timeout(timeout)
        if isinstance(self.state, Open):
            return
        if isinstance(self.state, Opening):
            await _wait(self.state.result, timeout, self._timing)
            return
        if not isinstance(self.state, New):
            raise _disposed()
        result = _future()
        opening = Opening(result)
        self.state = opening
        async def start() -> None:
            try:
                await initialize()
                if self.state is opening:
                    self.state = Open()
                    if opened is not None:
                        opened()
                    if not result.done():
                        if self.is_open:
                            result.set_result(None)
                        else:
                            result.set_exception(_disposed())
            except BaseException as error:
                if not result.done():
                    result.set_exception(error)
                if self.state is opening or self.is_open:
                    self._start_close(None, False, OpenFailure(error))
        self._work(start)
        await _wait(result, timeout, self._timing)

    async def run(self, operation: Callable[[], Awaitable[T]], *, timeout: Optional[float] = None) -> T:
        timeout = _timeout(timeout)
        self.assert_open()
        return await _wait(self._work(operation), timeout, self._timing)

    async def publish(self, create: Callable[[], Awaitable[T]], destroy: Callable[[T, bool], Awaitable[None]],
                      *, timeout: Optional[float] = None, retry: Retry = "unsafe") -> T:
        timeout = _timeout(timeout)
        self.assert_open()
        invalidated = _future()
        self._invalidations.add(invalidated)
        publication: Literal["waiting", "published", "abandoned"] = "waiting"
        deadline = None if timeout is None else self._timing.now() + timeout
        async def acquire() -> T:
            value = await create()
            self.own(value, lambda again: destroy(value, again), retry=retry)
            return value
        created = self._work(acquire)
        # Keep a separate ownership token until either publication or late cleanup.
        released = _future()
        async def hold() -> None:
            await released
        self._work(hold)
        async def select() -> T:
            done, _ = await asyncio.wait((created, invalidated), return_when=asyncio.FIRST_COMPLETED)
            if invalidated in done:
                invalidated.result()
                raise _disposed()
            return created.result()
        selection = asyncio.create_task(select())
        selection.add_done_callback(lambda value: None if value.cancelled() else value.exception())
        try:
            value = await _wait(selection, timeout, self._timing)
            if not self.is_open:
                raise _disposed()
            if deadline is not None and self._timing.now() >= deadline:
                raise asyncio.TimeoutError()
            publication = "published"
            return value
        finally:
            if publication != "published":
                publication = "abandoned"
            self._invalidations.discard(invalidated)
            async def finish() -> None:
                try:
                    value = await asyncio.shield(created)
                    if publication != "published":
                        pair = self._obligations.get(id(value))
                        if pair is not None:
                            await self._attempt(*pair)
                except BaseException:
                    pass
                finally:
                    released.set_result(None)
            # Cleanup belongs to the owner; repeated caller cancellation cannot cancel it.
            self._work(finish)

    async def close(self, *, timeout: Optional[float] = None) -> None:
        timeout = _timeout(timeout)
        state = self.state
        if isinstance(state, Closed):
            return
        if isinstance(state, CleanupFailed):
            raise state.failure
        if isinstance(state, ClosingOverdue):
            raise CleanupFailure(True)
        if isinstance(state, Closing):
            await _wait(state.generation.result, timeout, self._timing)
            return
        generation = self._start_close(timeout, False)
        await _wait(generation.result, None, self._timing)

    async def retry_cleanup(self, *, timeout: Optional[float] = None) -> None:
        timeout = _timeout(timeout)
        state = self.state
        if isinstance(state, (Closed, Closing, ClosingOverdue)):
            await self.close(timeout=timeout)
        elif isinstance(state, CleanupFailed):
            if not any(value.retry == "idempotent" for _, value in self._obligations.values()):
                raise state.failure
            await _wait(self._start_close(timeout, True, state.reason).result, None, self._timing)
        else:
            raise _disposed()

    def _start_close(self, timeout: Optional[float], retry: bool, reason: CloseReason = NormalClose()) -> Generation:
        if isinstance(self.state, Opening) and not self.state.result.done():
            self.state.result.set_exception(_disposed())
        for pending in self._invalidations:
            if not pending.done():
                pending.set_exception(_disposed())
        generation = Generation(_future(), None if timeout is None else self._timing.now() + timeout, reason)
        self.state = Closing(generation)
        timer: Optional[Timer] = None
        def expired() -> None:
            nonlocal timer
            if not isinstance(self.state, Closing) or self.state.generation is not generation:
                return
            if generation.deadline is not None and self._timing.now() < generation.deadline:
                timer = self._timing.schedule(expired, generation.deadline - self._timing.now())
                return
            if isinstance(self.state, Closing) and self.state.generation is generation:
                self.state = ClosingOverdue(generation)
                if not generation.result.done():
                    generation.result.set_exception(CleanupFailure(True))
        timer = None if timeout is None else self._timing.schedule(expired, timeout)
        async def cleanup() -> None:
            try:
                # No new admissions after Closing. Acquisitions register late resources
                # before releasing their tokens, so every obligation is visible here.
                while self._active:
                    # Python 3.12 gather can return synchronously for completed
                    # tasks, before their queued removal callbacks have run.
                    # Prune those tokens explicitly instead of starving the loop.
                    self._active.difference_update(task for task in tuple(self._active) if task.done())
                    if self._active:
                        await asyncio.gather(*tuple(self._active), return_exceptions=True)
                for resource, obligation in sorted(tuple(self._obligations.values()), key=lambda pair: pair[1].order):
                    if obligation.state == "pending" or (retry and obligation.retry == "idempotent"):
                        await self._attempt(resource, obligation, retry)
                if self._obligations:
                    failure = CleanupFailure()
                    self.state = CleanupFailed(failure, generation.reason)
                    if not generation.result.done():
                        generation.result.set_exception(failure)
                else:
                    self.state = Closed(reason)
                    if not generation.result.done():
                        generation.result.set_result(None)
            finally:
                if timer is not None:
                    timer.cancel()
        self._cleanup = asyncio.create_task(cleanup())
        self._cleanup.add_done_callback(lambda value: None if value.cancelled() else value.exception())
        return generation

    async def _attempt(self, resource: object, obligation: Obligation, retry: bool = False) -> None:
        try:
            await obligation.run(retry)
            self._obligations.pop(id(resource), None)
        except BaseException:
            self._obligations[id(resource)] = (resource, Obligation(obligation.run, obligation.retry, obligation.order, "failed"))


def own_adapter(owner: ResourceLifecycle, adapter: object, *, order: int = 0) -> None:
    """Optional retry declaration is a capability, not a requirement on borrowed adapters."""
    close = getattr(adapter, "aclose", None)
    if not callable(close):
        raise TypeError("owned adapter must implement aclose")
    close_operation = cast(Callable[[], Awaitable[None]], close)
    candidate = getattr(adapter, "retry_cleanup", None)
    retry_operation = cast(Callable[[], Awaitable[None]], candidate) if callable(candidate) else None
    async def cleanup(retry: bool) -> None:
        await (retry_operation() if retry and retry_operation is not None else close_operation())
    owner.own(adapter, cleanup, retry="idempotent" if getattr(adapter, "cleanup_retry", None) == "idempotent" else "unsafe", order=order)
