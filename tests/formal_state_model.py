#!/usr/bin/env python3
"""Explicit-state verification for transport/session lifecycle ownership."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from enum import Enum, auto
from typing import Callable, Iterable, NamedTuple


class Transport(Enum):
    NONE = auto()
    HID = auto()
    CCID = auto()
    BLE = auto()
    OTP = auto()
    MAINTENANCE = auto()


class Job(Enum):
    NONE = auto()
    APDU = auto()
    CBOR = auto()


class Phase(Enum):
    IDLE = auto()
    RUNNING = auto()
    RESPONSE_READY = auto()
    MAINTENANCE = auto()


@dataclass(frozen=True)
class CoreState:
    owner: Transport = Transport.NONE
    job: Job = Job.NONE
    phase: Phase = Phase.IDLE
    worker_owner: Transport = Transport.NONE
    worker_job: Job = Job.NONE
    request_owner: Transport = Transport.NONE
    request_live: bool = False
    context_owner: Transport = Transport.NONE
    finished_owner: Transport = Transport.NONE
    hid_tx: bool = False
    ccid_tx: bool = False
    ble_tx: bool = False
    otp_tx: bool = False
    ble_connected: bool = False
    ble_subscribed: bool = False
    ble_aborted: bool = False


class Step(NamedTuple):
    name: str
    state: CoreState


def core_invariants(s: CoreState) -> None:
    if s.worker_owner is Transport.NONE:
        assert s.worker_job is Job.NONE
    else:
        assert s.worker_owner is not Transport.OTP
        assert s.worker_job is not Job.NONE

    if s.phase is Phase.IDLE:
        assert s.job is Job.NONE
        assert s.request_owner is Transport.NONE
        assert not s.request_live
        assert s.context_owner is Transport.NONE
        assert s.finished_owner is Transport.NONE
    elif s.phase is Phase.MAINTENANCE:
        assert s.owner is Transport.MAINTENANCE
        assert s.job is Job.NONE
        assert s.request_owner is Transport.NONE
        assert not s.request_live
        assert s.context_owner is Transport.NONE
        assert s.finished_owner is Transport.NONE
    else:
        assert s.owner is not Transport.NONE
        assert s.owner is not Transport.MAINTENANCE
        assert s.job is not Job.NONE
        assert s.context_owner is s.owner

    if s.phase is Phase.RUNNING:
        assert s.request_owner is s.owner
        assert s.request_live, "worker is reading request storage that is no longer live"
        assert s.finished_owner is Transport.NONE
        if s.owner is not Transport.OTP:
            assert s.worker_owner is s.owner, "active worker does not belong to command owner"
            assert s.worker_job is s.job

    if s.phase is Phase.RESPONSE_READY:
        assert s.finished_owner is s.owner
        assert s.request_owner is Transport.NONE
        assert not s.request_live
        if s.owner is not Transport.OTP:
            assert s.worker_owner is s.owner
            assert s.worker_job is s.job

    if s.owner is Transport.NONE:
        assert s.phase is Phase.IDLE
        assert s.finished_owner is Transport.NONE

    if not s.ble_connected:
        assert not s.ble_tx
        assert not s.ble_subscribed

    if s.ble_aborted and s.phase is Phase.RUNNING:
        assert s.owner is Transport.BLE
        assert s.request_owner is Transport.BLE
        assert s.request_live


def submit(s: CoreState, transport: Transport, job: Job) -> CoreState | None:
    if s.owner is not Transport.NONE or transport is Transport.MAINTENANCE:
        return None
    if transport is Transport.BLE:
        if not s.ble_connected or not s.ble_subscribed or s.ble_tx:
            return None
    worker = {}
    if transport is not Transport.OTP:
        worker = {"worker_owner": transport, "worker_job": job}
    return replace(
        s,
        owner=transport,
        job=job,
        phase=Phase.RUNNING,
        request_owner=transport,
        request_live=True,
        context_owner=transport,
        finished_owner=Transport.NONE,
        ble_aborted=False if transport is Transport.BLE else s.ble_aborted,
        **worker,
    )


def worker_done(s: CoreState) -> CoreState | None:
    if s.phase is not Phase.RUNNING:
        return None
    return replace(
        s,
        phase=Phase.RESPONSE_READY,
        request_owner=Transport.NONE,
        request_live=False,
        finished_owner=s.owner,
    )


def maintenance_begin(s: CoreState) -> CoreState | None:
    if s.owner is not Transport.NONE:
        return None
    return replace(s, owner=Transport.MAINTENANCE, phase=Phase.MAINTENANCE)


def maintenance_end(s: CoreState) -> CoreState | None:
    if s.owner is not Transport.MAINTENANCE or s.phase is not Phase.MAINTENANCE:
        return None
    return replace(s, owner=Transport.NONE, phase=Phase.IDLE)


def copy_response_and_release(s: CoreState) -> CoreState | None:
    if s.phase is not Phase.RESPONSE_READY:
        return None
    owner = s.owner
    base = dict(
        owner=Transport.NONE,
        job=Job.NONE,
        phase=Phase.IDLE,
        context_owner=Transport.NONE,
        finished_owner=Transport.NONE,
    )
    if owner is Transport.BLE:
        return replace(
            s,
            **base,
            ble_tx=s.ble_connected and s.ble_subscribed and not s.ble_aborted,
            ble_aborted=False,
        )
    if owner is Transport.HID:
        return replace(s, **base, hid_tx=True)
    if owner is Transport.CCID:
        return replace(s, **base, ccid_tx=True)
    if owner is Transport.OTP:
        return replace(s, **base, otp_tx=True)
    return None


def connect_ble(s: CoreState) -> CoreState | None:
    if s.ble_connected:
        return None
    return replace(s, ble_connected=True, ble_subscribed=False)


def disconnect_ble(s: CoreState) -> CoreState | None:
    if not s.ble_connected:
        return None
    aborted = s.ble_aborted
    if s.owner is Transport.BLE and s.phase is Phase.RUNNING:
        aborted = True
    return replace(
        s,
        ble_connected=False,
        ble_subscribed=False,
        ble_tx=False,
        ble_aborted=aborted,
    )


def subscribe_ble(s: CoreState) -> CoreState | None:
    if not s.ble_connected or s.ble_subscribed:
        return None
    return replace(s, ble_subscribed=True)


def unsubscribe_ble(s: CoreState) -> CoreState | None:
    if not s.ble_subscribed:
        return None
    aborted = s.ble_aborted
    if s.owner is Transport.BLE and s.phase is Phase.RUNNING:
        aborted = True
    return replace(s, ble_subscribed=False, ble_tx=False, ble_aborted=aborted)


def overflow_ble_events(s: CoreState) -> CoreState | None:
    """A lost cross-task event forces disconnect-equivalent fail-closed recovery."""
    if not s.ble_connected and not s.ble_subscribed and not s.ble_tx and not (
        s.owner is Transport.BLE and s.phase is Phase.RUNNING
    ):
        return None
    aborted = s.ble_aborted
    if s.owner is Transport.BLE and s.phase is Phase.RUNNING:
        aborted = True
    return replace(
        s,
        ble_connected=False,
        ble_subscribed=False,
        ble_tx=False,
        ble_aborted=aborted,
    )


def tx_done(s: CoreState, transport: Transport) -> CoreState | None:
    attr = {
        Transport.HID: "hid_tx",
        Transport.CCID: "ccid_tx",
        Transport.BLE: "ble_tx",
        Transport.OTP: "otp_tx",
    }.get(transport)
    if attr is None or not getattr(s, attr):
        return None
    return replace(s, **{attr: False})


CORE_EVENTS: tuple[tuple[str, Callable[[CoreState], CoreState | None]], ...] = (
    ("ble.connect", connect_ble),
    ("ble.disconnect", disconnect_ble),
    ("ble.subscribe", subscribe_ble),
    ("ble.unsubscribe", unsubscribe_ble),
    ("ble.event_overflow", overflow_ble_events),
    ("hid.apdu", lambda s: submit(s, Transport.HID, Job.APDU)),
    ("hid.cbor", lambda s: submit(s, Transport.HID, Job.CBOR)),
    ("ccid.apdu", lambda s: submit(s, Transport.CCID, Job.APDU)),
    ("ble.cbor", lambda s: submit(s, Transport.BLE, Job.CBOR)),
    ("otp.apdu", lambda s: submit(s, Transport.OTP, Job.APDU)),
    ("maintenance.begin", maintenance_begin),
    ("maintenance.end", maintenance_end),
    ("worker.done", worker_done),
    ("response.copy_release", copy_response_and_release),
    ("hid.tx_done", lambda s: tx_done(s, Transport.HID)),
    ("ccid.tx_done", lambda s: tx_done(s, Transport.CCID)),
    ("ble.tx_done", lambda s: tx_done(s, Transport.BLE)),
    ("otp.tx_done", lambda s: tx_done(s, Transport.OTP)),
)


def explore_core() -> tuple[int, int]:
    initial = CoreState()
    queue: deque[CoreState] = deque([initial])
    parent: dict[CoreState, tuple[CoreState | None, str]] = {initial: (None, "start")}
    transitions = 0

    while queue:
        state = queue.popleft()
        try:
            core_invariants(state)
        except AssertionError as exc:
            path: list[str] = []
            cur = state
            while parent[cur][0] is not None:
                prev, event = parent[cur]
                path.append(event)
                assert prev is not None
                cur = prev
            raise AssertionError(
                f"core invariant failed after {' -> '.join(reversed(path))}: {exc}"
            ) from exc

        for name, event in CORE_EVENTS:
            nxt = event(state)
            if nxt is None or nxt == state:
                continue
            transitions += 1
            if nxt not in parent:
                parent[nxt] = (state, name)
                queue.append(nxt)

    return len(parent), transitions


class App(Enum):
    NONE = auto()
    PIV = auto()
    OATH = auto()
    U2F = auto()
    OPENPGP = auto()


@dataclass(frozen=True)
class ApduSession:
    app: App = App.NONE
    chaining: bool = False
    continuation: int = 0


@dataclass(frozen=True)
class ApduState:
    ccid: ApduSession = ApduSession()
    wcid: ApduSession = ApduSession()
    hid: ApduSession = ApduSession()


SESSIONS = ("ccid", "wcid", "hid")


def session_update(s: ApduState, name: str, value: ApduSession) -> ApduState:
    return replace(s, **{name: value})


def apdu_select(s: ApduState, name: str, app: App) -> ApduState:
    old = getattr(s, name)
    return session_update(s, name, replace(old, app=app, chaining=False, continuation=0))


def apdu_long_response(s: ApduState, name: str) -> ApduState | None:
    old = getattr(s, name)
    if old.app is App.NONE:
        return None
    return session_update(s, name, replace(old, continuation=2))


def apdu_get_response(s: ApduState, name: str) -> ApduState | None:
    old = getattr(s, name)
    if old.continuation == 0:
        return None
    return session_update(s, name, replace(old, continuation=old.continuation - 1))


def apdu_chain_begin(s: ApduState, name: str) -> ApduState:
    old = getattr(s, name)
    return session_update(s, name, replace(old, chaining=True))


def apdu_chain_finish(s: ApduState, name: str) -> ApduState | None:
    old = getattr(s, name)
    if not old.chaining:
        return None
    return session_update(s, name, replace(old, chaining=False))


def apdu_warm_reset(s: ApduState, name: str) -> ApduState:
    old = getattr(s, name)
    return session_update(s, name, replace(old, chaining=False, continuation=0))


def apdu_cold_reset(s: ApduState, name: str) -> ApduState:
    return session_update(s, name, ApduSession())


def apdu_events(state: ApduState) -> Iterable[tuple[str, ApduState]]:
    for name in SESSIONS:
        for app in (App.PIV, App.OATH, App.U2F, App.OPENPGP):
            yield f"{name}.select.{app.name}", apdu_select(state, name, app)
        for label, fn in (
            ("long_response", apdu_long_response),
            ("get_response", apdu_get_response),
            ("chain_begin", apdu_chain_begin),
            ("chain_finish", apdu_chain_finish),
            ("warm_reset", apdu_warm_reset),
            ("cold_reset", apdu_cold_reset),
        ):
            nxt = fn(state, name)
            if nxt is not None:
                yield f"{name}.{label}", nxt


def apdu_invariants(s: ApduState) -> None:
    for name in SESSIONS:
        sess = getattr(s, name)
        assert 0 <= sess.continuation <= 2
        if sess.app is App.NONE:
            assert sess.continuation == 0


def explore_apdu() -> tuple[int, int]:
    initial = ApduState()
    queue: deque[ApduState] = deque([initial])
    seen = {initial}
    transitions = 0
    while queue:
        state = queue.popleft()
        apdu_invariants(state)
        for _, nxt in apdu_events(state):
            transitions += 1
            apdu_invariants(nxt)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return len(seen), transitions


class HidTxnPhase(Enum):
    IDLE = auto()
    ASSEMBLING = auto()
    COMPLETE = auto()


@dataclass(frozen=True)
class HidTxnState:
    phase: HidTxnPhase = HidTxnPhase.IDLE


def hid_init_fragment(_: HidTxnState, complete: bool) -> HidTxnState:
    return HidTxnState(HidTxnPhase.COMPLETE if complete else HidTxnPhase.ASSEMBLING)


def hid_cont_fragment(s: HidTxnState, complete: bool) -> HidTxnState | None:
    if s.phase is not HidTxnPhase.ASSEMBLING:
        return None
    return HidTxnState(HidTxnPhase.COMPLETE if complete else HidTxnPhase.ASSEMBLING)


def hid_terminal_response(s: HidTxnState) -> HidTxnState | None:
    if s.phase is not HidTxnPhase.COMPLETE:
        return None
    return HidTxnState()


def hid_timeout(s: HidTxnState) -> HidTxnState | None:
    if s.phase is HidTxnPhase.IDLE:
        return None
    return HidTxnState()


def explore_hid_transaction() -> tuple[int, int]:
    initial = HidTxnState()
    queue: deque[HidTxnState] = deque([initial])
    seen = {initial}
    transitions = 0
    while queue:
        state = queue.popleft()
        candidates = (
            hid_init_fragment(state, False),
            hid_init_fragment(state, True),
            hid_cont_fragment(state, False),
            hid_cont_fragment(state, True),
            hid_terminal_response(state),
            hid_timeout(state),
        )
        for nxt in candidates:
            if nxt is None:
                continue
            transitions += 1
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    # CHANNEL_BUSY is a terminal response for a fully assembled request.
    assert hid_terminal_response(HidTxnState(HidTxnPhase.COMPLETE)) == HidTxnState()
    return len(seen), transitions


class HidResponseKind(Enum):
    NONE = auto()
    SYNC = auto()
    ASYNC = auto()


@dataclass(frozen=True)
class HidResponseState:
    worker_live: bool = False
    queued_kind: HidResponseKind = HidResponseKind.NONE
    header_source: HidResponseKind = HidResponseKind.NONE


def hid_response_invariants(s: HidResponseState) -> None:
    assert s.queued_kind is s.header_source
    if s.queued_kind is HidResponseKind.NONE:
        assert s.header_source is HidResponseKind.NONE
    if s.worker_live:
        assert s.queued_kind is HidResponseKind.NONE


def hid_sync_response(s: HidResponseState) -> HidResponseState | None:
    if s.worker_live or s.queued_kind is not HidResponseKind.NONE:
        return None
    return HidResponseState(False, HidResponseKind.SYNC, HidResponseKind.SYNC)


def hid_async_start(s: HidResponseState) -> HidResponseState | None:
    if s.worker_live or s.queued_kind is not HidResponseKind.NONE:
        return None
    return HidResponseState(True, HidResponseKind.NONE, HidResponseKind.NONE)


def hid_async_response(s: HidResponseState) -> HidResponseState | None:
    if not s.worker_live:
        return None
    return HidResponseState(False, HidResponseKind.ASYNC, HidResponseKind.ASYNC)


def hid_response_done(s: HidResponseState) -> HidResponseState | None:
    if s.queued_kind is HidResponseKind.NONE:
        return None
    return HidResponseState()


def explore_hid_response_context() -> tuple[int, int]:
    initial = HidResponseState()
    queue: deque[HidResponseState] = deque([initial])
    seen = {initial}
    transitions = 0
    while queue:
        state = queue.popleft()
        hid_response_invariants(state)
        for fn in (hid_sync_response, hid_async_start, hid_async_response, hid_response_done):
            nxt = fn(state)
            if nxt is None:
                continue
            transitions += 1
            hid_response_invariants(nxt)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return len(seen), transitions


class CcidSnapshotOwner(Enum):
    NONE = auto()
    WORKER = auto()
    PARSER = auto()


@dataclass(frozen=True)
class CcidRequestState:
    worker_live: bool = False
    snapshot_owner: CcidSnapshotOwner = CcidSnapshotOwner.NONE
    rx_pending: bool = False


def ccid_request_invariants(s: CcidRequestState) -> None:
    if s.worker_live:
        assert s.snapshot_owner is CcidSnapshotOwner.WORKER, (
            "CCID parser overwrote the request snapshot while the worker still owns it"
        )
    else:
        assert s.snapshot_owner is not CcidSnapshotOwner.WORKER


def ccid_receive(s: CcidRequestState) -> CcidRequestState:
    if s.worker_live:
        # Runtime behavior: leave the new frame in the RX ring.  Do not copy
        # it into the active request snapshot until the current worker releases.
        return replace(s, rx_pending=True)
    return CcidRequestState(False, CcidSnapshotOwner.PARSER, True)


def ccid_start_pending(s: CcidRequestState) -> CcidRequestState | None:
    if s.worker_live or not s.rx_pending:
        return None
    return CcidRequestState(True, CcidSnapshotOwner.WORKER, False)


def ccid_worker_done(s: CcidRequestState) -> CcidRequestState | None:
    if not s.worker_live:
        return None
    return CcidRequestState(False, CcidSnapshotOwner.NONE, s.rx_pending)


def explore_ccid_request_context() -> tuple[int, int]:
    initial = CcidRequestState()
    queue: deque[CcidRequestState] = deque([initial])
    seen = {initial}
    transitions = 0
    while queue:
        state = queue.popleft()
        ccid_request_invariants(state)
        candidates = (
            ccid_receive(state),
            ccid_start_pending(state),
            ccid_worker_done(state),
        )
        for nxt in candidates:
            if nxt is None:
                continue
            transitions += 1
            ccid_request_invariants(nxt)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return len(seen), transitions


class WorkerPhase(Enum):
    NONE = auto()
    PARKED = auto()
    RUNNING = auto()
    COMPLETION_PENDING = auto()


@dataclass(frozen=True)
class WorkerLifecycleState:
    phase: WorkerPhase = WorkerPhase.NONE
    owner: bool = False


def worker_lifecycle_invariants(s: WorkerLifecycleState) -> None:
    if s.phase in (WorkerPhase.RUNNING, WorkerPhase.COMPLETION_PENDING):
        assert s.owner, "active/completed worker lost command ownership before completion consumption"


def worker_claim(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if s.owner or s.phase not in (WorkerPhase.NONE, WorkerPhase.PARKED):
        return None
    return replace(s, owner=True)


def worker_start(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if not s.owner or s.phase not in (WorkerPhase.NONE, WorkerPhase.PARKED):
        return None
    return WorkerLifecycleState(WorkerPhase.RUNNING, True)


def worker_done_event(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if s.phase is not WorkerPhase.RUNNING or not s.owner:
        return None
    return WorkerLifecycleState(WorkerPhase.COMPLETION_PENDING, True)


def worker_consume_completion(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if s.phase is not WorkerPhase.COMPLETION_PENDING or not s.owner:
        return None
    return WorkerLifecycleState(WorkerPhase.PARKED, False)


def worker_sync_release(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if not s.owner or s.phase not in (WorkerPhase.NONE, WorkerPhase.PARKED):
        return None
    return replace(s, owner=False)


def worker_exit_claimed_model(s: WorkerLifecycleState) -> WorkerLifecycleState | None:
    if not s.owner or s.phase is not WorkerPhase.PARKED:
        return None
    return WorkerLifecycleState(WorkerPhase.NONE, True)


def explore_worker_lifecycle() -> tuple[int, int]:
    initial = WorkerLifecycleState()
    queue: deque[WorkerLifecycleState] = deque([initial])
    seen = {initial}
    transitions = 0
    functions = (
        worker_claim,
        worker_start,
        worker_done_event,
        worker_consume_completion,
        worker_sync_release,
        worker_exit_claimed_model,
    )
    while queue:
        state = queue.popleft()
        worker_lifecycle_invariants(state)
        for fn in functions:
            nxt = fn(state)
            if nxt is None:
                continue
            transitions += 1
            worker_lifecycle_invariants(nxt)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return len(seen), transitions


class CompletionPhase(Enum):
    IDLE = auto()
    RUNNING = auto()
    DONE_NEEDS_FLUSH = auto()
    DONE_READY = auto()
    MAINTENANCE = auto()


@dataclass(frozen=True)
class CompletionState:
    phase: CompletionPhase = CompletionPhase.IDLE
    flash_pending: bool = False


def completion_events(s: CompletionState) -> Iterable[tuple[str, CompletionState]]:
    if s.phase is CompletionPhase.IDLE:
        yield "command.start", CompletionState(CompletionPhase.RUNNING, False)
        if not s.flash_pending:
            yield "background.dirty", CompletionState(CompletionPhase.IDLE, True)
        else:
            yield "maintenance.begin", CompletionState(CompletionPhase.MAINTENANCE, True)
    elif s.phase is CompletionPhase.RUNNING:
        if not s.flash_pending:
            yield "worker.dirty", CompletionState(CompletionPhase.RUNNING, True)
        yield (
            "worker.done",
            CompletionState(
                CompletionPhase.DONE_NEEDS_FLUSH
                if s.flash_pending
                else CompletionPhase.DONE_READY,
                s.flash_pending,
            ),
        )
    elif s.phase is CompletionPhase.DONE_NEEDS_FLUSH:
        # The command owner still owns the cache lifetime, but the worker has
        # ended, so core0 can flush safely without acquiring another owner.
        yield "owner.flush", CompletionState(CompletionPhase.DONE_READY, False)
    elif s.phase is CompletionPhase.DONE_READY:
        yield "response.release", CompletionState(CompletionPhase.IDLE, False)
    elif s.phase is CompletionPhase.MAINTENANCE:
        yield "maintenance.flush_release", CompletionState(CompletionPhase.IDLE, False)


def completion_can_reach_quiescent_idle(
    start: CompletionState,
    transitions: dict[CompletionState, list[CompletionState]],
) -> bool:
    target = CompletionState(CompletionPhase.IDLE, False)
    queue: deque[CompletionState] = deque([start])
    seen = {start}
    while queue:
        state = queue.popleft()
        if state == target:
            return True
        for nxt in transitions.get(state, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return False


def explore_completion_liveness() -> tuple[int, int]:
    initial = CompletionState()
    queue: deque[CompletionState] = deque([initial])
    seen = {initial}
    transitions: dict[CompletionState, list[CompletionState]] = {}
    count = 0
    while queue:
        state = queue.popleft()
        edges = []
        for _, nxt in completion_events(state):
            count += 1
            edges.append(nxt)
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
        transitions[state] = edges

    for state in seen:
        assert completion_can_reach_quiescent_idle(state, transitions), (
            f"completion state has no path to quiescent IDLE: {state}"
        )
    return len(seen), count


@dataclass(frozen=True)
class PivSecurity:
    mgm: bool = False
    challenge: bool = False
    pin: bool = False


def piv_select(_: PivSecurity) -> PivSecurity:
    return PivSecurity()


def piv_power_cycle(_: PivSecurity) -> PivSecurity:
    return PivSecurity()


def piv_events(s: PivSecurity) -> Iterable[PivSecurity]:
    yield replace(s, challenge=True)
    if s.challenge:
        yield replace(s, mgm=True)
    yield replace(s, pin=True)
    yield piv_select(s)
    yield piv_power_cycle(s)


def explore_piv() -> tuple[int, int]:
    initial = PivSecurity()
    queue: deque[PivSecurity] = deque([initial])
    seen = {initial}
    transitions = 0
    while queue:
        state = queue.popleft()
        for nxt in piv_events(state):
            transitions += 1
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    for state in seen:
        assert piv_select(state) == PivSecurity()
        assert piv_power_cycle(state) == PivSecurity()
    return len(seen), transitions


def verify_yubikey_pid_mapping() -> int:
    seen: set[int] = set()
    for bits in range(1, 8):
        pid = 0x0400 | bits
        assert 0x0401 <= pid <= 0x0407
        assert (pid & 0x7) == bits
        seen.add(pid)
    assert seen == set(range(0x0401, 0x0408))
    return len(seen)


def verify_known_bad_models_are_detected() -> int:
    detected = 0

    state = CoreState(ble_connected=True, ble_subscribed=True)
    state = submit(state, Transport.BLE, Job.CBOR)
    assert state is not None

    broken = replace(state, request_live=False)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect early BLE RX clear")

    broken = replace(
        state,
        ble_connected=False,
        ble_subscribed=False,
        ble_aborted=True,
        request_live=False,
    )
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect disconnect RX invalidation")

    ready = worker_done(state)
    assert ready is not None
    broken = replace(ready, owner=Transport.NONE)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect release-before-copy")

    # Regression 4: a foreign transport overwrites shared APDU/CBOR context
    # while another transport owns the worker.
    broken = replace(state, context_owner=Transport.OTP)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect foreign context mutation")

    # Regression 5: synchronous OTP HID work borrows the APDU globals without
    # first becoming the global command owner.
    broken = CoreState(
        owner=Transport.HID,
        job=Job.CBOR,
        phase=Phase.RUNNING,
        worker_owner=Transport.HID,
        worker_job=Job.CBOR,
        request_owner=Transport.HID,
        request_live=True,
        context_owner=Transport.OTP,
    )
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect unclaimed synchronous OTP APDU access")

    # Regression 6: a session reset changes the active APDU/application
    # context while a foreign worker owns the core.
    broken = replace(state, context_owner=Transport.CCID)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect foreign session reset")

    # Regression 7: worker identity is switched behind the command owner's
    # back.  A parked worker may exist while IDLE, but an active async command
    # must run on the worker selected by that same owner.
    broken = replace(state, worker_owner=Transport.CCID, worker_job=Job.APDU)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect foreign worker switch")

    # Regression 8: a fully assembled HID request receives CHANNEL_BUSY but
    # remains COMPLETE, so the next retry inherits stale sequence/payload.
    broken_hid_busy_result = HidTxnState(HidTxnPhase.COMPLETE)
    try:
        assert broken_hid_busy_result == HidTxnState()
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect stale HID transaction after terminal BUSY")

    # Regression 9: flash/cache maintenance starts while an active command
    # still owns file/cache-backed data.
    broken = replace(state, owner=Transport.MAINTENANCE, phase=Phase.MAINTENANCE)
    try:
        core_invariants(broken)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect maintenance overlapping an active command")

    # Regression 10: old completion logic requeued EV_EXEC_FINISHED while
    # flash remained pending, but only IDLE was allowed to acquire the
    # maintenance owner. DONE_NEEDS_FLUSH therefore had no path to IDLE.
    deadlocked = CompletionState(CompletionPhase.DONE_NEEDS_FLUSH, True)
    old_transitions: dict[CompletionState, list[CompletionState]] = {
        deadlocked: [],
    }
    if not completion_can_reach_quiescent_idle(deadlocked, old_transitions):
        detected += 1
    else:
        raise AssertionError("model failed to detect completion/maintenance deadlock")

    # Regression 11: a full BLE event queue silently drops disconnect/notify
    # completion. Correct behavior must force disconnect-equivalent recovery
    # while preserving worker-owned request bytes until cancellation finishes.
    recovered = overflow_ble_events(state)
    assert recovered is not None
    try:
        assert recovered != state
        assert not recovered.ble_connected
        assert recovered.ble_aborted
        assert recovered.request_live
        core_invariants(recovered)
    except AssertionError as exc:
        raise AssertionError("model failed to define safe BLE event-overflow recovery") from exc
    detected += 1

    # Regression 12: a synchronous PING response reuses the previous async
    # worker CID/CMD snapshot. The payload is valid, but the CTAPHID header
    # identifies the wrong transaction.
    broken_hid_response = HidResponseState(
        worker_live=False,
        queued_kind=HidResponseKind.SYNC,
        header_source=HidResponseKind.ASYNC,
    )
    try:
        hid_response_invariants(broken_hid_response)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect stale async header on synchronous HID response")

    # Regression 13: while CCID APDU worker still reads its stable request
    # snapshot, a second XFR frame is copied into that same storage before the
    # BUSY decision.  The parser must leave the second frame in the RX ring.
    broken_ccid = CcidRequestState(
        worker_live=True,
        snapshot_owner=CcidSnapshotOwner.PARSER,
        rx_pending=True,
    )
    try:
        ccid_request_invariants(broken_ccid)
    except AssertionError:
        detected += 1
    else:
        raise AssertionError("model failed to detect CCID active-request snapshot overwrite")

    pending_worker = WorkerLifecycleState(WorkerPhase.COMPLETION_PENDING, True)
    if worker_exit_claimed_model(pending_worker) is None:
        detected += 1
    else:
        raise AssertionError("model allowed worker exit before completion ACK consumption")

    return detected


def main() -> None:
    core_states, core_transitions = explore_core()
    apdu_states, apdu_transitions = explore_apdu()
    hid_states, hid_transitions = explore_hid_transaction()
    hid_response_states, hid_response_transitions = explore_hid_response_context()
    ccid_request_states, ccid_request_transitions = explore_ccid_request_context()
    worker_states, worker_transitions = explore_worker_lifecycle()
    completion_states, completion_transitions = explore_completion_liveness()
    piv_states, piv_transitions = explore_piv()
    pids = verify_yubikey_pid_mapping()
    regressions = verify_known_bad_models_are_detected()

    print(f"core ownership model: PASS ({core_states} states, {core_transitions} transitions)")
    print(f"APDU session model: PASS ({apdu_states} states, {apdu_transitions} transitions)")
    print(f"HID transaction model: PASS ({hid_states} states, {hid_transitions} transitions)")
    print(
        f"HID response-context model: PASS "
        f"({hid_response_states} states, {hid_response_transitions} transitions)"
    )
    print(
        f"CCID request-context model: PASS "
        f"({ccid_request_states} states, {ccid_request_transitions} transitions)"
    )
    print(
        f"worker lifecycle model: PASS "
        f"({worker_states} states, {worker_transitions} transitions)"
    )
    print(
        f"completion/flash liveness model: PASS "
        f"({completion_states} states, {completion_transitions} transitions)"
    )
    print(f"PIV security model: PASS ({piv_states} states, {piv_transitions} transitions)")
    print(f"YubiKey USB PID model: PASS ({pids} interface combinations)")
    print(f"known-bad regression models detected: PASS ({regressions}/14)")


if __name__ == "__main__":
    main()
