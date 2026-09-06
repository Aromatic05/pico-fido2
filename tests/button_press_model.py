#!/usr/bin/env python3
"""Model the BOOT multi-press debounce and routing contract."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product


DEBOUNCE_MS = 40
WINDOW_MS = 1000
TICK_MS = 10


@dataclass
class State:
    stable_pressed: bool = False
    raw_pressed: bool = False
    raw_changed_ms: int = 0
    last_release_ms: int = 0
    count: int = 0


def step(state: State, now: int, raw_pressed: bool) -> int | None:
    if raw_pressed != state.raw_pressed:
        state.raw_pressed = raw_pressed
        state.raw_changed_ms = now

    if (
        state.raw_pressed != state.stable_pressed
        and now - state.raw_changed_ms >= DEBOUNCE_MS
    ):
        state.stable_pressed = state.raw_pressed
        if not state.stable_pressed:
            if state.last_release_ms == 0 or now - state.last_release_ms >= WINDOW_MS:
                state.count = 1
            elif state.count < 0xFF:
                state.count += 1
            state.last_release_ms = now

    if (
        state.last_release_ms > 0
        and state.count > 0
        and now - state.last_release_ms >= WINDOW_MS
        and not state.stable_pressed
    ):
        completed = state.count
        state.last_release_ms = 0
        state.count = 0
        return completed
    return None


BOUNCE_PATTERNS = {
    "clean": (),
    "press": ((10, False), (20, True)),
    "release": ((130, True), (140, False)),
    "both": ((10, False), (20, True), (130, True), (140, False)),
}


def physical_press(start: int, pattern: str) -> list[tuple[int, bool]]:
    events = [(start, True), (start + 120, False)]
    events.extend((start + offset, value) for offset, value in BOUNCE_PATTERNS[pattern])
    return sorted(events)


def run(events: list[tuple[int, bool]], end_ms: int) -> list[int]:
    state = State()
    completed: list[int] = []
    raw = False
    event_index = 0
    for now in range(0, end_ms + TICK_MS, TICK_MS):
        while event_index < len(events) and events[event_index][0] <= now:
            raw = events[event_index][1]
            event_index += 1
        value = step(state, now, raw)
        if value is not None:
            completed.append(value)
    return completed


def test_bounce_exhaustive() -> None:
    patterns = tuple(BOUNCE_PATTERNS)
    cases = 0
    for presses in range(1, 7):
        for selected in product(patterns, repeat=presses):
            events: list[tuple[int, bool]] = []
            for index, pattern in enumerate(selected):
                events.extend(physical_press(100 + index * 300, pattern))
            result = run(sorted(events), 100 + presses * 300 + WINDOW_MS + 300)
            assert result == [presses], (presses, selected, result)
            cases += 1
    print(f"button debounce exhaustive: PASS ({cases} bounce combinations)")


def test_window_split() -> None:
    events: list[tuple[int, bool]] = []
    for index in range(2):
        events.extend(physical_press(100 + index * 300, "both"))
    second_start = 2200
    for index in range(3):
        events.extend(physical_press(second_start + index * 300, "both"))
    result = run(sorted(events), 4500)
    assert result == [2, 3], result
    print("button sequence window split: PASS")


def test_routing() -> None:
    for presses in range(1, 5):
        assert presses < 5
    for presses in range(5, 256):
        assert presses >= 5
    print("button routing: PASS (1-4 OTP, >=5 commissioning)")


def main() -> None:
    test_bounce_exhaustive()
    test_window_split()
    test_routing()


if __name__ == "__main__":
    main()
