#!/usr/bin/env python3
"""Exhaustive model for the two-layer LED state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from itertools import product


class Base(Enum):
    BOOTING = auto()
    NORMAL_IDLE = auto()
    USB_SUSPENDED = auto()
    PROCESSING = auto()
    MAINTENANCE = auto()
    ERROR = auto()


class Interaction(Enum):
    NONE = auto()
    WAITING_TOUCH = auto()
    TOUCH_ACCEPTED = auto()


class Event(Enum):
    USB_MOUNTED = auto()
    USB_UNMOUNTED = auto()
    USB_SUSPENDED = auto()
    USB_RESUMED = auto()
    PROCESSING_BEGIN = auto()
    PROCESSING_END = auto()
    MAINTENANCE_BEGIN = auto()
    TOUCH_WAIT_BEGIN = auto()
    TOUCH_ACCEPTED = auto()
    TOUCH_CANCELLED = auto()
    ERROR = auto()


@dataclass(frozen=True)
class State:
    base: Base
    interaction: Interaction


TOUCH_FEEDBACK_MS = 320
WAIT_POLL_MS = 1


def legal(state: State) -> bool:
    return state.base is not Base.ERROR or state.interaction is Interaction.NONE


def transition(state: State, event: Event) -> State:
    base = state.base
    interaction = state.interaction

    if event in (Event.USB_MOUNTED, Event.USB_RESUMED):
        if base not in (Base.MAINTENANCE, Base.ERROR):
            base = Base.NORMAL_IDLE
    elif event is Event.USB_UNMOUNTED:
        if base not in (Base.MAINTENANCE, Base.ERROR):
            base = Base.BOOTING
            interaction = Interaction.NONE
    elif event is Event.USB_SUSPENDED:
        if base not in (Base.MAINTENANCE, Base.ERROR):
            base = Base.USB_SUSPENDED
            interaction = Interaction.NONE
    elif event is Event.PROCESSING_BEGIN:
        if base not in (Base.MAINTENANCE, Base.ERROR):
            base = Base.PROCESSING
    elif event is Event.PROCESSING_END:
        if base is Base.PROCESSING:
            base = Base.NORMAL_IDLE
    elif event is Event.MAINTENANCE_BEGIN:
        if base is not Base.ERROR:
            base = Base.MAINTENANCE
            interaction = Interaction.NONE
    elif event is Event.TOUCH_WAIT_BEGIN:
        if base is not Base.ERROR:
            interaction = Interaction.WAITING_TOUCH
    elif event is Event.TOUCH_ACCEPTED:
        if interaction is Interaction.WAITING_TOUCH:
            interaction = Interaction.TOUCH_ACCEPTED
    elif event is Event.TOUCH_CANCELLED:
        interaction = Interaction.NONE
    elif event is Event.ERROR:
        base = Base.ERROR
        interaction = Interaction.NONE

    return State(base, interaction)


def tick(state: State, accepted_age_ms: int) -> State:
    if state.interaction is Interaction.TOUCH_ACCEPTED and accepted_age_ms >= TOUCH_FEEDBACK_MS:
        return State(state.base, Interaction.NONE)
    return state


def render(state: State, accepted_age_ms: int = 0) -> str:
    if state.interaction is Interaction.WAITING_TOUCH:
        return "yellow-blink"
    if state.interaction is Interaction.TOUCH_ACCEPTED and accepted_age_ms < TOUCH_FEEDBACK_MS:
        if accepted_age_ms < 120 or accepted_age_ms >= 200:
            return "white"
        return "off"
    return {
        Base.BOOTING: "red-blink",
        Base.NORMAL_IDLE: "blue-steady",
        Base.USB_SUSPENDED: "blue-slow-blink",
        Base.PROCESSING: "cyan-fast-blink",
        Base.MAINTENANCE: "green-steady",
        Base.ERROR: "red-fast-blink",
    }[state.base]


def main() -> None:
    legal_states = [
        State(base, interaction)
        for base, interaction in product(Base, Interaction)
        if legal(State(base, interaction))
    ]

    checked = 0
    for state, event in product(legal_states, Event):
        result = transition(state, event)
        assert legal(result), (state, event, result)
        checked += 1

    error = State(Base.ERROR, Interaction.NONE)
    for event in Event:
        assert transition(error, event).base is Base.ERROR
        assert transition(error, event).interaction is Interaction.NONE

    maintenance = State(Base.MAINTENANCE, Interaction.NONE)
    for event in (
        Event.USB_MOUNTED,
        Event.USB_UNMOUNTED,
        Event.USB_SUSPENDED,
        Event.USB_RESUMED,
        Event.PROCESSING_BEGIN,
        Event.PROCESSING_END,
    ):
        assert transition(maintenance, event).base is Base.MAINTENANCE

    for base in Base:
        for interaction in Interaction:
            state = State(base, interaction)
            if not legal(state):
                continue
            accepted = transition(state, Event.TOUCH_ACCEPTED)
            if interaction is Interaction.WAITING_TOUCH and base is not Base.ERROR:
                assert accepted.interaction is Interaction.TOUCH_ACCEPTED
            else:
                assert accepted.interaction is interaction

    idle = State(Base.NORMAL_IDLE, Interaction.NONE)
    processing = transition(idle, Event.PROCESSING_BEGIN)
    assert processing == State(Base.PROCESSING, Interaction.NONE)
    assert transition(processing, Event.PROCESSING_END) == idle

    assert transition(idle, Event.USB_SUSPENDED).base is Base.USB_SUSPENDED
    assert transition(State(Base.USB_SUSPENDED, Interaction.NONE), Event.USB_RESUMED) == idle

    accepted = State(Base.NORMAL_IDLE, Interaction.TOUCH_ACCEPTED)
    assert render(accepted, 0) == "white"
    assert render(accepted, 119) == "white"
    assert render(accepted, 120) == "off"
    assert render(accepted, 199) == "off"
    assert render(accepted, 200) == "white"
    assert render(accepted, 319) == "white"
    assert tick(accepted, 319) == accepted
    assert tick(accepted, 320) == idle
    assert render(tick(accepted, 320), 320) == "blue-steady"

    assert render(State(Base.NORMAL_IDLE, Interaction.NONE)) == "blue-steady"
    assert render(State(Base.MAINTENANCE, Interaction.NONE)) == "green-steady"
    assert render(State(Base.PROCESSING, Interaction.NONE)) == "cyan-fast-blink"
    assert render(State(Base.NORMAL_IDLE, Interaction.WAITING_TOUCH)) == "yellow-blink"

    waiting = transition(State(Base.PROCESSING, Interaction.NONE), Event.TOUCH_WAIT_BEGIN)
    rendered_wait_polls = [render(waiting) for _ in range(15_000 // WAIT_POLL_MS)]
    assert rendered_wait_polls
    assert all(frame == "yellow-blink" for frame in rendered_wait_polls)

    print(f"LED state model: PASS ({len(legal_states)} legal states, {checked} event transitions)")


if __name__ == "__main__":
    main()
