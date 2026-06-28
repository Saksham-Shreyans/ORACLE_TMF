"""
ORACLE-TMF  ·  phantom/behavioral_biometrics.py
=================================================
PHANTOM Behavioral Biometrics — Stage 2 Tier 2.

Generates realistic inter-keystroke timing delays for the PHANTOM deception
engine.  Banking malware increasingly uses behavioral biometric analysis
to detect automated environments — detecting when keystrokes arrive at
inhuman speeds or with impossible uniformity.

Parameters (per ORACLE-TMF spec):
  Mean inter-keystroke delay: 150ms
  Standard deviation: 80ms

The timing distribution is modeled as a truncated normal distribution
to avoid non-physical values (negative delays, impossibly fast typing).
Additional realistic features:
  • Burst-pause pattern: humans type in short bursts with micro-pauses
  • Error correction pauses: occasional longer delays (500ms–2s) simulating
    the user spotting and correcting a typo
  • Field navigation delays: extra time when switching between form fields
  • Cognitive load variation: passwords take longer than known usernames

This module also generates:
  • Touch event coordinates with natural noise (finger landing variation)
  • Swipe gesture velocity profiles (deceleration at end of swipe)
  • Screen tap duration (press_time: mean 100ms, std 30ms)
"""
from __future__ import annotations

import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Optional

from config.stage2_settings import (
    KEYSTROKE_MAX_MS,
    KEYSTROKE_MEAN_MS,
    KEYSTROKE_MIN_MS,
    KEYSTROKE_STD_MS,
)

logger = logging.getLogger(__name__)


@dataclass
class KeyEvent:
    """A single synthetic keystroke event."""

    character: str = ""
    key_down_ns: int = 0       # KEY_DOWN event timestamp
    key_up_ns: int = 0         # KEY_UP event timestamp
    iki_ms: float = 0.0        # Inter-keystroke interval (preceding gap)
    press_duration_ms: float = 0.0  # How long the key was held


@dataclass
class TouchEvent:
    """A single synthetic touch event."""

    action: str = "DOWN"        # DOWN, MOVE, UP
    timestamp_ns: int = 0
    x: float = 0.0
    y: float = 0.0
    pressure: float = 0.5       # [0.0, 1.0]
    size: float = 0.3           # Contact area size


@dataclass
class BiometricSession:
    """
    A complete typing session with all key events and timing.
    Used by PHANTOM to replay the session into the target APK.
    """

    text: str = ""
    key_events: list[KeyEvent] = field(default_factory=list)
    total_duration_ms: float = 0.0
    mean_iki_ms: float = 0.0
    std_iki_ms: float = 0.0
    error_count: int = 0


class BehavioralBiometricGenerator:
    """
    Generates synthetic behavioral biometric data for PHANTOM detonation.

    The generated patterns match real human typing statistics to defeat
    anti-automation behavioral checks in banking malware.

    Usage
    -----
    >>> gen = BehavioralBiometricGenerator()
    >>> session = gen.simulate_typing("secretpassword123")
    >>> touch_stream = gen.simulate_tap(x=540, y=960)
    """

    # Error probability: 1 in 15 keystrokes triggers a correction pause
    _ERROR_PROB: float = 1 / 15

    # Field navigation delay range (ms): e.g., tapping next field
    _FIELD_NAV_MIN_MS: float = 400.0
    _FIELD_NAV_MAX_MS: float = 1200.0

    # Press duration distribution (key held down time)
    _PRESS_MEAN_MS: float = 100.0
    _PRESS_STD_MS: float = 30.0
    _PRESS_MIN_MS: float = 40.0
    _PRESS_MAX_MS: float = 350.0

    # Burst length: how many characters before a micro-pause
    _BURST_MIN: int = 3
    _BURST_MAX: int = 8

    # Micro-pause range (ms) between bursts
    _PAUSE_MIN_MS: float = 300.0
    _PAUSE_MAX_MS: float = 800.0

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        logger.info("[BiometricBiometrics] Generator initialised (seed=%s)", seed)

    def simulate_typing(
        self,
        text: str,
        cognitive_load: float = 0.5,
    ) -> BiometricSession:
        """
        Simulate typing a string with realistic human timing patterns.

        Parameters
        ----------
        text : str
            The text to type (e.g., a password or account number).
        cognitive_load : float
            [0.0, 1.0] — 0.0 = very familiar text, 1.0 = novel/complex.
            Increases mean IKI and error rate.

        Returns
        -------
        BiometricSession
        """
        if not text:
            return BiometricSession(text=text)

        # Adjust timing for cognitive load
        mean_iki = KEYSTROKE_MEAN_MS * (1.0 + cognitive_load * 0.8)
        std_iki = KEYSTROKE_STD_MS * (1.0 + cognitive_load * 0.4)
        error_prob = self._ERROR_PROB * (1.0 + cognitive_load * 2.0)

        key_events: list[KeyEvent] = []
        t_ns = time.time_ns()
        burst_remaining = self._rng.randint(self._BURST_MIN, self._BURST_MAX)
        error_count = 0

        for i, char in enumerate(text):
            # Check for error correction pause (probabilistic)
            if i > 0 and self._rng.random() < error_prob:
                error_count += 1
                # Longer pause: user noticed a mistake
                correction_ms = self._rng.uniform(500.0, 1800.0)
                t_ns += int(correction_ms * 1e6)

            # Check for burst pause
            burst_remaining -= 1
            if burst_remaining <= 0:
                pause_ms = self._rng.uniform(self._PAUSE_MIN_MS, self._PAUSE_MAX_MS)
                t_ns += int(pause_ms * 1e6)
                burst_remaining = self._rng.randint(self._BURST_MIN, self._BURST_MAX)

            # Sample IKI from truncated normal
            iki_ms = self._sample_iki(mean_iki, std_iki)

            key_down_ns = t_ns + int(iki_ms * 1e6) if i > 0 else t_ns
            press_ms = self._sample_press_duration()
            key_up_ns = key_down_ns + int(press_ms * 1e6)

            key_events.append(KeyEvent(
                character=char,
                key_down_ns=key_down_ns,
                key_up_ns=key_up_ns,
                iki_ms=round(iki_ms, 2) if i > 0 else 0.0,
                press_duration_ms=round(press_ms, 2),
            ))
            t_ns = key_up_ns

        # Compute statistics
        ikis = [e.iki_ms for e in key_events[1:]]
        total_ms = (t_ns - key_events[0].key_down_ns) / 1e6

        return BiometricSession(
            text=text,
            key_events=key_events,
            total_duration_ms=round(total_ms, 2),
            mean_iki_ms=round(sum(ikis) / len(ikis), 2) if ikis else 0.0,
            std_iki_ms=round(math.sqrt(
                sum((v - (sum(ikis) / len(ikis))) ** 2 for v in ikis) / len(ikis)
            ), 2) if ikis else 0.0,
            error_count=error_count,
        )

    def simulate_tap(
        self,
        x: float,
        y: float,
        target_radius: float = 20.0,
    ) -> list[TouchEvent]:
        """
        Simulate a realistic finger tap at coordinates (x, y).

        Includes natural finger landing variation (Gaussian offset from
        intended target center) and realistic down-up timing.

        Parameters
        ----------
        x, y : float
            Intended tap coordinates (screen pixels).
        target_radius : float
            Standard deviation of finger landing position (pixels).

        Returns
        -------
        list[TouchEvent]
            DOWN and UP events with realistic timing.
        """
        # Natural finger landing variation
        actual_x = x + self._rng.gauss(0, target_radius * 0.3)
        actual_y = y + self._rng.gauss(0, target_radius * 0.3)
        pressure = self._rng.uniform(0.35, 0.75)
        size = self._rng.uniform(0.2, 0.5)
        press_ms = self._sample_press_duration()

        t_down_ns = time.time_ns()
        t_up_ns = t_down_ns + int(press_ms * 1e6)

        return [
            TouchEvent(
                action="DOWN",
                timestamp_ns=t_down_ns,
                x=round(actual_x, 1),
                y=round(actual_y, 1),
                pressure=round(pressure, 3),
                size=round(size, 3),
            ),
            TouchEvent(
                action="UP",
                timestamp_ns=t_up_ns,
                x=round(actual_x, 1),
                y=round(actual_y, 1),
                pressure=0.0,
                size=0.0,
            ),
        ]

    def simulate_swipe(
        self,
        x_start: float,
        y_start: float,
        x_end: float,
        y_end: float,
        duration_ms: Optional[float] = None,
    ) -> list[TouchEvent]:
        """
        Simulate a realistic swipe gesture from (x_start, y_start) to (x_end, y_end).

        Uses decelerating velocity profile (easing-out) to match real
        human swipe physics.
        """
        if duration_ms is None:
            duration_ms = self._rng.uniform(200.0, 600.0)

        n_steps = max(5, int(duration_ms / 16))  # ~60 Hz motion events
        t0_ns = time.time_ns()
        events: list[TouchEvent] = []

        for step in range(n_steps + 1):
            # Ease-out: t² for decelerating finish
            t = step / n_steps
            ease = 1 - (1 - t) ** 2   # Cubic ease-out

            x = x_start + ease * (x_end - x_start)
            y = y_start + ease * (y_end - y_start)
            # Add slight finger wobble
            x += self._rng.gauss(0, 2.0)
            y += self._rng.gauss(0, 2.0)

            action = "DOWN" if step == 0 else ("UP" if step == n_steps else "MOVE")
            timestamp_ns = t0_ns + int(step * (duration_ms / n_steps) * 1e6)

            events.append(TouchEvent(
                action=action,
                timestamp_ns=timestamp_ns,
                x=round(x, 1),
                y=round(y, 1),
                pressure=round(0.5 - 0.3 * (step / n_steps), 3),
                size=round(0.4 - 0.2 * (step / n_steps), 3),
            ))

        return events

    def field_navigation_delay_ms(self) -> float:
        """Return a realistic delay (ms) between form field interactions."""
        return round(self._rng.uniform(self._FIELD_NAV_MIN_MS, self._FIELD_NAV_MAX_MS), 1)

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _sample_iki(self, mean_ms: float, std_ms: float) -> float:
        """Sample IKI from a truncated normal distribution."""
        while True:
            sample = self._rng.gauss(mean_ms, std_ms)
            if KEYSTROKE_MIN_MS <= sample <= KEYSTROKE_MAX_MS:
                return round(sample, 2)

    def _sample_press_duration(self) -> float:
        """Sample key/tap press duration from a truncated normal distribution."""
        while True:
            sample = self._rng.gauss(self._PRESS_MEAN_MS, self._PRESS_STD_MS)
            if self._PRESS_MIN_MS <= sample <= self._PRESS_MAX_MS:
                return round(sample, 2)
