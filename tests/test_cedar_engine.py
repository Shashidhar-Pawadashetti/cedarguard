"""Unit tests for engine/cedar_engine.py.

Verifies the CedarEngine abstraction, including SubprocessCedarEngine,
LambdaCedarEngine, and get_cedar_engine factory.
"""

from __future__ import annotations

from engine.cedar_engine import (
    CedarEngine,
    LambdaCedarEngine,
    SubprocessCedarEngine,
    get_cedar_engine,
)


class TestCedarEngineAbstraction:
    def test_subprocess_engine_instantiation(self):
        engine = SubprocessCedarEngine()
        assert isinstance(engine, CedarEngine)
        bin_path = engine._resolve_binary()
        assert bin_path is not None
        assert len(bin_path) > 0

    def test_lambda_engine_instantiation(self):
        engine = LambdaCedarEngine()
        assert isinstance(engine, CedarEngine)

    def test_get_cedar_engine_returns_singleton_or_override(self):
        engine1 = get_cedar_engine()
        engine2 = get_cedar_engine()
        assert engine1 is engine2

        custom = SubprocessCedarEngine()
        assert get_cedar_engine(custom) is custom
