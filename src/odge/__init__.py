"""Legacy import alias. The canonical package is :mod:`ogde`.

``import odge.<module>`` re-exports the canonical module's classes and functions.
There is no second implementation. ``python -m odge`` stays a real ``__main__``
so the module runner can load it.
"""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import sys
import types

import ogde

__version__ = ogde.__version__

_SKIP = {"__name__", "__spec__", "__loader__", "__package__", "__file__", "__cached__", "__path__", "__builtins__"}


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, target: str) -> None:
        self._target = target

    def create_module(self, spec):
        real = importlib.import_module(self._target)
        module = types.ModuleType(spec.name)
        for key, value in real.__dict__.items():
            if key not in _SKIP:
                module.__dict__[key] = value
        module.__file__ = getattr(real, "__file__", None)
        return module

    def exec_module(self, module) -> None:
        return None


class _AliasFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        prefix = "odge."
        if fullname == "odge.__main__" or not fullname.startswith(prefix):
            return None
        target_name = "ogde." + fullname[len(prefix):]
        return importlib.machinery.ModuleSpec(fullname, _AliasLoader(target_name))


def _install() -> None:
    if any(isinstance(finder, _AliasFinder) for finder in sys.meta_path):
        return
    sys.meta_path.insert(0, _AliasFinder())


_install()


def __getattr__(name: str):
    if name.startswith("_"):
        raise AttributeError(name)
    return importlib.import_module(f"odge.{name}")
