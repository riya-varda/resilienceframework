"""Attack-vector registry.

Any module in this package that defines NAME and build() is auto-registered.
Adding a new attack vector = dropping in a new file; nothing else changes.
"""

import importlib
import pkgutil

_registry = None


def _discover():
    global _registry
    if _registry is None:
        import vectors as pkg
        reg = {}
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_"):
                continue
            mod = importlib.import_module("vectors." + info.name)
            if hasattr(mod, "NAME") and hasattr(mod, "build"):
                reg[mod.NAME] = mod
        _registry = reg
    return _registry


def all_vectors():
    return dict(_discover())


def get_vector(name):
    reg = _discover()
    if name not in reg:
        raise KeyError("unknown vector %r; have %s" % (name, sorted(reg)))
    return reg[name]
