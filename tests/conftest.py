"""Load this repo the way Hermes loads an installed plugin, against a Hermes checkout.

Set HERMES_AGENT_HOME to the checkout (unless Hermes is already importable), e.g.
``HERMES_AGENT_HOME=../hermes-agent python -m pytest``.
"""

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if os.environ.get("HERMES_AGENT_HOME"):
    sys.path.insert(0, os.environ["HERMES_AGENT_HOME"])

# Isolated homes before any Hermes module reads them at import time.
_ROOT = Path(tempfile.mkdtemp(prefix="cwtch-plugin-tests-"))
for _key in ("HERMES_HOME", "HERMES_GATEWAY_LOCK_DIR"):
    (_ROOT / _key).mkdir()
    os.environ[_key] = str(_ROOT / _key)


def _load_plugin_package():
    spec = importlib.util.spec_from_file_location(
        "hermes_cwtch_platform", REPO / "__init__.py", submodule_search_locations=[str(REPO)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _PluginContext:
    """The one PluginContext method this plugin calls, registering the entry the way Hermes does."""

    def register_platform(self, name, label, adapter_factory, check_fn, validate_config=None,
                          required_env=None, install_hint="", **entry_kwargs):
        from gateway.platform_registry import PlatformEntry, platform_registry
        platform_registry.register(PlatformEntry(
            name=name, label=label, adapter_factory=adapter_factory, check_fn=check_fn,
            validate_config=validate_config, required_env=required_env or [], install_hint=install_hint,
            source="plugin", **entry_kwargs))


_load_plugin_package().register(_PluginContext())


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("HERMES_GATEWAY_LOCK_DIR", str(tmp_path / "gateway-locks"))
    for var in [v for v in os.environ if v.startswith("CWTCH_") or v == "GATEWAY_ALLOW_ALL_USERS"]:
        monkeypatch.delenv(var)


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_ROOT, ignore_errors=True)
