import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from xdr.config import DEFAULTS, Config, deep_merge  # noqa: E402
from xdr.events import Event  # noqa: E402


def make_config(tmp_path, **extra):
    base = {
        "agent": {"data_dir": str(tmp_path / "agent"), "enroll_key": "enroll-test"},
        "server": {"data_dir": str(tmp_path / "server"), "enroll_key": "enroll-test",
                   "admin_token": "admin-test", "port": 0},
        "detection": {"learning_period": 0},
        "response": {"dry_run": True},
    }
    return Config(deep_merge(deep_merge(DEFAULTS, base), extra))


@pytest.fixture
def config(tmp_path):
    return make_config(tmp_path)


def ev(category, action, **data):
    return Event(category=category, action=action, data=data, host="test-host")
