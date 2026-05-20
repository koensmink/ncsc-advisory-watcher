import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("harvest_ncsc", Path(__file__).resolve().parents[1] / "harvest_ncsc.py")
harvest_ncsc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harvest_ncsc)


def test_days_default(monkeypatch):
    monkeypatch.setattr('sys.argv', ['harvest_ncsc.py'])
    args = harvest_ncsc.parse_args()
    assert args.days == 1


def test_days_7(monkeypatch):
    monkeypatch.setattr('sys.argv', ['harvest_ncsc.py', '--days', '7'])
    args = harvest_ncsc.parse_args()
    assert args.days == 7


def test_days_0_invalid(monkeypatch):
    monkeypatch.setattr('sys.argv', ['harvest_ncsc.py', '--days', '0'])
    with pytest.raises(SystemExit):
        harvest_ncsc.parse_args()
