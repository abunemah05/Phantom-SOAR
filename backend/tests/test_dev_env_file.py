"""scripts/dev_env.py must read .env files saved by Windows editors (UTF-16, BOM, CRLF) instead of crashing."""
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("dev_env", Path(__file__).resolve().parents[2] / "scripts" / "dev_env.py")
dev_env = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dev_env)

TEXT = "VIRUSTOTAL_API_KEY=abc\r\nOPENROUTER_MODEL=nvidia/nemotron-3.5-super-vl:free\r\nPHANTOM_AI_ENABLED=true"
EXPECTED = {"VIRUSTOTAL_API_KEY": "abc", "OPENROUTER_MODEL": "nvidia/nemotron-3.5-super-vl:free", "PHANTOM_AI_ENABLED": "true"}


def _parse(tmp_path, data: bytes):
    path = tmp_path / ".env"
    path.write_bytes(data)
    return dev_env.parse_env_file(path)


def test_utf8_crlf(tmp_path):
    assert _parse(tmp_path, TEXT.encode()) == EXPECTED


def test_utf8_with_bom(tmp_path):
    assert _parse(tmp_path, b"\xef\xbb\xbf" + TEXT.encode()) == EXPECTED


def test_utf16_from_notepad_unicode(tmp_path):
    assert _parse(tmp_path, TEXT.encode("utf-16")) == EXPECTED


def test_unreadable_bytes_do_not_crash(tmp_path):
    assert isinstance(_parse(tmp_path, b"\x81\x8d\x8f\x90\x9d"), dict)
