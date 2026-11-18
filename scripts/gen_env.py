#!/usr/bin/env python3
"""Create .env from .env.example with freshly generated random secrets (standard library only).

    python scripts/gen_env.py                         # writes ./.env (refuses to overwrite)
    python scripts/gen_env.py --domain soar.example.org
    python scripts/gen_env.py --out /tmp/test.env --set PHANTOM_INGEST_TOKEN=... --set PHANTOM_BOOTSTRAP_ADMIN_PASSWORD=...

Generated: POSTGRES_PASSWORD, REDIS_PASSWORD, PHANTOM_JWT_SECRET, PHANTOM_ENCRYPTION_KEY (a valid Fernet
key). Everything else keeps the template value unless --domain / --set override it. The values are never
printed. The file is created with mode 0600. Keep PHANTOM_ENCRYPTION_KEY somewhere safe and separate from
database backups: without it the secrets stored in the database cannot be decrypted.
"""
import argparse
import base64
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GENERATORS = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "REDIS_PASSWORD": lambda: secrets.token_urlsafe(32),
    "PHANTOM_JWT_SECRET": lambda: secrets.token_urlsafe(48),
    # Fernet keys are urlsafe base64 of 32 random bytes.
    "PHANTOM_ENCRYPTION_KEY": lambda: base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
}
LINE_RE = re.compile(r"^(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>.*)$")


def render(template, overrides, generate):
    """Template text with the values applied; returns (text, names_set)."""
    applied = []
    out = []
    for line in template.splitlines():
        match = LINE_RE.match(line)
        if match:
            key = match.group("key")
            if key in overrides:
                line = f"{key}={overrides[key]}"
                applied.append(key)
            elif generate and key in GENERATORS and not match.group("value"):
                line = f"{key}={GENERATORS[key]()}"
                applied.append(key)
        out.append(line)
    # Overrides for variables that are only commented out in the template are appended.
    for key, value in overrides.items():
        if key not in applied:
            out.append(f"{key}={value}")
            applied.append(key)
    return "\n".join(out) + "\n", applied


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=str(ROOT / ".env"), help="file to create (default: ./.env)")
    parser.add_argument("--template", default=str(ROOT / ".env.example"))
    parser.add_argument("--domain", help="value for PHANTOM_DOMAIN (default: keep localhost)")
    parser.add_argument("--set", dest="sets", action="append", default=[], metavar="KEY=VALUE",
                        help="set or override one variable (repeatable)")
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"error: {out} already exists; delete it or pass --force (a new key would make secrets "
              "stored under the old PHANTOM_ENCRYPTION_KEY unreadable).", file=sys.stderr)
        return 1
    overrides = {}
    if args.domain:
        overrides["PHANTOM_DOMAIN"] = args.domain
    for item in args.sets:
        key, sep, value = item.partition("=")
        if not sep or not re.match(r"^[A-Z][A-Z0-9_]*$", key) or "\n" in value:
            print(f"error: --set expects KEY=VALUE, got {key!r}", file=sys.stderr)
            return 2
        overrides[key] = value

    text, applied = render(Path(args.template).read_text(encoding="utf-8"), overrides, generate=True)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"wrote {out} (mode 0600); set: {', '.join(sorted(applied))}")
    print("Next: back up PHANTOM_ENCRYPTION_KEY separately from database backups, then run")
    print("  docker compose up -d --build --wait")
    if "PHANTOM_BOOTSTRAP_ADMIN_PASSWORD" not in overrides:
        print("The first admin password is generated on first start; read it with:")
        print("  docker compose exec backend cat /app/run/bootstrap_admin_password.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
