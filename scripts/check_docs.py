#!/usr/bin/env python3
"""Consistency checks between the code, .env.example, docker-compose.yml and the documentation.

    python scripts/check_docs.py          # exit 1 and a list of problems when something is inconsistent

Checks (standard library only, no network):
  1. every ${VAR} used in docker-compose.yml / deploy/ is documented in .env.example
  2. every environment variable the backend reads (INTEGRATION_KEYS, os.getenv, get_setting) is documented in .env.example
  3. every variable documented in .env.example is read by the backend, used by compose or by a script (no stale names)
  4. every UPPER_CASE_NAME written in backticks in the Markdown docs is a known variable (typos, removed settings)
  5. relative Markdown links resolve, anchors match a heading, and repo paths named in backticks exist
  6. documentation must not contain claims known to be false (see BANNED)
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = [
    ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "LIVE_CHECKLIST.md", ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "DEPLOYMENT.md", ROOT / "docs" / "PLAYBOOK_IMPORT.md", ROOT / "wazuh" / "README.md",
]
NAME = r"[A-Z][A-Z0-9_]*"

# Variables read by scripts / Docker rather than the backend, or documented on purpose.
SCRIPT_AND_COMPOSE_ONLY = {
    "BACKEND_HOST", "BACKEND_PORT", "FRONTEND_PORT",                      # scripts/dev.sh, run_backend.bat
    "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "REDIS_PASSWORD",  # compose
    "PHANTOM_DOMAIN", "PHANTOM_PUBLISH_HOST", "PHANTOM_HTTP_PORT", "PHANTOM_HTTPS_PORT",
    "NEXT_PUBLIC_API_URL", "CELERY_CONCURRENCY",
    "PHANTOM_BACKUP_DIR", "BACKUP_KEEP", "BACKUP_INTERVAL_SECONDS",
}
# Names that may appear in backticks in the docs although they are not backend settings.
DOC_OK = {
    "NET_BIND_SERVICE", "BACKUP_CONFIRM_RESTORE", "BACKUP_DIR", "BACKUP_REPORTS_DIR", "BACKUP_VERIFY_DB",
    "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "HOME",
    "PHANTOM_AR_DRY_RUN", "PHANTOM_AR_LOG", "PHANTOM_AR_STATE_DIR", "PHANTOM_AR_OSSEC_DIR", "PHANTOM_AR_MANAGER_IPS",
    "PHANTOM_AR_ALLOWLIST", "PHANTOM_AR_QUARANTINE_DIR",
    "PHANTOM_TEST_POSTGRES_URL", "PHANTOM_TEST_DATABASE_URL", "SMOKE_HTTP_URL", "SMOKE_INSECURE", "SMOKE_WAIT_SECONDS",
    "DATABASE_URL_HERE",
}
# Statements that were true of the old documentation and are false for this code base.
BANNED = [
    (r"production[- ]ready", "'production-ready' is not a claim this project can make"),
    (r"13 passing", "stale test count"),
    (r"sub-2-second|10,000\+ alerts", "no benchmark exists for this claim"),
    (r"Dockerfile\.backend|Dockerfile\.frontend", "the files are backend/Dockerfile and frontend/Dockerfile"),
    (r"Cairo", "the backend image has no Cairo libraries"),
    (r"abunemah.{0,40}(default|password)|default.{0,40}abunemah", "the default administrator is 'admin'"),
    (r"localhost:8000/docs|localhost:3000/docs", "API docs are not served in production mode"),
    (r"Gemini|GPT-4o|Ollama", "no such LLM integration exists (AI triage uses OpenRouter)"),
]


def read(path):
    return path.read_text(encoding="utf-8")


# ----------------------------------------------------------------------------- variable inventory
def code_env_vars():
    names = {}

    def add(name, where):
        names.setdefault(name, where)

    cfg = ROOT / "backend" / "integration_config.py"
    tree = ast.parse(read(cfg))
    integration_keys = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "INTEGRATION_KEYS":
            integration_keys = ast.literal_eval(node.value)
    for key, (_category, env) in integration_keys.items():
        add(env, f"INTEGRATION_KEYS[{key}]")

    for path in sorted((ROOT / "backend").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if "/tests/" in rel or "/alembic/versions/" in rel:
            continue
        text = read(path)
        for m in re.finditer(r"""(?:os\.getenv|os\.environ\.get|os\.environ)\(?\[?\s*["'](%s)["']""" % NAME, text):
            add(m.group(1), rel)
        for m in re.finditer(r"""(?:_int_env|get_setting|get_bool|get_list)\(\s*["']([a-z][a-z0-9_]*)["']""", text):
            key = m.group(1)
            if key in integration_keys:
                continue
            add(key.upper(), rel)

    rl = read(ROOT / "backend" / "ratelimit.py")
    m = re.search(r"DEFAULT_LIMITS[^=]*=\s*(\{.*?\n\})", rl, re.S)
    if m:
        for scope in re.findall(r'^\s*"([a-z_]+)":\s*\(', m.group(1), re.M):
            add(f"PHANTOM_RATE_LIMIT_{scope.upper()}", "backend/ratelimit.py")
    return names


def compose_vars():
    found = set()
    # Shell scripts under deploy/ use their own ${...} variables, so only compose files and the Caddyfile count.
    for path in [ROOT / "docker-compose.yml", ROOT / "docker-compose.override.example.yml", ROOT / "deploy" / "caddy" / "Caddyfile"]:
        text = read(path)
        found |= set(re.findall(r"\$\{(%s)(?::?[-?][^}]*)?\}" % NAME, text))
        found |= set(re.findall(r"\{\$(%s)(?::[^}]*)?\}" % NAME, text))  # Caddy placeholders
    return found


def documented_vars():
    names = set()
    for line in read(ROOT / ".env.example").splitlines():
        m = re.match(r"^#?\s*(%s)=" % NAME, line)
        if m:
            names.add(m.group(1))
    return names


# ----------------------------------------------------------------------------- markdown
def slug(heading):
    heading = re.sub(r"`", "", heading.strip().lower())
    heading = re.sub(r"[^\w\- ]", "", heading)
    return heading.replace(" ", "-")


def anchors(path):
    out = set()
    in_fence = False
    for line in read(path).splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            m = re.match(r"^#{1,6}\s+(.*)$", line)
            if m:
                out.add(slug(m.group(1)))
    return out


def strip_fences(text):
    return re.sub(r"```.*?```", "", text, flags=re.S)


PATH_TOKEN = re.compile(r"^(?:backend|frontend|deploy|docs|scripts|wazuh|\.github)/[\w./-]+$|^[\w-]+\.(?:md|bat|py|html|pdf)$")
PATH_IGNORE = {"deploy/certs/", "backend/reports", "frontend/.next"}


def check_markdown(errors, known_vars):
    for path in DOCS:
        if not path.exists():
            errors.append(f"{path.relative_to(ROOT)}: file is missing")
            continue
        rel = path.relative_to(ROOT).as_posix()
        text = strip_fences(read(path))
        for target in re.findall(r"\[[^\]]*\]\(([^)\s]+)\)", text):
            if re.match(r"^(https?:|mailto:)", target):
                continue
            file_part, _, frag = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if not dest.exists():
                errors.append(f"{rel}: broken link '{target}'")
            elif frag and dest.suffix == ".md" and frag not in anchors(dest):
                errors.append(f"{rel}: link '{target}' points to a heading that does not exist")
        for token in re.findall(r"`([^`\n]+)`", text):
            if PATH_TOKEN.match(token) and not any(token.startswith(i) for i in PATH_IGNORE):
                candidates = [ROOT / token, path.parent / token]
                if not any(c.exists() for c in candidates):
                    errors.append(f"{rel}: path `{token}` does not exist")
            if re.fullmatch(r"%s_%s" % (NAME, r"[A-Z0-9_]+"), token) and token not in known_vars and token not in DOC_OK:
                errors.append(f"{rel}: `{token}` is not a known setting (typo, or removed from the code)")
        for pattern, why in BANNED:
            for m in re.finditer(pattern, text, re.I):
                line = text.count("\n", 0, m.start()) + 1
                errors.append(f"{rel}:~{line}: banned statement '{m.group(0)}' ({why})")


def main():
    errors = []
    code = code_env_vars()
    compose = compose_vars()
    documented = documented_vars()

    for name in sorted(compose - documented):
        errors.append(f"compose/deploy uses ${{{name}}} but .env.example does not document it")
    for name, where in sorted(code.items()):
        if name not in documented:
            errors.append(f"{name} is read by the backend ({where}) but .env.example does not document it")
    known = set(code) | compose | SCRIPT_AND_COMPOSE_ONLY
    for name in sorted(documented - known):
        errors.append(f".env.example documents {name} but nothing in the code, compose file or scripts reads it")
    # Settings used by compose or scripts but also listed explicitly above must really be used there.
    for name in sorted(SCRIPT_AND_COMPOSE_ONLY - compose):
        used = any(name in read(p) for p in list((ROOT / "scripts").glob("*")) + [ROOT / "run_backend.bat", ROOT / "docker-compose.yml"] if p.is_file())
        if not used:
            errors.append(f"{name} is listed as script/compose-only but no script or compose file mentions it")

    check_markdown(errors, known | documented)

    if errors:
        print(f"{len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"ok: {len(code)} backend variables, {len(compose)} compose variables, {len(documented)} documented, "
          f"{len(DOCS)} documents checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
