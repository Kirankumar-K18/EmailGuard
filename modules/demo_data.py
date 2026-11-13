"""Demo Mode data: five fictional scenarios evaluated against a simulated DNS zone.

All results produced here are labelled DEMONSTRATION DATA. The e-mails are
fictional, the domains are reserved ``.example`` names and the DNS zone is
local JSON - no network access is needed.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import random
from datetime import datetime, timedelta, timezone

import config
from database import db
from modules.analysis_engine import analyze_email
from modules.dns_utils import DictResolver

DEMO_NOTICE = "DEMONSTRATION DATA - fictional e-mail evaluated against a simulated DNS zone. Not a real-world result."


def ensure_demo_files() -> None:
    """Regenerate the demo files if they are missing (e.g. a partial copy of the project)."""
    if config.DEMO_SCENARIOS_PATH.exists() and config.DEMO_DNS_PATH.exists():
        return
    script = config.BASE_DIR / "tools" / "generate_demo_emails.py"
    spec = importlib.util.spec_from_file_location("generate_demo_emails", script)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"Demo data is missing and {script} could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


def load_scenarios() -> list[dict]:
    ensure_demo_files()
    return json.loads(config.DEMO_SCENARIOS_PATH.read_text(encoding="utf-8"))["scenarios"]


def load_zone() -> dict:
    ensure_demo_files()
    return json.loads(config.DEMO_DNS_PATH.read_text(encoding="utf-8"))["zone"]


def demo_resolver() -> DictResolver:
    return DictResolver(load_zone())


def scenario_by_id(scenario_id: int) -> dict:
    for s in load_scenarios():
        if int(s["id"]) == int(scenario_id):
            return s
    raise KeyError(f"No demo scenario with id {scenario_id}")


def read_scenario_email(scenario: dict) -> bytes:
    return (config.DEMO_DIR / scenario["file"]).read_bytes()


def run_scenario(scenario: dict | int) -> dict:
    """Analyse one demo scenario with real SPF/DKIM/DMARC logic against the simulated zone."""
    if isinstance(scenario, int):
        scenario = scenario_by_id(scenario)
    result = analyze_email(
        read_scenario_email(scenario),
        dns_mode="simulated",
        resolver=demo_resolver(),
        sending_ip=scenario["sending_ip"],
        is_demo=True,
        scenario=scenario["title"],
        source="demo_scenario",
    )
    result["scenario_info"] = {k: scenario[k] for k in ("id", "title", "description", "expected", "learning_points")}
    return result


def seed_demo_data(count: int = 36, rng_seed: int = 2026) -> int:
    """Insert ``count`` demo rows spread over the last 14 days (flagged ``is_demo``)."""
    scenarios = load_scenarios()
    cache = {s["id"]: run_scenario(s) for s in scenarios}
    weights = {1: 22, 2: 4, 3: 3, 4: 3, 5: 5}
    ids = list(cache)
    rng = random.Random(rng_seed)
    now = datetime.now(timezone.utc)
    inserted = 0
    for _ in range(count):
        sid = rng.choices(ids, weights=[weights.get(i, 1) for i in ids])[0]
        result = copy.deepcopy(cache[sid])
        when = now - timedelta(days=rng.randint(0, 13), hours=rng.randint(0, 9), minutes=rng.randint(0, 59))
        result["source"] = "demo_seed"
        result["timestamp"] = when.isoformat(timespec="seconds")
        db.save_analysis(result, created_at=when.strftime("%Y-%m-%dT%H:%M:%SZ"))
        inserted += 1
    return inserted


def remove_demo_data() -> int:
    return db.delete_all(demo_only=True)
