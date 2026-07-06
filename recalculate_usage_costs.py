#!/usr/bin/env python3
"""Recalculate persisted usage costs from current pricing metadata.

This keeps token/request counters intact and only rewrites cost fields in
llm_proxy/stats/usage_YYYY-MM-DD.json files. A .bak file is written before each
changed file unless --no-backup is passed.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from usage_controller import UsageController


def usage_file_sort_key(path: Path) -> str:
    return path.stem.removeprefix("usage_")


def recalculate_stats_costs(controller: UsageController, stats: dict[str, Any]) -> float:
    input_tokens = int(stats.get("input_tokens") or 0)
    output_tokens = int(stats.get("output_tokens") or 0)
    return controller.estimate_cost(str(stats.get("_model_name") or ""), input_tokens, output_tokens)


def is_zero_marginal_model(controller: UsageController, model_name: str) -> bool:
    return controller._is_zero_marginal_cost(
        controller.per_model_limits.get(model_name, {}) or {},
        controller.model_configs.get(model_name, {}) or {},
    )


def recalculate_usage_file(controller: UsageController, path: Path, mode: str) -> tuple[bool, float, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    old_total_cost = float((payload.get("total") or {}).get("cost") or 0)
    new_total_cost = 0.0

    for model_name, stats in (payload.get("models") or {}).items():
        if not isinstance(stats, dict):
            continue
        if mode == "zero-marginal" and not is_zero_marginal_model(controller, model_name):
            cost = float(stats.get("cost") or 0)
        else:
            cost = controller.estimate_cost(
                model_name,
                int(stats.get("input_tokens") or 0),
                int(stats.get("output_tokens") or 0),
            )
        stats["cost"] = cost
        new_total_cost += cost

    total = payload.setdefault("total", {})
    total["cost"] = new_total_cost

    for _slot, models in (payload.get("hourly") or {}).items():
        if not isinstance(models, dict):
            continue
        slot_total_cost = 0.0
        for model_name, stats in models.items():
            if model_name == "total" or not isinstance(stats, dict):
                continue
            if mode == "zero-marginal" and not is_zero_marginal_model(controller, model_name):
                cost = float(stats.get("cost") or 0)
            else:
                cost = controller.estimate_cost(
                    model_name,
                    int(stats.get("input_tokens") or 0),
                    int(stats.get("output_tokens") or 0),
                )
            stats["cost"] = cost
            slot_total_cost += cost
        if isinstance(models.get("total"), dict):
            models["total"]["cost"] = slot_total_cost

    changed = round(old_total_cost, 10) != round(new_total_cost, 10)
    if changed:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return changed, old_total_cost, new_total_cost


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="llm_proxy/proxy_config.yaml", help="proxy config path")
    parser.add_argument("--stats-dir", default="llm_proxy/stats", help="directory containing usage_YYYY-MM-DD.json")
    parser.add_argument("--dry-run", action="store_true", help="print changes without writing files")
    parser.add_argument("--no-backup", action="store_true", help="do not create .bak files before rewriting")
    parser.add_argument("--exclude-today", action="store_true", help="skip today's usage file to avoid active writer races")
    parser.add_argument(
        "--mode",
        choices=("zero-marginal", "all"),
        default="zero-marginal",
        help="zero-marginal only clears free/subscription model costs; all recomputes every model from current prices",
    )
    args = parser.parse_args()

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
    controller = UsageController(config, stats_dir=args.stats_dir)
    files = sorted(Path(args.stats_dir).glob("usage_????-??-??.json"), key=usage_file_sort_key)
    if args.exclude_today:
        today_name = f"usage_{datetime.now().strftime('%Y-%m-%d')}.json"
        files = [path for path in files if path.name != today_name]

    changed_count = 0
    for path in files:
        original = path.read_text(encoding="utf-8")
        payload = json.loads(original)
        old_cost = float((payload.get("total") or {}).get("cost") or 0)
        changed, _old, new_cost = recalculate_usage_file(controller, path, args.mode)
        if args.dry_run:
            path.write_text(original, encoding="utf-8")
            changed = round(old_cost, 10) != round(new_cost, 10)
        elif changed and not args.no_backup:
            backup = path.with_suffix(path.suffix + ".bak")
            if not backup.exists():
                backup.write_text(original, encoding="utf-8")
        if changed:
            changed_count += 1
            print(f"{path}: ${old_cost:.4f} -> ${new_cost:.4f}")

    print(f"processed={len(files)} changed={changed_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
