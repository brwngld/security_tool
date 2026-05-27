from __future__ import annotations

import typer
from rich.console import Console

from app.models import FixPlan, ScanResult
from app.reports.console import render_interactive_fix_catalog


_prompt_console = Console()


def approve(plan: FixPlan, approver: str) -> FixPlan:
    return plan.model_copy(
        update={
            "status": "approved",
            "approved_by": approver,
        }
    )


def ask_to_create_backup() -> bool:
    return typer.confirm("Create backup first?", default=True)


def ask_to_apply_local_fix() -> bool:
    return typer.confirm("Apply selected local fixes?", default=False)


def confirm_risky_command(action: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    return typer.confirm(
        f"Only use {action} on systems you own or have explicit permission to test.\n"
        "Unauthorized scanning or changes may be illegal.\n"
        f"Continue with {action}?",
        default=False,
    )


def choose_interactive_fix_mode() -> str:
    _prompt_console.print("Choose action:")
    _prompt_console.print("  [1] Generate fix artifacts only")
    _prompt_console.print("  [2] Apply fixes locally")
    _prompt_console.print("  [3] Skip")
    while True:
        choice = typer.prompt("Action", default="1").strip().lower()
        if choice in {"1", "generate", "g"}:
            return "generate"
        if choice in {"2", "local", "fix", "apply"}:
            return "local"
        if choice in {"3", "skip", "none"}:
            return "skip"
        _prompt_console.print("Pick 1, 2, or 3.")


def choose_interactive_fix_selection(result: ScanResult, *, show_catalog: bool = True) -> str:
    total = len(result.fix_plans)
    if total == 0:
        return "none"

    page_size = 10
    page_start = 0

    while True:
        page_end = min(page_start + page_size, total)
        _prompt_console.print("Select fixes:")
        _prompt_console.print("Enter all, none, comma lists, or ranges like 3-4.")
        if total > page_size:
            _prompt_console.print(f"Page {page_start + 1}-{page_end} of {total}")
            _prompt_console.print("[n] Next page")
            _prompt_console.print("[p] Previous page")
        if show_catalog:
            _prompt_console.print(render_interactive_fix_catalog(result, page_start=page_start, page_size=page_size))
        show_catalog = True

        choice = typer.prompt("Selection", default="all").strip()
        lowered = choice.lower()
        if lowered in {"n", "next"} and page_end < total:
            page_start = page_end
            show_catalog = True
            continue
        if lowered in {"n", "next"}:
            _prompt_console.print("That was the last page.")
            continue
        if lowered in {"p", "prev", "previous"} and page_start > 0:
            page_start = max(0, page_start - page_size)
            show_catalog = True
            continue
        if lowered in {"p", "prev", "previous"}:
            _prompt_console.print("That was the first page.")
            continue
        if lowered in {"all", "*"}:
            return "all"
        if lowered in {"none", "skip", "0"}:
            return "none"
        return choice
