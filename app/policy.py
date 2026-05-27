from __future__ import annotations

from app.config import AppConfig
from app.models import Finding, FixPlan


def approval_required(finding: Finding, allowed_fix_level: int) -> bool:
    return finding.fix_level > allowed_fix_level


def plan_requires_approval(plan: FixPlan, policy: AppConfig) -> bool:
    if plan.fix_level > policy.allowed_fix_level:
        return True
    if plan.fix_level >= 2 and policy.require_approval_for_level_2:
        return True
    return False

