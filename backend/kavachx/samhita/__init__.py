"""
SAMHITA: Report synthesis & documentation for KavachX patches.

Generates comprehensive reports for all discovered patches:
- Executive summary
- Per-patch details (CVE info, remediation, testing)
- Risk assessment
- Remediation timeline
- Dashboard metrics
"""

import logging
from datetime import datetime
from typing import Optional

from kavachx.core.state import (
    KavachState,
    DiscoveryBatch,
    StagedPatch,
    PatchVerification,
)

logger = logging.getLogger(__name__)


async def synthesize_reports(
    state: KavachState,
) -> dict:
    """
    LangGraph node: Synthesizes comprehensive patch reports.
    
    Generates:
    - Executive summary
    - Risk dashboard
    - Per-patch details
    - Timeline & SLA tracking
    
    Args:
        state: KavachState with discovery_batch, staged_patches, verifications
        
    Returns:
        Updated state dict with synthesis results
    """
    logger.info(f"[SAMHITA] Synthesizing reports for run {state['run_id']}")
    
    discovery_batch = state.get("discovery_batch")
    staged_patches = state.get("staged_patches", [])
    verifications = state.get("verifications", [])
    
    if not discovery_batch:
        logger.warning("[SAMHITA] No discovery batch to synthesize")
        return {}
    
    # Generate reports
    exec_summary = _generate_executive_summary(discovery_batch)
    risk_dashboard = _generate_risk_dashboard(discovery_batch)
    patch_details = _generate_patch_details(staged_patches, verifications)
    timeline = _generate_remediation_timeline(discovery_batch, verifications)
    
    logger.info(
        f"[SAMHITA] Synthesis complete: "
        f"{len(exec_summary.get('patches', []))} patches, "
        f"Risk: {risk_dashboard.get('overall_risk', 'UNKNOWN')}"
    )
    
    return {
        "synthesis": {
            "executive_summary": exec_summary,
            "risk_dashboard": risk_dashboard,
            "patch_details": patch_details,
            "remediation_timeline": timeline,
            "generated_at": datetime.utcnow().isoformat(),
        }
    }


def _generate_executive_summary(batch: dict) -> dict:
    """
    Generate executive summary from discovery batch.
    
    Includes:
    - Total vulnerabilities by type
    - Top risks
    - Remediation status
    """
    candidates = batch.get("patch_candidates", [])
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for patch in candidates:
        severity = patch.get("severity", "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Count by type
    type_counts = {}
    for patch in candidates:
        ptype = patch.get("finding_type", "unknown")
        type_counts[ptype] = type_counts.get(ptype, 0) + 1
    
    return {
        "total_patches": len(candidates),
        "severity_breakdown": severity_counts,
        "type_breakdown": type_counts,
        "channels_scanned": len(batch.get("channel_results", [])),
        "discovery_period": {
            "started": batch.get("discovery_started", ""),
            "ended": batch.get("discovery_ended", ""),
        },
        "patches": [
            {
                "id": p.get("id"),
                "title": p.get("title"),
                "severity": p.get("severity"),
                "type": p.get("finding_type"),
                "component": p.get("affected_component"),
            }
            for p in candidates[:10]  # Top 10
        ],
        "key_findings": _extract_key_findings(candidates),
    }


def _generate_risk_dashboard(batch: dict) -> dict:
    """
    Generate risk assessment dashboard.
    
    Determines overall risk level and priorities.
    """
    candidates = batch.get("patch_candidates", [])
    
    critical_count = len([p for p in candidates if p.get("severity") == "critical"])
    high_count = len([p for p in candidates if p.get("severity") == "high"])
    
    # Determine overall risk
    if critical_count > 0:
        overall_risk = "CRITICAL"
        risk_score = 9.0
    elif high_count > 3:
        overall_risk = "HIGH"
        risk_score = 7.0
    elif high_count > 0:
        overall_risk = "MEDIUM"
        risk_score = 5.0
    else:
        overall_risk = "LOW"
        risk_score = 2.0
    
    return {
        "overall_risk": overall_risk,
        "risk_score": risk_score,  # 0-10
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": len([p for p in candidates if p.get("severity") == "medium"]),
        "low_count": len([p for p in candidates if p.get("severity") == "low"]),
        "remediation_urgency": "IMMEDIATE" if critical_count > 0 else "SOON",
        "priority_actions": _generate_priority_actions(candidates),
    }


def _generate_patch_details(
    staged_patches: list,
    verifications: list,
) -> list[dict]:
    """
    Generate detailed information for each patch.
    
    Includes remediation steps, testing status, deployment plan.
    """
    details = []
    
    for patch in staged_patches:
        patch_id = patch.get("patch_id", "unknown")
        
        # Find verification for this patch
        verification = next(
            (v for v in verifications if v.get("patch_id") == patch_id),
            None
        )
        
        details.append({
            "patch_id": patch_id,
            "title": patch.get("title", ""),
            "description": patch.get("description", ""),
            "source_channel": patch.get("source_channel", ""),
            "remediation_steps": patch.get("remediation_steps", []),
            "artifacts": [
                {
                    "type": a.get("artifact_type"),
                    "path": a.get("path"),
                }
                for a in patch.get("artifacts", [])
            ],
            "deployment_instructions": patch.get("deploy_instructions", ""),
            "verification": {
                "status": verification.get("overall_result") if verification else "pending",
                "checks": verification.get("checks", []) if verification else [],
            },
            "staged_at": patch.get("staged_at", ""),
        })
    
    return details


def _generate_remediation_timeline(
    batch: dict,
    verifications: list,
) -> dict:
    """
    Generate remediation timeline and SLA tracking.
    
    Shows progress through discovery → staging → verification → publishing.
    """
    candidates = batch.get("patch_candidates", [])
    verified_count = len(verifications)
    
    return {
        "phase_breakdown": {
            "discovered": len(candidates),
            "staged": len(candidates),  # Would be updated after staging
            "verified": verified_count,
            "published": 0,  # Would be updated after publishing
        },
        "timeline": [
            {
                "phase": "discovery",
                "started": batch.get("discovery_started", ""),
                "ended": batch.get("discovery_ended", ""),
                "duration_seconds": _calc_duration(
                    batch.get("discovery_started"),
                    batch.get("discovery_ended"),
                ),
            },
            {
                "phase": "staging",
                "started": batch.get("discovery_ended", ""),
                "ended": datetime.utcnow().isoformat(),
                "duration_seconds": 0,  # To be calculated
            },
            {
                "phase": "verification",
                "started": datetime.utcnow().isoformat(),
                "ended": None,
                "duration_seconds": None,
            },
        ],
        "estimated_completion": _estimate_completion(candidates),
        "sla_status": "ON_TRACK",
    }


def _extract_key_findings(candidates: list) -> list[str]:
    """Extract key findings and insights from patch candidates."""
    findings = []
    
    # Find critical issues
    critical = [p for p in candidates if p.get("severity") == "critical"]
    if critical:
        findings.append(f"⚠️  {len(critical)} CRITICAL vulnerabilities require immediate attention")
    
    # Most common component
    components = {}
    for p in candidates:
        comp = p.get("affected_component", "unknown")
        components[comp] = components.get(comp, 0) + 1
    
    if components:
        top_comp = max(components, key=components.get)
        findings.append(f"🎯 Most affected component: {top_comp} ({components[top_comp]} issues)")
    
    # Finding types
    types = {}
    for p in candidates:
        ptype = p.get("finding_type", "unknown")
        types[ptype] = types.get(ptype, 0) + 1
    
    if types:
        type_breakdown = ", ".join(f"{k}: {v}" for k, v in types.items())
        findings.append(f"📊 Finding breakdown: {type_breakdown}")
    
    return findings


def _generate_priority_actions(candidates: list) -> list[str]:
    """Generate priority actions based on risk assessment."""
    actions = []
    
    critical = [p for p in candidates if p.get("severity") == "critical"]
    high = [p for p in candidates if p.get("severity") == "high"]
    
    if critical:
        actions.append(f"1. URGENT: Patch {len(critical)} critical vulnerabilities within 24 hours")
        actions.append(f"   - {', '.join([p.get('finding_id', 'N/A') for p in critical[:3]])}")
    
    if high:
        actions.append(f"2. HIGH: Patch {len(high)} high-severity issues within 1 week")
    
    actions.append("3. TEST: Run full test suite before deployment")
    actions.append("4. AUDIT: Document all changes in CHANGELOG")
    actions.append("5. MONITOR: Track metrics post-deployment")
    
    return actions


def _calc_duration(start: Optional[str], end: Optional[str]) -> float:
    """Calculate duration between two ISO timestamp strings."""
    if not start or not end:
        return 0.0
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return (end_dt - start_dt).total_seconds()
    except:
        return 0.0


def _estimate_completion(candidates: list) -> str:
    """Estimate completion date based on patch count."""
    # Mock estimation: assume 2 hours per critical patch, 1 hour per high
    critical = len([p for p in candidates if p.get("severity") == "critical"])
    high = len([p for p in candidates if p.get("severity") == "high"])
    
    estimated_hours = (critical * 2) + (high * 1) + 4  # Base 4 hours
    
    from datetime import timedelta
    completion = datetime.utcnow() + timedelta(hours=estimated_hours)
    return completion.isoformat()


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "synthesize_reports",
]
