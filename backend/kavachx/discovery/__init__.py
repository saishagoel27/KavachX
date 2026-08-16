"""
Discovery orchestrator for KavachX.

Coordinates patch discovery across all GitHub channels using:
- LangGraph for workflow orchestration
- Parallel channel scanning
- Finding aggregation & deduplication
- Patch candidate generation
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from kavachx.core.state import (
    KavachState,
    ChannelDiscoveryResult,
    PatchCandidate,
    DiscoveryBatch,
    FindingType,
    PatchStatus,
)

logger = logging.getLogger(__name__)


async def discover_patches(
    state: KavachState,
) -> dict:
    """
    LangGraph node: Orchestrates patch discovery across all channels.
    
    Args:
        state: KavachState with channels list populated
        
    Returns:
        Updated state dict with discovery_batch and patch_candidates
    """
    logger.info(f"[Discovery] Starting discovery workflow for run {state['run_id']}")
    
    channels = state.get("channels", [])
    if not channels:
        logger.warning("[Discovery] No channels configured, skipping discovery")
        return {
            "discovery_batch": None,
            "patch_candidates": [],
        }
    
    # Parallel channel scanning
    batch_id = f"batch-{state['run_id']}-{datetime.utcnow().isoformat()}"
    results = await _scan_channels_parallel(channels, state)
    
    # Aggregate findings
    patch_candidates = _aggregate_findings(results, batch_id)
    
    discovery_batch = DiscoveryBatch(
        batch_id=batch_id,
        channel_results=results,
        patch_candidates=patch_candidates,
        total_findings=sum(r.found_count for r in results),
        discovery_started=state.get("workflow_started", datetime.utcnow()),
        discovery_ended=datetime.utcnow(),
    )
    
    logger.info(
        f"[Discovery] Completed: {len(results)} channels, "
        f"{len(patch_candidates)} patch candidates"
    )
    
    return {
        "discovery_batch": discovery_batch.model_dump(),
        "patch_candidates": [p.model_dump() for p in patch_candidates],
        "phase": "staging",  # Transition to staging phase
    }


async def _scan_channels_parallel(
    channels: list[str],
    state: KavachState,
) -> list[ChannelDiscoveryResult]:
    """
    Scan all channels in parallel using asyncio.
    
    Args:
        channels: List of channel names (org/repo#branch)
        state: KavachState for auth context
        
    Returns:
        List of ChannelDiscoveryResult
    """
    tasks = [
        _scan_single_channel(channel, state)
        for channel in channels
    ]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return [r for r in results if r is not None]


async def _scan_single_channel(
    channel: str,
    state: KavachState,
) -> Optional[ChannelDiscoveryResult]:
    """
    Scan a single GitHub channel for vulnerabilities.
    
    Calls into discovery.channels module for scanner integration.
    
    Args:
        channel: Channel name (org/repo#branch)
        state: KavachState for auth
        
    Returns:
        ChannelDiscoveryResult or None on error
    """
    try:
        logger.info(f"[Discovery.scan] Scanning channel: {channel}")
        
        # Import scanner here to avoid circular imports
        from kavachx.discovery.channels import semgrep_scanner
        
        findings = await semgrep_scanner.scan(channel, state)
        
        # Count by type
        cve_count = len([f for f in findings if f.get("type") == "cve"])
        misconfig_count = len([f for f in findings if f.get("type") == "misconfig"])
        
        result = ChannelDiscoveryResult(
            channel_name=channel,
            found_count=len(findings),
            cve_count=cve_count,
            misconfig_count=misconfig_count,
            findings=findings,
            scanned_at=datetime.utcnow(),
        )
        
        logger.info(
            f"[Discovery.scan] Channel {channel}: "
            f"{len(findings)} findings ({cve_count} CVE, {misconfig_count} misconfig)"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"[Discovery.scan] Error scanning {channel}: {e}")
        return ChannelDiscoveryResult(
            channel_name=channel,
            scan_error=str(e),
        )


def _aggregate_findings(
    results: list[ChannelDiscoveryResult],
    batch_id: str,
) -> list[PatchCandidate]:
    """
    Aggregate findings from all channels and deduplicate.
    
    Creates patch candidates from raw findings.
    
    Args:
        results: List of per-channel results
        batch_id: Batch ID for traceability
        
    Returns:
        List of PatchCandidate objects
    """
    candidates = []
    seen_findings = set()  # (channel, finding_id) -> dedup
    
    for result in results:
        if result.scan_error:
            logger.warning(
                f"[Discovery.agg] Skipping {result.channel_name}: {result.scan_error}"
            )
            continue
        
        for finding in result.findings:
            finding_id = finding.get("id", "unknown")
            dedup_key = (result.channel_name, finding_id)
            
            if dedup_key in seen_findings:
                logger.debug(f"[Discovery.agg] Duplicate: {dedup_key}")
                continue
            
            seen_findings.add(dedup_key)
            
            # Map finding to patch candidate
            patch = _finding_to_patch_candidate(
                finding,
                result.channel_name,
                batch_id,
            )
            if patch:
                candidates.append(patch)
    
    logger.info(f"[Discovery.agg] Generated {len(candidates)} unique patch candidates")
    return candidates


def _finding_to_patch_candidate(
    finding: dict,
    channel: str,
    batch_id: str,
) -> Optional[PatchCandidate]:
    """
    Convert raw finding to PatchCandidate.
    
    Args:
        finding: Raw finding dict from scanner
        channel: Channel name
        batch_id: Batch ID for traceability
        
    Returns:
        PatchCandidate or None if invalid
    """
    try:
        finding_type_str = finding.get("type", "").lower()
        if finding_type_str == "cve":
            ftype = FindingType.CVE
        elif finding_type_str == "misconfig":
            ftype = FindingType.MISCONFIG
        else:
            ftype = FindingType.CODE_QUALITY
        
        patch_id = f"patch-{batch_id}-{finding.get('id', 'unknown')}"
        
        candidate = PatchCandidate(
            id=patch_id,
            channel_name=channel,
            finding_type=ftype,
            finding_id=finding.get("id", "unknown"),
            title=finding.get("title", "Unnamed finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "medium").lower(),
            affected_component=finding.get("component", "unknown"),
            remediation_path=finding.get("remediation_path"),
            status=PatchStatus.DISCOVERED,
            created_at=datetime.utcnow(),
        )
        
        return candidate
        
    except Exception as e:
        logger.error(f"[Discovery.to_patch] Error converting finding: {e}")
        return None


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "discover_patches",
]
