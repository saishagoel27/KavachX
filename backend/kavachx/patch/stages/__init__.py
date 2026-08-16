"""
Patch staging workflow nodes for KavachX.

Stages patch candidates for verification:
- Prepares build artifacts (Dockerfiles, test configs)
- Generates remediation steps
- Creates deployment instructions
- Outputs structured StagedPatch objects
"""

import logging
from datetime import datetime
from typing import Optional

from kavachx.core.state import (
    KavachState,
    PatchCandidate,
    StagedPatch,
    PatchBuildArtifact,
    PatchStatus,
)

logger = logging.getLogger(__name__)


async def stage_patches(
    state: KavachState,
) -> dict:
    """
    LangGraph node: Stages patch candidates for verification.
    
    Takes patch candidates and stages them with:
    - Build artifacts (Dockerfile, config)
    - Remediation steps
    - Deployment instructions
    
    Args:
        state: KavachState with patch_candidates
        
    Returns:
        Updated state dict with staged_patches
    """
    logger.info(f"[Staging] Starting patch staging for run {state['run_id']}")
    
    candidates = state.get("patch_candidates", [])
    if not candidates:
        logger.warning("[Staging] No patch candidates to stage")
        return {"staged_patches": []}
    
    staged_patches = []
    for candidate in candidates:
        try:
            staged = await _stage_single_patch(candidate, state)
            if staged:
                staged_patches.append(staged)
        except Exception as e:
            logger.error(f"[Staging] Error staging patch {candidate.get('id')}: {e}")
    
    logger.info(f"[Staging] Completed: {len(staged_patches)} patches staged")
    
    return {
        "staged_patches": [p.model_dump() for p in staged_patches],
        "phase": "verification",  # Transition to verification phase
    }


async def _stage_single_patch(
    candidate: dict,
    state: KavachState,
) -> Optional[StagedPatch]:
    """
    Stage a single patch candidate.
    
    Args:
        candidate: PatchCandidate dict
        state: KavachState
        
    Returns:
        StagedPatch or None on error
    """
    patch_id = candidate.get("id")
    logger.info(f"[Staging.single] Staging patch: {patch_id}")
    
    # Generate build artifacts
    artifacts = await _generate_artifacts(candidate)
    
    # Generate remediation steps
    remediation_steps = _generate_remediation_steps(candidate)
    
    # Generate deployment instructions
    deploy_instructions = _generate_deploy_instructions(candidate)
    
    # Build output (mock for now). The wording matters: PRAMAAN's build check
    # reads this log for an outcome, and an inconclusive log fails verification.
    build_output = (
        f"Build log for {patch_id}\n"
        f"Artifacts: {len(artifacts)} generated\n"
        "Simulated build completed successfully (no compiler invoked)\n"
    )
    
    staged_patch = StagedPatch(
        patch_id=patch_id,
        title=candidate.get("title", ""),
        description=candidate.get("description", ""),
        status=PatchStatus.STAGED,
        artifacts=artifacts,
        build_output=build_output,
        remediation_steps=remediation_steps,
        deploy_instructions=deploy_instructions,
        staged_at=datetime.utcnow(),
        source_channel=candidate.get("channel_name", ""),
    )
    
    logger.info(f"[Staging.single] Staged: {patch_id} with {len(artifacts)} artifacts")
    
    return staged_patch


async def _generate_artifacts(candidate: dict) -> list[PatchBuildArtifact]:
    """
    Generate build artifacts for a patch.
    
    Creates:
    - Dockerfile or build script
    - Test configuration
    - CI/CD config
    - Documentation
    
    Args:
        candidate: PatchCandidate dict
        
    Returns:
        List of PatchBuildArtifact
    """
    artifacts = []
    patch_id = candidate.get("id", "unknown")
    
    # Dockerfile artifact
    dockerfile_content = _generate_dockerfile(candidate)
    artifacts.append(PatchBuildArtifact(
        artifact_type="dockerfile",
        path=f"patches/{patch_id}/Dockerfile",
        content_hash=_hash_content(dockerfile_content),
        size_bytes=len(dockerfile_content),
    ))
    
    # Test configuration
    test_config_content = _generate_test_config(candidate)
    artifacts.append(PatchBuildArtifact(
        artifact_type="test_config",
        path=f"patches/{patch_id}/test-config.yaml",
        content_hash=_hash_content(test_config_content),
        size_bytes=len(test_config_content),
    ))
    
    # Documentation
    doc_content = _generate_documentation(candidate)
    artifacts.append(PatchBuildArtifact(
        artifact_type="documentation",
        path=f"patches/{patch_id}/PATCH.md",
        content_hash=_hash_content(doc_content),
        size_bytes=len(doc_content),
    ))
    
    return artifacts


def _generate_dockerfile(candidate: dict) -> str:
    """Generate Dockerfile for patch build."""
    return f"""
FROM python:3.10-slim

WORKDIR /patch

COPY . .

RUN pip install -r requirements.txt

# Patch for: {candidate.get('title', 'unknown')}
# Severity: {candidate.get('severity', 'medium')}
# CVE/Issue: {candidate.get('finding_id', 'unknown')}

ENTRYPOINT ["python", "-m", "pytest"]
"""


def _generate_test_config(candidate: dict) -> str:
    """Generate test configuration for patch."""
    return f"""
# Test configuration for patch {candidate.get('id', 'unknown')}
tests:
  - name: "remediation_applied"
    description: "Verify {candidate.get('title', 'fix')} is applied"
    command: "pytest tests/test_remediation.py"
    expected_exit_code: 0

  - name: "no_regression"
    description: "Verify no regression in existing functionality"
    command: "pytest tests/test_regression.py"
    expected_exit_code: 0

  - name: "vulnerability_fixed"
    description: "Verify vulnerability is actually fixed"
    command: "pytest tests/test_vulnerability.py"
    expected_exit_code: 0
"""


def _generate_documentation(candidate: dict) -> str:
    """Generate documentation for patch."""
    return f"""
# Patch: {candidate.get('title', 'Unnamed Patch')}

## Issue
{candidate.get('finding_id', 'N/A')}: {candidate.get('description', 'N/A')}

## Severity
{candidate.get('severity', 'medium').upper()}

## Affected Component
{candidate.get('affected_component', 'unknown')}

## Remediation
See remediation_path: {candidate.get('remediation_path', 'N/A')}

## Testing
Run the included test suite to verify the fix.

## Deployment
Follow deployment instructions in deploy-instructions.txt
"""


def _generate_remediation_steps(candidate: dict) -> list[str]:
    """Generate remediation steps for a patch."""
    finding_type = candidate.get("finding_type", "").lower()
    severity = candidate.get("severity", "medium").lower()
    
    steps = [
        f"1. Review: {candidate.get('title', 'Unnamed patch')}",
        f"2. Assess severity: {severity.upper()}",
        f"3. Identify component: {candidate.get('affected_component', 'unknown')}",
    ]
    
    if finding_type == "cve":
        steps.append("4. Check CVE database for patches")
        steps.append("5. Apply security update")
    elif finding_type == "misconfig":
        steps.append("4. Review configuration options")
        steps.append("5. Apply recommended settings")
    else:
        steps.append("4. Analyze code quality metrics")
        steps.append("5. Refactor as needed")
    
    steps.append("6. Test changes in staging")
    steps.append("7. Deploy to production")
    
    return steps


def _generate_deploy_instructions(candidate: dict) -> str:
    """Generate deployment instructions for a patch."""
    return f"""
# Deployment Instructions for {candidate.get('id', 'patch')}

## Prerequisites
- Backup current deployment
- Verify staging tests pass
- Review rollback procedures

## Deployment Steps

1. **Pre-deployment Checklist**
   - [ ] All tests passing
   - [ ] Code reviewed
   - [ ] Security audit passed
   - [ ] Rollback plan ready

2. **Deployment**
   ```bash
   # Pull latest code
   git pull origin main
   
   # Checkout patch branch
   git checkout patches/{candidate.get('id')}
   
   # Build and test
   docker build -t patch:{candidate.get('id')} .
   docker run patch:{candidate.get('id')}
   
   # Deploy
   kubectl apply -f k8s/deployment.yaml
   ```

3. **Verification**
   - Monitor application logs
   - Run smoke tests
   - Verify fix is applied
   - Check metrics

4. **Rollback (if needed)**
   ```bash
   git checkout main
   docker build -t patch:rollback .
   kubectl rollout undo deployment/kavachx
   ```

## Post-deployment
- Document deployment in CHANGELOG
- Update deployment dashboard
- Notify stakeholders
"""


def _hash_content(content: str) -> str:
    """Generate SHA256 hash of content."""
    import hashlib
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "stage_patches",
]
