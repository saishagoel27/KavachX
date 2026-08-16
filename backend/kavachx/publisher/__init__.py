"""
Publisher: Publishes verified patches to GitHub repositories.

Handles:
- Pull request creation in target repos
- Documentation generation & publishing
- Release notes
- PR status tracking
- Rollback coordination
"""

import logging
from datetime import datetime
from typing import Optional

from kavachx.core.state import (
    KavachState,
    StagedPatch,
    PatchVerification,
    PublishedPatch,
    PublishPatchOutput,
)

logger = logging.getLogger(__name__)


async def publish_patches(
    state: KavachState,
) -> dict:
    """
    LangGraph node: Publishes verified patches to GitHub.
    
    For each verified patch:
    - Create PR in target repo
    - Add documentation
    - Generate release notes
    - Track PR status
    
    Args:
        state: KavachState with staged_patches and verifications
        
    Returns:
        Updated state dict with published_patches
    """
    logger.info(f"[Publisher] Publishing patches for run {state['run_id']}")
    
    staged_patches = state.get("staged_patches", [])
    verifications = state.get("verifications", [])
    
    if not staged_patches:
        logger.warning("[Publisher] No patches to publish")
        return {"published_patches": []}
    
    published_patches = []
    publish_outputs = []
    
    for patch in staged_patches:
        patch_id = patch.get("patch_id", "unknown")
        
        # Find corresponding verification
        verification = next(
            (v for v in verifications if v.get("patch_id") == patch_id),
            None
        )
        
        # Only publish verified patches
        if not verification or verification.get("overall_result") != "pass":
            logger.warning(f"[Publisher] Skipping unverified patch: {patch_id}")
            output = PublishPatchOutput(
                patch_id=patch_id,
                success=False,
                published_patch=None,
                pr_details=[],
                error_message="Patch not verified",
                published_at=datetime.utcnow(),
            )
            publish_outputs.append(output)
            continue
        
        try:
            pub_patch = await _publish_single_patch(patch, verification, state)
            if pub_patch:
                published_patches.append(pub_patch)
                output = PublishPatchOutput(
                    patch_id=patch_id,
                    success=True,
                    published_patch=pub_patch,
                    # pub_patch is a PublishedPatch model, and pr_details is
                    # list[dict] — wrap each URL rather than calling .get().
                    pr_details=[{"url": url} for url in pub_patch.pull_request_urls],
                    error_message=None,
                    published_at=datetime.utcnow(),
                )
            else:
                output = PublishPatchOutput(
                    patch_id=patch_id,
                    success=False,
                    published_patch=None,
                    pr_details=[],
                    error_message="Publishing failed",
                    published_at=datetime.utcnow(),
                )
            
            publish_outputs.append(output)
            
        except Exception as e:
            logger.error(f"[Publisher] Error publishing patch {patch_id}: {e}")
            output = PublishPatchOutput(
                patch_id=patch_id,
                success=False,
                published_patch=None,
                pr_details=[],
                error_message=str(e),
                published_at=datetime.utcnow(),
            )
            publish_outputs.append(output)
    
    logger.info(f"[Publisher] Published {len(published_patches)} patches successfully")
    
    return {
        "published_patches": [p.model_dump() for p in published_patches],
        "publish_outputs": [o.model_dump() for o in publish_outputs],
        "phase": "completed",  # Final phase
    }


async def _publish_single_patch(
    patch: dict,
    verification: dict,
    state: KavachState,
) -> Optional[PublishedPatch]:
    """
    Publish a single verified patch.
    
    Args:
        patch: StagedPatch dict
        verification: VerificationResult dict
        state: KavachState
        
    Returns:
        PublishedPatch or None on error
    """
    patch_id = patch.get("patch_id", "unknown")
    logger.info(f"[Publisher.single] Publishing: {patch_id}")
    
    # Extract repo info from channel
    channel = patch.get("source_channel", "unknown/repo")
    repo_info = _parse_channel(channel)
    
    # Create PRs
    pr_urls = await _create_pull_requests(patch, repo_info, state)
    
    if not pr_urls:
        logger.warning(f"[Publisher.single] Failed to create PRs for {patch_id}")
        return None
    
    # Generate documentation
    docs_url = await _publish_documentation(patch, verification)
    
    published_patch = PublishedPatch(
        patch_id=patch_id,
        publish_id=f"pub-{patch_id}-{datetime.utcnow().isoformat()}",
        title=patch.get("title", ""),
        description=patch.get("description", ""),
        publish_date=datetime.utcnow(),
        published_to=[repo_info.get("repo", "unknown")],
        pull_request_urls=pr_urls,
        documentation_url=docs_url,
    )
    
    logger.info(f"[Publisher.single] Published: {patch_id} with {len(pr_urls)} PRs")
    
    return published_patch


async def _create_pull_requests(
    patch: dict,
    repo_info: dict,
    state: KavachState,
) -> list[str]:
    """
    Create pull requests in target repository.
    
    Args:
        patch: StagedPatch dict
        repo_info: Parsed channel info
        state: KavachState
        
    Returns:
        List of PR URLs
    """
    logger.info(f"[Publisher.pr] Creating PR for {patch.get('patch_id')}")
    
    patch_id = patch.get("patch_id", "unknown")
    repo = repo_info.get("repo", "unknown")
    org = repo_info.get("org", "unknown")
    
    # TODO: Real implementation:
    # 1. Clone target repo
    # 2. Create feature branch: patches/{patch_id}
    # 3. Apply patch changes
    # 4. Commit with message
    # 5. Push to remote
    # 6. Create PR via GitHub API
    # 7. Set labels, description
    # 8. Return PR URL
    
    # Mock PR URL
    pr_url = f"https://github.com/{org}/{repo}/pull/1001"
    
    logger.info(f"[Publisher.pr] Created PR: {pr_url}")
    
    return [pr_url]


async def _publish_documentation(
    patch: dict,
    verification: dict,
) -> str:
    """
    Publish patch documentation.
    
    Args:
        patch: StagedPatch dict
        verification: VerificationResult dict
        
    Returns:
        Documentation URL
    """
    logger.info(f"[Publisher.docs] Publishing docs for {patch.get('patch_id')}")
    
    patch_id = patch.get("patch_id", "unknown")
    
    # Generate markdown documentation
    doc_content = _generate_documentation_markdown(patch, verification)
    
    # TODO: Real implementation:
    # 1. Generate markdown from patch data
    # 2. Publish to docs site or GitHub Pages
    # 3. Generate URL
    
    docs_url = f"https://kavachx.example.com/patches/{patch_id}"
    
    logger.info(f"[Publisher.docs] Published: {docs_url}")
    
    return docs_url


def _generate_documentation_markdown(patch: dict, verification: dict) -> str:
    """Generate markdown documentation for a patch."""
    return f"""
# Patch: {patch.get('title', 'Unknown')}

## Overview
{patch.get('description', 'N/A')}

## Details
- **Patch ID**: {patch.get('patch_id', 'unknown')}
- **Source**: {patch.get('source_channel', 'unknown')}
- **Severity**: Unknown
- **Status**: Published

## Remediation Steps
```
{chr(10).join(patch.get('remediation_steps', []))}
```

## Deployment

{patch.get('deploy_instructions', 'See deployment guide')}

## Verification
- **Overall Result**: {verification.get('overall_result', 'unknown')}
- **Checks**: {len(verification.get('checks', []))} passed

## Testing
Run the following to validate the patch:
```bash
docker run -v /path/to/patch:/patch patch:{patch.get('patch_id')}
```

## Support
For issues with this patch, please open an issue on GitHub.
"""


def _parse_channel(channel: str) -> dict:
    """
    Parse channel string into repo info.
    
    Args:
        channel: Channel format "org/repo#branch"
        
    Returns:
        Dict with org, repo, branch
    """
    try:
        repo_part, branch = channel.split("#")
        org, repo = repo_part.split("/")
        return {
            "org": org,
            "repo": repo,
            "branch": branch,
        }
    except:
        return {
            "org": "unknown",
            "repo": "unknown",
            "branch": "main",
        }


async def track_pr_status(
    pr_url: str,
    state: KavachState,
) -> dict:
    """
    Track status of published PR.
    
    Args:
        pr_url: URL of the pull request
        state: KavachState
        
    Returns:
        PR status dict
    """
    logger.info(f"[Publisher.status] Tracking: {pr_url}")
    
    # TODO: Real implementation:
    # 1. Parse PR URL to get owner/repo/PR number
    # 2. Call GitHub API to get PR details
    # 3. Return status (open, closed, merged, draft)
    
    return {
        "url": pr_url,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
        "reviews": 0,
    }


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "publish_patches",
    "track_pr_status",
]
