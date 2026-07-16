"""Regression contracts for GitHub Actions workflow coordination."""

from pathlib import Path

import yaml


def test_pr_agent_comments_cannot_cancel_pull_request_reviews() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/pr-agent.yml").read_text())

    assert workflow["concurrency"]["group"] == (
        "pr-agent-${{ github.event_name }}-"
        "${{ github.event.pull_request.number || github.event.issue.number }}"
    )
