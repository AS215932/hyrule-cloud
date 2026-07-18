from __future__ import annotations

from pathlib import Path

import yaml

SKILLS_ROOT = Path(__file__).parents[1] / "skills"
PUBLISHABLE_SKILLS = (
    "hyrule-cloud",
    "hyrule-network-intel",
    "hyrule-bgp",
    "hyrule-dns-registry",
    "hyrule-mx",
    "hyrule-web-reachability",
    "hyrule-port-reachability",
    "hyrule-nat-cgnat",
    "hyrule-voip-sip",
    "hyrule-mail-deliverability",
)


def _skill(slug: str) -> tuple[dict[str, object], str]:
    text = (SKILLS_ROOT / slug / "SKILL.md").read_text()
    _, frontmatter, body = text.split("---", 2)
    metadata = yaml.safe_load(frontmatter)
    assert isinstance(metadata, dict)
    return metadata, body


def test_publishable_skills_have_portable_routing_metadata() -> None:
    for slug in PUBLISHABLE_SKILLS:
        metadata, body = _skill(slug)
        assert metadata["name"] == slug
        description = metadata.get("description")
        assert isinstance(description, str) and len(description) >= 40
        assert body.strip()


def test_publishable_skills_use_x402_v2_client_terminology() -> None:
    for slug in PUBLISHABLE_SKILLS:
        _, body = _skill(slug)
        assert "X-PAYMENT" not in body, slug
        if slug != "hyrule-cloud":
            assert "official x402 v2 client" in body, slug

    _, umbrella = _skill("hyrule-cloud")
    assert "pip install hyrule-cloud" not in umbrella
    assert "Payment-Required" not in umbrella or "official x402 v2 client" in umbrella


def test_umbrella_skill_uses_progressive_references() -> None:
    _, body = _skill("hyrule-cloud")
    for relative in (
        "references/discovery.md",
        "references/payments.md",
        "references/workflows.md",
    ):
        assert relative in body
        assert (SKILLS_ROOT / "hyrule-cloud" / relative).is_file()
