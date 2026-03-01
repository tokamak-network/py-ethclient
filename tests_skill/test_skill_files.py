"""
Skill file validation tests.

Validates that all .claude/skills/*/SKILL.md files have correct structure,
valid YAML frontmatter, required fields, and no Korean text remnants.

Run:
    python -m pytest tests_skill/ -v
"""

import re
from pathlib import Path

import pytest

SKILLS_DIR = Path(__file__).resolve().parent.parent / ".claude" / "skills"

EXPECTED_SKILLS = [
    "l2-rollup",
    "zk-circuit",
    "bridge",
    "sepolia-deploy",
    "test",
    "l1-node",
    "debug-p2p",
]

REQUIRED_FRONTMATTER_FIELDS = [
    "description",
    "allowed-tools",
    "argument-hint",
    "user-invocable",
]

SKILLS_WITH_SECURITY = [
    "l2-rollup",
    "zk-circuit",
    "bridge",
    "sepolia-deploy",
    "test",
]

KOREAN_RANGE = re.compile(r"[\uac00-\ud7a3]")

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Parse YAML frontmatter into a dict (simple key: value parser)."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def _skill_paths() -> list[tuple[str, Path]]:
    """Return (skill_name, path) pairs for all expected skills."""
    return [(name, SKILLS_DIR / name / "SKILL.md") for name in EXPECTED_SKILLS]


class TestSkillFilesExist:
    """Verify all expected skill files exist."""

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_skill_file_exists(self, name, path):
        assert path.exists(), f"Missing skill file: {path}"

    def test_no_unexpected_skills(self):
        actual = {p.parent.name for p in SKILLS_DIR.glob("*/SKILL.md")}
        expected = set(EXPECTED_SKILLS)
        unexpected = actual - expected
        assert not unexpected, f"Unexpected skill directories: {unexpected}"


class TestFrontmatter:
    """Validate YAML frontmatter structure and required fields."""

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_has_frontmatter(self, name, path):
        text = path.read_text()
        assert text.startswith("---\n"), f"{name}: missing frontmatter delimiter"
        assert FRONTMATTER_RE.match(text), f"{name}: malformed frontmatter"

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_required_fields(self, name, path):
        fm = _parse_frontmatter(path.read_text())
        for field in REQUIRED_FRONTMATTER_FIELDS:
            assert field in fm, f"{name}: missing required field '{field}'"

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_user_invocable_is_true(self, name, path):
        fm = _parse_frontmatter(path.read_text())
        assert fm.get("user-invocable") == "true", f"{name}: user-invocable should be true"

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_description_is_english(self, name, path):
        fm = _parse_frontmatter(path.read_text())
        desc = fm.get("description", "")
        assert not KOREAN_RANGE.search(desc), f"{name}: description contains Korean"

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_argument_hint_is_english(self, name, path):
        fm = _parse_frontmatter(path.read_text())
        hint = fm.get("argument-hint", "")
        assert not KOREAN_RANGE.search(hint), f"{name}: argument-hint contains Korean"


class TestNoKorean:
    """Verify no Korean text remains in any skill file."""

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_no_korean_text(self, name, path):
        text = path.read_text()
        matches = KOREAN_RANGE.findall(text)
        assert not matches, (
            f"{name}: found {len(matches)} Korean character(s) — "
            f"first occurrence near: ...{_context(text, matches[0])}..."
        )


def _context(text: str, char: str, window: int = 30) -> str:
    """Return surrounding context for a character match."""
    idx = text.index(char)
    start = max(0, idx - window)
    end = min(len(text), idx + window)
    return text[start:end].replace("\n", "\\n")


class TestContentStructure:
    """Validate content structure: headings, sections, code blocks."""

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_has_h1_heading(self, name, path):
        text = path.read_text()
        body = FRONTMATTER_RE.sub("", text)
        assert re.search(r"^# .+", body, re.MULTILINE), f"{name}: missing H1 heading"

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_has_key_file_references(self, name, path):
        text = path.read_text()
        assert "Key File Reference" in text or "Key Reference" in text, (
            f"{name}: missing Key File References section"
        )

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_has_caveats(self, name, path):
        text = path.read_text()
        assert "## Caveats" in text or "## Caveat" in text, (
            f"{name}: missing Caveats section"
        )

    @pytest.mark.parametrize("name,path", _skill_paths(), ids=EXPECTED_SKILLS)
    def test_code_blocks_balanced(self, name, path):
        text = path.read_text()
        count = text.count("```")
        assert count % 2 == 0, (
            f"{name}: unbalanced code blocks ({count} ``` markers)"
        )


class TestSecuritySections:
    """Verify security sections exist in the 5 relevant skills."""

    @pytest.mark.parametrize(
        "name",
        SKILLS_WITH_SECURITY,
        ids=SKILLS_WITH_SECURITY,
    )
    def test_has_security_section(self, name):
        path = SKILLS_DIR / name / "SKILL.md"
        text = path.read_text()
        assert "## Security" in text, (
            f"{name}: missing Security Considerations section"
        )

    def test_l1_node_no_security_section(self):
        text = (SKILLS_DIR / "l1-node" / "SKILL.md").read_text()
        assert "## Security" not in text, "l1-node should not have Security section"

    def test_debug_p2p_no_security_section(self):
        text = (SKILLS_DIR / "debug-p2p" / "SKILL.md").read_text()
        assert "## Security" not in text, "debug-p2p should not have Security section"


class TestSkillSpecific:
    """Skill-specific content checks."""

    def test_l2_rollup_has_stf_integrity_gap(self):
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        assert "STF Integrity Gap" in text

    def test_l2_rollup_731_circuit_equation(self):
        """WHITEPAPER 7.3.1: circuit constraint equation must be present."""
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        assert "old_root" in text and "tx_commitment" in text and "(mod p)" in text

    def test_l2_rollup_731_not_enforce(self):
        """WHITEPAPER 7.3.1: 'What the circuit does NOT enforce' items."""
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        assert "does NOT enforce" in text or "does not enforce" in text
        assert "apply_tx" in text
        assert "balance checks" in text

    def test_l2_rollup_731_attack_scenarios(self):
        """WHITEPAPER 7.3.1: two attack scenarios."""
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        assert "failed transaction" in text.lower()
        assert "Manipulating the STF" in text

    def test_l2_rollup_731_defense_layers(self):
        """WHITEPAPER 7.3.1: defense layers table."""
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        for layer in ["Groth16 proof", "Data availability", "Off-chain re-execution", "Social consensus"]:
            assert layer in text, f"Missing defense layer: {layer}"

    def test_l2_rollup_731_optimistic_model(self):
        """WHITEPAPER 7.3.1: optimistic verification model conclusion."""
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        assert "optimistic verification model" in text

    def test_l2_rollup_has_four_properties(self):
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        for prop in ["Validity", "Data Availability", "Censorship Resistance", "Value Safety"]:
            assert prop in text, f"l2-rollup: missing security property '{prop}'"

    def test_l2_rollup_has_new_config_fields(self):
        text = (SKILLS_DIR / "l2-rollup" / "SKILL.md").read_text()
        for field in ["hash_function", "l1_confirmations", "rate_limit_rps", "enable_metrics"]:
            assert field in text, f"l2-rollup: missing config field '{field}'"

    def test_zk_circuit_has_poseidon(self):
        text = (SKILLS_DIR / "zk-circuit" / "SKILL.md").read_text()
        assert "Poseidon" in text
        assert "poseidon_circuit" in text

    def test_zk_circuit_has_field_truncation(self):
        text = (SKILLS_DIR / "zk-circuit" / "SKILL.md").read_text()
        assert "Field Truncation" in text

    def test_zk_circuit_has_trusted_setup_risk(self):
        text = (SKILLS_DIR / "zk-circuit" / "SKILL.md").read_text()
        assert "Trusted Setup Risk" in text

    def test_bridge_has_security_mechanisms_table(self):
        text = (SKILLS_DIR / "bridge" / "SKILL.md").read_text()
        assert "Replay protection" in text
        assert "Force inclusion" in text or "force inclusion" in text
        assert "Escape hatch" in text or "escape hatch" in text

    def test_bridge_has_dispute_limitation(self):
        text = (SKILLS_DIR / "bridge" / "SKILL.md").read_text()
        assert "dispute" in text.lower()

    def test_sepolia_has_confirmations(self):
        text = (SKILLS_DIR / "sepolia-deploy" / "SKILL.md").read_text()
        assert "confirmations" in text

    def test_sepolia_has_blob_expiry(self):
        text = (SKILLS_DIR / "sepolia-deploy" / "SKILL.md").read_text()
        assert "blob" in text.lower() or "Blob" in text

    def test_test_skill_stats_updated(self):
        text = (SKILLS_DIR / "test" / "SKILL.md").read_text()
        assert "1,031" in text, "test skill should show 1,031 tests"
        assert "42" in text, "test skill should show 42 test files"

    def test_test_skill_has_hardening_file(self):
        text = (SKILLS_DIR / "test" / "SKILL.md").read_text()
        assert "test_l2_framework_hardening.py" in text

    def test_test_skill_has_poseidon_file(self):
        text = (SKILLS_DIR / "test" / "SKILL.md").read_text()
        assert "test_poseidon.py" in text

    def test_test_skill_has_security_test_patterns(self):
        text = (SKILLS_DIR / "test" / "SKILL.md").read_text()
        assert "Security Test Patterns" in text
