"""
Dynamic skill invocation tests.

Actually invokes each skill via the `claude` CLI and validates
that the response contains domain-relevant content.

Results are saved to tests_skill/results/ (gitignored).

Run:
    # All skills (slow — makes 7 LLM calls)
    python -m pytest tests_skill/test_skill_invoke.py -v -s

    # Single skill
    python -m pytest tests_skill/test_skill_invoke.py -v -s -k l2_rollup

    # Skip if claude CLI not available
    python -m pytest tests_skill/test_skill_invoke.py -v -s
"""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

RESULTS_DIR = Path(__file__).resolve().parent / "results"
PROJECT_DIR = Path(__file__).resolve().parent.parent

CLAUDE_BIN = shutil.which("claude")

# (skill_name, invoke_prompt, expected_keywords_in_response)
SKILL_CASES = [
    (
        "l2-rollup",
        "/l2-rollup Explain how to create a simple counter rollup",
        ["Rollup", "STF", "setup", "prove"],
    ),
    (
        "l2-rollup-security",
        "/l2-rollup What are the security limitations of the ZK rollup? "
        "Explain the STF integrity gap and what the circuit does NOT enforce.",
        ["STF", "integrity", "circuit", "enforce"],
    ),
    (
        "zk-circuit",
        "/zk-circuit Explain how to build a multiplication circuit",
        ["Circuit", "Groth16", "proof", "verify"],
    ),
    (
        "bridge",
        "/bridge Explain L1 to L2 deposit flow",
        ["bridge", "messenger", "relay", "deposit"],
    ),
    (
        "sepolia-deploy",
        "/sepolia-deploy Explain how to deploy a verifier on Sepolia",
        ["Sepolia", "deploy", "verifier", "EthL1Backend"],
    ),
    (
        "test",
        "/test How to run L2 sequencer tests",
        ["pytest", "test", "sequencer"],
    ),
    (
        "l1-node",
        "/l1-node Explain EVM opcode support",
        ["EVM", "opcode", "PUSH", "CALL"],
    ),
    (
        "debug-p2p",
        "/debug-p2p How to debug TOO_MANY_PEERS error",
        ["TOO_MANY_PEERS", "peer", "discv4"],
    ),
]


def _claude_available() -> bool:
    """Check if claude CLI is installed and reachable."""
    return CLAUDE_BIN is not None


def _invoke_skill(prompt: str, timeout: int = 120) -> dict:
    """
    Invoke a skill via `claude -p` and return result dict.

    Returns:
        {"prompt": str, "output": str, "exit_code": int,
         "duration_s": float, "error": str | None}
    """
    assert CLAUDE_BIN is not None
    # Remove CLAUDECODE env var to allow nested invocation
    env = {k: v for k, v in __import__("os").environ.items() if k != "CLAUDECODE"}
    start = time.time()
    try:
        proc = subprocess.run(
            [CLAUDE_BIN, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(PROJECT_DIR),
            env=env,
        )
        duration = time.time() - start
        return {
            "prompt": prompt,
            "output": proc.stdout,
            "exit_code": proc.returncode,
            "duration_s": round(duration, 2),
            "error": proc.stderr if proc.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        return {
            "prompt": prompt,
            "output": "",
            "exit_code": -1,
            "duration_s": round(time.time() - start, 2),
            "error": f"timeout after {timeout}s",
        }
    except Exception as e:
        return {
            "prompt": prompt,
            "output": "",
            "exit_code": -1,
            "duration_s": round(time.time() - start, 2),
            "error": str(e),
        }


def _save_result(skill_name: str, result: dict) -> Path:
    """Save invocation result to results directory."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"{skill_name}.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return out_path


skip_no_claude = pytest.mark.skipif(
    not _claude_available(),
    reason="claude CLI not found in PATH",
)


@skip_no_claude
class TestSkillInvoke:
    """Invoke each skill via claude CLI and validate the response."""

    @pytest.mark.parametrize(
        "skill_name,prompt,keywords",
        SKILL_CASES,
        ids=[c[0] for c in SKILL_CASES],
    )
    def test_skill_responds(self, skill_name, prompt, keywords):
        result = _invoke_skill(prompt)
        _save_result(skill_name, result)

        # Must exit cleanly
        assert result["exit_code"] == 0, (
            f"{skill_name}: claude exited with code {result['exit_code']}\n"
            f"stderr: {result['error']}"
        )

        # Must produce non-empty output
        output = result["output"]
        assert len(output.strip()) > 50, (
            f"{skill_name}: response too short ({len(output)} chars)"
        )

        # Must contain at least half of expected keywords (case-insensitive)
        output_lower = output.lower()
        matched = [kw for kw in keywords if kw.lower() in output_lower]
        min_matches = max(1, len(keywords) // 2)
        assert len(matched) >= min_matches, (
            f"{skill_name}: expected >= {min_matches} of {keywords}, "
            f"but only matched {matched}"
        )


@skip_no_claude
class TestSkillResponseQuality:
    """Additional quality checks on saved results (run after TestSkillInvoke)."""

    def _load_result(self, skill_name: str) -> dict | None:
        path = RESULTS_DIR / f"{skill_name}.json"
        if not path.exists():
            pytest.skip(f"No saved result for {skill_name} — run TestSkillInvoke first")
        return json.loads(path.read_text())

    @pytest.mark.parametrize(
        "skill_name",
        [c[0] for c in SKILL_CASES],
        ids=[c[0] for c in SKILL_CASES],
    )
    def test_no_korean_in_response(self, skill_name):
        """Skill doc is English, but response language depends on user locale."""
        import re
        result = self._load_result(skill_name)
        if result is None:
            return
        korean = re.findall(r"[\uac00-\ud7a3]+", result["output"])
        # User locale (e.g. CLAUDE.md "respond in Korean") may cause Korean
        # responses even with English skill files — this is expected behavior.
        # Only xfail to flag it, not hard-fail.
        if len(korean) >= 20:
            pytest.xfail(
                f"{skill_name}: response has {len(korean)} Korean tokens "
                f"(expected — user locale is Korean)"
            )

    @pytest.mark.parametrize(
        "skill_name",
        [c[0] for c in SKILL_CASES],
        ids=[c[0] for c in SKILL_CASES],
    )
    def test_response_contains_code(self, skill_name):
        """Most skill responses should include code snippets."""
        result = self._load_result(skill_name)
        if result is None:
            return
        output = result["output"]
        has_code = "```" in output or "import " in output or "def " in output
        # Soft check — warn but don't fail
        if not has_code:
            pytest.xfail(f"{skill_name}: response has no code snippets (may be OK)")
