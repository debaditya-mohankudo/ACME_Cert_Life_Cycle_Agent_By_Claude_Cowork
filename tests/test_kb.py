"""
Tests for the kb/ knowledge-base package.

Unit tests (1-4): pure Python — no heavy deps required.
Integration test (5): requires faiss-cpu + sentence-transformers.
                      Automatically skipped if those packages are absent.

Run:
    pytest tests/test_kb.py -v
    pytest tests/test_kb.py -v -k test_search   # integration only
"""
from __future__ import annotations

from pathlib import Path

import pytest

# Add project root to path so kb.build_index is importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kb.build_index import chunk_markdown, chunk_python


# ── Test 1 ────────────────────────────────────────────────────────────────────

def test_markdown_splits_into_sections(tmp_path: Path) -> None:
    """chunk_markdown splits a file on ## headings; each section is one chunk."""
    md = tmp_path / "sample.md"
    md.write_text(
        "# Top-level Title\n\nIntroduction text.\n\n"
        "## Section Alpha\n\nContent A.\n\n"
        "## Section Beta\n\nContent B.\n"
    )
    chunks = chunk_markdown(md, root=tmp_path)

    assert len(chunks) == 3, f"Expected 3 chunks, got {len(chunks)}"
    headings = [c["heading"] for c in chunks]
    assert "Section Alpha" in headings
    assert "Section Beta" in headings
    assert all(c["type"] == "docs" for c in chunks)


# ── Test 2 ────────────────────────────────────────────────────────────────────

def test_markdown_chunk_contains_full_text(tmp_path: Path) -> None:
    """Each markdown chunk carries the heading and all body text for that section."""
    md = tmp_path / "doc.md"
    md.write_text(
        "## Network Exposure\n\n"
        "Only port 80 is exposed, transiently.\n"
        "All other traffic is outbound-only.\n"
    )
    chunks = chunk_markdown(md, root=tmp_path)

    assert len(chunks) == 1
    chunk = chunks[0]
    assert chunk["heading"] == "Network Exposure"
    assert "port 80" in chunk["text"]
    assert "outbound-only" in chunk["text"]
    assert chunk["source"].endswith("doc.md")


# ── Test 3 ────────────────────────────────────────────────────────────────────

def test_python_extracts_top_level_functions(tmp_path: Path) -> None:
    """chunk_python produces one chunk per top-level function definition."""
    py = tmp_path / "funcs.py"
    py.write_text(
        'def generate_key(size: int = 2048):\n'
        '    """Generate an RSA key."""\n'
        '    return size\n\n'
        'def save_key(path: str) -> None:\n'
        '    pass\n'
    )
    chunks = chunk_python(py, root=tmp_path)

    headings = [c["heading"] for c in chunks]
    assert "def:generate_key" in headings
    assert "def:save_key" in headings
    # Source file reference must be present in chunk text
    assert any("generate_key" in c["text"] for c in chunks)
    assert all(c["type"] == "code" for c in chunks)


# ── Test 4 ────────────────────────────────────────────────────────────────────

def test_python_extracts_class_overview_and_methods(tmp_path: Path) -> None:
    """chunk_python produces a class overview chunk plus a chunk per method."""
    py = tmp_path / "client.py"
    py.write_text(
        'class AcmeClient:\n'
        '    """ACME RFC 8555 client."""\n\n'
        '    def get_nonce(self, directory: dict) -> str:\n'
        '        """Fetch a fresh anti-replay nonce."""\n'
        '        return "abc"\n\n'
        '    def create_order(self, domains: list) -> dict:\n'
        '        return {}\n'
    )
    chunks = chunk_python(py, root=tmp_path)

    headings = [c["heading"] for c in chunks]
    assert "class:AcmeClient" in headings,          f"Missing class overview chunk; got {headings}"
    assert "method:AcmeClient.get_nonce" in headings,    f"Missing get_nonce; got {headings}"
    assert "method:AcmeClient.create_order" in headings, f"Missing create_order; got {headings}"
    # Line numbers must be recorded for method chunks
    method_chunks = [c for c in chunks if "method:" in c["heading"]]
    assert all("line_start" in c for c in method_chunks)


# ── Test 5 ────────────────────────────────────────────────────────────────────

def test_search_returns_semantically_relevant_result() -> None:
    """
    Build a tiny in-memory FAISS index from 5 known sentences and verify that
    a natural-language query retrieves the semantically closest sentence.

    Skipped automatically if faiss-cpu or sentence-transformers are not installed.
    """
    faiss = pytest.importorskip("faiss")
    np    = pytest.importorskip("numpy")
    st    = pytest.importorskip("sentence_transformers")

    from sentence_transformers import SentenceTransformer

    corpus = [
        # index 0
        "The ACME account private key is stored on disk and never placed in AgentState.",
        # index 1
        "Docker exposes only port 80 for the HTTP-01 challenge, transiently during renewal.",
        # index 2
        "The planner node validates LLM output against managed_domains to strip hallucinated domains.",
        # index 3
        "Nonces are fetched before every ACME POST request to prevent replay attacks.",
        # index 4
        "Private key files are written with chmod 0o600 so only the owner can read them.",
    ]

    model      = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = model.encode(
        corpus, normalize_embeddings=True, convert_to_numpy=True
    ).astype("float32")

    index = faiss.IndexFlatIP(384)
    index.add(embeddings)

    queries_expected = [
        ("where is the account key kept?",            0),
        ("what port does the container open?",         1),
        ("how does the planner prevent hallucination?",2),
        ("anti-replay nonce mechanism",                3),
        ("file permissions on the private key",        4),
    ]

    for question, expected_idx in queries_expected:
        vec = model.encode(
            [question], normalize_embeddings=True, convert_to_numpy=True
        ).astype("float32")
        _, indices = index.search(vec, 1)
        top = int(indices[0][0])
        assert top == expected_idx, (
            f"Query {question!r}: expected corpus[{expected_idx}], "
            f"got corpus[{top}] = {corpus[top]!r}"
        )
