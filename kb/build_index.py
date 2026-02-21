#!/usr/bin/env python3
"""
Build a FAISS vector index from the project's docs and source code.

Run once, then re-run whenever docs or code change:
    python kb/build_index.py

Outputs (written to kb/):
    index.faiss   — FAISS flat inner-product index (cosine similarity)
    chunks.json   — chunk metadata + text (source file, heading, type)

Embedding model: sentence-transformers/all-MiniLM-L6-v2 (local, no API key needed)
Embedding dim:   384
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT    = Path(__file__).resolve().parent.parent
KB_DIR  = Path(__file__).resolve().parent
INDEX_PATH  = KB_DIR / "index.faiss"
CHUNKS_PATH = KB_DIR / "chunks.json"

EMBED_MODEL = "all-MiniLM-L6-v2"
EMBED_DIM   = 384

# ── What to index ─────────────────────────────────────────────────────────────

DOC_GLOBS = [
    "README.md",
    "doc/*.md",
]

CODE_GLOBS = [
    "config.py",
    "main.py",
    "agent/**/*.py",
    "acme/**/*.py",
    "llm/**/*.py",
    "storage/**/*.py",
]

# Directories to skip when globbing Python files
CODE_EXCLUDES = {"__pycache__", "tests", ".venv"}


# ── Markdown chunking ─────────────────────────────────────────────────────────

def chunk_markdown(path: Path, root: Path = ROOT) -> list[dict[str, Any]]:
    """Split a markdown file into chunks at every level-2 heading (##)."""
    text = path.read_text(encoding="utf-8")
    # Split on ## headings; keep each heading with its content
    parts = re.split(r"(?m)^(?=## )", text)
    chunks: list[dict[str, Any]] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        first_line = part.splitlines()[0]
        heading = first_line.lstrip("#").strip() if first_line.startswith("#") else path.stem
        chunks.append({
            "source":  str(path.relative_to(root)),
            "heading": heading,
            "type":    "docs",
            "text":    part,
        })
    return chunks


# ── Python chunking ───────────────────────────────────────────────────────────

def _node_text(lines: list[str], node: ast.AST) -> str:
    return "\n".join(lines[node.lineno - 1 : node.end_lineno])  # type: ignore[attr-defined]


def chunk_python(path: Path, root: Path = ROOT) -> list[dict[str, Any]]:
    """
    Split a Python file into semantically coherent chunks:
      - Module docstring  (if present)
      - Top-level functions  (one chunk each)
      - Classes  (class header + docstring as overview, then each method separately)
    """
    source = path.read_text(encoding="utf-8")
    rel    = str(path.relative_to(root))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines: list[str] = source.splitlines()
    chunks: list[dict[str, Any]] = []

    # Module docstring
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        doc = tree.body[0].value.value.strip()
        if doc:
            chunks.append({
                "source":  rel,
                "heading": f"module:{path.stem}",
                "type":    "code",
                "text":    f"# {rel}\n{doc}",
            })

    for node in ast.iter_child_nodes(tree):
        # Top-level functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            chunks.append({
                "source":     rel,
                "heading":    f"def:{node.name}",
                "type":       "code",
                "line_start": node.lineno,
                "line_end":   node.end_lineno,
                "text":       f"# {rel}:{node.lineno}\n{_node_text(lines, node)}",
            })

        # Classes — overview chunk + per-method chunks
        elif isinstance(node, ast.ClassDef):
            # Class overview: signature + class-level docstring only
            method_lines = [
                child.lineno
                for child in ast.iter_child_nodes(node)
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            overview_end = (min(method_lines) - 1) if method_lines else node.end_lineno
            # Include a few lines of context even if first method starts immediately
            overview_text = "\n".join(lines[node.lineno - 1 : max(overview_end, node.lineno + 5)])
            chunks.append({
                "source":     rel,
                "heading":    f"class:{node.name}",
                "type":       "code",
                "line_start": node.lineno,
                "line_end":   overview_end,
                "text":       f"# {rel}:{node.lineno}\n{overview_text}",
            })

            # Each method as its own chunk
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    chunks.append({
                        "source":     rel,
                        "heading":    f"method:{node.name}.{child.name}",
                        "type":       "code",
                        "line_start": child.lineno,
                        "line_end":   child.end_lineno,
                        "text":       f"# {rel}:{child.lineno} — {node.name}.{child.name}\n{_node_text(lines, child)}",
                    })

    return chunks


# ── Collect all chunks ────────────────────────────────────────────────────────

def collect_chunks() -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []

    print("  [docs]")
    for pattern in DOC_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            c = chunk_markdown(path)
            chunks.extend(c)
            print(f"    {path.relative_to(ROOT)}  →  {len(c)} chunks")

    print("  [code]")
    for pattern in CODE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            if any(ex in path.parts for ex in CODE_EXCLUDES):
                continue
            if path.suffix != ".py":
                continue
            c = chunk_python(path)
            if c:
                chunks.extend(c)
                print(f"    {path.relative_to(ROOT)}  →  {len(c)} chunks")

    return chunks


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with:  pip install -r kb/requirements.txt")
        sys.exit(1)

    print("\n── Collecting chunks ─────────────────────────────────────────────────")
    chunks = collect_chunks()
    print(f"\n  Total: {len(chunks)} chunks")

    texts = [c["text"] for c in chunks]

    print(f"\n── Loading embedding model ({EMBED_MODEL}) ──────────────────────────")
    print("  (first run downloads ~90 MB and caches locally)")
    model = SentenceTransformer(EMBED_MODEL)

    print("\n── Embedding all chunks ─────────────────────────────────────────────")
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=True,
        normalize_embeddings=True,   # cosine similarity via inner product
        convert_to_numpy=True,
    )
    matrix = embeddings.astype("float32")
    print(f"  Matrix shape: {matrix.shape}")

    print("\n── Building FAISS index (IndexFlatIP) ───────────────────────────────")
    index = faiss.IndexFlatIP(EMBED_DIM)
    index.add(matrix)
    faiss.write_index(index, str(INDEX_PATH))
    print(f"  Saved → {INDEX_PATH.relative_to(ROOT)}")

    with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2, ensure_ascii=False)
    print(f"  Saved → {CHUNKS_PATH.relative_to(ROOT)}  ({len(chunks)} chunks)")

    print("\n✓  Knowledge base ready.")
    print('   Query with:  python kb/query.py "<your question>"')


if __name__ == "__main__":
    main()
