#!/usr/bin/env python3
"""
Query the FAISS knowledge base with a natural language question.

Usage:
    python kb/query.py "how does the challenge server prevent directory traversal?"
    python kb/query.py "where is the account key stored?" --top 3
    python kb/query.py "nonce retry logic" --type code
    python kb/query.py "docker volume" --type docs

Options:
    --top N          Number of results to return (default: 5)
    --type docs|code Filter results by chunk type

Build the index first if it doesn't exist:
    python kb/build_index.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KB_DIR     = Path(__file__).resolve().parent
ROOT       = KB_DIR.parent
INDEX_PATH = KB_DIR / "index.faiss"
CHUNKS_PATH = KB_DIR / "chunks.json"

EMBED_MODEL = "all-MiniLM-L6-v2"


def load_kb():
    if not INDEX_PATH.exists() or not CHUNKS_PATH.exists():
        print("Knowledge base not found. Build it first:")
        print("    python kb/build_index.py")
        sys.exit(1)

    try:
        import faiss
    except ImportError:
        print("Missing dependency. Install with:  pip install -r kb/requirements.txt")
        sys.exit(1)

    index = faiss.read_index(str(INDEX_PATH))
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        chunks = json.load(f)
    return index, chunks


def search(question: str, top_k: int = 5, filter_type: str | None = None) -> list[tuple[float, dict]]:
    try:
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with:  pip install -r kb/requirements.txt")
        sys.exit(1)

    index, chunks = load_kb()

    model = SentenceTransformer(EMBED_MODEL)
    vec = model.encode(
        [question],
        normalize_embeddings=True,
        convert_to_numpy=True,
    ).astype("float32")

    # Over-fetch when filtering so we still return top_k after the filter
    k = min(top_k * 4 if filter_type else top_k, index.ntotal)
    scores, indices = index.search(vec, k)

    results: list[tuple[float, dict]] = []
    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue
        chunk = chunks[idx]
        if filter_type and chunk.get("type") != filter_type:
            continue
        results.append((float(score), chunk))
        if len(results) == top_k:
            break

    return results


def _divider(width: int = 70) -> str:
    return "─" * width


def print_results(question: str, results: list[tuple[float, dict]]) -> None:
    if not results:
        print("No results found.")
        return

    print(f"\n{_divider()}")
    print(f"  Query: {question!r}")
    print(_divider())

    for i, (score, chunk) in enumerate(results, 1):
        source  = chunk["source"]
        heading = chunk["heading"]
        ctype   = chunk["type"]
        line_info = f":{chunk['line_start']}" if "line_start" in chunk else ""

        print(f"\n  #{i}  [{ctype}]  {source}{line_info}")
        print(f"       {heading}  (score: {score:.3f})")
        print(_divider())

        lines   = chunk["text"].splitlines()
        preview = "\n".join(lines[:25])
        if len(lines) > 25:
            preview += f"\n  … ({len(lines) - 25} more lines, open {source}{line_info})"
        print(preview)
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query the ACME agent knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("question", help="Natural language question")
    parser.add_argument(
        "--top", type=int, default=5, metavar="N",
        help="Number of results to return (default: 5)",
    )
    parser.add_argument(
        "--type", choices=["docs", "code"], dest="filter_type",
        help="Filter results by chunk type",
    )
    args = parser.parse_args()

    results = search(args.question, top_k=args.top, filter_type=args.filter_type)
    print_results(args.question, results)


if __name__ == "__main__":
    main()
