"""Index merged PR descriptions + doc/ markdown into ChromaDB.

Uses sentence-transformers (all-MiniLM-L6-v2) — no API key needed.

Usage:
    python tools/rag_indexer.py                  # index PRs + doc/
    python tools/rag_indexer.py --docs-only      # skip GitHub API
    python tools/rag_indexer.py --pr-limit 100
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

COLLECTION_NAME = "acme_team"
INDEX_DIR = Path(__file__).parent.parent / "rag_index"
DOC_DIR = Path(__file__).parent.parent / "doc"
EMBED_MODEL = "all-MiniLM-L6-v2"
CHUNK_SIZE = 400  # words per chunk


def _chunk_text(text: str, source: str, title: str = "") -> list[dict]:
    words = text.split()
    chunks = []
    for i in range(0, len(words), CHUNK_SIZE):
        chunk = " ".join(words[i : i + CHUNK_SIZE])
        if len(chunk.strip()) < 20:
            continue
        chunks.append({
            "text": chunk,
            "source": source,
            "title": title,
            "chunk_index": i // CHUNK_SIZE,
        })
    return chunks


def _fetch_merged_prs(limit: int) -> list[dict]:
    try:
        result = subprocess.run(
            ["gh", "pr", "list", "--state", "merged", "--limit", str(limit),
             "--json", "number,title,body,mergedAt,author"],
            capture_output=True, text=True, check=True,
            cwd=Path(__file__).parent.parent,
        )
        prs = json.loads(result.stdout)
    except Exception as e:
        print(f"  warning: could not fetch PRs via gh CLI ({e})")
        return []

    chunks = []
    for pr in prs:
        body = (pr.get("body") or "").strip()
        if not body:
            continue
        text = f"{pr['title']}\n\n{body}"
        source = f"pr#{pr['number']}"
        title = pr["title"]
        chunks.extend(_chunk_text(text, source, title))
    return chunks


def _fetch_docs() -> list[dict]:
    chunks = []
    for md_file in sorted(DOC_DIR.rglob("*.md")):
        text = md_file.read_text(errors="replace")
        # strip frontmatter
        text = re.sub(r"^---.*?---\n", "", text, flags=re.DOTALL)
        rel = str(md_file.relative_to(Path(__file__).parent.parent))
        chunks.extend(_chunk_text(text, rel, md_file.stem))
    return chunks


def build_index(pr_limit: int = 50, docs_only: bool = False):
    INDEX_DIR.mkdir(exist_ok=True)
    client = chromadb.PersistentClient(path=str(INDEX_DIR))

    # delete and recreate for a clean rebuild
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass
    collection = client.create_collection(COLLECTION_NAME)

    model = SentenceTransformer(EMBED_MODEL)

    all_chunks: list[dict] = []
    if not docs_only:
        print("Fetching merged PRs...")
        pr_chunks = _fetch_merged_prs(pr_limit)
        print(f"  {len(pr_chunks)} chunks from PRs")
        all_chunks.extend(pr_chunks)

    print("Indexing doc/ markdown...")
    doc_chunks = _fetch_docs()
    print(f"  {len(doc_chunks)} chunks from docs")
    all_chunks.extend(doc_chunks)

    if not all_chunks:
        print("Nothing to index.")
        return

    print(f"Embedding {len(all_chunks)} chunks...")
    texts = [c["text"] for c in all_chunks]
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_list=True)

    ids = [f"{c['source']}__chunk{c['chunk_index']}" for c in all_chunks]
    metadatas = [{"source": c["source"], "title": c["title"]} for c in all_chunks]

    # upsert in batches of 500
    batch = 500
    for i in range(0, len(all_chunks), batch):
        collection.add(
            ids=ids[i:i+batch],
            embeddings=embeddings[i:i+batch],
            documents=texts[i:i+batch],
            metadatas=metadatas[i:i+batch],
        )

    print(f"✓ Indexed {len(all_chunks)} chunks → {INDEX_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-limit", type=int, default=50)
    parser.add_argument("--docs-only", action="store_true")
    args = parser.parse_args()
    build_index(pr_limit=args.pr_limit, docs_only=args.docs_only)
