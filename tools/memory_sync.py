"""Sync memory/*.md files → team_memory.sqlite."""
import re
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "team_memory.sqlite"
MEMORY_DIR = Path(__file__).parent.parent / "memory"

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL,
    type    TEXT,
    domain  TEXT,
    priority INTEGER DEFAULT 20,
    tags    TEXT,
    body    TEXT,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def _parse_md(path: Path) -> dict | None:
    text = path.read_text()
    fm_match = re.match(r"^---\n(.+?)\n---\n(.*)$", text, re.DOTALL)
    if not fm_match:
        return None

    raw_fm, body = fm_match.group(1), fm_match.group(2).strip()
    meta: dict = {}
    for line in raw_fm.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()

    # pull nested metadata fields
    nested: dict = {}
    in_meta = False
    for line in raw_fm.splitlines():
        if line.strip() == "metadata:":
            in_meta = True
            continue
        if in_meta:
            m = re.match(r"\s+(\w+):\s*(.+)", line)
            if m:
                nested[m.group(1)] = m.group(2).strip()
            else:
                in_meta = False

    return {
        "name": meta.get("name", path.stem),
        "type": nested.get("type", meta.get("type", "project")),
        "domain": nested.get("domain", meta.get("domain", "acme")),
        "priority": int(nested.get("priority", meta.get("priority", 20))),
        "tags": nested.get("tags", meta.get("tags", "")),
        "body": body,
        "updated": datetime.utcnow().isoformat(),
    }


def sync():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)

    synced = 0
    for md_file in sorted(MEMORY_DIR.glob("*.md")):
        record = _parse_md(md_file)
        if not record:
            print(f"  skip (no frontmatter): {md_file.name}")
            continue
        con.execute(
            """INSERT INTO memories (name, type, domain, priority, tags, body, updated)
               VALUES (:name, :type, :domain, :priority, :tags, :body, :updated)
               ON CONFLICT(name) DO UPDATE SET
                 type=excluded.type, domain=excluded.domain,
                 priority=excluded.priority, tags=excluded.tags,
                 body=excluded.body, updated=excluded.updated""",
            record,
        )
        print(f"  synced: {record['name']}")
        synced += 1

    con.commit()
    con.close()
    print(f"\n✓ {synced} memories synced → {DB_PATH}")


if __name__ == "__main__":
    sync()
