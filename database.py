"""SQLiteの接続と初期化。旧版のDBには接続しません。"""
import sqlite3
from pathlib import Path

from flask import current_app, g


# 1回のリクエストの間は、同じ接続を使います。
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


# レスポンスを返したら接続を閉じます。
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# テーブルだけを作り、サンプルデータは登録しません。
def init_db():
    Path(current_app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    db = get_db()
    db.executescript(schema_path.read_text(encoding="utf-8"))
    # 更新前のv2にも退会状態の列を追加し、既存ユーザー・試合を残します。
    with db:
        db.execute("BEGIN IMMEDIATE")
        columns = [row["name"] for row in db.execute("PRAGMA table_info(users)")]
        if "is_active" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))")
