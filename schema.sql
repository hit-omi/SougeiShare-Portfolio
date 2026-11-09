-- グループコードは、先頭の0を保持するため文字列で保存します。
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 30),
    code TEXT NOT NULL UNIQUE
        CHECK (length(code) = 6 AND code NOT GLOB '*[^0-9]*'),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- idは内部の番号、user_idはログインに入力するIDです。
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE CHECK (length(user_id) BETWEEN 3 AND 30),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 20),
    password_hash TEXT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, group_id)
);

-- 状態・担当者・所属の組み合わせをDBでも保護します。
CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    match_date TEXT NOT NULL,
    venue TEXT NOT NULL CHECK (length(venue) BETWEEN 1 AND 50),
    distance_km REAL NOT NULL CHECK (distance_km BETWEEN 0 AND 999.9),
    going_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (going_status IN ('PENDING', 'ASSIGNED', 'OUTSIDE')),
    going_user_id INTEGER,
    going_version INTEGER NOT NULL DEFAULT 0 CHECK (going_version >= 0),
    returning_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (returning_status IN ('PENDING', 'ASSIGNED', 'OUTSIDE')),
    returning_user_id INTEGER,
    returning_version INTEGER NOT NULL DEFAULT 0 CHECK (returning_version >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (going_user_id, group_id) REFERENCES users(id, group_id),
    FOREIGN KEY (returning_user_id, group_id) REFERENCES users(id, group_id),
    CHECK ((going_status = 'ASSIGNED' AND going_user_id IS NOT NULL)
        OR (going_status IN ('PENDING', 'OUTSIDE') AND going_user_id IS NULL)),
    CHECK ((returning_status = 'ASSIGNED' AND returning_user_id IS NOT NULL)
        OR (returning_status IN ('PENDING', 'OUTSIDE') AND returning_user_id IS NULL))
);
CREATE INDEX IF NOT EXISTS matches_group_date ON matches(group_id, match_date, id);
CREATE INDEX IF NOT EXISTS users_group ON users(group_id);

-- ログインや参加コードの連続試行を抑えるための補助テーブルです。
CREATE TABLE IF NOT EXISTS auth_attempts (
    key_hash TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL
);
