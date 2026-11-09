"""SougeiShare-v2：画面、入力チェック、認証、担当操作と集計。"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import close_db, get_db, init_db

BASE_DIR = Path(__file__).resolve().parent


# Windowsでも追加ライブラリなしで、日本の日付を使用します。
def today_in_japan():
    return datetime.now(timezone(timedelta(hours=9))).date().isoformat()


# 固定の秘密値をコードに書かず、ローカルでは専用ファイルへ保存します。
def load_secret(instance_path, production):
    value = os.environ.get("SOUGEISHARE_SECRET_KEY")
    if value:
        if len(value) < 32:
            raise RuntimeError("SOUGEISHARE_SECRET_KEYは32文字以上にしてください。")
        return value
    if production:
        raise RuntimeError("公開モードではSOUGEISHARE_SECRET_KEYの設定が必要です。")
    path = Path(instance_path) / "secret_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as file:
            file.write(secrets.token_hex(32))
        path.chmod(0o600)
    except FileExistsError:
        pass
    return path.read_text(encoding="utf-8").strip()


# テストでも別のDBを指定できるように、アプリ作成を関数にします。
def create_app(test_config=None):
    app = Flask(__name__, instance_path=str(BASE_DIR / "instance"))
    production = os.environ.get("SOUGEISHARE_PRODUCTION") == "1"
    app.config.update(
        DATABASE=str(Path(app.instance_path) / "sougeishare_v2.db"),
        SECRET_KEY=None,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        app.config["SECRET_KEY"] = load_secret(app.instance_path, production)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    # 不明なIDでもハッシュ照合し、応答時間の違いを減らします。
    dummy_hash = generate_password_hash(secrets.token_hex(16))

    # 全フォームに共通のCSRFトークンを渡します。
    @app.context_processor
    def template_values():
        return {"csrf_token": session.get("csrf_token"), "login_user": g.user}

    # POSTの保護と、ログイン本人・所属の取得を共通化します。
    @app.before_request
    def prepare_request():
        g.user = None
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not re.fullmatch(r"[0-9a-f]{64}", token):
                abort(400, description="送信を確認できません。画面を開き直してください。")
            if not hmac.compare_digest(token, session["csrf_token"]):
                abort(400, description="画面の有効期限が切れました。開き直してください。")
        if "user_id" in session:
            g.user = get_db().execute("""
                SELECT u.id, u.user_id, u.name, u.group_id,
                       gr.name AS group_name, gr.code AS group_code
                FROM users u JOIN groups gr ON u.group_id = gr.id
                WHERE u.id = ? AND u.is_active = 1
            """, (session["user_id"],)).fetchone()
            if g.user is None:
                session.clear()
                session["csrf_token"] = secrets.token_hex(32)

    # 個人・グループ情報をブラウザのキャッシュに残しにくくします。
    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    # 画面に安全なエラーメッセージを表示します。
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def show_error(error):
        messages = {
            403: "この操作はできません。", 404: "画面または試合が見つかりません。",
            405: "この操作方法は利用できません。", 413: "送信内容が大きすぎます。",
            429: "連続した操作が多いため、10分ほど待ってからお試しください。",
        }
        message = messages.get(error.code, error.description)
        return render_template("error.html", message=message), error.code

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", message="処理できませんでした。時間をおいてお試しください。"), 500

    # ログイン必須の画面・操作を保護します。
    def login_required(view):
        @wraps(view)
        def wrapped(**kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(**kwargs)
        return wrapped

    # 10分の試行回数をDBで管理し、アプリ再起動によるリセットを防ぎます。
    def limit_attempts(action, limit, identifier=None):
        source = request.remote_addr or "unknown"
        key = f"{action}:{identifier if identifier is not None else source}"
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        now = int(time.time())
        db = get_db()
        with db:
            db.execute("DELETE FROM auth_attempts WHERE started_at <= ?", (now - 600,))
            db.execute("""
                INSERT INTO auth_attempts (key_hash, started_at, attempt_count)
                VALUES (?, ?, 1)
                ON CONFLICT(key_hash) DO UPDATE SET attempt_count = attempt_count + 1
            """, (key_hash, now))
            count = db.execute("SELECT attempt_count FROM auth_attempts WHERE key_hash = ?",
                               (key_hash,)).fetchone()[0]
        if count > limit:
            abort(429)

    # ログイン成功時はセッションとCSRFトークンを作り直します。
    def start_session(user_id):
        session.clear()
        session["user_id"] = user_id
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

    # 登録2画面に共通する入力を確認します。
    def account_values():
        values = {
            "name": request.form.get("name", "").strip(),
            "user_id": request.form.get("user_id", "").strip(),
            "password": request.form.get("password", ""),
        }
        error = None
        if not 1 <= len(values["name"]) <= 20:
            error = "表示名は1～20文字で入力してください。"
        elif not re.fullmatch(r"[A-Za-z0-9_-]{3,30}", values["user_id"]):
            error = "ユーザーIDは半角英数字・_・-の3～30文字で入力してください。"
        elif not 8 <= len(values["password"]) <= 128:
            error = "パスワードは8～128文字で入力してください。"
        return values, error

    @app.route("/")
    def index():
        return redirect(url_for("matches" if g.user else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("matches"))
        if request.method == "POST":
            limit_attempts("login-ip", 60)
            user_id = request.form.get("user_id", "").strip()
            limit_attempts("login-id", 20, user_id)
            password = request.form.get("password", "")
            user = get_db().execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            stored_hash = user["password_hash"] if user else dummy_hash
            valid_password = check_password_hash(stored_hash, password[:129])
            if user and user["is_active"] and 8 <= len(password) <= 128 and valid_password:
                start_session(user["id"])
                return redirect(url_for("matches"))
            return render_template("login.html", error="ユーザーIDまたはパスワードが違います。")
        return render_template("login.html")

    @app.route("/groups/create", methods=["GET", "POST"])
    def group_create():
        if g.user:
            return redirect(url_for("matches"))
        error = None
        if request.method == "POST":
            limit_attempts("create-ip", 10)
            values, error = account_values()
            group_name = request.form.get("group_name", "").strip()
            if not 1 <= len(group_name) <= 30:
                error = "グループ名は1～30文字で入力してください。"
            if not error:
                db = get_db()
                password_hash = generate_password_hash(values["password"])
                try:
                    # 書き込みを一まとまりにし、同時登録でもコード重複を防ぎます。
                    db.execute("BEGIN IMMEDIATE")
                    while True:
                        code = f"{secrets.randbelow(1_000_000):06d}"
                        if not db.execute("SELECT 1 FROM groups WHERE code = ?", (code,)).fetchone():
                            break
                    group_id = db.execute("INSERT INTO groups (name, code) VALUES (?, ?)",
                                          (group_name, code)).lastrowid
                    user_id = db.execute("""
                        INSERT INTO users (user_id, name, password_hash, group_id)
                        VALUES (?, ?, ?, ?)
                    """, (values["user_id"], values["name"], password_hash, group_id)).lastrowid
                    db.commit()
                except sqlite3.IntegrityError:
                    db.rollback()
                    error = "そのユーザーIDは使用されています。別のIDを入力してください。"
                else:
                    start_session(user_id)
                    flash("グループを作成しました。コードをメンバーに伝えてください。", "success")
                    return redirect(url_for("matches"))
        return render_template("group_create.html", error=error)

    @app.route("/groups/join", methods=["GET", "POST"])
    def group_join():
        if g.user:
            return redirect(url_for("matches"))
        error = None
        if request.method == "POST":
            limit_attempts("join-ip", 20)
            values, error = account_values()
            code = request.form.get("group_code", "").strip()
            if not re.fullmatch(r"[0-9]{6}", code):
                error = "グループコードは半角数字6桁で入力してください。"
            if not error:
                db = get_db()
                group = db.execute("SELECT id FROM groups WHERE code = ?", (code,)).fetchone()
                if not group:
                    error = "グループコードを確認してください。"
                else:
                    try:
                        with db:
                            user_id = db.execute("""
                                INSERT INTO users (user_id, name, password_hash, group_id)
                                VALUES (?, ?, ?, ?)
                            """, (values["user_id"], values["name"],
                                  generate_password_hash(values["password"]), group["id"])).lastrowid
                    except sqlite3.IntegrityError:
                        error = "そのユーザーIDは使用されています。別のIDを入力してください。"
                    else:
                        start_session(user_id)
                        flash("グループに参加しました。", "success")
                        return redirect(url_for("matches"))
        return render_template("group_join.html", error=error)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("ログアウトしました。", "success")
        return redirect(url_for("login"))

    # 退会と削除では、保存処理直前にもログイン本人の状態を確認します。
    def confirmed_user(db):
        user = db.execute("SELECT * FROM users WHERE id = ? AND group_id = ? AND is_active = 1",
                          (g.user["id"], g.user["group_id"])).fetchone()
        if not user:
            db.rollback()
            abort(403)
        password = request.form.get("password", "")
        if not 8 <= len(password) <= 128 or not check_password_hash(user["password_hash"], password):
            return None
        return user

    @app.route("/account/withdraw", methods=["GET", "POST"])
    @login_required
    def account_withdraw():
        error = None
        db = get_db()
        if request.method == "POST":
            limit_attempts("withdraw", 10, str(g.user["id"]))
            if request.form.get("confirmed") != "yes":
                error = "退会内容を確認し、チェックを入れてください。"
            else:
                db.execute("BEGIN IMMEDIATE")
                user = confirmed_user(db)
                if user is None:
                    db.rollback()
                    error = "パスワードが違います。"
                else:
                    # 過去の担当は残し、今日以降だけ解除します。更新番号も進めます。
                    today = today_in_japan()
                    with db:
                        for direction in ("going", "returning"):
                            db.execute(f"""
                                UPDATE matches SET {direction}_status = 'PENDING',
                                    {direction}_user_id = NULL,
                                    {direction}_version = {direction}_version + 1
                                WHERE group_id = ? AND match_date >= ?
                                    AND {direction}_status = 'ASSIGNED' AND {direction}_user_id = ?
                            """, (user["group_id"], today, user["id"]))
                        db.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user["id"],))
                    session.clear()
                    flash("退会しました。過去の担当実績はグループに残ります。", "success")
                    return redirect(url_for("login"))
        active_count = db.execute("SELECT COUNT(*) FROM users WHERE group_id = ? AND is_active = 1",
                                  (g.user["group_id"],)).fetchone()[0]
        return render_template("account_withdraw.html", error=error, last_member=active_count == 1)

    @app.route("/groups/delete", methods=["GET", "POST"])
    @login_required
    def group_delete():
        error = None
        if request.method == "POST":
            limit_attempts("group-delete", 10, str(g.user["id"]))
            code = request.form.get("group_code", "").strip()
            if request.form.get("confirmed") != "yes":
                error = "削除内容を確認し、チェックを入れてください。"
            elif not re.fullmatch(r"[0-9]{6}", code):
                error = "グループコードは半角の数字6桁で入力してください。"
            else:
                db = get_db()
                db.execute("BEGIN IMMEDIATE")
                user = confirmed_user(db)
                group = db.execute("SELECT code FROM groups WHERE id = ?", (g.user["group_id"],)).fetchone()
                if user is None or group is None or not hmac.compare_digest(code, group["code"]):
                    db.rollback()
                    error = "パスワードまたはグループコードが違います。"
                else:
                    # 外部キーの参照元から順番に、同じグループだけを削除します。
                    with db:
                        group_id = user["group_id"]
                        db.execute("DELETE FROM matches WHERE group_id = ?", (group_id,))
                        db.execute("DELETE FROM users WHERE group_id = ?", (group_id,))
                        db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
                    session.clear()
                    flash("グループと全メンバーのアカウント・試合・担当履歴を削除しました。", "success")
                    return redirect(url_for("login"))
        return render_template("group_delete.html", error=error)

    @app.route("/matches")
    @login_required
    def matches():
        # 指定がなければ「今後の試合」を表示する
        view = request.args.get("view", "upcoming")

        # 「過去」以外の指定は「今後」として扱う
        if view != "past":
            view = "upcoming"

        # 退会処理と同じく、日本時間の今日を使う
        today = today_in_japan()

        if view == "past":
            # 昨日以前の試合を、新しい日付から取得する
            rows = get_db().execute("""
                SELECT m.*, gu.name AS going_user_name,
                       ru.name AS returning_user_name
                FROM matches m
                LEFT JOIN users gu
                    ON m.going_user_id = gu.id
                    AND m.group_id = gu.group_id
                LEFT JOIN users ru
                    ON m.returning_user_id = ru.id
                    AND m.group_id = ru.group_id
                WHERE m.group_id = ? AND m.match_date < ?
                ORDER BY m.match_date DESC, m.id DESC
            """, (g.user["group_id"], today)).fetchall()
        else:
            # 今日以降の試合を、近い日付から取得する
            rows = get_db().execute("""
                SELECT m.*, gu.name AS going_user_name,
                       ru.name AS returning_user_name
                FROM matches m
                LEFT JOIN users gu
                    ON m.going_user_id = gu.id
                    AND m.group_id = gu.group_id
                LEFT JOIN users ru
                    ON m.returning_user_id = ru.id
                    AND m.group_id = ru.group_id
                WHERE m.group_id = ? AND m.match_date >= ?
                ORDER BY m.match_date, m.id
            """, (g.user["group_id"], today)).fetchall()

        # 各試合の日付から曜日を求める
        match_list = []
        for row in rows:
            item = dict(row)
            item["day"] = "月火水木金土日"[
                date.fromisoformat(row["match_date"]).weekday()
            ]
            match_list.append(item)

        # 試合一覧と、選択中の表示区分をHTMLに渡す
        return render_template(
            "match_list.html",
            match_list=match_list,
            view=view
        )

    @app.route("/matches/register", methods=["GET", "POST"])
    @login_required
    def match_register():
        error = None
        if request.method == "POST":
            match_date = request.form.get("match_date", "").strip()
            venue = request.form.get("venue", "").strip()
            distance_text = request.form.get("distance_km", "").strip()
            try:
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", match_date):
                    raise ValueError
                parsed_date = date.fromisoformat(match_date)
                if not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9])?", distance_text):
                    raise ValueError
                distance = Decimal(distance_text)
                if not 0 <= distance <= Decimal("999.9") or not 1 <= len(venue) <= 50:
                    raise ValueError
            except ValueError:
                error = "正しい日付、会場名1～50文字、距離0～999.9km（小数第1位まで）を入力してください。"
            else:
                db = get_db()
                with db:
                    result = db.execute("""
                        INSERT INTO matches (group_id, match_date, venue, distance_km)
                        SELECT ?, ?, ?, ?
                        WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND is_active = 1)
                    """, (g.user["group_id"], parsed_date.isoformat(), venue, float(distance), g.user["id"]))
                    if result.rowcount != 1:
                        abort(403)
                flash("試合を登録しました。", "success")
                return redirect(url_for("matches"))
        return render_template("match_register.html", error=error)

    @app.route("/matches/update", methods=["POST"])
    @login_required
    def match_update():
        match_id = request.form.get("match_id", type=int)
        direction = request.form.get("direction", "")
        action = request.form.get("action", "")
        version = request.form.get("version", type=int)
        if (match_id is None or not 1 <= match_id <= 2**63 - 1
                or direction not in ("going", "returning")
                or action not in ("assign", "outside", "cancel")
                or version is None or version < 0 or version > 2**63 - 2):
            abort(400, description="操作内容を確認できません。")
        db = get_db()
        match = db.execute("SELECT * FROM matches WHERE id = ? AND group_id = ?",
                           (match_id, g.user["group_id"])).fetchone()
        if not match:
            abort(404)
        # 列名は検証済みの2方向からのみ作り、入力値をSQLへ直接入れません。
        status_column = direction + "_status"
        user_column = direction + "_user_id"
        version_column = direction + "_version"
        current_status = match[status_column]
        if action == "assign":
            status, user_id, expected_status = "ASSIGNED", g.user["id"], "PENDING"
        elif action == "outside":
            status, user_id, expected_status = "OUTSIDE", None, "PENDING"
        else:
            status, user_id, expected_status = "PENDING", None, current_status
        if action == "cancel" and current_status == "PENDING":
            flash("既に募集中です。最新の状態をご確認ください。", "info")
            return redirect(url_for("matches"))
        with db:
            result = db.execute(f"""
                UPDATE matches SET {status_column} = ?, {user_column} = ?,
                    {version_column} = {version_column} + 1
                WHERE id = ? AND group_id = ? AND {status_column} = ? AND {version_column} = ?
                    AND EXISTS (SELECT 1 FROM users WHERE id = ? AND is_active = 1)
            """, (status, user_id, match_id, g.user["group_id"], expected_status, version, g.user["id"]))
        if result.rowcount == 1:
            flash("担当状況を更新しました。", "success")
        else:
            flash("担当状況が変わっています。最新の状態をご確認ください。", "info")
        return redirect(url_for("matches"))

    @app.route("/matches/delete", methods=["POST"])
    @login_required
    def match_delete():
        match_id = request.form.get("match_id", type=int)
        if match_id is None or not 1 <= match_id <= 2**63 - 1:
            abort(400, description="試合を確認できません。")
        db = get_db()
        with db:
            result = db.execute("""
                DELETE FROM matches WHERE id = ? AND group_id = ?
                AND EXISTS (SELECT 1 FROM users WHERE id = ? AND is_active = 1)
            """, (match_id, g.user["group_id"], g.user["id"]))
        if result.rowcount != 1:
            abort(404)
        flash("試合を削除しました。担当履歴も更新されました。", "success")
        return redirect(url_for("matches"))

    @app.route("/history")
    @login_required
    def history():
        # 行き・帰りをまとめて集計。担当0回のメンバーもLEFT JOINで残します。
        rows = get_db().execute("""
            WITH assignments AS (
                SELECT going_user_id AS user_id, 'going' AS direction, distance_km
                FROM matches WHERE group_id = ? AND going_status = 'ASSIGNED'
                UNION ALL
                SELECT returning_user_id, 'returning', distance_km
                FROM matches WHERE group_id = ? AND returning_status = 'ASSIGNED'
            )
            SELECT u.id, u.name, u.is_active,
                SUM(CASE WHEN a.direction = 'going' THEN 1 ELSE 0 END) AS going_count,
                SUM(CASE WHEN a.direction = 'returning' THEN 1 ELSE 0 END) AS returning_count,
                COUNT(a.user_id) AS total_count,
                COALESCE(SUM(a.distance_km), 0) AS total_distance_km
            FROM users u LEFT JOIN assignments a ON u.id = a.user_id
            WHERE u.group_id = ? GROUP BY u.id
            ORDER BY total_count DESC, u.name, u.id
        """, (g.user["group_id"],) * 3).fetchall()
        history_list = [dict(row) for row in rows]
        maximum = max((item["total_distance_km"] for item in history_list), default=0)
        for item in history_list:
            item["bar_width"] = item["total_distance_km"] / maximum * 100 if maximum else 0
        return render_template("history.html", history_list=history_list)

    return app


# 手元での起動は自分のPCだけに限定し、debugは無効にします。
if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
