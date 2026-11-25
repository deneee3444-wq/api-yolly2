"""
Admin Module - Direct Database Management Panel & API
Access is strictly gated by ADMIN_API_KEY. Any unauthorized request aborts with 404,
falling through api.py's Exception handler so the endpoint behaves identically to non-existent routes.
"""
import contextlib
import hmac
import json
import random
import re
import secrets
import string
from datetime import date, datetime
from flask import abort, jsonify, make_response, render_template, request
from psycopg2.extras import RealDictCursor
import database as db

ADMIN_API_KEY = "a9F3kLmP2xQ7vR8tY1zW4bNc6DeGhJ9KlMnOpQrStUvWxYz12"
ADMIN_COOKIE_NAME = "admin_key"

RANDOM_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
]

TASK_EDITABLE_COLUMNS = [
    "api_key_id",
    "task_id",
    "status",
    "mode",
    "result_url",
    "external_task_id",
    "account_email",
    "prompt",
    "model",
    "size",
    "resolution",
    "duration",
    "reference_image_urls",
    "start_frame_url",
    "end_frame_url",
    "style",
    "lyrics",
    "instrumental",
    "audio_usage",
    "reference_audio_url",
    "voice_id",
    "speed",
    "pitch",
    "volume",
    "emotion",
    "logs",
    "token",
]


def _ph():
    return "%s" if db.DB_TYPE == "postgresql" else "?"


def _db_lock():
    return db.db_lock if db.DB_TYPE != "postgresql" else contextlib.nullcontext()


def _serialize_value(val):
    if isinstance(val, (datetime, date)):
        return val.isoformat(sep=" ", timespec="seconds")
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    return val


def _serialize_row(row):
    if row is None:
        return None
    return {k: _serialize_value(v) for k, v in dict(row).items()}


def _query(sql, params=None, fetch_one=False, fetch_all=False):
    with _db_lock():
        conn = db.get_connection()
        try:
            cursor = (
                conn.cursor(cursor_factory=RealDictCursor)
                if db.DB_TYPE == "postgresql"
                else conn.cursor()
            )
            cursor.execute(sql, params or ())
            if fetch_one:
                return _serialize_row(cursor.fetchone())
            if fetch_all:
                return [_serialize_row(r) for r in cursor.fetchall()]
            conn.commit()
            return cursor.rowcount
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()


def _extract_admin_key():
    auth = request.headers.get("Authorization", "").strip()
    if auth:
        return auth[7:].strip() if auth.startswith("Bearer ") else auth
    cookie_key = request.cookies.get(ADMIN_COOKIE_NAME, "").strip()
    if cookie_key:
        return cookie_key
    return ""


def _is_valid_admin_key(provided_key):
    if not provided_key:
        return False
    return hmac.compare_digest(provided_key, ADMIN_API_KEY)


def is_request_admin_key():
    """Public helper for api.py to check if the current request carries ADMIN_API_KEY."""
    return _is_valid_admin_key(_extract_admin_key())


def set_admin_cookie(response):
    """Attaches the HttpOnly admin_key cookie scoped to /admin."""
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        ADMIN_API_KEY,
        path="/admin",
        httponly=True,
        samesite="Lax",
    )
    return response


def clear_admin_cookie(response):
    """Removes the admin_key cookie if present."""
    if request.cookies.get(ADMIN_COOKIE_NAME):
        response.delete_cookie(ADMIN_COOKIE_NAME, path="/admin")
    return response


def _generate_random_email(domain=None):
    adj_chars = string.ascii_lowercase
    num_chars = string.digits
    prefix = "".join(random.choices(adj_chars, k=random.randint(6, 10)))
    suffix = "".join(random.choices(num_chars, k=random.randint(2, 4)))
    chosen_domain = domain.strip().lstrip("@") if domain and domain.strip() else random.choice(RANDOM_DOMAINS)
    return f"{prefix}{suffix}@{chosen_domain}"


def _generate_random_password(length=12):
    length = max(6, min(64, int(length)))
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    # Guarantee at least one upper, lower, digit
    chars = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
    ]
    chars.extend(random.choices(alphabet, k=max(0, length - 3)))
    random.shuffle(chars)
    return "".join(chars)


# --- Page & Auth Routes ---


def admin_page():
    resp = make_response(render_template("admin.html"))
    return set_admin_cookie(resp)


def admin_logout():
    resp = make_response(jsonify({"message": "Oturum kapatıldı"}))
    resp.delete_cookie(ADMIN_COOKIE_NAME, path="/admin")
    return resp


# --- Overview ---


def admin_overview():
    p = _ph()
    today_start = datetime.now().strftime("%Y-%m-%d 00:00:00")
    key_count = _query("SELECT COUNT(*) AS count FROM api_keys", fetch_one=True)["count"]
    acc_stats = _query(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END), 0) AS unused,
            COALESCE(SUM(CASE WHEN used != 0 THEN 1 ELSE 0 END), 0) AS used
        FROM accounts
        """,
        fetch_one=True,
    )
    acc_today = _query(
        f"SELECT COUNT(*) AS count FROM accounts WHERE created_at >= {p}",
        (today_start,),
        fetch_one=True,
    )["count"]
    task_total = _query("SELECT COUNT(*) AS count FROM tasks", fetch_one=True)["count"]
    task_today = _query(
        f"SELECT COUNT(*) AS count FROM tasks WHERE created_at >= {p}",
        (today_start,),
        fetch_one=True,
    )["count"]
    tasks_by_status = _query(
        "SELECT COALESCE(status, 'unknown') AS status, COUNT(*) AS count FROM tasks GROUP BY status ORDER BY count DESC",
        fetch_all=True,
    )
    tasks_by_mode = _query(
        "SELECT COALESCE(mode, 'unknown') AS mode, COUNT(*) AS count FROM tasks GROUP BY mode ORDER BY count DESC",
        fetch_all=True,
    )
    recent_tasks = _query(
        "SELECT id, task_id, status, mode, model, account_email, created_at FROM tasks ORDER BY created_at DESC, id DESC LIMIT 5",
        fetch_all=True,
    )
    return jsonify({
        "db_type": db.DB_TYPE,
        "api_keys_count": key_count,
        "accounts": acc_stats,
        "accounts_today": acc_today,
        "tasks_total": task_total,
        "tasks_today": task_today,
        "tasks_by_status": tasks_by_status,
        "tasks_by_mode": tasks_by_mode,
        "recent_tasks": recent_tasks,
    })


# --- API Keys CRUD ---


def list_api_keys():
    p = _ph()
    search = (request.args.get("search") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort = request.args.get("sort", "created_desc")

    where = []
    params = []
    if search:
        op = "ILIKE" if db.DB_TYPE == "postgresql" else "LIKE"
        where.append(f"k.key {op} {p}")
        params.append(f"%{search}%")
    if date_from:
        where.append(f"k.created_at >= {p}")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        where.append(f"k.created_at <= {p}")
        params.append(f"{date_to} 23:59:59")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sort_map = {
        "created_desc": "k.created_at DESC, k.id DESC",
        "created_asc": "k.created_at ASC, k.id ASC",
        "id_desc": "k.id DESC",
        "id_asc": "k.id ASC",
        "accounts_desc": "accounts_unused DESC, accounts_total DESC",
        "tasks_desc": "tasks_total DESC, k.id DESC",
    }
    order_sql = sort_map.get(sort, "k.created_at DESC, k.id DESC")

    rows = _query(
        f"""
        SELECT
            k.id,
            k.key,
            k.created_at,
            COALESCE(a.total_accounts, 0) AS accounts_total,
            COALESCE(a.unused_accounts, 0) AS accounts_unused,
            COALESCE(a.used_accounts, 0) AS accounts_used,
            COALESCE(t.total_tasks, 0) AS tasks_total,
            COALESCE(t.running_tasks, 0) AS tasks_running,
            COALESCE(t.completed_tasks, 0) AS tasks_completed,
            COALESCE(t.failed_tasks, 0) AS tasks_failed
        FROM api_keys k
        LEFT JOIN (
            SELECT
                api_key_id,
                COUNT(*) AS total_accounts,
                SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) AS unused_accounts,
                SUM(CASE WHEN used != 0 THEN 1 ELSE 0 END) AS used_accounts
            FROM accounts
            GROUP BY api_key_id
        ) a ON a.api_key_id = k.id
        LEFT JOIN (
            SELECT
                api_key_id,
                COUNT(*) AS total_tasks,
                SUM(CASE WHEN status IN ('running', 'pending') THEN 1 ELSE 0 END) AS running_tasks,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_tasks,
                SUM(CASE WHEN status IN ('failed', 'error', 'timeout') THEN 1 ELSE 0 END) AS failed_tasks
            FROM tasks
            GROUP BY api_key_id
        ) t ON t.api_key_id = k.id
        {where_sql}
        ORDER BY {order_sql}
        """,
        tuple(params),
        fetch_all=True,
    )
    return jsonify({"api_keys": rows})


def create_api_key_admin():
    data = request.get_json(silent=True) or {}
    key_val = (data.get("key") or "").strip()
    if not key_val or data.get("auto_generate"):
        key_val = "sk_" + secrets.token_urlsafe(32)

    p = _ph()
    existing = _query(f"SELECT id FROM api_keys WHERE key = {p}", (key_val,), fetch_one=True)
    if existing:
        return jsonify({"error": "Bu API anahtarı zaten mevcut"}), 409

    with _db_lock():
        conn = db.get_connection()
        try:
            if db.DB_TYPE == "postgresql":
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("INSERT INTO api_keys (key) VALUES (%s) RETURNING id, key, created_at", (key_val,))
                created = _serialize_row(cur.fetchone())
            else:
                cur = conn.cursor()
                cur.execute("INSERT INTO api_keys (key) VALUES (?)", (key_val,))
                new_id = cur.lastrowid
                cur.execute("SELECT id, key, created_at FROM api_keys WHERE id = ?", (new_id,))
                created = _serialize_row(cur.fetchone())
            conn.commit()
            return jsonify({"api_key": created, "message": "API anahtarı oluşturuldu"}), 201
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 400
        finally:
            conn.close()


def update_api_key_admin(key_id):
    data = request.get_json(silent=True) or {}
    new_key = (data.get("key") or "").strip()
    if not new_key:
        return jsonify({"error": "key alanı boş olamaz"}), 400

    p = _ph()
    try:
        updated = _query(f"UPDATE api_keys SET key = {p} WHERE id = {p}", (new_key, key_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    if not updated:
        return jsonify({"error": "API anahtarı bulunamadı"}), 404
    return jsonify({"message": "API anahtarı güncellendi"})


def delete_api_key_admin(key_id):
    p = _ph()
    with _db_lock():
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(f"DELETE FROM tasks WHERE api_key_id = {p}", (key_id,))
            deleted_tasks = cur.rowcount
            cur.execute(f"DELETE FROM accounts WHERE api_key_id = {p}", (key_id,))
            deleted_accounts = cur.rowcount
            cur.execute(f"DELETE FROM api_keys WHERE id = {p}", (key_id,))
            deleted_keys = cur.rowcount
            conn.commit()
            if not deleted_keys:
                return jsonify({"error": "API anahtarı bulunamadı"}), 404
            return jsonify({
                "message": "API anahtarı ve bağlı tüm veriler silindi",
                "deleted_tasks": deleted_tasks,
                "deleted_accounts": deleted_accounts,
            })
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 400
        finally:
            conn.close()


# --- Accounts CRUD & Generators (Direct DB) ---


def list_accounts_admin():
    p = _ph()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = max(1, min(200, request.args.get("per_page", 50, type=int)))
    api_key_id = request.args.get("api_key_id", type=int)
    used_filter = request.args.get("used", "all")
    search = (request.args.get("search") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort = request.args.get("sort", "created_desc")

    where = []
    params = []
    if api_key_id is not None:
        where.append(f"a.api_key_id = {p}")
        params.append(api_key_id)
    if used_filter in ("0", "1"):
        where.append(f"a.used = {p}")
        params.append(int(used_filter))
    if search:
        op = "ILIKE" if db.DB_TYPE == "postgresql" else "LIKE"
        where.append(f"(a.email {op} {p} OR a.password {op} {p})")
        like_val = f"%{search}%"
        params.extend([like_val, like_val])
    if date_from:
        where.append(f"a.created_at >= {p}")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        where.append(f"a.created_at <= {p}")
        params.append(f"{date_to} 23:59:59")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sort_map = {
        "created_desc": "a.created_at DESC, a.id DESC",
        "created_asc": "a.created_at ASC, a.id ASC",
        "id_desc": "a.id DESC",
        "id_asc": "a.id ASC",
        "email_asc": "a.email ASC",
        "email_desc": "a.email DESC",
        "used_asc": "a.used ASC, a.id DESC",
        "used_desc": "a.used DESC, a.id DESC",
    }
    order_sql = sort_map.get(sort, "a.created_at DESC, a.id DESC")

    summary = _query(
        f"""
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN a.used = 0 THEN 1 ELSE 0 END), 0) AS unused,
            COALESCE(SUM(CASE WHEN a.used != 0 THEN 1 ELSE 0 END), 0) AS used
        FROM accounts a
        {where_sql}
        """,
        tuple(params),
        fetch_one=True,
    )
    total = summary["total"]
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    rows = _query(
        f"""
        SELECT
            a.id,
            a.api_key_id,
            k.key AS api_key,
            a.email,
            a.password,
            a.used,
            a.created_at
        FROM accounts a
        LEFT JOIN api_keys k ON k.id = a.api_key_id
        {where_sql}
        ORDER BY {order_sql}
        LIMIT {p} OFFSET {p}
        """,
        tuple(params + [per_page, offset]),
        fetch_all=True,
    )

    return jsonify({
        "accounts": rows,
        "total": total,
        "unused": summary["unused"],
        "used": summary["used"],
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    })


def _insert_accounts_batch(api_key_id, pairs, used=0):
    """Inserts (email, password) pairs directly into DB, skipping duplicates."""
    p = _ph()
    inserted_pairs = []
    skipped = 0

    with _db_lock():
        conn = db.get_connection()
        try:
            cur = conn.cursor()
            if db.DB_TYPE == "postgresql":
                from psycopg2.extras import execute_values
                values = [(api_key_id, email, password, used) for email, password in pairs]
                res = execute_values(
                    cur,
                    "INSERT INTO accounts (api_key_id, email, password, used) VALUES %s "
                    "ON CONFLICT (api_key_id, email) DO NOTHING RETURNING email, password",
                    values,
                    fetch=True,
                )
                inserted_pairs = [{"email": r[0], "password": r[1]} for r in res]
                skipped = len(pairs) - len(inserted_pairs)
            else:
                for email, password in pairs:
                    cur.execute(
                        f"INSERT OR IGNORE INTO accounts (api_key_id, email, password, used) VALUES ({p}, {p}, {p}, {p})",
                        (api_key_id, email, password, used),
                    )
                    if cur.rowcount > 0:
                        inserted_pairs.append({"email": email, "password": password})
                    else:
                        skipped += 1
            conn.commit()
            return inserted_pairs, skipped
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def create_account_admin():
    data = request.get_json(silent=True) or {}
    api_key_id = data.get("api_key_id")
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    used = 1 if int(data.get("used", 0)) else 0

    if not api_key_id or not email or not password:
        return jsonify({"error": "api_key_id, email ve password zorunludur"}), 400

    p = _ph()
    if not _query(f"SELECT id FROM api_keys WHERE id = {p}", (int(api_key_id),), fetch_one=True):
        return jsonify({"error": "Geçersiz api_key_id"}), 404

    inserted, skipped = _insert_accounts_batch(int(api_key_id), [(email, password)], used=used)
    if skipped:
        return jsonify({"error": "Bu email bu API anahtarı için zaten kayıtlı"}), 409
    return jsonify({"message": "Hesap DB'ye eklendi", "account": inserted[0]}), 201


def bulk_add_accounts_admin():
    data = request.get_json(silent=True) or {}
    api_key_id = data.get("api_key_id")
    raw_text = data.get("text") or ""
    used = 1 if int(data.get("used", 0)) else 0

    if not api_key_id:
        return jsonify({"error": "api_key_id zorunludur"}), 400

    p = _ph()
    if not _query(f"SELECT id FROM api_keys WHERE id = {p}", (int(api_key_id),), fetch_one=True):
        return jsonify({"error": "Geçersiz api_key_id"}), 404

    pairs = []
    invalid = 0
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            invalid += 1
            continue
        email, password = line.split(":", 1)
        email = email.strip()
        password = password.strip()
        if email and password:
            pairs.append((email, password))
        else:
            invalid += 1

    if not pairs:
        return jsonify({"error": "Geçerli email:pass satırı bulunamadı"}), 400

    inserted, skipped = _insert_accounts_batch(int(api_key_id), pairs, used=used)
    return jsonify({
        "message": f"{len(inserted)} hesap eklendi, {skipped} mükerrer atlandı, {invalid} geçersiz satır",
        "added": len(inserted),
        "skipped": skipped,
        "invalid": invalid,
    })


def generate_random_accounts_admin():
    data = request.get_json(silent=True) or {}
    api_key_id = data.get("api_key_id")
    count = data.get("count", 1)
    domain = (data.get("domain") or "").strip()
    fixed_password = (data.get("password") or "").strip()
    password_length = data.get("password_length", 12)
    used = 1 if int(data.get("used", 0)) else 0

    if not api_key_id:
        return jsonify({"error": "api_key_id zorunludur"}), 400

    try:
        count = int(count)
    except (TypeError, ValueError):
        return jsonify({"error": "count sayı olmalıdır"}), 400

    if count < 1 or count > 10000:
        return jsonify({"error": "count 1 ile 10000 arasında olmalıdır"}), 400

    p = _ph()
    if not _query(f"SELECT id FROM api_keys WHERE id = {p}", (int(api_key_id),), fetch_one=True):
        return jsonify({"error": "Geçersiz api_key_id"}), 404

    seen = set()
    pairs = []
    attempts = 0
    max_attempts = count * 5
    while len(pairs) < count and attempts < max_attempts:
        attempts += 1
        email = _generate_random_email(domain)
        if email in seen:
            continue
        seen.add(email)
        pwd = fixed_password if fixed_password else _generate_random_password(password_length)
        pairs.append((email, pwd))

    inserted, skipped = _insert_accounts_batch(int(api_key_id), pairs, used=used)
    preview_limit = 200
    return jsonify({
        "message": f"{len(inserted)} rastgele hesap DB'ye eklendi" + (f" ({skipped} çakışma atlandı)" if skipped else ""),
        "requested": count,
        "added": len(inserted),
        "skipped": skipped,
        "preview": [f"{item['email']}:{item['password']}" for item in inserted[:preview_limit]],
        "truncated": len(inserted) > preview_limit,
    }), 201


def update_account_admin(acc_id):
    data = request.get_json(silent=True) or {}
    p = _ph()
    existing = _query(f"SELECT * FROM accounts WHERE id = {p}", (acc_id,), fetch_one=True)
    if not existing:
        return jsonify({"error": "Hesap bulunamadı"}), 404

    api_key_id = int(data.get("api_key_id", existing["api_key_id"]))
    email = (data.get("email", existing["email"]) or "").strip()
    password = (data.get("password", existing["password"]) or "").strip()
    used = 1 if int(data.get("used", existing["used"])) else 0

    if not email or not password:
        return jsonify({"error": "email ve password boş olamaz"}), 400

    try:
        _query(
            f"UPDATE accounts SET api_key_id = {p}, email = {p}, password = {p}, used = {p} WHERE id = {p}",
            (api_key_id, email, password, used, acc_id),
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"message": "Hesap güncellendi"})


def delete_account_admin(acc_id):
    p = _ph()
    deleted = _query(f"DELETE FROM accounts WHERE id = {p}", (acc_id,))
    if not deleted:
        return jsonify({"error": "Hesap bulunamadı"}), 404
    return jsonify({"message": "Hesap silindi"})


def bulk_action_accounts_admin():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    ids = data.get("ids") or []
    api_key_id = data.get("api_key_id")
    p = _ph()

    if action not in ("set_used_0", "set_used_1", "delete"):
        return jsonify({"error": "Geçersiz işlem"}), 400

    if ids:
        clean_ids = [int(i) for i in ids]
        placeholders = ", ".join([p] * len(clean_ids))
        if action == "set_used_0":
            affected = _query(f"UPDATE accounts SET used = 0 WHERE id IN ({placeholders})", tuple(clean_ids))
        elif action == "set_used_1":
            affected = _query(f"UPDATE accounts SET used = 1 WHERE id IN ({placeholders})", tuple(clean_ids))
        else:
            affected = _query(f"DELETE FROM accounts WHERE id IN ({placeholders})", tuple(clean_ids))
        return jsonify({"message": f"{affected} hesap güncellendi/silindi", "affected": affected})

    where = ""
    params = ()
    if api_key_id is not None and str(api_key_id) != "":
        where = f" WHERE api_key_id = {p}"
        params = (int(api_key_id),)

    if action == "set_used_0":
        affected = _query(f"UPDATE accounts SET used = 0{where}", params)
    elif action == "set_used_1":
        affected = _query(f"UPDATE accounts SET used = 1{where}", params)
    else:
        only_used = bool(data.get("only_used"))
        if only_used:
            where = f"{where} AND used != 0" if where else " WHERE used != 0"
        affected = _query(f"DELETE FROM accounts{where}", params)

    return jsonify({"message": f"{affected} hesap işlendi", "affected": affected})


def export_accounts_admin():
    p = _ph()
    api_key_id = request.args.get("api_key_id", type=int)
    used_filter = request.args.get("used", "all")
    search = (request.args.get("search") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort = request.args.get("sort", "created_desc")

    where = []
    params = []
    if api_key_id is not None:
        where.append(f"api_key_id = {p}")
        params.append(api_key_id)
    if used_filter in ("0", "1"):
        where.append(f"used = {p}")
        params.append(int(used_filter))
    if search:
        op = "ILIKE" if db.DB_TYPE == "postgresql" else "LIKE"
        where.append(f"(email {op} {p} OR password {op} {p})")
        like_val = f"%{search}%"
        params.extend([like_val, like_val])
    if date_from:
        where.append(f"created_at >= {p}")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        where.append(f"created_at <= {p}")
        params.append(f"{date_to} 23:59:59")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    order_sql = "created_at ASC, id ASC" if sort == "created_asc" else "created_at DESC, id DESC"
    rows = _query(
        f"SELECT email, password FROM accounts {where_sql} ORDER BY {order_sql}",
        tuple(params),
        fetch_all=True,
    )
    text_out = "\n".join(f"{r['email']}:{r['password']}" for r in rows)
    return jsonify({"count": len(rows), "text": text_out})


# --- Tasks CRUD ---


def list_tasks_admin():
    p = _ph()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = max(1, min(200, request.args.get("per_page", 25, type=int)))
    api_key_id = request.args.get("api_key_id", type=int)
    status = (request.args.get("status") or "").strip()
    mode = (request.args.get("mode") or "").strip()
    search = (request.args.get("search") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    has_result = (request.args.get("has_result") or "").strip()
    sort = request.args.get("sort", "created_desc")

    where = []
    params = []
    if api_key_id is not None:
        where.append(f"t.api_key_id = {p}")
        params.append(api_key_id)
    if status:
        where.append(f"t.status = {p}")
        params.append(status)
    if mode:
        where.append(f"t.mode = {p}")
        params.append(mode)
    if has_result == "1":
        where.append("t.result_url IS NOT NULL AND t.result_url != ''")
    elif has_result == "0":
        where.append("(t.result_url IS NULL OR t.result_url = '')")
    if date_from:
        where.append(f"t.created_at >= {p}")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        where.append(f"t.created_at <= {p}")
        params.append(f"{date_to} 23:59:59")
    if search:
        op = "ILIKE" if db.DB_TYPE == "postgresql" else "LIKE"
        where.append(
            f"(t.task_id {op} {p} OR COALESCE(t.prompt, '') {op} {p} "
            f"OR COALESCE(t.account_email, '') {op} {p} "
            f"OR COALESCE(t.external_task_id, '') {op} {p} "
            f"OR COALESCE(t.model, '') {op} {p})"
        )
        like_val = f"%{search}%"
        params.extend([like_val] * 5)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sort_map = {
        "created_desc": "t.created_at DESC, t.id DESC",
        "created_asc": "t.created_at ASC, t.id ASC",
        "id_desc": "t.id DESC",
        "id_asc": "t.id ASC",
        "status_asc": "t.status ASC, t.id DESC",
        "mode_asc": "t.mode ASC, t.id DESC",
    }
    order_sql = sort_map.get(sort, "t.created_at DESC, t.id DESC")

    total = _query(f"SELECT COUNT(*) AS count FROM tasks t {where_sql}", tuple(params), fetch_one=True)["count"]
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    rows = _query(
        f"""
        SELECT
            t.id,
            t.api_key_id,
            k.key AS api_key,
            t.task_id,
            t.status,
            t.mode,
            t.model,
            t.prompt,
            t.result_url,
            t.account_email,
            t.external_task_id,
            t.size,
            t.resolution,
            t.duration,
            t.logs,
            CASE WHEN t.token IS NOT NULL AND t.token != '' THEN 1 ELSE 0 END AS has_token,
            t.created_at
        FROM tasks t
        LEFT JOIN api_keys k ON k.id = t.api_key_id
        {where_sql}
        ORDER BY {order_sql}
        LIMIT {p} OFFSET {p}
        """,
        tuple(params + [per_page, offset]),
        fetch_all=True,
    )
    return jsonify({
        "tasks": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    })


def get_task_admin(row_id):
    p = _ph()
    row = _query(f"SELECT * FROM tasks WHERE id = {p}", (row_id,), fetch_one=True)
    if not row:
        return jsonify({"error": "Görev bulunamadı"}), 404
    return jsonify({"task": row})


def update_task_admin(row_id):
    data = request.get_json(silent=True) or {}
    p = _ph()
    existing = _query(f"SELECT id FROM tasks WHERE id = {p}", (row_id,), fetch_one=True)
    if not existing:
        return jsonify({"error": "Görev bulunamadı"}), 404

    updates = []
    params = []
    for col in TASK_EDITABLE_COLUMNS:
        if col not in data:
            continue
        val = data[col]
        if col in ("api_key_id", "duration", "instrumental"):
            val = int(val) if val not in (None, "") else None
        elif col in ("speed", "pitch", "volume"):
            val = float(val) if val not in (None, "") else None
        elif col in ("logs", "reference_image_urls") and isinstance(val, (list, dict)):
            val = json.dumps(val, ensure_ascii=False)
        elif val == "":
            val = None if col not in ("logs", "reference_image_urls") else "[]"
        updates.append(f"{col} = {p}")
        params.append(val)

    if not updates:
        return jsonify({"error": "Güncellenecek alan yok"}), 400

    params.append(row_id)
    try:
        _query(f"UPDATE tasks SET {', '.join(updates)} WHERE id = {p}", tuple(params))
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": "Görev güncellendi"})


def delete_task_admin(row_id):
    p = _ph()
    deleted = _query(f"DELETE FROM tasks WHERE id = {p}", (row_id,))
    if not deleted:
        return jsonify({"error": "Görev bulunamadı"}), 404
    return jsonify({"message": "Görev silindi"})


def release_task_account_admin(row_id):
    p = _ph()
    task = _query(f"SELECT api_key_id, account_email FROM tasks WHERE id = {p}", (row_id,), fetch_one=True)
    if not task:
        return jsonify({"error": "Görev bulunamadı"}), 404
    if not task.get("account_email"):
        return jsonify({"error": "Bu göreve bağlı hesap yok"}), 400
    affected = _query(
        f"UPDATE accounts SET used = 0 WHERE api_key_id = {p} AND email = {p}",
        (task["api_key_id"], task["account_email"]),
    )
    return jsonify({"message": f"{task['account_email']} hesabı boşa çekildi ({affected} satır)"})


def bulk_action_tasks_admin():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    ids = data.get("ids") or []
    api_key_id = data.get("api_key_id")
    status = (data.get("status") or "").strip()
    p = _ph()

    if action not in ("mark_failed", "mark_completed", "delete"):
        return jsonify({"error": "Geçersiz işlem"}), 400

    if ids:
        clean_ids = [int(i) for i in ids]
        placeholders = ", ".join([p] * len(clean_ids))
        if action == "delete":
            affected = _query(f"DELETE FROM tasks WHERE id IN ({placeholders})", tuple(clean_ids))
        else:
            new_status = "failed" if action == "mark_failed" else "completed"
            affected = _query(f"UPDATE tasks SET status = {p} WHERE id IN ({placeholders})", tuple([new_status] + clean_ids))
        return jsonify({"message": f"{affected} görev işlendi", "affected": affected})

    where = []
    params = []
    if api_key_id is not None and str(api_key_id) != "":
        where.append(f"api_key_id = {p}")
        params.append(int(api_key_id))
    if status:
        where.append(f"status = {p}")
        params.append(status)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    if action == "delete":
        affected = _query(f"DELETE FROM tasks{where_sql}", tuple(params))
    else:
        new_status = "failed" if action == "mark_failed" else "completed"
        affected = _query(f"UPDATE tasks SET status = {p}{where_sql}", tuple([new_status] + params))
    return jsonify({"message": f"{affected} görev işlendi", "affected": affected})


# --- Schema, Maintenance & Direct SQL Console ---


def get_schema_admin():
    tables = {}
    if db.DB_TYPE == "postgresql":
        cols = _query(
            """
            SELECT table_name, column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
            ORDER BY table_name, ordinal_position
            """,
            fetch_all=True,
        )
        for c in cols:
            tables.setdefault(c["table_name"], []).append({
                "name": c["column_name"],
                "type": c["data_type"],
                "nullable": c["is_nullable"] == "YES",
                "default": c["column_default"],
            })
    else:
        tbls = _query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", fetch_all=True)
        for t in tbls:
            tname = t["name"]
            if tname.startswith("sqlite_"):
                continue
            info = _query(f'PRAGMA table_info("{tname}")', fetch_all=True)
            tables[tname] = [
                {
                    "name": c["name"],
                    "type": c["type"],
                    "nullable": not bool(c["notnull"]),
                    "default": c["dflt_value"],
                    "pk": bool(c["pk"]),
                }
                for c in info
            ]
    return jsonify({"db_type": db.DB_TYPE, "tables": tables})


def maintenance_admin():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action == "reset_all_accounts":
        affected = _query("UPDATE accounts SET used = 0")
        return jsonify({"message": f"Tüm hesaplar sıfırlandı ({affected} satır)"})
    if action == "delete_used_accounts":
        affected = _query("DELETE FROM accounts WHERE used != 0")
        return jsonify({"message": f"Kullanılmış hesaplar silindi ({affected} satır)"})
    if action == "fail_stale_tasks":
        affected = _query("UPDATE tasks SET status = 'failed' WHERE status IN ('running', 'pending')")
        return jsonify({"message": f"Bekleyen/çalışan görevler failed yapıldı ({affected} satır)"})
    if action == "clear_all_tasks":
        affected = _query("DELETE FROM tasks")
        return jsonify({"message": f"Tüm görevler silindi ({affected} satır)"})
    if action == "clear_all_accounts":
        affected = _query("DELETE FROM accounts")
        return jsonify({"message": f"Tüm hesaplar silindi ({affected} satır)"})
    return jsonify({"error": "Bilinmeyen bakım işlemi"}), 400


def execute_sql_admin():
    data = request.get_json(silent=True) or {}
    sql = (data.get("sql") or "").strip()
    if not sql:
        return jsonify({"error": "SQL sorgusu boş olamaz"}), 400

    with _db_lock():
        conn = db.get_connection()
        try:
            cur = (
                conn.cursor(cursor_factory=RealDictCursor)
                if db.DB_TYPE == "postgresql"
                else conn.cursor()
            )
            cur.execute(sql)
            if cur.description is not None:
                columns = [desc[0] for desc in cur.description]
                rows_raw = cur.fetchmany(500)
                rows = [_serialize_row(r) for r in rows_raw]
                conn.commit()
                return jsonify({
                    "has_rows": True,
                    "columns": columns,
                    "rows": rows,
                    "row_count": len(rows),
                    "truncated": len(rows) == 500,
                })
            conn.commit()
            return jsonify({
                "has_rows": False,
                "row_count": cur.rowcount,
                "message": f"Sorgu çalıştırıldı. Etkilenen satır: {cur.rowcount}",
            })
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            return jsonify({"error": str(e)}), 400
        finally:
            conn.close()



# --- Unified Request Dispatcher ---

_STATIC_ROUTES = {
    ("", "GET"): admin_page,
    ("api/logout", "POST"): admin_logout,
    ("api/overview", "GET"): admin_overview,
    ("api/keys", "GET"): list_api_keys,
    ("api/keys", "POST"): create_api_key_admin,
    ("api/accounts", "GET"): list_accounts_admin,
    ("api/accounts", "POST"): create_account_admin,
    ("api/accounts/bulk", "POST"): bulk_add_accounts_admin,
    ("api/accounts/random", "POST"): generate_random_accounts_admin,
    ("api/accounts/bulk-action", "POST"): bulk_action_accounts_admin,
    ("api/accounts/export", "GET"): export_accounts_admin,
    ("api/tasks", "GET"): list_tasks_admin,
    ("api/tasks/bulk-action", "POST"): bulk_action_tasks_admin,
    ("api/schema", "GET"): get_schema_admin,
    ("api/maintenance", "POST"): maintenance_admin,
    ("api/sql", "POST"): execute_sql_admin,
}

_PARAM_ROUTES = [
    (re.compile(r"^api/keys/(\d+)$"), "PUT", update_api_key_admin),
    (re.compile(r"^api/keys/(\d+)$"), "DELETE", delete_api_key_admin),
    (re.compile(r"^api/accounts/(\d+)$"), "PUT", update_account_admin),
    (re.compile(r"^api/accounts/(\d+)$"), "DELETE", delete_account_admin),
    (re.compile(r"^api/tasks/(\d+)$"), "GET", get_task_admin),
    (re.compile(r"^api/tasks/(\d+)$"), "PUT", update_task_admin),
    (re.compile(r"^api/tasks/(\d+)$"), "DELETE", delete_task_admin),
    (re.compile(r"^api/tasks/(\d+)/release-account$"), "POST", release_task_account_admin),
]


def handle_admin_request(subpath=""):
    """Single entry point called by api.py's /admin route."""
    if not _is_valid_admin_key(_extract_admin_key()):
        abort(404)

    path = (subpath or "").strip("/")
    method = request.method.upper()

    handler = _STATIC_ROUTES.get((path, method))
    if handler:
        return handler()

    for pattern, route_method, param_handler in _PARAM_ROUTES:
        if method == route_method:
            match = pattern.match(path)
            if match:
                return param_handler(int(match.group(1)))

    abort(404)



def init_app(app):
    """Registers /admin routes and automatic /api/models admin cookie handshake on the Flask app."""
    app.add_url_rule(
        "/admin",
        endpoint="admin_root",
        defaults={"subpath": ""},
        view_func=handle_admin_request,
        methods=["GET", "POST", "PUT", "DELETE"],
    )
    app.add_url_rule(
        "/admin/<path:subpath>",
        endpoint="admin_subpath",
        view_func=handle_admin_request,
        methods=["GET", "POST", "PUT", "DELETE"],
    )

    @app.before_request
    def _admin_models_before_request():
        if request.path == "/api/models" and request.method == "GET" and is_request_admin_key():
            import service
            return set_admin_cookie(make_response(jsonify(service.get_available_models())))

    @app.after_request
    def _admin_models_after_request(response):
        if request.path == "/api/models" and request.method == "GET" and not is_request_admin_key():
            clear_admin_cookie(response)
        return response
