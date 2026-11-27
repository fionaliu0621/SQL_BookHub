import os
from datetime import date
from decimal import Decimal, InvalidOperation

import psycopg
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation
from dotenv import load_dotenv
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, request, session, render_template, redirect, url_for

from werkzeug.security import generate_password_hash, check_password_hash

# -------------------- CONFIG --------------------

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Change to True for HTTPS deployment
)
UPLOAD_FOLDER = Path(app.root_path) / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
# Ordered list (used for the college links); COLLEGES is the set used for validation.
COLLEGE_ORDER = [
    "教育學院",
    "文學院",
    "理學院",
    "科技與工程學院",
    "藝術學院",
    "音樂學院",
    "管理學院",
    "國際與社會科學學院",
    "運動與休閒學院",
    "跨域科技產業創新研究學院",
    "其他",
]
COLLEGES = set(COLLEGE_ORDER)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Max selling price (NT$) for each book condition.
PRICE_LIMITS = {"NEW": 2000, "LIKE_NEW": 1500, "GOOD": 1200, "FAIR": 800}
MAX_NOTE_LENGTH = 500


def get_db_connection():
    return psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row)


def ensure_schema():
    """Make sure columns added by newer features exist (safe to run repeatedly)."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                "ALTER TABLE books ADD COLUMN IF NOT EXISTS condition_note TEXT"
            )
    except Exception:
        app.logger.exception("Schema check failed")


ensure_schema()

# -------------------- ROLES --------------------
# One account can hold several roles (BUYER and/or SELLER).
# Roles are stored in the user_roles table (see migration_roles_unique_name.sql);
# the legacy users.role column is no longer read.

VALID_ROLES = ("BUYER", "SELLER")


def get_user_roles(cur, user_id):
    cur.execute(
        "SELECT role FROM user_roles WHERE user_id = %s ORDER BY role",
        (user_id,),
    )
    roles = [row["role"] for row in cur.fetchall()]

    if not roles:
        # Account registered by older code (no user_roles row yet):
        # copy its role from the legacy users.role column, once.
        cur.execute(
            """
            INSERT INTO user_roles (user_id, role)
            SELECT id, role FROM users
            WHERE id = %s AND role IN ('BUYER', 'SELLER')
            ON CONFLICT (user_id, role) DO NOTHING
            RETURNING role
        """,
            (user_id,),
        )
        roles = [row["role"] for row in cur.fetchall()]

    return roles


def current_roles():
    roles = session.get("roles")
    if roles is None and "role" in session:
        # Session created before the roles change: fall back to the old value.
        roles = [session["role"]]
    return roles or []


def has_role(role):
    return role in current_roles()


# -------------------- HOME --------------------


@app.route("/")
def home():
    return render_template("home.html", colleges=COLLEGE_ORDER)


# -------------------- DATABASE TEST --------------------


@app.route("/api/db-test")
def db_test():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)

            tables = [row["table_name"] for row in cur.fetchall()]

    return jsonify({"connected": True, "tables": tables})


# -------------------- REGISTER --------------------


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400

    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    password = data.get("password")

    # New format: "roles": ["BUYER", "SELLER"]. Old format "role": "BUYER" still works.
    roles = data.get("roles")
    if roles is None:
        roles = [data.get("role", "BUYER")]

    if not name or not email or not isinstance(password, str):
        return jsonify({"error": "請填寫所有必填欄位"}), 400

    if len(name) > 50:
        return jsonify({"error": "姓名／暱稱最多 50 個字元"}), 400

    if len(password) < 8:
        return jsonify({"error": "密碼至少需要 8 個字元"}), 400

    if (
        not isinstance(roles, list)
        or not roles
        or any(r not in VALID_ROLES for r in roles)
    ):
        return jsonify({"error": "請至少選擇一種帳號身分（買家或賣家）"}), 400

    roles = sorted(set(roles))
    password_hash = generate_password_hash(password)

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Check first so the user gets a clear message.
                # The UNIQUE indexes below still protect against race conditions.
                cur.execute(
                    "SELECT 1 FROM users WHERE LOWER(name) = LOWER(%s)", (name,)
                )
                if cur.fetchone():
                    return jsonify({"error": "這個名稱已經有人使用，請換一個"}), 409

                cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({"error": "電子郵件已被註冊"}), 409

                # users.role is legacy; it is still filled in so older
                # constraints on that column keep working.
                cur.execute(
                    """
                    INSERT INTO users
                        (name, email, password_hash, role)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, name, email
                """,
                    (
                        name,
                        email,
                        password_hash,
                        "SELLER" if "SELLER" in roles else "BUYER",
                    ),
                )

                user = cur.fetchone()

                for role in roles:
                    cur.execute(
                        "INSERT INTO user_roles (user_id, role) VALUES (%s, %s)",
                        (user["id"], role),
                    )

        user["roles"] = roles
        return jsonify({"message": "註冊成功", "user": user}), 201

    except UniqueViolation as error:
        constraint = (error.diag.constraint_name or "").lower()
        if "name" in constraint:
            return jsonify({"error": "這個名稱已經有人使用，請換一個"}), 409
        return jsonify({"error": "電子郵件已被註冊"}), 409


# -------------------- LOGIN --------------------


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400

    email = str(data.get("email") or "").strip().lower()
    password = data.get("password")

    if not email or not isinstance(password, str) or not password:
        return jsonify({"error": "請輸入電子郵件與密碼"}), 400

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, email, password_hash
                FROM users
                WHERE email = %s
            """,
                (email,),
            )

            user = cur.fetchone()

            if not user or not check_password_hash(user["password_hash"], password):
                return jsonify({"error": "電子郵件或密碼錯誤"}), 401

            roles = get_user_roles(cur, user["id"])

    session.clear()
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["roles"] = roles

    return jsonify(
        {
            "message": "登入成功",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "roles": roles,
            },
        }
    )


# -------------------- CURRENT USER --------------------


@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"error": "尚未登入"}), 401

    return jsonify(
        {
            "id": session["user_id"],
            "name": session["user_name"],
            "roles": current_roles(),
        }
    )


# -------------------- ADD A ROLE (e.g. buyer becomes seller) --------------------


@app.route("/api/me/roles", methods=["POST"])
def add_my_role():
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401

    data = request.get_json(silent=True)
    role = data.get("role") if isinstance(data, dict) else None

    if role not in VALID_ROLES:
        return jsonify({"error": "身分類型錯誤"}), 400

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            get_user_roles(cur, session["user_id"])  # keeps an older account's existing role
            cur.execute(
                """
                INSERT INTO user_roles (user_id, role) VALUES (%s, %s)
                ON CONFLICT (user_id, role) DO NOTHING
            """,
                (session["user_id"], role),
            )
            roles = get_user_roles(cur, session["user_id"])

    session["roles"] = roles
    label = "賣家" if role == "SELLER" else "買家"
    return jsonify({"message": f"已開通{label}身分", "roles": roles})


# -------------------- LOGOUT --------------------


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "登出成功"})


# -------------------- AUTH PAGES --------------------


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


# -------------------- DASHBOARD --------------------


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    return render_template(
        "dashboard.html", name=session["user_name"], roles=current_roles()
    )


# -------------------- SELL PAGE --------------------


@app.route("/sell")
def sell_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    if not has_role("SELLER"):
        return "只有賣家帳號可以上架書籍", 403

    return render_template("sell.html", price_limits=PRICE_LIMITS)


# -------------------- BOOK MARKETPLACE PAGE --------------------


@app.route("/marketplace")
def marketplace_page():
    return render_template(
        "marketplace.html", colleges=COLLEGE_ORDER, preset_college=""
    )


@app.route("/college/<college_name>")
def college_page(college_name):
    if college_name not in COLLEGES:
        return "找不到這個學院", 404
    return render_template(
        "marketplace.html", colleges=COLLEGE_ORDER, preset_college=college_name
    )


# -------------------- GET BOOKS --------------------


@app.route("/api/books", methods=["GET"])
def get_books():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    seller_id,
                    title,
                    price,
                    condition,
                    image_url,
                    college,
                    condition_note
                FROM books
                WHERE status = 'AVAILABLE'
                ORDER BY created_at DESC
            """)

            books = cur.fetchall()

    return jsonify(books)

# -------------------- CREATE BOOK --------------------


# -------------------- CREATE BOOK --------------------


@app.route("/api/books", methods=["POST"])
def create_book():

    # 1. Check login
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401

    # 2. Only sellers can upload books
    if not has_role("SELLER"):
        return jsonify({"error": "只有賣家可以上架書籍"}), 403

    # 3. Get form data
    title = request.form.get("title", "").strip()
    condition = request.form.get("condition", "").strip()
    college = request.form.get("college", "").strip()
    price_input = request.form.get("price", "").strip()
    image = request.files.get("image")

    # 4. Validate book title
    if not title or len(title) > 200:
        return jsonify({"error": "請輸入正確的書籍名稱"}), 400

    # 5. Validate book condition
    if condition not in ("NEW", "LIKE_NEW", "GOOD", "FAIR"):
        return jsonify({"error": "請選擇書籍狀況"}), 400

    # 6. Validate department
    if college not in COLLEGES:
        return jsonify({"error": "請選擇有效的學院分類"}), 400

    # 7. Validate price
    try:
        price = Decimal(price_input)

        if not price.is_finite() or price <= 0 or price > 99999999.99:
            raise ValueError()

        price = price.quantize(Decimal("0.01"))

    except (InvalidOperation, ValueError, TypeError):
        return jsonify({"error": "價格格式錯誤"}), 400

    # 7.1 Validate price limit by condition
    limit = PRICE_LIMITS[condition]
    if price > limit:
        return jsonify({"error": f"此書況售價上限為 NT${limit}"}), 400

    # 7.2 Validate condition note (optional)
    condition_note = request.form.get("condition_note", "").strip()
    if len(condition_note) > MAX_NOTE_LENGTH:
        return jsonify({"error": f"書況說明不可超過 {MAX_NOTE_LENGTH} 字"}), 400

    # 8. Check image
    if not image or not image.filename:
        return jsonify({"error": "請上傳書籍照片"}), 400

    # Extract the extension from the original filename before sanitizing it.
    # secure_filename("書籍封面.PNG") can strip non-ASCII characters.
    original_filename = image.filename.strip()
    extension = Path(original_filename).suffix.lstrip(".").lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": "僅支援 JPG、PNG、WEBP",
            "detected_extension": extension or "(none)"
        }), 400

    # 9. Verify actual image format
    from PIL import Image, UnidentifiedImageError

    try:
        image.stream.seek(0)

        with Image.open(image.stream) as picture:
            actual_format = picture.format
            picture.verify()

    except (UnidentifiedImageError, OSError, ValueError):
        return jsonify({"error": "圖片檔案無效"}), 400

    allowed_formats = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "webp": "WEBP"}

    if actual_format != allowed_formats[extension]:
        return jsonify({"error": "圖片格式不正確"}), 400

    # 10. Generate unique filename
    new_filename = f"{uuid4().hex}.{extension}"

    image_path = UPLOAD_FOLDER / new_filename

    image_url = f"/static/uploads/{new_filename}"

    # 11. Save image and insert book into Neon
    try:
        image.stream.seek(0)
        image.save(image_path)

        with get_db_connection() as conn:

            with conn.cursor() as cur:

                cur.execute("""
    INSERT INTO books (
        seller_id,
        title,
        price,
        condition,
        status,
        image_url,
        college,
        condition_note
    )
    VALUES (
        %s, %s, %s, %s,
        'AVAILABLE', %s, %s, %s
    )
    RETURNING id
""", (
    session["user_id"],
    title,
    price,
    condition,
    image_url,
    college,
    condition_note or None
))

                book = cur.fetchone()

    except Exception:
        image_path.unlink(missing_ok=True)
        app.logger.exception("Failed to create book")
        raise

    # 12. Return success
    return (
        jsonify(
            {"message": "書籍上架成功！", "book_id": book["id"], "image_url": image_url}
        ),
        201,
    )


# -------------------- SHOPPING CART --------------------


def buyer_required():
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401
    if not has_role("BUYER"):
        return jsonify({"error": "只有買家可以使用購物車"}), 403
    return None


@app.route("/cart")
def cart_page():
    if "user_id" not in session:
        return redirect(url_for("login_page", next="/cart"))
    if not has_role("BUYER"):
        return redirect(url_for("marketplace_page"))
    return render_template("cart.html")


@app.route("/api/cart", methods=["GET"])
def get_cart():
    denied = buyer_required()
    if denied:
        return denied
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ci.id, b.id AS book_id, b.title, b.price,
                       b.condition, b.image_url, b.status
                FROM cart_items ci
                JOIN books b ON b.id = ci.book_id
                WHERE ci.buyer_id = %s
                ORDER BY ci.id DESC
            """,
                (session["user_id"],),
            )
            items = cur.fetchall()
    total = sum(
        (item["price"] for item in items if item["status"] == "AVAILABLE"), Decimal("0")
    )
    return jsonify({"items": items, "total": str(total)})


@app.route("/api/cart", methods=["POST"])
def add_to_cart():
    denied = buyer_required()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400
    try:
        book_id = int(data.get("book_id"))
        if book_id <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "書籍編號錯誤"}), 400

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, seller_id, status FROM books WHERE id = %s", (book_id,)
            )
            book = cur.fetchone()
            if not book or book["status"] != "AVAILABLE":
                return jsonify({"error": "這本書目前無法購買"}), 404
            if str(book["seller_id"]) == str(session["user_id"]):
                return jsonify({"error": "不能購買自己上架的書籍"}), 400
            # Serialize additions for the same buyer and book, even without
            # a unique constraint on (buyer_id, book_id).
            cur.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                (int(session["user_id"]), book_id),
            )
            cur.execute(
                """
                SELECT id FROM cart_items
                WHERE buyer_id = %s AND book_id = %s
                LIMIT 1
            """,
                (session["user_id"], book_id),
            )
            existing = cur.fetchone()
            if existing:
                return jsonify({"message": "這本書已在購物車中"}), 200
            cur.execute(
                """
                INSERT INTO cart_items (buyer_id, book_id)
                VALUES (%s, %s)
                RETURNING id
            """,
                (session["user_id"], book_id),
            )
            inserted = cur.fetchone()
    return jsonify({"message": "已加入購物車", "cart_item_id": inserted["id"]}), 201


@app.route("/api/cart/<int:item_id>", methods=["DELETE"])
def remove_from_cart(item_id):
    denied = buyer_required()
    if denied:
        return denied
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM cart_items WHERE id = %s AND buyer_id = %s RETURNING id",
                (item_id, session["user_id"]),
            )
            deleted = cur.fetchone()
    if not deleted:
        return jsonify({"error": "找不到購物車項目"}), 404
    return jsonify({"message": "已從購物車移除"})


# -------------------- CHECKOUT / ORDERS --------------------
# Requires migration_checkout.sql (dedicated tables, avoiding conflicts with
# any pre-existing orders / order_items schema).


@app.route("/orders")
def orders_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    if not has_role("BUYER"):
        return redirect(url_for("dashboard"))
    return render_template("orders.html")


@app.route("/api/orders", methods=["GET"])
def get_orders():

    denied = buyer_required()
    if denied:
        return denied

    with get_db_connection() as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    o.id AS order_id,
                    o.total_amount,
                    o.created_at,
                    o.payment_method,
                    o.payment_status,
                    o.card_last4,

                    i.id AS order_item_id,
                    i.book_id,
                    i.title,
                    i.price,
                    i.image_url,

                    b.seller_id,
                    u.name AS seller_name,

                    r.id AS review_id

                FROM checkout_orders o

                JOIN checkout_order_items i
                    ON i.order_id = o.id

                JOIN books b
                    ON b.id = i.book_id

                JOIN users u
                    ON u.id = b.seller_id

                LEFT JOIN seller_reviews r
                    ON r.order_item_id = i.id

                WHERE o.buyer_id = %s

                ORDER BY
                    o.created_at DESC,
                    o.id DESC,
                    i.id ASC

            """,
                (session["user_id"],),
            )

            rows = cur.fetchall()

    orders_by_id = {}

    for row in rows:

        order_id = row["order_id"]

        if order_id not in orders_by_id:

            orders_by_id[order_id] = {
                "id": order_id,
                "total": str(row["total_amount"]),
                "created_at": row["created_at"].isoformat(),
                "payment_method": row["payment_method"],
                "payment_status": row["payment_status"],
                "card_last4": row["card_last4"],
                "items": [],
            }

        orders_by_id[order_id]["items"].append(
            {
                "order_item_id": row["order_item_id"],
                "book_id": row["book_id"],
                "title": row["title"],
                "price": str(row["price"]),
                "image_url": row["image_url"],
                "seller_id": row["seller_id"],
                "seller_name": row["seller_name"],
                "review_id": row["review_id"],
            }
        )

    return jsonify({"orders": list(orders_by_id.values())})


PAYMENT_METHODS = ("COD", "CARD")
# Simulated card that is always declined, so the failure path can be demoed.
DECLINED_TEST_CARD = "4000000000000002"


def validate_simulated_card(card):
    """Check card fields for the simulated payment. Returns (last4, error)."""
    if not isinstance(card, dict):
        return None, "請填寫信用卡資料"

    number = "".join(str(card.get("number") or "").split())
    expiry = str(card.get("expiry") or "").strip()
    cvv = str(card.get("cvv") or "").strip()
    holder = str(card.get("holder") or "").strip()

    if not number.isdigit() or len(number) != 16:
        return None, "卡號需為 16 位數字"
    if not holder or len(holder) > 100:
        return None, "請填寫持卡人姓名"
    if not cvv.isdigit() or len(cvv) != 3:
        return None, "安全碼需為 3 位數字"

    try:
        month_text, year_text = expiry.split("/")
        month, year = int(month_text), 2000 + int(year_text)
        if len(year_text) != 2 or not 1 <= month <= 12:
            raise ValueError()
    except ValueError:
        return None, "到期日格式需為 MM/YY"

    today = date.today()
    if (year, month) < (today.year, today.month):
        return None, "信用卡已過期"

    if number == DECLINED_TEST_CARD:
        return None, "付款失敗：發卡銀行拒絕交易（測試卡）"

    return number[-4:], None


@app.route("/api/checkout", methods=["POST"])
def checkout():
    denied = buyer_required()
    if denied:
        return denied

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400

    payment_method = data.get("payment_method")
    if payment_method not in PAYMENT_METHODS:
        return jsonify({"error": "請選擇付款方式"}), 400

    card_last4 = None
    if payment_method == "CARD":
        # Card details are only checked here; nothing except the last 4
        # digits is stored.
        card_last4, card_error = validate_simulated_card(data.get("card"))
        if card_error:
            return jsonify({"error": card_error}), 402 if "付款失敗" in card_error else 400

    payment_status = "PAID" if payment_method == "CARD" else "PENDING"

    # One transaction: lock buyer, lock books, create order, mark SOLD, clear cart.
    # The row locks prevent concurrent buyers from buying the same book.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM users WHERE id = %s FOR UPDATE", (session["user_id"],)
            )
            cur.execute(
                """
                SELECT DISTINCT book_id FROM cart_items
                WHERE buyer_id = %s ORDER BY book_id
            """,
                (session["user_id"],),
            )
            book_ids = [r["book_id"] for r in cur.fetchall()]
            if not book_ids:
                return jsonify({"error": "購物車目前是空的"}), 400

            # Lock books in consistent order to reduce deadlock risk.
            cur.execute(
                """
                SELECT id, seller_id, title, price, image_url, status
                FROM books WHERE id = ANY(%s)
                ORDER BY id FOR UPDATE
            """,
                (book_ids,),
            )
            books = cur.fetchall()
            if len(books) != len(book_ids) or any(
                b["status"] != "AVAILABLE"
                or str(b["seller_id"]) == str(session["user_id"])
                for b in books
            ):
                return (
                    jsonify(
                        {"error": "購物車中有已售出或無法購買的書籍，請重新整理購物車"}
                    ),
                    409,
                )

            total = sum((b["price"] for b in books), Decimal("0"))
            cur.execute(
                """
                INSERT INTO checkout_orders
                    (buyer_id, total_amount, payment_method, payment_status, card_last4)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """,
                (session["user_id"], total, payment_method, payment_status, card_last4),
            )
            order_id = cur.fetchone()["id"]
            for book in books:
                cur.execute(
                    """
                    INSERT INTO checkout_order_items
                        (order_id, book_id, title, price, image_url)
                    VALUES (%s, %s, %s, %s, %s)
                """,
                    (
                        order_id,
                        book["id"],
                        book["title"],
                        book["price"],
                        book["image_url"],
                    ),
                )

            cur.execute(
                "UPDATE books SET status = 'SOLD' WHERE id = ANY(%s)", (book_ids,)
            )
            # Clear these now-sold items from everyone's cart.
            cur.execute("DELETE FROM cart_items WHERE book_id = ANY(%s)", (book_ids,))

    return (
        jsonify(
            {
                "message": "付款成功，訂單已建立"
                if payment_method == "CARD"
                else "訂單已建立，請於取貨時付款",
                "order_id": order_id,
                "total": str(total),
                "payment_method": payment_method,
                "payment_status": payment_status,
            }
        ),
        201,
    )


# -------------------- SELLER MANAGEMENT --------------------


def seller_required():
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401
    if not has_role("SELLER"):
        return jsonify({"error": "只有賣家可以管理書籍"}), 403
    return None


@app.route("/seller")
def seller_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    if not has_role("SELLER"):
        return redirect(url_for("dashboard"))
    return render_template("seller.html")


@app.route("/api/seller/books", methods=["GET"])
def seller_books():
    denied = seller_required()
    if denied:
        return denied
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, title, price, condition, status, image_url, created_at
                FROM books WHERE seller_id = %s ORDER BY created_at DESC, id DESC
            """,
                (session["user_id"],),
            )
            books = cur.fetchall()
            cur.execute(
                """
                SELECT COUNT(*) AS sold_count,
                       COALESCE(SUM(i.price), 0) AS revenue
                FROM checkout_order_items i
                JOIN books b ON b.id = i.book_id
                WHERE b.seller_id = %s
            """,
                (session["user_id"],),
            )
            sales = cur.fetchone()
    return jsonify(
        {
            "books": books,
            "stats": {
                "total": len(books),
                "available": sum(b["status"] == "AVAILABLE" for b in books),
                "sold": sum(b["status"] == "SOLD" for b in books),
                "revenue": str(sales["revenue"]),
                "sold_order_items": sales["sold_count"],
            },
        }
    )


@app.route("/api/seller/books/<int:book_id>", methods=["PATCH"])
def update_seller_book(book_id):
    denied = seller_required()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400
    if set(data) - {"title", "price", "condition", "status"}:
        return jsonify({"error": "包含不允許修改的欄位"}), 400
    if not data:
        return jsonify({"error": "沒有要更新的資料"}), 400
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, title, price, condition, status FROM books
                WHERE id = %s AND seller_id = %s FOR UPDATE
            """,
                (book_id, session["user_id"]),
            )
            book = cur.fetchone()
            if not book:
                return jsonify({"error": "找不到你的書籍"}), 404
            if book["status"] == "SOLD":
                return jsonify({"error": "已售出的書籍不可修改"}), 409
            title = data.get("title", book["title"])
            condition = data.get("condition", book["condition"])
            status = data.get("status", book["status"])
            if (
                not isinstance(title, str)
                or not title.strip()
                or len(title.strip()) > 200
            ):
                return jsonify({"error": "書籍名稱不正確"}), 400
            if condition not in ("NEW", "LIKE_NEW", "GOOD", "FAIR"):
                return jsonify({"error": "書況不正確"}), 400
            if status not in ("AVAILABLE", "RESERVED"):
                return jsonify({"error": "僅可上架或暫停販售"}), 400
            try:
                price = Decimal(str(data.get("price", book["price"])))
                if not price.is_finite() or not (0 < price <= Decimal("99999999.99")):
                    raise ValueError()
                price = price.quantize(Decimal("0.01"))
            except (InvalidOperation, ValueError, TypeError):
                return jsonify({"error": "價格不正確"}), 400
            if ("price" in data or "condition" in data) and price > PRICE_LIMITS[condition]:
                return (
                    jsonify({"error": f"此書況售價上限為 NT${PRICE_LIMITS[condition]}"}),
                    400,
                )
            cur.execute(
                """
                UPDATE books SET title=%s, price=%s, condition=%s, status=%s
                WHERE id=%s AND seller_id=%s RETURNING id
            """,
                (title.strip(), price, condition, status, book_id, session["user_id"]),
            )
            if status == "RESERVED":
                cur.execute("DELETE FROM cart_items WHERE book_id = %s", (book_id,))
    return jsonify({"message": "書籍更新成功"})


@app.route("/api/seller/sales", methods=["GET"])
def seller_sales():

    denied = seller_required()
    if denied:
        return denied

    with get_db_connection() as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    o.id AS order_id,
                    o.created_at AS order_date,
                    o.payment_method,
                    o.payment_status,

                    o.buyer_id AS buyer_id,
                    u.name AS buyer_name,

                    i.id AS order_item_id,
                    i.book_id,
                    i.title AS book_title,
                    i.price,
                    i.image_url

                FROM checkout_order_items i

                JOIN checkout_orders o
                    ON o.id = i.order_id

                JOIN books b
                    ON b.id = i.book_id

                JOIN users u
                    ON u.id = o.buyer_id

                WHERE b.seller_id = %s

                ORDER BY
                    o.created_at DESC,
                    o.id DESC,
                    i.id DESC

            """,
                (session["user_id"],),
            )

            rows = cur.fetchall()

    sales = []

    for row in rows:
        sales.append(
            {
                "order_id": row["order_id"],
                "order_date": row["order_date"].isoformat(),
                "payment_method": row["payment_method"],
                "payment_status": row["payment_status"],
                "buyer_id": row["buyer_id"],
                "buyer_name": row["buyer_name"],
                "order_item_id": row["order_item_id"],
                "book_id": row["book_id"],
                "book_title": row["book_title"],
                "price": str(row["price"]),
                "image_url": row["image_url"],
            }
        )

    return jsonify(
        {
            "sales": sales,
            "total_items": len(sales),
            "total_revenue": str(sum(Decimal(sale["price"]) for sale in sales)),
        }
    )


# -------------------- PUBLIC SELLER PROFILE --------------------


@app.route("/seller/<int:seller_id>")
def public_seller_page(seller_id):
    return render_template("seller_profile.html", seller_id=seller_id)


@app.route("/api/sellers/<int:seller_id>")
def public_seller_api(seller_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.name, u.created_at, u.seller_bio
                FROM users u
                WHERE u.id = %s
                  AND (
                    EXISTS (SELECT 1 FROM user_roles ur
                            WHERE ur.user_id = u.id AND ur.role = 'SELLER')
                    -- older account with no user_roles rows yet
                    OR (u.role = 'SELLER' AND NOT EXISTS (
                            SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id))
                  )
            """,
                (seller_id,),
            )
            seller = cur.fetchone()
            if not seller:
                return jsonify({"error": "找不到賣家"}), 404
            cur.execute(
                """
                SELECT id, title, price, condition, image_url, created_at
                FROM books WHERE seller_id = %s AND status = 'AVAILABLE'
                ORDER BY created_at DESC, id DESC
            """,
                (seller_id,),
            )
            books = cur.fetchall()
            cur.execute(
                """
                SELECT COUNT(*) AS sold_books,
                       COUNT(DISTINCT i.order_id) AS completed_orders
                FROM checkout_order_items i
                JOIN books b ON b.id = i.book_id
                WHERE b.seller_id = %s
            """,
                (seller_id,),
            )
            sales = cur.fetchone()
            cur.execute(
                """
                SELECT COUNT(*) AS review_count, ROUND(AVG(r.rating)::numeric, 1) AS avg_rating
                FROM seller_reviews r WHERE r.seller_id = %s
            """,
                (seller_id,),
            )
            rating = cur.fetchone()
            cur.execute(
                """
                SELECT r.rating, r.comment, r.created_at, u.name AS buyer_name
                FROM seller_reviews r JOIN users u ON u.id = r.buyer_id
                WHERE r.seller_id = %s ORDER BY r.created_at DESC LIMIT 20
            """,
                (seller_id,),
            )
            reviews = cur.fetchall()
    return jsonify(
        {
            "seller": seller,
            "books": books,
            "sales": sales,
            "rating": rating,
            "reviews": reviews,
        }
    )


@app.route("/api/seller/profile", methods=["GET", "PATCH"])
def seller_profile_settings():
    denied = seller_required()
    if denied:
        return denied
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if request.method == "PATCH":
                data = request.get_json(silent=True)
                if not isinstance(data, dict) or set(data) != {"seller_bio"}:
                    return jsonify({"error": "資料格式錯誤"}), 400
                bio = data["seller_bio"]
                if not isinstance(bio, str) or len(bio.strip()) > 300:
                    return jsonify({"error": "自我介紹不可超過 300 字"}), 400
                cur.execute(
                    "UPDATE users SET seller_bio = %s WHERE id = %s",
                    (bio.strip(), session["user_id"]),
                )
            cur.execute(
                "SELECT id, name, created_at, seller_bio FROM users WHERE id = %s",
                (session["user_id"],),
            )
            profile = cur.fetchone()
    return jsonify({"profile": profile})


@app.route("/api/seller/reviewable", methods=["GET"])
def reviewable_purchases():
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id AS item_id, i.title, b.seller_id,
                       u.name AS seller_name, r.id AS review_id
                FROM checkout_order_items i
                JOIN checkout_orders o ON o.id = i.order_id
                JOIN books b ON b.id = i.book_id
                JOIN users u ON u.id = b.seller_id
                LEFT JOIN seller_reviews r ON r.order_item_id = i.id
                WHERE o.buyer_id = %s
                ORDER BY o.created_at DESC, i.id DESC
            """,
                (session["user_id"],),
            )
            items = cur.fetchall()
    return jsonify({"items": items})


@app.route("/api/seller/reviews", methods=["POST"])
def create_seller_review():
    if "user_id" not in session:
        return jsonify({"error": "請先登入"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "資料格式錯誤"}), 400
    try:
        item_id, rating = int(data.get("order_item_id")), int(data.get("rating"))
    except (ValueError, TypeError):
        return jsonify({"error": "訂單或評分不正確"}), 400
    comment = data.get("comment", "")
    if (
        not isinstance(comment, str)
        or len(comment.strip()) > 500
        or rating not in range(1, 6)
    ):
        return jsonify({"error": "評分需為 1–5，評論最多 500 字"}), 400
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT b.seller_id
                FROM checkout_order_items i
                JOIN checkout_orders o ON o.id = i.order_id
                JOIN books b ON b.id = i.book_id
                WHERE i.id = %s AND o.buyer_id = %s
            """,
                (item_id, session["user_id"]),
            )
            item = cur.fetchone()
            if not item or item["seller_id"] == session["user_id"]:
                return jsonify({"error": "只有實際買家可以評價該筆交易"}), 403
            cur.execute(
                """
                INSERT INTO seller_reviews (order_item_id, buyer_id, seller_id, rating, comment)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (order_item_id) DO NOTHING RETURNING id
            """,
                (
                    item_id,
                    session["user_id"],
                    item["seller_id"],
                    rating,
                    comment.strip(),
                ),
            )
            if not cur.fetchone():
                return jsonify({"error": "這筆交易已評價過"}), 409
    return jsonify({"message": "評價已送出"}), 201


# -------------------- RUN SERVER --------------------

if __name__ == "__main__":
    app.run(debug=True)
