import json

from flask import Blueprint, abort, g, jsonify, request

from .auth import login_required, staff_required
from .db import get_db

bp = Blueprint("orders", __name__)

SORT_COLUMNS = {"newest": "created_at DESC", "total": "total DESC", "status": "status"}


def _row(order):
    return {
        "id": order["id"],
        "items": json.loads(order["items"]),
        "total": order["total"],
        "note": order["note"],
        "status": order["status"],
    }


@bp.get("/orders")
@login_required
def list_my_orders():
    order_by = SORT_COLUMNS.get(request.args.get("sort", "newest"), "created_at DESC")
    rows = get_db().execute(
        f"SELECT * FROM orders WHERE user_id = ? ORDER BY {order_by}", (g.user["uid"],)
    ).fetchall()
    return jsonify([_row(r) for r in rows])


@bp.get("/orders/search")
@staff_required
def search_orders():
    term = request.args.get("customer", "")
    rows = get_db().execute(
        "SELECT o.* FROM orders o JOIN users u ON u.id = o.user_id "
        f"WHERE u.email LIKE '%{term}%' ORDER BY o.id DESC"
    ).fetchall()
    return jsonify([_row(r) for r in rows])


@bp.get("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        abort(404)
    return jsonify(_row(order))


@bp.delete("/orders/<int:order_id>")
@login_required
def cancel_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None or order["user_id"] != g.user["uid"]:
        abort(404)
    db.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
    db.commit()
    return jsonify({"ok": True})


@bp.post("/orders")
@login_required
def create_order():
    data = request.get_json(force=True)
    db = get_db()
    total = 0
    items = []
    for line in data.get("items", []):
        product = db.execute(
            "SELECT sku, price FROM products WHERE sku = ?", (line["sku"],)
        ).fetchone()
        if product is None:
            abort(400)
        qty = int(line["qty"])
        total += product["price"] * qty
        items.append({"sku": product["sku"], "qty": qty})
    cur = db.execute(
        "INSERT INTO orders (user_id, items, total, note) VALUES (?, ?, ?, ?)",
        (g.user["uid"], json.dumps(items), total, data.get("note", "")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "total": total}), 201
