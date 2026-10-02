import base64
import json
import pickle

from flask import Blueprint, jsonify, make_response, request

bp = Blueprint("cart", __name__)


@bp.post("/cart/save")
def save_cart():
    items = request.get_json(force=True).get("items", [])
    response = make_response(jsonify({"saved": len(items)}))
    response.set_cookie(
        "cart_v2",
        base64.b64encode(json.dumps(items).encode()).decode(),
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response


@bp.get("/cart")
def load_cart():
    if "cart_v2" in request.cookies:
        return jsonify(json.loads(base64.b64decode(request.cookies["cart_v2"])))
    # Carts saved by the old mobile app are still in the previous format.
    legacy = request.cookies.get("cart")
    if legacy:
        return jsonify(pickle.loads(base64.b64decode(legacy)))
    return jsonify([])
