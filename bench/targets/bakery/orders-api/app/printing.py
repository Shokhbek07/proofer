import subprocess

from flask import Blueprint, abort, jsonify, request

from . import config
from .auth import staff_required

bp = Blueprint("printing", __name__)


@bp.get("/printers/<name>/status")
@staff_required
def printer_status(name):
    if name not in config.PRINTERS:
        abort(404)
    result = subprocess.run(
        ["lpstat", "-p", config.PRINTERS[name]], capture_output=True, text=True
    )
    return jsonify({"printer": name, "status": result.stdout.strip()})


@bp.post("/orders/<int:order_id>/print")
@staff_required
def print_ticket(order_id):
    printer = request.get_json(force=True).get("printer", "KITCHEN_1")
    ticket = f"/tmp/ticket-{order_id}.txt"
    result = subprocess.run(
        f"lp -d {printer} {ticket}", shell=True, capture_output=True, text=True
    )
    return jsonify({"queued": result.returncode == 0})
