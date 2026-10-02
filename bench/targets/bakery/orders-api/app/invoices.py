import hashlib
import os

from flask import Blueprint, Response, abort, g, request

from . import config
from .auth import login_required

bp = Blueprint("invoices", __name__)


def _etag(body):
    return hashlib.md5(body).hexdigest()


@bp.get("/brand/asset")
def brand_asset():
    name = request.args.get("name", "logo.png")
    root = os.path.realpath(config.BRAND_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        abort(404)
    with open(path, "rb") as handle:
        body = handle.read()
    return Response(body, headers={"ETag": _etag(body)})


@bp.get("/invoices/download")
@login_required
def download_invoice():
    name = request.args.get("name", "")
    path = os.path.join(config.INVOICE_DIR, str(g.user["uid"]), name)
    if not os.path.isfile(path):
        abort(404)
    with open(path, "rb") as handle:
        body = handle.read()
    return Response(body, mimetype="application/pdf", headers={"ETag": _etag(body)})
