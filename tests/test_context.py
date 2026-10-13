from proofer.context import COMPARES_IDENTITY, build_map
from proofer.workspace import Workspace


def flask_repo(tmp_path):
    (tmp_path / "auth.py").write_text(
        "def login_required(view):\n"
        "    return view\n"
        "\n"
        "def check_owner(record, user):\n"
        "    return record.owner_id == user.id\n"
    )
    (tmp_path / "orders.py").write_text(
        "from auth import login_required\n"
        "\n"
        "@bp.get('/orders')\n"
        "@login_required\n"
        "def list_orders():\n"
        "    return rows\n"
        "\n"
        "@bp.delete('/orders/<int:oid>')\n"
        "@login_required\n"
        "def cancel(oid):\n"
        "    if order.user_id != g.user.id:\n"
        "        abort(404)\n"
    )
    (tmp_path / "admin.py").write_text(
        "import auth\n"
        "\n"
        "@bp.post('/admin/wipe')\n"
        "def wipe():\n"
        "    auth.check_owner(thing, user)\n"
        "    return 'ok'\n"
    )
    return Workspace(tmp_path)


def test_python_entry_points_and_their_protections(tmp_path):
    pmap = build_map(flask_repo(tmp_path))
    by_name = {e.name: e for e in pmap.entries}
    assert by_name["list_orders"].route == "GET /orders"
    assert by_name["list_orders"].guards == ["login_required"]
    assert by_name["cancel"].guards == ["login_required", COMPARES_IDENTITY]
    assert by_name["wipe"].guards == ["auth.check_owner()"]


def test_rendered_map_compares_a_file_with_its_peers(tmp_path):
    ws = flask_repo(tmp_path)
    text = build_map(ws).render(ws, "admin.py")
    assert "POST /admin/wipe wipe (line 4): auth.check_owner()" in text
    assert "login_required: 2 of 2 entry points in 1 file(s), defined in auth.py:1" in text
    # check_owner is called through a module, so it is not an imported name; its
    # definition comes from the map instead.
    assert "--- auth.py (definition of check_owner) ---" in text
    assert text.index("<repo_data>") < text.index("Entry points in this file")
    assert "report findings only in `admin.py`" in text


def test_express_middleware_and_php_input_files(tmp_path):
    (tmp_path / "mw.js").write_text(
        "function requireUser(req, res, next) { next(); }\nmodule.exports = { requireUser };\n"
    )
    (tmp_path / "a.js").write_text(
        "router.get('/me', requireUser, (req, res) => res.json(req.user));\n"
        "router.post('/me', requireUser, async (req, res) => res.json({}));\n"
    )
    (tmp_path / "b.js").write_text("router.get('/feed', (req, res) => res.json(feed));\n")
    (tmp_path / "form.php").write_text("<?php\ncheckToken($_POST['t']);\n$x = $_POST['x'];\n")
    ws = Workspace(tmp_path)
    pmap = build_map(ws)
    routes = {(e.path, e.route): e.guards for e in pmap.entries}
    assert routes[("a.js", "GET /me")] == ["requireUser"]
    assert routes[("b.js", "GET /feed")] == []
    assert routes[("form.php", "reads request input")] == ["checkToken()"]
    text = pmap.render(ws, "b.js")
    assert "GET /feed handler (line 1): no protection found" in text
    assert "requireUser: 2 of 2 entry points in 1 file(s), defined in mw.js:1" in text


def test_files_outside_the_known_languages_get_no_map(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    ws = Workspace(tmp_path)
    assert build_map(ws).render(ws, "Dockerfile") == ""
