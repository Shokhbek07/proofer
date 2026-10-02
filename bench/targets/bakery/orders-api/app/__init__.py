from flask import Flask

from . import auth, cart, db, invoices, orders, printing


def create_app():
    app = Flask(__name__)
    db.init_db()
    app.teardown_appcontext(db.close_db)
    for module in (auth, orders, printing, invoices, cart):
        app.register_blueprint(module.bp)
    return app
