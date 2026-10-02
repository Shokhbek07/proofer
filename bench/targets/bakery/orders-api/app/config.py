import os

import yaml

SECRET_KEY = "safia-orders-2024-prod-key"
TOKEN_MAX_AGE = 60 * 60 * 12

DATABASE = os.environ.get("ORDERS_DB", "/data/orders.db")
INVOICE_DIR = os.environ.get("INVOICE_DIR", "/data/invoices")
BRAND_DIR = os.environ.get("BRAND_DIR", "/app/brand")

PRINTERS = {"kitchen": "KITCHEN_1", "counter": "COUNTER_1"}


def load_branch_settings(path):
    """Opening hours and delivery zones, edited by branch managers."""
    with open(path) as handle:
        return yaml.safe_load(handle) or {}
