from flask import Flask
import sys

sys.path.insert(0, "..")

app = Flask(__name__)
app.config.from_object('config')

try:
    from . import (
        views,
        forms
    )
except Exception:
    raise
