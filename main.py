import json
from flask import Flask,render_template
import hashlib
with open("config.json") as f:
    config=json.load(f)
with open("database.json") as f:
    database=json.load(f)

app=Flask(__name__)

@app.route("/")
def root():
    return render_template("docs.html")