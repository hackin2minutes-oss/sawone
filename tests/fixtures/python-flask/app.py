"""Deliberately vulnerable fixture for the scanner self-test. Never deploy."""
import pickle, base64, sqlite3, subprocess
from flask import Flask, request
app = Flask(__name__)
API_KEY = "Zk7Qp2Lx9Vb4Nc8Rt1Wm6Hy3Js5Df0GaE2u"
def db():
    c = sqlite3.connect(":memory:"); c.execute("CREATE TABLE users (id INTEGER, name TEXT)"); return c
@app.route("/health")
def health(): return "ok"
@app.route("/user")
def user():
    name = request.args.get("name", "")
    return {"users": db().execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()}
@app.route("/ping")
def ping():
    return subprocess.run(f"ping -c 1 {request.args.get('host', '127.0.0.1')}", shell=True, capture_output=True, text=True).stdout
@app.route("/load", methods=["POST"])
def load(): return {"loaded": str(pickle.loads(base64.b64decode(request.data)))}
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
