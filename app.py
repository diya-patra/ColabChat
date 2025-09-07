# app.py
import os
import json
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import jwt
from dotenv import load_dotenv
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# === Import Chatbot Logic ===
from ch import get_ai_response


# === Load Environment ===
load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/colabchat")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
PORT = int(os.getenv("PORT", "5000"))
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "1440"))  # 24h

# === Flask App ===
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app, supports_credentials=True)

# === Logging Setup ===
os.makedirs("logs", exist_ok=True)
logger = logging.getLogger("colabchat")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("logs/app.log")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# === MongoDB ===
client = MongoClient(MONGODB_URI)
db = client.get_database()  # default from URI
users_col = db["users"]
chats_col = db["chats"]

# === Models / Helpers ===
def serialize_id(obj):
    obj["_id"] = str(obj["_id"])
    return obj

def get_user_by_email(email: str):
    return users_col.find_one({"email": email})

def get_user_by_id(user_id: str):
    return users_col.find_one({"_id": ObjectId(user_id)})

def create_user(username: str, email: str, password: str):
    if get_user_by_email(email):
        return None, "Email already registered"
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    res = users_col.insert_one({
        "username": username,
        "email": email,
        "passwordHash": pw_hash
    })
    return str(res.inserted_id), None

def verify_password(password: str, password_hash: str):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False

def create_chat(user_id: str, first_message=None):
    doc = {
        "userId": ObjectId(user_id),
        "messages": []
    }
    if first_message:
        doc["messages"].append(first_message)
    res = chats_col.insert_one(doc)
    return str(res.inserted_id)

def append_message(chat_id: str, message: dict):
    chats_col.update_one({"_id": ObjectId(chat_id)}, {"$push": {"messages": message}})

def get_user_chats(user_id: str, limit=50):
    cur = chats_col.find({"userId": ObjectId(user_id)}).sort([("_id", -1)]).limit(limit)
    out = []
    for c in cur:
        c["_id"] = str(c["_id"])
        c["userId"] = str(c["userId"])
        out.append(c)
    return out

def get_chat(chat_id: str, user_id: str):
    chat = chats_col.find_one({"_id": ObjectId(chat_id), "userId": ObjectId(user_id)})
    if chat:
        chat["_id"] = str(chat["_id"])
        chat["userId"] = str(chat["userId"])
    return chat

# === JWT Helpers ===
def create_token(user_id: str):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def current_user():
    token = request.cookies.get("token")
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    user = get_user_by_id(payload["sub"])
    return user

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.accept_mimetypes.best == "application/json" or request.is_json:
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs, user=user)
    return wrapper

# === Request/Response Logging ===
SENSITIVE_FIELDS = {"password", "confirmPassword"}

@app.before_request
def log_request():
    try:
        payload = None
        if request.is_json:
            data = request.get_json(silent=True) or {}
            redacted = {k: ("<redacted>" if k in SENSITIVE_FIELDS else v) for k, v in data.items()}
            payload = json.dumps(redacted)
        elif request.form:
            redacted = {k: ("<redacted>" if k in SENSITIVE_FIELDS else v) for k, v in request.form.items()}
            payload = json.dumps(redacted)
        logger.info(f"REQ {request.method} {request.path} | IP={request.remote_addr} | Body={payload}")
    except Exception as e:
        logger.error(f"REQ-LOG-ERR: {e}")

@app.after_request
def log_response(response):
    try:
        user = current_user()
        uid = str(user["_id"]) if user else "anon"
        logger.info(f"RES {request.method} {request.path} | Status={response.status_code} | User={uid}")
    except Exception as e:
        logger.error(f"RES-LOG-ERR: {e}")
    return response

# === Chatbot Integration ===
def get_bot_reply(message: str) -> str:
    return get_ai_response(message)

# === Routes ===

# Landing Page
@app.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)

# Sign Up
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not email or not password:
        return render_template("signup.html", error="All fields are required.", form={"username": username, "email": email})

    user_id, err = create_user(username, email, password)
    if err:
        return render_template("signup.html", error=err, form={"username": username, "email": email})

    token = create_token(user_id)
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("token", token, httponly=True, samesite="Lax")
    return resp

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = get_user_by_email(email)
    if not user or not verify_password(password, user.get("passwordHash", "")):
        return render_template("login.html", error="Invalid credentials.", form={"email": email})

    token = create_token(str(user["_id"]))
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("token", token, httponly=True, samesite="Lax")
    return resp

# Logout
@app.route("/logout", methods=["POST", "GET"])
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("token", "", expires=0)
    return resp

# Dashboard
@app.route("/dashboard")
@login_required
def dashboard(user):
    return render_template("dashboard.html", username=user.get("username"), email=user.get("email"))

# API: Get previous chats
@app.route("/chats", methods=["GET"])
@login_required
def chats(user):
    arr = get_user_chats(str(user["_id"]))
    summaries = []
    for c in arr:
        first = c["messages"][0]["text"] if c["messages"] else "(empty)"
        summaries.append({
            "id": c["_id"],
            "title": (first[:40] + "…") if len(first) > 40 else first
        })
    return jsonify({"chats": summaries})

# API: Load a chat by id
@app.route("/chats/<chat_id>", methods=["GET"])
@login_required
def get_chat_by_id(user, chat_id):
    chat = get_chat(chat_id, str(user["_id"]))
    if not chat:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"chat": chat})

# API: Create a new empty chat
@app.route("/chats", methods=["POST"])
@login_required
def create_new_chat(user):
    chat_id = create_chat(str(user["_id"]))
    return jsonify({"chatId": chat_id})

# API: Chat endpoint
@app.route("/chat", methods=["POST"])
@login_required
def chat_endpoint(user):
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    chat_id = data.get("chatId")
    if not message:
        return jsonify({"error": "Message is required."}), 400

    ts = datetime.now(timezone.utc).isoformat()
    user_msg = {"sender": "user", "text": message, "timestamp": ts}

    # Create chat if missing
    if not chat_id:
        chat_id = create_chat(str(user["_id"]), first_message=user_msg)
    else:
        if not get_chat(chat_id, str(user["_id"])):
            return jsonify({"error": "Chat not found"}), 404
        append_message(chat_id, user_msg)

    # AI reply
    bot_text = get_bot_reply(message)
    bot_msg = {"sender": "bot", "text": bot_text, "timestamp": datetime.now(timezone.utc).isoformat()}
    append_message(chat_id, bot_msg)

    return jsonify({
        "chatId": chat_id,
        "reply": bot_text,
        "messages": [user_msg, bot_msg]
    })

# Health check
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
