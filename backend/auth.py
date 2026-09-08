from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)
import sqlite3


auth = Blueprint("auth", __name__)

bcrypt = Bcrypt()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    conn = sqlite3.connect("scanner.db")
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# CREATE USERS TABLE
# ============================================================

def init_auth_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# REGISTER
# ============================================================

@auth.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required."
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters."
        }), 400

    hashed_password = bcrypt.generate_password_hash(
        password
    ).decode("utf-8")

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO users (username, password)
            VALUES (?, ?)
            """,
            (username, hashed_password)
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error": "Username already exists."
        }), 409

    conn.close()

    return jsonify({
        "message": "Registration successful."
    }), 201


# ============================================================
# LOGIN
# ============================================================

@auth.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required."
        }), 400

    conn = get_db()

    user = conn.execute(
        """
        SELECT * FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({
            "error": "Invalid username or password."
        }), 401

    if not bcrypt.check_password_hash(
        user["password"],
        password
    ):
        return jsonify({
            "error": "Invalid username or password."
        }), 401

    access_token = create_access_token(
        identity=str(user["id"])
    )

    return jsonify({
        "message": "Login successful.",
        "access_token": access_token,
        "username": username
    }), 200


# ============================================================
# CHECK LOGIN
# ============================================================

@auth.route("/profile", methods=["GET"])
@jwt_required()
def profile():

    user_id = get_jwt_identity()

    conn = get_db()

    user = conn.execute(
        """
        SELECT id, username
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({
            "error": "User not found."
        }), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"]
    }), 200