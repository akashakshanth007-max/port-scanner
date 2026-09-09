import os
import time
from datetime import timedelta

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from dotenv import load_dotenv

from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    get_jwt_identity
)

from scanner import scan_target
from auth import auth, bcrypt, init_auth_db


# ============================================================
# BASE DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env"
)


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv(
    ENV_FILE,
    override=True
)


# ============================================================
# SUPABASE IMPORT
# ============================================================

try:

    from supabase import create_client

except ImportError:

    create_client = None

    print(
        "WARNING: Supabase package is not installed."
    )


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# CORS
# ============================================================

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)


# ============================================================
# JWT CONFIGURATION
# ============================================================

app.config["JWT_SECRET_KEY"] = os.getenv(
    "JWT_SECRET_KEY",
    "port-scanner-development-secret-key-2026"
)

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    hours=24
)

jwt = JWTManager(app)


# ============================================================
# BCRYPT
# ============================================================

bcrypt.init_app(app)


# ============================================================
# EMAIL CONFIGURATION
# ============================================================

MAIL_USERNAME = os.getenv(
    "MAIL_USERNAME"
)

MAIL_PASSWORD = os.getenv(
    "MAIL_PASSWORD"
)

app.config["MAIL_SERVER"] = "smtp.gmail.com"

app.config["MAIL_PORT"] = 587

app.config["MAIL_USE_TLS"] = True

app.config["MAIL_USE_SSL"] = False

app.config["MAIL_USERNAME"] = MAIL_USERNAME

app.config["MAIL_PASSWORD"] = MAIL_PASSWORD

app.config["MAIL_DEFAULT_SENDER"] = MAIL_USERNAME

mail = Mail(app)


# ============================================================
# SUPABASE CONFIGURATION
# ============================================================

SUPABASE_URL = os.getenv(
    "SUPABASE_URL"
)

SUPABASE_KEY = os.getenv(
    "SUPABASE_KEY"
)

supabase = None


if (
    create_client
    and SUPABASE_URL
    and SUPABASE_KEY
):

    try:

        supabase = create_client(
            SUPABASE_URL,
            SUPABASE_KEY
        )

        print(
            "Supabase connected successfully."
        )

    except Exception as e:

        print(
            "SUPABASE CONNECTION ERROR:",
            str(e)
        )

else:

    print(
        "WARNING: Supabase is not configured."
    )


# ============================================================
# AUTH BLUEPRINT
# ============================================================

app.register_blueprint(
    auth
)


# ============================================================
# ROOT ROUTE
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({

        "message":
        "Port Scanner API is running.",

        "status":
        "Online"

    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({

        "status":
        "healthy",

        "service":
        "port-scanner-backend",

        "supabase":
        bool(supabase)

    })


# ============================================================
# SCAN ROUTE
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
@jwt_required()
def scan():

    try:

        # ----------------------------------------------------
        # GET CURRENT USER ID
        # ----------------------------------------------------

        user_id = get_jwt_identity()


        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({

                "error":
                "Request body is required."

            }), 400


        target = data.get(
            "target",
            ""
        ).strip()


        if not target:

            return jsonify({

                "error":
                "Target is required."

            }), 400


        print(
            f"Starting scan for user {user_id}: {target}"
        )


        # ----------------------------------------------------
        # START TIMER
        # ----------------------------------------------------

        start_time = time.time()


        # ----------------------------------------------------
        # RUN SCANNER
        # ----------------------------------------------------

        results = scan_target(
            target
        )


        # ----------------------------------------------------
        # SCAN DURATION
        # ----------------------------------------------------

        scan_duration = round(
            time.time() - start_time,
            2
        )


        print(
            f"Scan completed for: {target}"
        )


        # ====================================================
        # SAVE SCAN TO SUPABASE
        # ====================================================

        if supabase:

            try:

                supabase.table(
                    "scans"
                ).insert({

                    "user_id":
                    int(user_id),

                    "target":
                    target,

                    "results":
                    results,

                    "scan_duration":
                    scan_duration

                }).execute()


                print(
                    f"Scan saved for user: {user_id}"
                )


            except Exception as e:

                print(
                    "SUPABASE SAVE ERROR:",
                    str(e)
                )


        else:

            print(
                "Supabase unavailable."
            )


        # ====================================================
        # RESPONSE
        # ====================================================

        return jsonify({

            "target":
            target,

            "results":
            results,

            "scan_duration":
            scan_duration

        }), 200


    except Exception as e:

        print(
            "SCAN ERROR:",
            str(e)
        )


        return jsonify({

            "error":
            "Scan failed.",

            "details":
            str(e)

        }), 500


# ============================================================
# HISTORY - GET
# ============================================================

@app.route(
    "/history",
    methods=["GET"]
)
@jwt_required()
def history():

    try:

        # ----------------------------------------------------
        # GET CURRENT USER ID
        # ----------------------------------------------------

        user_id = get_jwt_identity()


        if not supabase:

            return jsonify({

                "history":
                []

            }), 200


        # ----------------------------------------------------
        # GET ONLY CURRENT USER HISTORY
        # ----------------------------------------------------

        response = (

            supabase
            .table("scans")
            .select("*")
            .eq(
                "user_id",
                int(user_id)
            )
            .order(
                "created_at",
                desc=True
            )
            .limit(20)
            .execute()

        )


        return jsonify({

            "history":
            response.data

        }), 200


    except Exception as e:

        print(
            "HISTORY ERROR:",
            str(e)
        )


        return jsonify({

            "error":
            "Failed to load scan history.",

            "details":
            str(e)

        }), 500


# ============================================================
# DELETE SINGLE HISTORY
# ============================================================

@app.route(
    "/history/<int:scan_id>",
    methods=["DELETE"]
)
@jwt_required()
def delete_history(scan_id):

    try:

        # ----------------------------------------------------
        # GET CURRENT USER
        # ----------------------------------------------------

        user_id = get_jwt_identity()


        if not supabase:

            return jsonify({

                "error":
                "Supabase is not configured."

            }), 500


        # ----------------------------------------------------
        # DELETE ONLY CURRENT USER RECORD
        # ----------------------------------------------------

        supabase.table(
            "scans"
        ).delete().eq(
            "id",
            scan_id
        ).eq(
            "user_id",
            int(user_id)
        ).execute()


        return jsonify({

            "message":
            "Scan history deleted successfully."

        }), 200


    except Exception as e:

        print(
            "DELETE HISTORY ERROR:",
            str(e)
        )


        return jsonify({

            "error":
            "Failed to delete scan history.",

            "details":
            str(e)

        }), 500


# ============================================================
# DELETE ALL HISTORY
# ============================================================

@app.route(
    "/history",
    methods=["DELETE"]
)
@jwt_required()
def delete_all_history():

    try:

        # ----------------------------------------------------
        # GET CURRENT USER
        # ----------------------------------------------------

        user_id = get_jwt_identity()


        if not supabase:

            return jsonify({

                "error":
                "Supabase is not configured."

            }), 500


        # ----------------------------------------------------
        # DELETE ONLY CURRENT USER HISTORY
        # ----------------------------------------------------

        supabase.table(
            "scans"
        ).delete().eq(
            "user_id",
            int(user_id)
        ).execute()


        return jsonify({

            "message":
            "All your scan history deleted successfully."

        }), 200


    except Exception as e:

        print(
            "DELETE ALL HISTORY ERROR:",
            str(e)
        )


        return jsonify({

            "error":
            "Failed to delete scan history.",

            "details":
            str(e)

        }), 500


# ============================================================
# EMAIL REPORT
# ============================================================

@app.route(
    "/email-report",
    methods=["POST"]
)
@jwt_required()
def email_report():

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "error":
                "Request body is required."

            }), 400


        recipient = data.get(
            "recipient",
            ""
        ).strip()


        target = data.get(
            "target",
            ""
        ).strip()


        results = data.get(
            "results",
            []
        )


        scan_duration = data.get(
            "scan_duration",
            "-"
        )


        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not recipient:

            return jsonify({

                "error":
                "Recipient email is required."

            }), 400


        if "@" not in recipient:

            return jsonify({

                "error":
                "Invalid recipient email."

            }), 400


        if not target:

            return jsonify({

                "error":
                "Target is required."

            }), 400


        if not results:

            return jsonify({

                "error":
                "No scan results available."

            }), 400


        if not MAIL_USERNAME or not MAIL_PASSWORD:

            return jsonify({

                "error":
                "Email configuration is missing."

            }), 500


        # ====================================================
        # BUILD EMAIL ROWS
        # ====================================================

        rows = ""


        for item in results:

            port = item.get(
                "port",
                "-"
            )

            state = item.get(
                "state",
                "-"
            )

            service = item.get(
                "service",
                "-"
            )

            version = item.get(
                "version",
                "-"
            )

            risk = item.get(
                "risk",
                "-"
            )

            recommendation = item.get(
                "recommendation",
                "-"
            )


            rows += f"""

                <tr>

                    <td>{port}</td>

                    <td>{state}</td>

                    <td>{service}</td>

                    <td>{version}</td>

                    <td>{risk}</td>

                    <td>{recommendation}</td>

                </tr>

            """


        # ====================================================
        # EMAIL HTML
        # ====================================================

        html_content = f"""

        <html>

        <body>

            <h1>
                Port Scanner Security Report
            </h1>


            <p>

                <strong>
                    Target:
                </strong>

                {target}

            </p>


            <p>

                <strong>
                    Scan Duration:
                </strong>

                {scan_duration} seconds

            </p>


            <table
                border="1"
                cellpadding="8"
            >

                <tr>

                    <th>Port</th>

                    <th>State</th>

                    <th>Service</th>

                    <th>Version</th>

                    <th>Risk</th>

                    <th>Recommendation</th>

                </tr>


                {rows}


            </table>


        </body>

        </html>

        """


        # ====================================================
        # SEND EMAIL
        # ====================================================

        msg = Message(

            subject=
            f"Port Scanner Report - {target}",

            recipients=[
                recipient
            ]

        )


        msg.html = html_content


        mail.send(
            msg
        )


        return jsonify({

            "message":
            "Email report sent successfully.",

            "recipient":
            recipient

        }), 200


    except Exception as e:

        print(
            "EMAIL ERROR:",
            str(e)
        )


        return jsonify({

            "error":
            "Failed to send email report.",

            "details":
            str(e)

        }), 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "error":
        "Endpoint not found."

    }), 404


@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({

        "error":
        "Method not allowed."

    }), 405


# ============================================================
# INITIALIZE AUTH DATABASE
# ============================================================

try:

    init_auth_db()

    print(
        "Authentication database initialized."
    )

except Exception as e:

    print(
        "AUTH DATABASE ERROR:",
        str(e)
    )


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "Starting Port Scanner Backend..."
    )

    print(
        "Supabase:",
        "Connected"
        if supabase
        else "Not Connected"
    )

    print("=" * 60)


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )
