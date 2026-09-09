import os
import time
from datetime import timedelta

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, jwt_required

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

    print(
        "Run: pip install supabase"
    )


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# CORS
# ============================================================

CORS(
    app
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

    if not SUPABASE_URL:
        print(
            "SUPABASE_URL is missing."
        )

    if not SUPABASE_KEY:
        print(
            "SUPABASE_KEY is missing."
        )


# ============================================================
# DEBUG INFORMATION
# ============================================================

print("=" * 60)

print(
    "Environment file:",
    ENV_FILE
)

print(
    "MAIL_USERNAME configured:",
    bool(MAIL_USERNAME)
)

print(
    "MAIL_PASSWORD configured:",
    bool(MAIL_PASSWORD)
)

print(
    "SUPABASE_URL configured:",
    bool(SUPABASE_URL)
)

print(
    "SUPABASE_KEY configured:",
    bool(SUPABASE_KEY)
)

print(
    "SUPABASE connected:",
    bool(supabase)
)

print("=" * 60)


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
            f"Starting scan for: {target}"
        )

        # ----------------------------------------------------
        # START TIMER
        # ----------------------------------------------------

        start_time = time.time()

        # ----------------------------------------------------
        # RUN NMAP SCANNER
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

        print(
            f"Results found: {len(results)}"
        )

        print(
            f"Scan duration: {scan_duration} seconds"
        )


        # ====================================================
        # SAVE SCAN TO SUPABASE
        # ====================================================

        if supabase:

            try:

                supabase.table(
                    "scans"
                ).insert({

                    "target":
                    target,

                    "results":
                    results,

                    "scan_duration":
                    scan_duration

                }).execute()

                print(
                    "Scan saved to Supabase successfully."
                )

            except Exception as e:

                print(
                    "SUPABASE SAVE ERROR:",
                    str(e)
                )

        else:

            print(
                "Supabase unavailable. Scan not saved."
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
            scan_duration,

            "supabase_saved":
            bool(supabase)

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
        # CHECK SUPABASE
        # ----------------------------------------------------

        if not supabase:

            return jsonify({

                "message":
                "Supabase is not configured.",

                "history":
                []

            }), 200


        # ----------------------------------------------------
        # GET HISTORY
        # ----------------------------------------------------

        response = (

            supabase
            .table("scans")
            .select("*")
            .order(
                "created_at",
                desc=True
            )
            .limit(20)
            .execute()

        )


        print(
            f"History records found: {len(response.data)}"
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
# DELETE SINGLE HISTORY RECORD
# ============================================================

@app.route(
    "/history/<int:scan_id>",
    methods=["DELETE"]
)
@jwt_required()
def delete_history(scan_id):

    try:

        # ----------------------------------------------------
        # CHECK SUPABASE
        # ----------------------------------------------------

        if not supabase:

            return jsonify({

                "error":
                "Supabase is not configured."

            }), 500


        # ----------------------------------------------------
        # DELETE RECORD
        # ----------------------------------------------------

        response = (

            supabase
            .table("scans")
            .delete()
            .eq(
                "id",
                scan_id
            )
            .execute()

        )


        print(
            f"Deleted scan history record: {scan_id}"
        )


        return jsonify({

            "message":
            "Scan history deleted successfully.",

            "id":
            scan_id

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
# DELETE ALL HISTORY RECORDS
# ============================================================

@app.route(
    "/history",
    methods=["DELETE"]
)
@jwt_required()
def delete_all_history():

    try:

        # ----------------------------------------------------
        # CHECK SUPABASE
        # ----------------------------------------------------

        if not supabase:

            return jsonify({

                "error":
                "Supabase is not configured."

            }), 500


        # ----------------------------------------------------
        # DELETE ALL RECORDS
        # ----------------------------------------------------

        response = (

            supabase
            .table("scans")
            .delete()
            .neq(
                "id",
                0
            )
            .execute()

        )


        print(
            "All scan history records deleted."
        )


        return jsonify({

            "message":
            "All scan history deleted successfully."

        }), 200


    except Exception as e:

        print(
            "DELETE ALL HISTORY ERROR:",
            str(e)
        )

        return jsonify({

            "error":
            "Failed to delete all scan history.",

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
        # BUILD HTML TABLE
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

            cves = item.get(
                "cves",
                []
            )


            cve_text = (
                "No CVE found"
            )


            if cves:

                cve_items = []


                for cve in cves:

                    cve_id = cve.get(
                        "cve_id",
                        "-"
                    )

                    score = cve.get(
                        "cvss_score"
                    )


                    if score is not None:

                        cve_items.append(

                            f"{cve_id} "
                            f"(CVSS: {score})"

                        )

                    else:

                        cve_items.append(
                            cve_id
                        )


                cve_text = "<br>".join(
                    cve_items
                )


            rows += f"""

                <tr>

                    <td>
                        {port}
                    </td>

                    <td>
                        {state}
                    </td>

                    <td>
                        {service}
                    </td>

                    <td>
                        {version}
                    </td>

                    <td>
                        {risk}
                    </td>

                    <td>
                        {recommendation}
                    </td>

                    <td>
                        {cve_text}
                    </td>

                </tr>

            """


        # ====================================================
        # EMAIL HTML
        # ====================================================

        html_content = f"""

        <!DOCTYPE html>

        <html>

        <head>

            <meta charset="UTF-8">

            <style>

                body {{
                    font-family: Arial, sans-serif;
                    background: #f4f6f8;
                    padding: 25px;
                    color: #222;
                }}

                .container {{
                    max-width: 1100px;
                    margin: auto;
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                }}

                h1 {{
                    color: #2563eb;
                }}

                .info {{
                    margin-bottom: 20px;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}

                th {{
                    background: #2563eb;
                    color: white;
                    padding: 10px;
                    text-align: left;
                }}

                td {{
                    border: 1px solid #ddd;
                    padding: 10px;
                    vertical-align: top;
                }}

                tr:nth-child(even) {{
                    background: #f8fafc;
                }}

                .footer {{
                    margin-top: 25px;
                    color: #777;
                    font-size: 12px;
                }}

            </style>

        </head>


        <body>

            <div class="container">

                <h1>
                    Port Scanner Security Report
                </h1>


                <div class="info">

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


                    <p>

                        <strong>
                            Total Results:
                        </strong>

                        {len(results)}

                    </p>

                </div>


                <table>

                    <thead>

                        <tr>

                            <th>
                                Port
                            </th>

                            <th>
                                State
                            </th>

                            <th>
                                Service
                            </th>

                            <th>
                                Version
                            </th>

                            <th>
                                Risk
                            </th>

                            <th>
                                Recommendation
                            </th>

                            <th>
                                CVE
                            </th>

                        </tr>

                    </thead>


                    <tbody>

                        {rows}

                    </tbody>

                </table>


                <div class="footer">

                    Generated by
                    Port Scanner Security Tool.

                </div>

            </div>

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


        print(
            f"Email report sent to: {recipient}"
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
        "Backend URL: http://127.0.0.1:5000"
    )

    print(
        "Frontend URL: http://127.0.0.1:5173"
    )

    print(
        "Supabase:",
        "Connected" if supabase else "Not Connected"
    )

    print("=" * 60)


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )
