from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, hashlib, secrets, requests, json, socket, whois, tempfile, csv
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config.from_pyfile("config.py")

DB = "database.db"

# -------------------------- AUTH --------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or session.get("is_admin") != 1:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# -------------------------- USER ROUTES --------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        api_key = secrets.token_hex(16)
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password, api_key) VALUES (?, ?, ?)", 
                         (username, password, api_key))
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Username already exists!"
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and user["password"] == password:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            return redirect(url_for("index"))
        return "Invalid credentials"
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------------- SUBDOMAIN FUNCTIONS --------------------------
def passive_subdomain_lookup(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code != 200:
            return []

        entries = json.loads(res.text)
        subs = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                if sub.endswith(domain):
                    subs.add(sub.strip())
        return sorted(subs)
    except:
        return []

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except:
        return {"domain": domain, "ip": "Not found"}

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {k: str(v) for k, v in w.items()}
    except:
        return {"error": "WHOIS lookup failed"}

def screenshot_placeholder(subdomain):
    return f"https://via.placeholder.com/300x150?text={subdomain}"

# -------------------------- LOGGING --------------------------
def log_search(user_id, domain, sub_count):
    conn = get_db()
    conn.execute("INSERT INTO logs (user_id, domain, subdomains_count) VALUES (?, ?, ?)", 
                 (user_id, domain, sub_count))
    conn.commit()

# -------------------------- API ROUTES --------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session["username"])

@app.route("/api/subdomains", methods=["POST"])
@login_required
def api_subdomains():
    domain = request.json.get("domain")
    subs = passive_subdomain_lookup(domain)
    results = [{"subdomain": s, "screenshot": screenshot_placeholder(s)} for s in subs]
    log_search(session["user_id"], domain, len(subs))
    return jsonify({"domain": domain, "subdomains": results})

@app.route("/api/dns", methods=["POST"])
@login_required
def api_dns():
    domain = request.json.get("domain")
    return jsonify(dns_lookup(domain))

@app.route("/api/whois", methods=["POST"])
@login_required
def api_whois():
    domain = request.json.get("domain")
    return jsonify(whois_lookup(domain))

# -------------------------- EXPORT --------------------------
@app.route("/export/txt", methods=["POST"])
@login_required
def export_txt():
    subs = [s["subdomain"] for s in request.json.get("subdomains", [])]
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    with open(f.name, "w") as file:
        for s in subs:
            file.write(s + "\n")
    return send_file(f.name, as_attachment=True, download_name="subdomains.txt")

@app.route("/export/csv", methods=["POST"])
@login_required
def export_csv():
    subs = [s["subdomain"] for s in request.json.get("subdomains", [])]
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    with open(f.name, "w", newline="") as file:
        writer = csv.writer(file)
        for s in subs:
            writer.writerow([s])
    return send_file(f.name, as_attachment=True, download_name="subdomains.csv")

# -------------------------- ADMIN DASHBOARD --------------------------
@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    logs = conn.execute("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id=users.id ORDER BY timestamp DESC").fetchall()
    return render_template("admin.html", logs=logs)

# -------------------------- MAIN --------------------------
if __name__ == "__main__":
    app.secret_key = app.config["SECRET_KEY"]
    app.run(host="0.0.0.0", port=5000, debug=True)
