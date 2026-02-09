import json
import os
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

STATE_DIR = os.environ.get("HOMENETSEC_STATE_DIR", "/state")
FEEDBACK_PATH = os.path.join(STATE_DIR, "feedback.json")


def _load_feedback():
    try:
        with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"days": {}}
    except Exception:
        # Corrupt/partial file: don't crash the server
        return {"days": {}, "_warning": "failed_to_parse_existing"}


def _atomic_write(obj):
    os.makedirs(os.path.dirname(FEEDBACK_PATH), exist_ok=True)
    tmp = FEEDBACK_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, FEEDBACK_PATH)


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


@app.get("/api/feedback")
def get_feedback():
    day = (request.args.get("day") or "").strip()
    db = _load_feedback()
    days = db.get("days") or {}
    if not day:
        return jsonify({"days": list(days.keys())})
    return jsonify({"day": day, "feedback": days.get(day, {})})


@app.post("/api/feedback")
def put_feedback():
    data = request.get_json(force=True, silent=True) or {}
    day = (data.get("day") or "").strip()
    if not day:
        return jsonify({"error": "missing day"}), 400

    # Accept either a full map update, or a single alert update.
    full = data.get("feedback")
    alert_id = (data.get("alert_id") or data.get("id") or "").strip()

    db = _load_feedback()
    db.setdefault("days", {})
    db.setdefault("updated_at", time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    if isinstance(full, dict):
        db["days"][day] = full
    elif alert_id:
        db["days"].setdefault(day, {})
        rec = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "verdict": data.get("verdict") or "unsure",
            "note": data.get("note") or "",
            "action": data.get("action") or "",
            "action_value": data.get("action_value") or "",
        }
        db["days"][day][alert_id] = rec
    else:
        return jsonify({"error": "provide feedback map or alert_id"}), 400

    _atomic_write(db)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # For local debugging; container uses gunicorn.
    app.run(host="0.0.0.0", port=8000)
