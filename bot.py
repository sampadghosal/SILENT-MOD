#!/usr/bin/env python3
"""SILENT MOD Firebase enforcement + Telegram admin bot.

Firebase is the persistent source of truth. This process is replaceable and may restart.
It does not modify Java, DEX, the verification HTML, or Firebase rules.
"""
from __future__ import annotations

import logging
import math
import os
import re
import shlex
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import firebase_admin
from firebase_admin import credentials, db

LOG = logging.getLogger("silent-mod-bot")
HTTP_TIMEOUT = 25
TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
HWID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SCAN_INTERVAL_SECONDS = max(60, int(os.getenv("SCAN_INTERVAL_SECONDS", "900")))
MAX_TELEGRAM_TEXT = 3900


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def enabled(name: str, default: bool = False) -> bool:
    raw = env(name, "true" if default else "false").lower()
    return raw in {"1", "true", "yes", "on"}


def parse_admin_ids() -> list[str]:
    raw = env("ADMIN_IDS")
    ids = [item.strip() for item in re.split(r"[,\s]+", raw) if item.strip()]
    if not ids or any(not item.isdigit() for item in ids):
        raise RuntimeError("Set ADMIN_IDS to one or more trusted numeric Telegram user IDs, comma-separated.")
    return list(dict.fromkeys(ids))


def init_firebase() -> None:
    if firebase_admin._apps:
        return
    fields = {
        "project_id": env("FIREBASE_PROJECT_ID"),
        "client_email": env("FIREBASE_CLIENT_EMAIL"),
        "private_key": env("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    }
    if not all(fields.values()) or not env("FIREBASE_DATABASE_URL"):
        raise RuntimeError("Missing Firebase Admin credentials or FIREBASE_DATABASE_URL.")
    account = {
        "type": "service_account",
        "project_id": fields["project_id"],
        "private_key_id": env("FIREBASE_PRIVATE_KEY_ID", "github-actions"),
        "private_key": fields["private_key"],
        "client_email": fields["client_email"],
        "client_id": env("FIREBASE_CLIENT_ID"),
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    firebase_admin.initialize_app(credentials.Certificate(account), {
        "databaseURL": env("FIREBASE_DATABASE_URL").rstrip("/")
    })
    LOG.info("Firebase Admin SDK connected.")


def ref(path: str):
    return db.reference(path)


def ensure_persistent_nodes() -> None:
    """Create only missing nodes; never reset existing Firebase state."""
    whitelist_ref = ref("whitelist")
    if whitelist_ref.get() is None:
        whitelist_ref.set({})
        LOG.warning("Created missing whitelist node as an empty object.")

    configured = parse_admin_ids()
    admins_ref = ref("telegram_admins")
    current = admins_ref.get()
    if current is None:
        current = {}
    if not isinstance(current, dict):
        raise RuntimeError("Firebase telegram_admins node is not an object; refusing to overwrite it.")
    changed = False
    for admin_id in configured:
        entry = current.get(admin_id)
        if not isinstance(entry, dict) or entry.get("role") != "owner":
            current[admin_id] = {
                "role": "owner",
                "added_by": "ADMIN_IDS bootstrap secret",
                "created_at": int(time.time() * 1000),
            }
            changed = True
    if admins_ref.get() is None or changed:
        admins_ref.set(current)

    for path in ("bot_state", "bot_meta"):
        node = ref(path).get()
        if node is None:
            ref(path).set({})


def firebase_server_time() -> datetime:
    """Ask RTDB to resolve its server timestamp sentinel; fail closed if unavailable."""
    stamp_ref = ref("bot_meta/server_time_ms")
    stamp_ref.set({".sv": "timestamp"})
    raw = stamp_ref.get()
    if not isinstance(raw, (int, float)) or not math.isfinite(float(raw)):
        raise RuntimeError("Firebase did not return a numeric server timestamp; no enforcement performed.")
    return datetime.fromtimestamp(float(raw) / 1000.0, tz=timezone.utc)


def current_timezone() -> ZoneInfo:
    try:
        return ZoneInfo(env("ACCESS_TIMEZONE", "Asia/Kolkata"))
    except ZoneInfoNotFoundError as exc:
        raise RuntimeError("ACCESS_TIMEZONE must be a valid IANA timezone, e.g. Asia/Kolkata.") from exc


def access_hours() -> float:
    value = ref("settings/global_config/access_hours").get()
    try:
        hours = float(value)
        if not math.isfinite(hours) or hours <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise RuntimeError("settings/global_config/access_hours is missing or invalid; refusing automatic enforcement.")
    return hours


def grace_hours() -> float:
    """Extra tolerance beyond configured access_hours; defaults to 2 hours."""
    raw = env("GRACE_HOURS") or "24"
    try:
        value = float(raw)
        if not math.isfinite(value) or value < 0 or value > 168:
            raise ValueError
    except (TypeError, ValueError):
        raise RuntimeError("GRACE_HOURS must be a number between 0 and 168.")
    return value


def parse_expiry(value: Any, tz: ZoneInfo) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                parsed = datetime.strptime(raw, fmt)
                break
            except ValueError:
                pass
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed.astimezone(timezone.utc)


def valid_hwid(value: str) -> bool:
    return bool(HWID_RE.fullmatch(value))


def extract_hwid(user_key: str, record: dict[str, Any]) -> tuple[str | None, bool]:
    prefix = user_key.split("_", 1)[0]
    stored = str(record.get("hwid", "")).strip()
    if not valid_hwid(prefix):
        return None, True
    # Existing Java logic accepts the raw HWID or the complete per-app user key.
    if stored and stored not in (prefix, user_key):
        return prefix, True
    if not stored:
        return prefix, True
    return prefix, False


def fetch_root() -> dict[str, Any]:
    value = ref("/").get()
    if not isinstance(value, dict):
        raise RuntimeError("Firebase root was not a JSON object.")
    return value


def dict_node(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def is_admin(user_id: str) -> bool:
    entry = ref(f"telegram_admins/{user_id}").get()
    return isinstance(entry, dict) and entry.get("role") in {"owner", "admin"}


def admin_role(user_id: str) -> str | None:
    entry = ref(f"telegram_admins/{user_id}").get()
    if isinstance(entry, dict) and entry.get("role") in {"owner", "admin"}:
        return str(entry["role"])
    return None


def telegram(method: str, payload: dict[str, Any]) -> dict[str, Any]:
    token = env("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is missing.")
    response = requests.post(TELEGRAM_API.format(token=token, method=method), json=payload, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API error for {method}: {data.get('description', 'unknown error')}")
    return data


def send_message(chat_id: str | int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:MAX_TELEGRAM_TEXT], "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    telegram("sendMessage", payload)


def alert_admins(text: str) -> None:
    target = env("TELEGRAM_CHAT_ID")
    if not target:
        # Private Telegram chat IDs generally match the user's numeric Telegram ID.
        target = parse_admin_ids()[0]
    send_message(target, text)


def get_whitelist() -> dict[str, Any]:
    value = ref("whitelist").get()
    if value is None:
        # Safe self-heal only for a genuinely missing node.
        ref("whitelist").set({})
        return {}
    if not isinstance(value, dict):
        raise RuntimeError("Firebase whitelist node is not an object; refusing to treat it as empty.")
    return value


def get_bans() -> dict[str, Any]:
    value = ref("banned_hwids").get()
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RuntimeError("Firebase banned_hwids node is not an object.")
    return value


def format_local(dt: datetime, tz: ZoneInfo) -> str:
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")


def run_scan(trigger: str = "scheduled", notify: bool = True) -> dict[str, Any]:
    """Run one scan. Writes bans only when AUTO_BAN=true."""
    tz = current_timezone()
    hours = access_hours()
    grace = grace_hours()
    now_utc = firebase_server_time()
    now_local = now_utc.astimezone(tz)
    data = fetch_root()
    users = dict_node(data, "users")
    whitelist = get_whitelist()
    banned = get_bans()
    auto_ban = enabled("AUTO_BAN", False)
    over_limit: list[dict[str, str]] = []
    newly_banned: list[dict[str, str]] = []
    mismatch_count = 0
    invalid_expiry_count = 0
    skipped_whitelist = 0
    threshold = now_utc + timedelta(hours=hours + grace)

    for user_key, raw_record in users.items():
        if not isinstance(raw_record, dict):
            continue
        hwid, mismatch = extract_hwid(str(user_key), raw_record)
        if mismatch or not hwid:
            mismatch_count += 1
            continue
        expiry = parse_expiry(raw_record.get("expiry"), tz)
        if expiry is None:
            invalid_expiry_count += 1
            continue
        if expiry <= threshold:
            continue
        if hwid in whitelist:
            skipped_whitelist += 1
            continue
        item = {
            "hwid": hwid,
            "user_key": str(user_key),
            "app": str(raw_record.get("appName") or "Unknown app"),
            "package": str(raw_record.get("packageName") or "Unknown package"),
            "model": str(raw_record.get("model") or "Unknown device"),
            "expiry": str(raw_record.get("expiry")),
        }
        # One device may have multiple per-app user records; keep a single alert/ban per HWID.
        existing = next((x for x in over_limit if x["hwid"] == hwid), None)
        if existing is None:
            over_limit.append(item)

    for item in over_limit:
        hwid = item["hwid"]
        already_boolean_banned = banned.get(hwid) is True
        if not auto_ban:
            # Persistent dedupe: don't alert every 15 minutes for the same expiry.
            alert_ref = ref(f"bot_state/overlimit_alerts/{hwid}")
            previous = alert_ref.get()
            if not isinstance(previous, dict) or previous.get("expiry") != item["expiry"]:
                alert_ref.set({"expiry": item["expiry"], "first_seen_ms": int(now_utc.timestamp() * 1000), "status": "dry_run"})
                item["action"] = "would_ban (AUTO_BAN=false)"
            else:
                item["action"] = "already_alerted (AUTO_BAN=false)"
        elif already_boolean_banned:
            item["action"] = "already_banned"
        else:
            # Match the Android client: HTTP body must be literal JSON true, not string "true".
            ref(f"banned_hwids/{hwid}").set(True)
            item["action"] = "banned"
            newly_banned.append(item)
            banned[hwid] = True
            ref(f"bot_state/overlimit_alerts/{hwid}").set({
                "expiry": item["expiry"], "first_seen_ms": int(now_utc.timestamp() * 1000), "status": "banned"
            })

    summary = {
        "timestamp_ms": int(now_utc.timestamp() * 1000),
        "timestamp": format_local(now_utc, tz),
        "trigger": trigger,
        "access_hours": hours,
        "grace_hours": grace,
        "enforcement_window_hours": hours + grace,
        "timezone": tz.key,
        "users": len(users),
        "whitelisted": len(whitelist),
        "banned": len(banned),
        "over_limit": len(over_limit),
        "newly_banned": len(newly_banned),
        "whitelist_exemptions": skipped_whitelist,
        "hwid_mismatches_skipped": mismatch_count,
        "invalid_expiries_skipped": invalid_expiry_count,
        "auto_ban": auto_ban,
    }
    ref("bot_state/last_scan").set(summary)

    # Alert for newly banned devices or first-time dry-run recommendations; don't spam unchanged findings.
    notify_items = newly_banned if auto_ban else [x for x in over_limit if x.get("action") == "would_ban (AUTO_BAN=false)"]
    if notify and (notify_items or mismatch_count or invalid_expiry_count):
        lines = [
            f"SILENT MOD enforcement scan ({trigger})",
            f"Time: {summary['timestamp']}",
            f"access_hours: {hours:g} | grace_hours: {grace:g} | enforcement window: {hours + grace:g}h",
            f"User records: {len(users)} | Whitelist: {len(whitelist)} | Over-limit devices: {len(over_limit)}",
            f"New bans: {len(newly_banned)} | Whitelist exemptions: {skipped_whitelist}",
            f"HWID mismatches skipped: {mismatch_count} | Invalid expiries skipped: {invalid_expiry_count}",
        ]
        for item in notify_items[:12]:
            lines.append(
                f"\n{item['action']}\nHWID: {item['hwid']}\nApp: {item['app']} ({item['package']})\n"
                f"Model: {item['model']}\nExpiry: {item['expiry']}"
            )
        if len(notify_items) > 12:
            lines.append(f"\n…and {len(notify_items) - 12} more device(s). Use /scan or /inspect HWID.")
        alert_admins("\n".join(lines))
    LOG.info("Scan completed: %s", summary)
    return {**summary, "over_limit_details": over_limit}


def lookup_user_records(hwid: str) -> list[tuple[str, dict[str, Any]]]:
    users = ref("users").get()
    if not isinstance(users, dict):
        return []
    found = []
    for key, record in users.items():
        if not isinstance(record, dict):
            continue
        prefix = str(key).split("_", 1)[0]
        stored = str(record.get("hwid", ""))
        if hwid in (prefix, stored):
            found.append((str(key), record))
    return found


def command_help() -> str:
    return (
        "SILENT MOD Firebase Admin Bot\n\n"
        "/status — monitor and Firebase status\n"
        "/hours — current configured access_hours\n"
        "/scan — run an immediate enforcement scan\n"
        "/users — list recent user records\n"
        "/inspect HWID — inspect a device across apps\n"
        "/ban HWID [reason] — manually ban\n"
        "/unban HWID — remove a ban\n"
        "/whitelist HWID [reason] — exempt device from automatic bans\n"
        "/unwhitelist HWID — remove exemption\n"
        "/whitelisted — list whitelist entries\n"
        "/banned — list ban entries\n"
        "/admins — list Telegram admins\n"
        "/admin_add TELEGRAM_ID — add an admin (owner only)\n"
        "/admin_remove TELEGRAM_ID — remove an admin (owner only)\n\n"
        "Whitelist, bans, admin roles, update offset and scan status are stored in Firebase, not local files."
    )


def split_command(text: str) -> tuple[str, list[str]]:
    parts = shlex.split(text)
    if not parts:
        return "", []
    command = parts[0].split("@", 1)[0].lower()
    return command, parts[1:]


def require_args(args: list[str], minimum: int, usage: str) -> None:
    if len(args) < minimum:
        raise ValueError(f"Usage: {usage}")


def handle_command(message: dict[str, Any]) -> None:
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    chat_id = chat.get("id")
    sender_id = str(sender.get("id", ""))
    text = str(message.get("text") or "").strip()
    if not chat_id or not text.startswith("/"):
        return
    command, args = split_command(text)
    if command in {"/start", "/help"}:
        send_message(chat_id, command_help())
        return
    if not is_admin(sender_id):
        send_message(chat_id, "Access denied. This Telegram account is not in Firebase telegram_admins.")
        LOG.warning("Unauthorized Telegram command attempt from user ID %s", sender_id)
        return

    try:
        if command == "/status":
            last = ref("bot_state/last_scan").get()
            hours = ref("settings/global_config/access_hours").get()
            whitelist = get_whitelist()
            banned = get_bans()
            admins = ref("telegram_admins").get() or {}
            if isinstance(last, dict):
                status = (
                    f"Last scan: {last.get('timestamp', 'unknown')}\n"
                    f"Trigger: {last.get('trigger', 'unknown')}\n"
                    f"User records: {last.get('users', '?')}\n"
                    f"Over-limit devices: {last.get('over_limit', '?')}\n"
                    f"New bans last scan: {last.get('newly_banned', '?')}\n"
                    f"Grace hours: {last.get('grace_hours', 24)}\n"
                    f"Enforcement window: {last.get('enforcement_window_hours', last.get('access_hours', 0) + 48)} hours\n"
                    f"AUTO_BAN: {last.get('auto_ban', False)}"
                )
            else:
                status = "No scan has completed yet."
            send_message(chat_id, f"SILENT MOD BOT STATUS\naccess_hours: {hours}\nWhitelist entries: {len(whitelist)}\nBan entries: {len(banned)}\nAdmins: {len(admins)}\n{status}")

        elif command == "/hours":
            send_message(chat_id, f"Current settings/global_config/access_hours = {access_hours():g} hours. This is read dynamically from Firebase.")

        elif command == "/scan":
            send_message(chat_id, "Starting Firebase scan…")
            result = run_scan(trigger=f"telegram:{sender_id}", notify=False)
            details = result["over_limit_details"]
            lines = [
                "Scan complete.", f"Time: {result['timestamp']}", f"access_hours: {result['access_hours']:g}",
                f"Grace period: {result['grace_hours']:g} hours (total window: {result['enforcement_window_hours']:g} hours)",
                f"User records: {result['users']}", f"Over-limit devices: {result['over_limit']}",
                f"New bans: {result['newly_banned']}", f"Whitelist exemptions: {result['whitelist_exemptions']}",
                f"HWID mismatches skipped: {result['hwid_mismatches_skipped']}",
                f"Invalid expiries skipped: {result['invalid_expiries_skipped']}",
            ]
            for item in details[:8]:
                lines.append(f"\n{item.get('action', 'flagged')} — {item['hwid']}\n{item['app']} | expiry {item['expiry']}")
            send_message(chat_id, "\n".join(lines))

        elif command == "/inspect":
            require_args(args, 1, "/inspect HWID")
            hwid = args[0]
            if not valid_hwid(hwid):
                raise ValueError("HWID contains unsupported characters.")
            records = lookup_user_records(hwid)
            whitelist = get_whitelist()
            banned = get_bans()
            lines = [f"Device: {hwid}", f"Banned: {banned.get(hwid) is True}", f"Whitelisted: {hwid in whitelist}", f"Matching app records: {len(records)}"]
            for key, record in records[:10]:
                lines.append(f"\nKey: {key}\nApp: {record.get('appName', '?')}\nPackage: {record.get('packageName', '?')}\nModel: {record.get('model', '?')}\nExpiry: {record.get('expiry', '?')}")
            send_message(chat_id, "\n".join(lines))

        elif command == "/ban":
            require_args(args, 1, "/ban HWID [reason]")
            hwid = args[0]
            if not valid_hwid(hwid):
                raise ValueError("HWID contains unsupported characters.")
            reason = " ".join(args[1:]) or "Manual admin ban"
            ref(f"banned_hwids/{hwid}").set(True)
            ref(f"bot_state/manual_bans/{hwid}").set({"reason": reason[:300], "admin_id": sender_id, "timestamp_ms": int(time.time() * 1000)})
            send_message(chat_id, f"Banned device {hwid}. Firebase value is JSON boolean true. Reason: {reason}")
            alert_admins(f"Manual ban by Telegram admin {sender_id}\nHWID: {hwid}\nReason: {reason}")

        elif command == "/unban":
            require_args(args, 1, "/unban HWID")
            hwid = args[0]
            if not valid_hwid(hwid):
                raise ValueError("HWID contains unsupported characters.")
            ref(f"banned_hwids/{hwid}").delete()
            ref(f"bot_state/manual_bans/{hwid}").delete()
            send_message(chat_id, f"Unbanned device {hwid} (deleted banned_hwids/{hwid}).")
            alert_admins(f"Device unbanned by Telegram admin {sender_id}\nHWID: {hwid}")

        elif command == "/whitelist":
            require_args(args, 1, "/whitelist HWID [reason]")
            hwid = args[0]
            if not valid_hwid(hwid):
                raise ValueError("HWID contains unsupported characters.")
            reason = " ".join(args[1:]) or "Admin-approved exception"
            ref(f"whitelist/{hwid}").set({
                "reason": reason[:300], "granted_by": sender_id,
                "created_at": int(time.time() * 1000),
            })
            send_message(chat_id, f"Whitelisted {hwid}. Automatic expiry-based bans will skip this device.")
            alert_admins(f"Whitelist updated by admin {sender_id}\nHWID: {hwid}\nReason: {reason}")

        elif command == "/unwhitelist":
            require_args(args, 1, "/unwhitelist HWID")
            hwid = args[0]
            if not valid_hwid(hwid):
                raise ValueError("HWID contains unsupported characters.")
            ref(f"whitelist/{hwid}").delete()
            send_message(chat_id, f"Removed {hwid} from whitelist.")
            alert_admins(f"Whitelist entry removed by admin {sender_id}\nHWID: {hwid}")

        elif command == "/whitelisted":
            entries = get_whitelist()
            if not entries:
                send_message(chat_id, "Whitelist is empty.")
            else:
                lines = [f"Whitelist entries: {len(entries)}"]
                for hwid, entry in list(entries.items())[:35]:
                    reason = entry.get("reason", "No reason") if isinstance(entry, dict) else str(entry)
                    lines.append(f"\n{hwid}\n{reason}")
                if len(entries) > 35:
                    lines.append(f"\n…and {len(entries) - 35} more.")
                send_message(chat_id, "\n".join(lines))

        elif command == "/banned":
            entries = get_bans()
            if not entries:
                send_message(chat_id, "No ban entries.")
            else:
                lines = [f"Ban entries: {len(entries)}"]
                for hwid, value in list(entries.items())[:35]:
                    lines.append(f"\n{hwid} — {value!r} ({'enforced' if value is True else 'value is not boolean true'})")
                if len(entries) > 35:
                    lines.append(f"\n…and {len(entries) - 35} more.")
                send_message(chat_id, "\n".join(lines))

        elif command == "/users":
            users = ref("users").get()
            if not isinstance(users, dict) or not users:
                send_message(chat_id, "No user records found.")
            else:
                lines = [f"User records: {len(users)} (showing up to 20)"]
                for key, record in list(users.items())[-20:]:
                    if not isinstance(record, dict):
                        continue
                    lines.append(f"\nHWID: {record.get('hwid', str(key).split('_', 1)[0])}\nApp: {record.get('appName', '?')}\nPackage: {record.get('packageName', '?')}\nExpiry: {record.get('expiry', '?')}")
                send_message(chat_id, "\n".join(lines))

        elif command == "/admins":
            admins = ref("telegram_admins").get() or {}
            lines = ["Telegram admins:"]
            for admin_id, entry in admins.items():
                if isinstance(entry, dict):
                    lines.append(f"{admin_id} — {entry.get('role', 'unknown')}")
            send_message(chat_id, "\n".join(lines))

        elif command == "/admin_add":
            if admin_role(sender_id) != "owner":
                raise PermissionError("Only an owner admin can add or remove admins.")
            require_args(args, 1, "/admin_add TELEGRAM_ID")
            target = args[0]
            if not target.isdigit():
                raise ValueError("Telegram ID must be numeric.")
            ref(f"telegram_admins/{target}").set({"role": "admin", "added_by": sender_id, "created_at": int(time.time() * 1000)})
            send_message(chat_id, f"Added Telegram user {target} as admin.")
            alert_admins(f"Telegram admin added\nID: {target}\nBy: {sender_id}")

        elif command == "/admin_remove":
            if admin_role(sender_id) != "owner":
                raise PermissionError("Only an owner admin can add or remove admins.")
            require_args(args, 1, "/admin_remove TELEGRAM_ID")
            target = args[0]
            if not target.isdigit():
                raise ValueError("Telegram ID must be numeric.")
            if target in parse_admin_ids():
                raise ValueError("Cannot remove an owner ID configured in the ADMIN_IDS secret.")
            ref(f"telegram_admins/{target}").delete()
            send_message(chat_id, f"Removed Telegram user {target} from admin access.")
            alert_admins(f"Telegram admin removed\nID: {target}\nBy: {sender_id}")

        else:
            send_message(chat_id, "Unknown command. Use /help.")

    except (ValueError, PermissionError) as exc:
        send_message(chat_id, str(exc))
    except Exception as exc:
        LOG.exception("Command %s failed", command)
        send_message(chat_id, f"Command failed: {type(exc).__name__}. Check GitHub Actions logs; no credentials are included here.")


def poll_telegram() -> None:
    token = env("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is missing.")
    webhook = telegram("getWebhookInfo", {}).get("result", {})
    if webhook.get("url"):
        raise RuntimeError("This bot token has a webhook configured. Remove that webhook in Telegram before using long polling, or use a new bot token.")

    offset_raw = ref("bot_state/telegram_update_offset").get()
    offset = int(offset_raw) if isinstance(offset_raw, (int, float)) else None
    next_scan = 0.0
    alert_admins("SILENT MOD Telegram enforcement bot is online. Firebase is the persistent state store. Use /help.")

    while True:
        now_mono = time.monotonic()
        if now_mono >= next_scan:
            try:
                run_scan(trigger="scheduled", notify=True)
            except Exception as exc:
                LOG.exception("Scheduled scan failed")
                try:
                    alert_admins(f"SILENT MOD bot scan failed: {type(exc).__name__}. No automatic ban was performed if time/config could not be verified.")
                except Exception:
                    LOG.exception("Could not send scan failure alert")
            next_scan = time.monotonic() + SCAN_INTERVAL_SECONDS

        try:
            payload: dict[str, Any] = {"timeout": 20, "allowed_updates": ["message"]}
            if offset is not None:
                payload["offset"] = offset
            updates = telegram("getUpdates", payload).get("result", [])
            for update in updates:
                update_id = int(update.get("update_id", 0))
                message = update.get("message")
                if isinstance(message, dict):
                    handle_command(message)
                offset = update_id + 1
                # Persist offset in Firebase so a runner restart does not replay old commands.
                ref("bot_state/telegram_update_offset").set(offset)
        except requests.RequestException:
            LOG.exception("Telegram polling network error")
            time.sleep(3)
        except Exception:
            LOG.exception("Telegram polling/handler error")
            time.sleep(3)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    init_firebase()
    ensure_persistent_nodes()
    poll_telegram()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Stopped.")
        raise SystemExit(0)
    except Exception as exc:
        LOG.exception("Bot startup failed (%s)", type(exc).__name__)
        print(f"Bot startup failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)
