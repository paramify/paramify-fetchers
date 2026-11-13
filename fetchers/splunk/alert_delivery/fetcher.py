#!/usr/bin/env python3
"""Whether Splunk alerts reach anyone: email and alert-action settings, and each triggered action's delivery outcome.

Advanced: delivery outcomes are parsed from the text of Splunk's own log lines (sendemail, sendmodalert), whose
wording is only proven on Splunk Enterprise 10.4. Re-check the searches against a live instance before copying them.
"""

import re
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import (  # noqa: E402
    NON_NOTIFYING_ACTIONS,
    as_bool,
    iso,
    run,
    split_list,
    to_epoch,
)

NAME = "splunk_alert_delivery"
CAPABILITIES = ["search", "rest_properties_get"]
CONFIG = {"lookback_days": ("SPLUNK_DELIVERY_LOOKBACK_DAYS", 30)}

ALERT_ACTIONS_CONF = "servicesNS/-/-/configs/conf-alert_actions"
# configs/conf-alert_actions omits these keys for a role without admin_all_objects; properties/ serves one key as text.
AUTH_KEYS = ("auth_username", "oauth_client_id")
SUCCESS_RULE = ('sendemail: an INFO "Sending email." line (logged after the mail server accepted the message); '
                'sendmodalert: "Alert action script completed ... with exit code=0"')

TRIGGERED_SPL = ('search index=_internal sourcetype=scheduler savedsearch_id=* alert_actions=* alert_actions!="" '
                 '| stats latest(_time) as triggered_at latest(alert_actions) as alert_actions by savedsearch_id sid')
EMAIL_SOURCE = 'search index=_internal sourcetype=splunk_python "Sending email."'
EMAIL_PIPELINE = (r' | rex "^\S+ \S+ \S+ (?<level>[A-Z]+)\s"'
                  r' | rex "Sending email\..*?[\s,]sid=\"?(?<delivery_sid>[^\",\s]+)"'
                  r' | rex "[\s,]server=\"(?<mailserver>[^\"]*)\""'
                  r' | rex "recipients=\"?\[(?<recipients>[^\]]*)\]"'
                  r' | rex "[\s,]subject=\"(?<subject>[^\"]*)\""'
                  r' | stats count as attempts count(eval(level="INFO")) as succeeded latest(_time) as last_attempt'
                  r' max(eval(if(level="INFO", _time, null()))) as last_success latest(mailserver) as mailserver'
                  r' latest(recipients) as recipients latest(subject) as subject by delivery_sid')
EMAIL_ERROR_SOURCE = 'search index=_internal sourcetype=splunkd component=ScriptRunner "sendemail.py"'
EMAIL_ERROR_PIPELINE = (r''' | rex "/dispatch/(?<delivery_sid>[^/\"]+)/results"'''
                        r''' | rex "sendemail\.py.*?':\s+(?<error>[^\r\n]+)"'''
                        r''' | stats latest(error) as error by delivery_sid''')
MODALERT_SOURCE = 'search index=_internal sourcetype=splunkd component=sendmodalert'
# Completion lines carry no sid, so each is tied to the latest invocation of the same action on the same worker thread.
MODALERT_PIPELINE = (r' | rex "sendmodalert(?: \[(?<worker>[^\]]*)\])? - (?<msg>.*)"'
                     r' | rex field=msg "^Invoking modular alert action=(?<invoked_action>\S+) for search=\"(?<ss_name>.*?)\"'
                     r' sid=\"(?<invoked_sid>[^\"]+)\" in app=\"(?<ss_app>[^\"]*)\" owner=\"(?<ss_owner>[^\"]*)\""'
                     r' | rex field=msg "^action=(?<line_action>\S+) (?:- Alert action script completed in duration=\d+ ms'
                     r' with exit code=(?<exit_code>-?\d+)|STDERR -\s*(?<stderr>.*))"'
                     r' | eval action=coalesce(invoked_action, line_action), worker=coalesce(worker, "-")'
                     r' | where isnotnull(action) | sort 0 _time'
                     r' | streamstats last(invoked_sid) as delivery_sid by worker action | where isnotnull(delivery_sid)'
                     r' | stats count(invoked_sid) as attempts count(eval(exit_code="0")) as succeeded'
                     r' max(eval(if(isnotnull(invoked_sid), _time, null()))) as last_attempt'
                     r' max(eval(if(exit_code="0", _time, null()))) as last_success latest(stderr) as error'
                     r' latest(ss_name) as ss_name latest(ss_app) as ss_app by delivery_sid action')
INTERNAL_EARLIEST_SPL = "| tstats min(_time) as earliest where index=_internal"


def delivery_log(content):
    command = str(content.get("command") or "")
    if re.search(r"\|\s*sendemail\b", command):
        return "sendemail"
    return "sendmodalert" if command.strip().startswith("sendalert") else None


def action_row(entry):
    c = entry["content"]
    return {
        "name": entry["name"],
        "app": (entry.get("acl") or {}).get("app"),
        "enabled": not as_bool(c.get("disabled")),
        "notifying": entry["name"] not in NON_NOTIFYING_ACTIONS,
        "delivery_log": delivery_log(c),
        "label": c.get("label") or None,
    }


def key_set(client, app, key):
    value = client.get_text(f"servicesNS/nobody/{quote(app, safe='')}/properties/alert_actions/email/{key}")
    return None if value is None else bool(value.strip())


def email_row(client, entry):
    c = entry["content"]
    app = (entry.get("acl") or {}).get("app") or "system"
    use_tls, use_ssl = bool(as_bool(c.get("use_tls"))), bool(as_bool(c.get("use_ssl")))
    return {
        "app": app,
        "enabled": not as_bool(c.get("disabled")),
        "mailserver": c.get("mailserver") or None,
        "transport_encrypted": use_tls or use_ssl,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
        "auth_username_set": key_set(client, app, AUTH_KEYS[0]),
        "oauth_client_id_set": key_set(client, app, AUTH_KEYS[1]),
        "allowed_domains": split_list(c.get("allowedDomainList")),
        "from": c.get("from") or None,
    }


def email_transport(client, ns_user, app, name):
    """The alert's own action.email.use_tls/use_ssl when set, else its app's [email] stanza, as sendemail resolves them."""
    ns = f"servicesNS/{quote(ns_user, safe='')}/{quote(app, safe='')}/properties"
    body = client.get(f"{ns}/savedsearches/{quote(name, safe='')}")
    if body is None:
        return None
    own = {e["name"]: e.get("content") for e in body.get("entry", [])}
    values = []
    for key in ("use_tls", "use_ssl"):
        value = own.get(f"action.email.{key}")
        if value is None:
            value = client.get_text(f"{ns}/alert_actions/email/{key}")
        if value is None:
            return None
        values.append(bool(as_bool(value)))
    return any(values)


def by_sid(rows, *fields):
    return None if rows is None else {tuple(r.get(f) for f in fields): r for r in rows}


def outcome(record):
    if record is None:
        return "not_attempted"
    attempts = int(record.get("attempts") or 0)
    return "succeeded" if attempts and int(record.get("succeeded") or 0) == attempts else "failed"


def recipients(text):
    return re.findall(r"[^'\"\s,\[\]]+@[^'\"\s,\[\]]+", text or "")


def delivery_row(client, key, runs, log, email, email_errors, modular, lookback_days):
    ns_user, app, name, action = key
    runs = sorted(runs, key=lambda r: r[0] or 0)
    records = None
    if log == "sendemail" and email is not None:
        records = [email.get((sid,)) for _, sid in runs]
    elif log == "sendmodalert" and modular is not None:
        records = [modular.get((sid, action)) for _, sid in runs]
    outcomes = None if records is None else [outcome(r) for r in records]
    attempted = [r for r in records or [] if r is not None]
    last = attempted[-1] if attempted else None
    error = None
    for (_, sid), rec, result in reversed(list(zip(runs, records or [], outcomes or []))):
        if result == "failed":
            error = (email_errors or {}).get((sid,), {}).get("error") if log == "sendemail" else rec.get("error")
            break
    success_times = [to_epoch(r.get("last_success")) for r, result in zip(records or [], outcomes or [])
                     if result == "succeeded" and r.get("last_success")]
    return {
        "name": name,
        "app": app,
        "namespace_user": ns_user,
        "action": action,
        "notifying": action not in NON_NOTIFYING_ACTIONS,
        "delivery_log": log,
        "lookback_days": lookback_days,
        "triggered": len(runs),
        "attempted": None if outcomes is None else len(attempted),
        "succeeded": None if outcomes is None else outcomes.count("succeeded"),
        "failed": None if outcomes is None else outcomes.count("failed"),
        "not_attempted": None if outcomes is None else outcomes.count("not_attempted"),
        "last_outcome": None if not outcomes else outcomes[-1],
        "last_triggered": iso(runs[-1][0]),
        "last_attempt": None if last is None else iso(to_epoch(last.get("last_attempt"))),
        "last_success": iso(max(success_times)) if success_times else None,
        "mailserver": last.get("mailserver") if last and log == "sendemail" else None,
        "transport_encrypted": email_transport(client, ns_user, app, name) if action == "email" else None,
        "recipients": recipients(last.get("recipients")) if last and log == "sendemail" else [],
        "last_error": error,
    }


def collect_deliveries(client, lookback_days, logs):
    earliest = f"-{lookback_days}d"
    triggered = client.search(TRIGGERED_SPL, earliest=earliest)
    if triggered is None:
        return None
    email = by_sid(client.search(EMAIL_SOURCE + EMAIL_PIPELINE, earliest=earliest), "delivery_sid")
    email_errors = by_sid(client.search(EMAIL_ERROR_SOURCE + EMAIL_ERROR_PIPELINE, earliest=earliest), "delivery_sid")
    modular = by_sid(client.search(MODALERT_SOURCE + MODALERT_PIPELINE, earliest=earliest), "delivery_sid", "action")
    runs, used = {}, set()
    for r in triggered:
        parts = r["savedsearch_id"].split(";", 2)
        if len(parts) != 3:
            client.fail("search " + TRIGGERED_SPL, "UnparsedSavedSearchId", r["savedsearch_id"], "internal_error")
            continue
        for action in split_list(r.get("alert_actions")):
            runs.setdefault((*parts, action), []).append((to_epoch(r.get("triggered_at")), r["sid"]))
            used.add((r["sid"], action))
    rows = [delivery_row(client, k, v, None if logs is None else logs.get(k[3]), email, email_errors, modular,
                         lookback_days)
            for k, v in sorted(runs.items(), key=lambda kv: (kv[0][2].lower(), kv[0][1], kv[0][3]))]
    unmatched = []
    for (sid,), rec in (email or {}).items():
        if not any((sid, a) in used for a, log in (logs or {}).items() if log == "sendemail"):
            unmatched.append(f"email;{sid};{rec.get('subject') or ''};{outcome(rec)}")
    for (sid, action), rec in (modular or {}).items():
        if (sid, action) not in used:
            unmatched.append(f"{action};{sid};{rec.get('ss_app') or ''}/{rec.get('ss_name') or ''};{outcome(rec)}")
    return {"rows": rows, "unmatched": sorted(unmatched),
            "outcomes_known": logs is not None and email is not None and modular is not None}


def internal_earliest(client):
    rows = client.search(INTERNAL_EARLIEST_SPL)
    return iso(to_epoch(rows[0].get("earliest"))) if rows else None


def summarize(email_settings, actions, result):
    rows = (result or {}).get("rows", [])
    known = bool(result and result["outcomes_known"])
    notifying = [r for r in rows if r["notifying"]]
    successes = [r["last_success"] for r in rows if r["last_success"]]

    def total(field):
        return sum(r[field] for r in rows if r["delivery_log"]) if known else None

    return {
        "email_settings_total": None if email_settings is None else len(email_settings),
        "alert_actions_total": None if actions is None else len(actions),
        "deliveries_total": None if result is None else len(rows),
        "triggered_total": None if result is None else sum(r["triggered"] for r in rows),
        "attempted_total": total("attempted"),
        "succeeded_total": total("succeeded"),
        "failed_total": total("failed"),
        "not_attempted_total": total("not_attempted"),
        "notifying_deliveries": None if result is None else len(notifying),
        "notifying_deliveries_with_success": sum(bool(r["succeeded"]) for r in notifying) if known else None,
        "notifying_deliveries_last_outcome_not_succeeded":
            sum(r["last_outcome"] != "succeeded" for r in notifying) if known else None,
        "last_success": (max(successes) if successes else None) if known else None,
        "attempts_unmatched": result["unmatched"] if known else None,
    }


def collect(client, config):
    days = config["lookback_days"]
    if not client.require_searchable_indexes(["_internal"]):  # so no attempts means none were logged, not hidden
        return None
    entries = client.list(ALERT_ACTIONS_CONF)
    if entries is None:
        return None
    actions = [action_row(e) for e in sorted(entries, key=lambda e: e["name"])]
    email_settings = [email_row(client, e) for e in entries if e["name"] == "email"]
    result = collect_deliveries(client, days, {a["name"]: a["delivery_log"] for a in actions})
    if result is None:
        return None
    return {
        "metadata": {"internal_earliest_event": internal_earliest(client), "delivery_success_rule": SUCCESS_RULE},
        "summary": summarize(email_settings, actions, result),
        "email_settings": email_settings,
        "alert_actions": actions,
        "deliveries": result["rows"],
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
