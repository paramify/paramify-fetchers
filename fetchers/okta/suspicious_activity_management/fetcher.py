#!/usr/bin/env python3
"""KSI-IAM-06: Suspicious Activity.

Auto-disable or secure accounts with privileged access on suspicious activity.
Collects security-event, failed-authentication, account-lockout and suspended-user
signals from the system log, plus ThreatInsight and Behavior Detection
configuration, as evidence that suspicious activity is detected and responded to.

Related controls: AC-2, AC-2.13, AC-7, PS-4, PS-8.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

# Import the category-shared client + run scaffolding from _shared/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from okta_client import OktaAPIClient  # noqa: E402
from okta_runner import run  # noqa: E402

logger = logging.getLogger("okta_suspicious_activity_management")

# How far back to scan the security/system log for suspicious activity.
# Overridable via env for orgs with longer/shorter retention.
SECURITY_LOG_LOOKBACK_DAYS = int(os.environ.get("OKTA_SECURITY_LOG_LOOKBACK_DAYS", "30"))


def collect(client: OktaAPIClient) -> Dict:
    logger.info("KSI-IAM-06: Suspicious Activity")
    evidence: Dict = {
        "ksi": "KSI-IAM-06",
        "name": "Suspicious Activity",
        "related_controls": ["AC-2", "AC-2.13", "AC-7", "PS-4", "PS-8"],
        "data": {},
    }

    since = (datetime.utcnow() - timedelta(days=SECURITY_LOG_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 1. Security threat events
    logger.info("Fetching security events...")
    security_events = client.get_system_logs(
        since=since,
        filter_query='eventType sw "security."',
    )
    evidence["data"]["security_events"] = security_events[:50]

    # 2. Failed authentication attempts
    logger.info("Fetching failed authentication logs...")
    failed_auths = client.get_system_logs(
        since=since,
        filter_query='outcome.result eq "FAILURE"',
    )
    evidence["data"]["failed_authentications"] = failed_auths[:50]

    # 3. Account lockout events
    logger.info("Fetching account lockout events...")
    lockouts = client.get_system_logs(
        since=since,
        filter_query='eventType eq "user.account.lock"',
    )
    evidence["data"]["account_lockouts"] = lockouts

    # 4. Suspended users (result of suspicious activity response)
    logger.info("Fetching suspended users...")
    suspended = client.list_users(filter_query='status eq "SUSPENDED"')
    evidence["data"]["suspended_users"] = [{
        "id": u["id"],
        "login": u.get("profile", {}).get("login"),
        "statusChanged": u.get("statusChanged"),
    } for u in suspended]

    # 5. ThreatInsight settings (Security > Identity Threat Protection > ThreatInsight)
    logger.info("Fetching ThreatInsight settings...")
    threat_insight_settings = {}
    threat_insight_action = "none"
    threat_insight_exempt_zones = []
    threat_insight_configured = False

    try:
        threat_insight_settings = client.get_threat_insight_settings()
        if threat_insight_settings:
            evidence["data"]["threat_insight_settings"] = threat_insight_settings
            threat_insight_action = threat_insight_settings.get("action", "none")
            threat_insight_exempt_zones = threat_insight_settings.get("exemptZones", [])
            threat_insight_configured = threat_insight_action != "none" and threat_insight_action is not None
    except Exception as exc:
        logger.warning("ThreatInsight API not available: %s", exc)
        evidence["data"]["threat_insight_settings"] = {"note": "ThreatInsight API not available or feature not enabled"}

    # 6. Behavior Detection rules (Security > Behavior Detection)
    logger.info("Fetching Behavior Detection rules...")
    behaviors = []
    active_behaviors = []
    behavior_types = {}

    try:
        behaviors = client.list_behaviors()
        if behaviors:
            evidence["data"]["behavior_detection_rules"] = behaviors
            active_behaviors = [b for b in behaviors if b.get("status") == "ACTIVE"]
            for behavior in active_behaviors:
                behavior_type = behavior.get("type", "unknown")
                behavior_types[behavior_type] = behavior_types.get(behavior_type, 0) + 1
    except Exception as exc:
        logger.warning("Behavior Detection API not available: %s", exc)
        evidence["data"]["behavior_detection_rules"] = {"note": "Behavior Detection API not available or feature not enabled"}

    # 7. ThreatInsight events from system logs
    logger.info("Fetching ThreatInsight events from system logs...")
    threat_insight_events = []
    try:
        threat_insight_events = client.get_system_logs(
            since=since,
            filter_query='eventType sw "security.threat.detected" or eventType sw "security.threat.blocked"',
        )
        evidence["data"]["threat_insight_events"] = threat_insight_events[:50]
    except Exception as exc:
        logger.warning("Could not fetch ThreatInsight events: %s", exc)
        evidence["data"]["threat_insight_events"] = []

    # 8. Behavior-based security events
    logger.info("Fetching behavior-based security events...")
    behavior_events = []
    try:
        behavior_events = client.get_system_logs(
            since=since,
            filter_query='eventType sw "user.session.risk" or eventType sw "user.authentication.risk"',
        )
        evidence["data"]["behavior_based_security_events"] = behavior_events[:50]
    except Exception as exc:
        logger.warning("Could not fetch behavior-based events: %s", exc)
        evidence["data"]["behavior_based_security_events"] = []

    # Summary - only show mechanisms that demonstrate suspicious activity detection
    evidence["summary"] = {
        "security_event_monitoring": {
            "security_events_last_30_days": len(security_events),
            "failed_auth_attempts": len(failed_auths),
            "account_lockouts": len(lockouts),
            "suspended_users": len(suspended),
            "description": "Security event monitoring tracks failed authentications, account lockouts, and suspended accounts",
        }
    }

    # ThreatInsight (if configured)
    if threat_insight_configured or threat_insight_settings:
        evidence["summary"]["threat_insight"] = {
            "configured": threat_insight_configured,
            "action": threat_insight_action,
            "exempt_zones_count": len(threat_insight_exempt_zones),
            "threat_events_detected": len(threat_insight_events),
            "description": "ThreatInsight monitors and responds to authentication requests from IPs exhibiting suspicious behaviors. Can log, rate limit, or block based on threat level.",
        }

    # Behavior Detection (if configured)
    if len(active_behaviors) > 0:
        evidence["summary"]["behavior_detection"] = {
            "total_rules": len(behaviors),
            "active_rules": len(active_behaviors),
            "behavior_types_configured": behavior_types,
            "behavior_based_events": len(behavior_events),
            "description": f"Behavior Detection rules monitor for anomalous user behavior patterns. {len(active_behaviors)} active rule(s) configured for: {', '.join(behavior_types.keys())}",
        }

    # Overall note
    detection_mechanisms = ["security event monitoring"]
    if threat_insight_configured:
        detection_mechanisms.append("ThreatInsight")
    if len(active_behaviors) > 0:
        detection_mechanisms.append("Behavior Detection")

    evidence["summary"]["suspicious_activity_detection"] = {
        "mechanisms_configured": len(detection_mechanisms),
        "mechanisms": detection_mechanisms,
        "description": f"Suspicious activity detection is implemented through {', '.join(detection_mechanisms)}. These mechanisms enable automated detection, logging, and response to suspicious authentication patterns and behaviors.",
    }

    return evidence


def main() -> int:
    return run(collect, output_filename="okta_suspicious_activity_management.json", logger_name="okta_suspicious_activity_management")


if __name__ == "__main__":
    sys.exit(main())
