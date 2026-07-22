#!/usr/bin/env python3
"""KSI-IAM-07: Automated Account Management.

Securely manage the lifecycle and privileges of all accounts using automation.
Collects the user-status distribution, deprovisioned users, automated group
rules, lifecycle events, provisioning-enabled (SCIM) apps, creation/deactivation
automation analysis, inactivity detection, account-age and activity
distributions, an HR/directory integration inventory, and workflow/hook
automation as evidence of automated account management.

Related controls: AC-2.2, AC-2.3, AC-2.13, IA-4.4, IA-12.
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

logger = logging.getLogger("okta_automated_account_management")

# How far back to scan the system log for user-lifecycle events. Also reused as
# the 30-day window for the lifecycle creation/deactivation rate calculations.
LIFECYCLE_EVENT_LOOKBACK_DAYS = int(os.environ.get("OKTA_LIFECYCLE_EVENT_LOOKBACK_DAYS", "30"))

# How far back to scan the system log for user creation/deactivation
# (provisioning) events.
PROVISIONING_LOG_LOOKBACK_DAYS = int(os.environ.get("OKTA_PROVISIONING_LOG_LOOKBACK_DAYS", "90"))

# Inactivity thresholds (days since last login) used to bucket active users.
INACTIVE_THRESHOLD_30_DAYS = int(os.environ.get("OKTA_INACTIVE_THRESHOLD_30_DAYS", "30"))
INACTIVE_THRESHOLD_60_DAYS = int(os.environ.get("OKTA_INACTIVE_THRESHOLD_60_DAYS", "60"))
INACTIVE_THRESHOLD_90_DAYS = int(os.environ.get("OKTA_INACTIVE_THRESHOLD_90_DAYS", "90"))

# Generic vendor keywords used to classify apps as HR or directory integrations.
# Not org-specific — lift here so they are easy to tune. Contents unchanged.
HR_APP_KEYWORDS = ["workday", "bamboo", "adp", "paychex", "paycom", "ultipro", "successfactors", "oracle hcm", "peoplesoft"]
DIRECTORY_APP_KEYWORDS = ["active directory", "ldap", "ad", "azure ad", "google workspace", "g suite"]


def collect(client: OktaAPIClient) -> Dict:
    logger.info("KSI-IAM-07: Automated Account Management")
    evidence: Dict = {
        "ksi": "KSI-IAM-07",
        "name": "Automated Account Management",
        "related_controls": ["AC-2.2", "AC-2.3", "AC-2.13", "IA-4.4", "IA-12"],
        "data": {},
    }

    since = (datetime.utcnow() - timedelta(days=LIFECYCLE_EVENT_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 1. User status distribution
    logger.info("Fetching user status distribution...")
    all_users = client.list_users()
    status_counts = {}
    for user in all_users:
        status = user.get("status", "UNKNOWN")
        status_counts[status] = status_counts.get(status, 0) + 1
    evidence["data"]["user_status_distribution"] = status_counts

    # 2. Deprovisioned users
    logger.info("Fetching deprovisioned users...")
    deprovisioned = client.list_users(filter_query='status eq "DEPROVISIONED"')
    evidence["data"]["deprovisioned_users"] = [{
        "id": u["id"],
        "login": u.get("profile", {}).get("login"),
        "statusChanged": u.get("statusChanged")
    } for u in deprovisioned[:50]]

    # 3. Group rules (automated membership)
    logger.info("Fetching automated group rules...")
    group_rules = client.list_group_rules()
    evidence["data"]["group_automation_rules"] = group_rules

    # 4. Lifecycle events
    logger.info("Fetching lifecycle events...")
    lifecycle_events = client.get_system_logs(
        since=since,
        filter_query='eventType sw "user.lifecycle"'
    )
    evidence["data"]["lifecycle_events"] = lifecycle_events[:50]

    # 5. Provisioning-enabled apps (SCIM)
    logger.info("Identifying provisioning-enabled apps...")
    apps = client.list_applications()
    provisioning_apps = []
    for app in apps:
        features = app.get("features", [])
        if any(f in features for f in ["IMPORT_NEW_USERS", "PUSH_NEW_USERS", "IMPORT_PROFILE_UPDATES"]):
            provisioning_apps.append({
                "id": app["id"],
                "name": app.get("name"),
                "label": app.get("label"),
                "features": features
            })
    evidence["data"]["provisioning_apps"] = provisioning_apps

    # 6. User creation/deactivation event analysis (who/what triggered it)
    logger.info("Analyzing user creation/deactivation automation...")
    since_90_days = (datetime.utcnow() - timedelta(days=PROVISIONING_LOG_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # User creation events
    creation_events = client.get_system_logs(
        since=since_90_days,
        filter_query='eventType eq "user.lifecycle.create"',
        limit=100
    )

    # Analyze who/what created users (automated vs manual)
    automated_creations = []
    manual_creations = []
    for event in creation_events:
        actor = event.get("actor", {})
        actor_type = actor.get("type", "")
        actor_id = actor.get("id", "")

        creation_info = {
            "timestamp": event.get("published"),
            "user_created": event.get("target", [{}])[0].get("alternateId", "unknown") if event.get("target") else "unknown",
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_name": actor.get("displayName", "unknown")
        }

        # System/automated actors
        if actor_type in ["System", "AppInstance", "Okta"] or "automation" in actor_id.lower():
            automated_creations.append(creation_info)
        else:
            manual_creations.append(creation_info)

    # User deactivation events
    deactivation_events = client.get_system_logs(
        since=since_90_days,
        filter_query='eventType eq "user.lifecycle.deactivate"',
        limit=100
    )

    automated_deactivations = []
    manual_deactivations = []
    for event in deactivation_events:
        actor = event.get("actor", {})
        actor_type = actor.get("type", "")
        actor_id = actor.get("id", "")

        deactivation_info = {
            "timestamp": event.get("published"),
            "user_deactivated": event.get("target", [{}])[0].get("alternateId", "unknown") if event.get("target") else "unknown",
            "actor_type": actor_type,
            "actor_id": actor_id,
            "actor_name": actor.get("displayName", "unknown")
        }

        if actor_type in ["System", "AppInstance", "Okta"] or "automation" in actor_id.lower():
            automated_deactivations.append(deactivation_info)
        else:
            manual_deactivations.append(deactivation_info)

    evidence["data"]["user_creation_automation"] = {
        "automated_creations": automated_creations,
        "manual_creations": manual_creations,
        "automated_creation_count": len(automated_creations),
        "manual_creation_count": len(manual_creations),
        "automation_percentage": round((len(automated_creations) / (len(automated_creations) + len(manual_creations)) * 100), 2) if (len(automated_creations) + len(manual_creations)) > 0 else 0
    }

    evidence["data"]["user_deactivation_automation"] = {
        "automated_deactivations": automated_deactivations,
        "manual_deactivations": manual_deactivations,
        "automated_deactivation_count": len(automated_deactivations),
        "manual_deactivation_count": len(manual_deactivations),
        "automation_percentage": round((len(automated_deactivations) / (len(automated_deactivations) + len(manual_deactivations)) * 100), 2) if (len(automated_deactivations) + len(manual_deactivations)) > 0 else 0
    }

    # 7. Inactivity detection (users not logging in)
    logger.info("Detecting inactive users...")
    inactive_threshold_30 = (datetime.utcnow() - timedelta(days=INACTIVE_THRESHOLD_30_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    inactive_threshold_60 = (datetime.utcnow() - timedelta(days=INACTIVE_THRESHOLD_60_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    inactive_threshold_90 = (datetime.utcnow() - timedelta(days=INACTIVE_THRESHOLD_90_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Get all active users and check their last login
    active_users = client.list_users(filter_query='status eq "ACTIVE"')

    # Identify service accounts (API-only accounts that don't login)
    logger.info("Identifying service accounts (API-only accounts)...")
    service_account_ids = set()
    try:
        api_tokens = client.list_api_tokens()
        for token in api_tokens:
            user_id = token.get("userId")
            if user_id:
                service_account_ids.add(user_id)
    except Exception as e:
        # If API tokens endpoint isn't available (requires Super Admin), log but continue
        logger.warning("Could not fetch API tokens (may require Super Admin): %s", e)

    # Separate user accounts from service accounts
    user_accounts = [u for u in active_users if u["id"] not in service_account_ids]
    service_accounts = [u for u in active_users if u["id"] in service_account_ids]
    inactive_users_30 = []
    inactive_users_60 = []
    inactive_users_90 = []
    never_logged_in = []

    for user in active_users:
        last_login = user.get("lastLogin")
        user_info = {
            "id": user["id"],
            "login": user.get("profile", {}).get("login"),
            "email": user.get("profile", {}).get("email"),
            "status": user.get("status"),
            "last_login": last_login,
            "created": user.get("created")
        }

        if not last_login:
            never_logged_in.append(user_info)
        else:
            # Parse last login date
            try:
                # Handle ISO format with or without timezone
                if last_login.endswith("Z"):
                    login_date = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                else:
                    login_date = datetime.fromisoformat(last_login)

                # Calculate days inactive
                now = datetime.utcnow()
                if login_date.tzinfo:
                    now = now.replace(tzinfo=login_date.tzinfo)
                else:
                    login_date = login_date.replace(tzinfo=None)
                    now = now.replace(tzinfo=None)

                days_inactive = (now - login_date).days

                if days_inactive >= 90:
                    inactive_users_90.append({**user_info, "days_inactive": days_inactive})
                elif days_inactive >= 60:
                    inactive_users_60.append({**user_info, "days_inactive": days_inactive})
                elif days_inactive >= 30:
                    inactive_users_30.append({**user_info, "days_inactive": days_inactive})
            except Exception:
                # If parsing fails, assume never logged in
                never_logged_in.append(user_info)

    # Calculate average inactive time for users who have logged in
    all_inactive_times = []
    for user_list in [inactive_users_30, inactive_users_60, inactive_users_90]:
        for user in user_list:
            if "days_inactive" in user:
                all_inactive_times.append(user["days_inactive"])

    avg_inactive_days = round(sum(all_inactive_times) / len(all_inactive_times), 1) if all_inactive_times else 0

    # Calculate account age distribution
    now = datetime.utcnow()
    account_ages = {
        "new_accounts_0_30_days": 0,
        "medium_accounts_31_180_days": 0,
        "established_accounts_181_365_days": 0,
        "mature_accounts_1_2_years": 0,
        "veteran_accounts_2_plus_years": 0
    }

    for user in active_users:
        created_str = user.get("created")
        if created_str:
            try:
                if created_str.endswith("Z"):
                    created_date = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                else:
                    created_date = datetime.fromisoformat(created_str)

                if created_date.tzinfo:
                    now_tz = now.replace(tzinfo=created_date.tzinfo)
                else:
                    created_date = created_date.replace(tzinfo=None)
                    now_tz = now.replace(tzinfo=None)

                age_days = (now_tz - created_date).days

                if age_days <= 30:
                    account_ages["new_accounts_0_30_days"] += 1
                elif age_days <= 180:
                    account_ages["medium_accounts_31_180_days"] += 1
                elif age_days <= 365:
                    account_ages["established_accounts_181_365_days"] += 1
                elif age_days <= 730:
                    account_ages["mature_accounts_1_2_years"] += 1
                else:
                    account_ages["veteran_accounts_2_plus_years"] += 1
            except Exception:
                pass

    # Calculate time-to-deprovision metrics (time between deactivation and deprovisioning)
    time_to_deprovision = []
    for deact_event in deactivation_events:
        user_id = deact_event.get("target", [{}])[0].get("id") if deact_event.get("target") else None
        deact_time = deact_event.get("published")

        if user_id and deact_time:
            # Find corresponding deprovision event
            deprov_events = client.get_system_logs(
                since=deact_time,
                filter_query=f'eventType eq "user.lifecycle.delete" and target.id eq "{user_id}"',
                limit=1
            )

            if deprov_events:
                deprov_time = deprov_events[0].get("published")
                try:
                    if deact_time.endswith("Z"):
                        deact_dt = datetime.fromisoformat(deact_time.replace("Z", "+00:00"))
                    else:
                        deact_dt = datetime.fromisoformat(deact_time)

                    if deprov_time.endswith("Z"):
                        deprov_dt = datetime.fromisoformat(deprov_time.replace("Z", "+00:00"))
                    else:
                        deprov_dt = datetime.fromisoformat(deprov_time)

                    if deact_dt.tzinfo:
                        deprov_dt = deprov_dt.replace(tzinfo=deact_dt.tzinfo)
                    else:
                        deact_dt = deact_dt.replace(tzinfo=None)
                        deprov_dt = deprov_dt.replace(tzinfo=None)

                    hours_to_deprov = (deprov_dt - deact_dt).total_seconds() / 3600
                    time_to_deprovision.append(hours_to_deprov)
                except Exception:
                    pass

    avg_time_to_deprovision_hours = round(sum(time_to_deprovision) / len(time_to_deprovision), 1) if time_to_deprovision else None

    # Calculate account lifecycle velocity (creation/deactivation rates)
    creation_rate_30d = len([e for e in creation_events if e.get("published", "") >= since])
    creation_rate_90d = len(creation_events)
    deactivation_rate_30d = len([e for e in deactivation_events if e.get("published", "") >= since])
    deactivation_rate_90d = len(deactivation_events)

    # Calculate last activity distribution (excluding service accounts)
    last_activity_distribution = {
        "active_last_7_days": 0,
        "active_last_30_days": 0,
        "active_last_90_days": 0,
        "inactive_90_plus_days": 0
    }

    for user in user_accounts:  # Only count user accounts, not service accounts
        last_login = user.get("lastLogin")
        if last_login:
            try:
                if last_login.endswith("Z"):
                    login_date = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                else:
                    login_date = datetime.fromisoformat(last_login)

                if login_date.tzinfo:
                    now_tz = now.replace(tzinfo=login_date.tzinfo)
                else:
                    login_date = login_date.replace(tzinfo=None)
                    now_tz = now.replace(tzinfo=None)

                days_since_login = (now_tz - login_date).days

                if days_since_login <= 7:
                    last_activity_distribution["active_last_7_days"] += 1
                elif days_since_login <= 30:
                    last_activity_distribution["active_last_30_days"] += 1
                elif days_since_login <= 90:
                    last_activity_distribution["active_last_90_days"] += 1
                else:
                    last_activity_distribution["inactive_90_plus_days"] += 1
            except Exception:
                pass

    # Calculate account health metrics (excluding service accounts)
    # Service accounts use API tokens and don't login, so they shouldn't affect health percentage
    total_active_user_accounts = len(user_accounts)
    active_recently = last_activity_distribution["active_last_7_days"] + last_activity_distribution["active_last_30_days"]
    health_percentage = round((active_recently / total_active_user_accounts * 100), 1) if total_active_user_accounts > 0 else 0

    evidence["data"]["inactive_users"] = {
        "never_logged_in": never_logged_in,
        "inactive_30_days": inactive_users_30,
        "inactive_60_days": inactive_users_60,
        "inactive_90_days": inactive_users_90,
        "never_logged_in_count": len(never_logged_in),
        "inactive_30_days_count": len(inactive_users_30),
        "inactive_60_days_count": len(inactive_users_60),
        "inactive_90_days_count": len(inactive_users_90),
        "average_inactive_days": avg_inactive_days,
        "total_users_with_login_history": len(all_inactive_times) + (total_active_user_accounts - len(never_logged_in) - len(inactive_users_30) - len(inactive_users_60) - len(inactive_users_90))
    }

    evidence["data"]["account_age_distribution"] = account_ages
    evidence["data"]["time_to_deprovision_metrics"] = {
        "average_hours_to_deprovision": avg_time_to_deprovision_hours,
        "samples_analyzed": len(time_to_deprovision),
        "note": "Time between user deactivation and account deprovisioning"
    }
    evidence["data"]["account_lifecycle_velocity"] = {
        "user_creation_rate_30_days": creation_rate_30d,
        "user_creation_rate_90_days": creation_rate_90d,
        "user_deactivation_rate_30_days": deactivation_rate_30d,
        "user_deactivation_rate_90_days": deactivation_rate_90d,
        "net_growth_30_days": creation_rate_30d - deactivation_rate_30d,
        "net_growth_90_days": creation_rate_90d - deactivation_rate_90d
    }
    evidence["data"]["last_activity_distribution"] = last_activity_distribution
    evidence["data"]["account_health_metrics"] = {
        "total_active_user_accounts": total_active_user_accounts,
        "total_active_accounts_including_service": len(active_users),
        "service_accounts_count": len(service_accounts),
        "accounts_active_recently": active_recently,
        "account_health_percentage": health_percentage,
        "note": "Percentage of active user accounts (excluding service/API-only accounts) that have logged in within the last 30 days. Service accounts are excluded because they use API tokens and don't login."
    }

    # 8. Integration inventory (HR systems, directories)
    logger.info("Identifying HR and directory integrations...")
    hr_keywords = HR_APP_KEYWORDS
    directory_keywords = DIRECTORY_APP_KEYWORDS

    hr_integrations = []
    directory_integrations = []
    other_automation_integrations = []

    for app in apps:
        app_name = app.get("name", "").lower()
        app_label = app.get("label", "").lower()
        sign_on_mode = app.get("signOnMode", "")
        features = app.get("features", [])

        # Check for HR integrations
        is_hr = any(keyword in app_name or keyword in app_label for keyword in hr_keywords)
        # Check for directory integrations
        is_directory = any(keyword in app_name or keyword in app_label for keyword in directory_keywords)
        # Check for provisioning features
        has_provisioning = any(f in features for f in ["IMPORT_NEW_USERS", "PUSH_NEW_USERS", "IMPORT_PROFILE_UPDATES", "PUSH_PROFILE_UPDATES"])

        app_info = {
            "id": app["id"],
            "name": app.get("name"),
            "label": app.get("label"),
            "sign_on_mode": sign_on_mode,
            "status": app.get("status"),
            "features": features,
            "has_provisioning": has_provisioning
        }

        if is_hr:
            hr_integrations.append(app_info)
        elif is_directory:
            directory_integrations.append(app_info)
        elif has_provisioning:
            other_automation_integrations.append(app_info)

    evidence["data"]["integration_inventory"] = {
        "hr_integrations": hr_integrations,
        "directory_integrations": directory_integrations,
        "other_automation_integrations": other_automation_integrations,
        "hr_integration_count": len(hr_integrations),
        "directory_integration_count": len(directory_integrations),
        "other_automation_count": len(other_automation_integrations)
    }

    # 9. Workflow/hook evidence (if available)
    logger.info("Checking for workflow automation and hooks...")

    # Check for Event Hooks (automation triggers)
    event_hooks = []
    try:
        event_hooks_response = client._request("GET", "/eventHooks")
        if isinstance(event_hooks_response, list):
            event_hooks = event_hooks_response
        elif isinstance(event_hooks_response, dict) and "data" in event_hooks_response:
            event_hooks = event_hooks_response["data"]
    except Exception as e:
        logger.warning("Event Hooks API not available: %s", e)

    # Check for Inline Hooks (real-time automation)
    inline_hooks = []
    try:
        inline_hooks_response = client._request("GET", "/inlineHooks")
        if isinstance(inline_hooks_response, list):
            inline_hooks = inline_hooks_response
        elif isinstance(inline_hooks_response, dict) and "data" in inline_hooks_response:
            inline_hooks = inline_hooks_response["data"]
    except Exception as e:
        logger.warning("Inline Hooks API not available: %s", e)

    # Check for Okta Workflows (if available)
    workflows = []
    try:
        workflows_response = client._request("GET", "/workflows")
        if isinstance(workflows_response, list):
            workflows = workflows_response
        elif isinstance(workflows_response, dict) and "data" in workflows_response:
            workflows = workflows_response["data"]
    except Exception as e:
        logger.warning("Workflows API not available: %s", e)

    evidence["data"]["workflow_automation"] = {
        "event_hooks": [{
            "id": h.get("id"),
            "name": h.get("name"),
            "status": h.get("status"),
            "events": h.get("events", []),
            "channel": h.get("channel", {})
        } for h in event_hooks[:20]],
        "inline_hooks": [{
            "id": h.get("id"),
            "name": h.get("name"),
            "status": h.get("status"),
            "type": h.get("type")
        } for h in inline_hooks[:20]],
        "workflows": [{
            "id": w.get("id"),
            "name": w.get("name"),
            "status": w.get("status")
        } for w in workflows[:20]] if workflows else [],
        "event_hooks_count": len(event_hooks),
        "inline_hooks_count": len(inline_hooks),
        "workflows_count": len(workflows) if workflows else 0
    }

    # Summary - Focus on evidence that demonstrates automated account management
    # Only include metrics that tell a meaningful story

    # Build lifecycle activity summary (only if non-zero)
    lifecycle_activity = []
    total_creations = len(automated_creations) + len(manual_creations)
    total_deactivations = len(automated_deactivations) + len(manual_deactivations)
    if total_creations > 0:
        auto_pct = evidence["data"]["user_creation_automation"]["automation_percentage"]
        lifecycle_activity.append(f"{total_creations} user creation(s) ({auto_pct}% automated)")
    if total_deactivations > 0:
        auto_pct = evidence["data"]["user_deactivation_automation"]["automation_percentage"]
        lifecycle_activity.append(f"{total_deactivations} user deactivation(s) ({auto_pct}% automated)")
    if avg_time_to_deprovision_hours is not None:
        lifecycle_activity.append(f"Average {avg_time_to_deprovision_hours:.1f} hours to deprovision")

    # Build inactive account summary (only if there are inactive accounts)
    inactive_summary = None
    total_inactive = len(never_logged_in) + len(inactive_users_30) + len(inactive_users_60) + len(inactive_users_90)
    if total_inactive > 0:
        inactive_summary = {
            "never_logged_in": len(never_logged_in),
            "inactive_30_plus_days": len(inactive_users_30) + len(inactive_users_60) + len(inactive_users_90),
            "average_inactive_days": avg_inactive_days if avg_inactive_days > 0 else None
        }

    # Build user lists for summary
    detected_users = {
        "never_logged_in_users": [{"email": u.get("email"), "login": u.get("login"), "created": u.get("created")} for u in never_logged_in[:20]],
        "inactive_users_30_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_30[:20]],
        "inactive_users_60_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_60[:20]],
        "inactive_users_90_days": [{"email": u.get("email"), "login": u.get("login"), "days_inactive": u.get("days_inactive")} for u in inactive_users_90[:20]],
        "automated_creations": [{"user_created": u.get("user_created"), "timestamp": u.get("timestamp"), "actor_name": u.get("actor_name")} for u in automated_creations[:20]],
        "automated_deactivations": [{"user_deactivated": u.get("user_deactivated"), "timestamp": u.get("timestamp"), "actor_name": u.get("actor_name")} for u in automated_deactivations[:20]]
    }

    # Build lists of all users and active users with details
    total_users_list = [{
        "id": u.get("id"),
        "email": u.get("profile", {}).get("email"),
        "login": u.get("profile", {}).get("login"),
        "status": u.get("status"),
        "created": u.get("created"),
        "last_login": u.get("lastLogin"),
        "status_changed": u.get("statusChanged")
    } for u in all_users]

    active_users_list = [{
        "id": u.get("id"),
        "email": u.get("profile", {}).get("email"),
        "login": u.get("profile", {}).get("login"),
        "status": u.get("status"),
        "created": u.get("created"),
        "last_login": u.get("lastLogin"),
        "status_changed": u.get("statusChanged")
    } for u in active_users]

    # Focused summary
    evidence["summary"] = {
        "account_management_overview": {
            "total_users": len(all_users),
            "total_users_details": total_users_list,
            "active_accounts": total_active_user_accounts,  # Excludes service accounts
            "active_accounts_including_service": len(active_users),  # Includes all active accounts
            "service_accounts_count": len(service_accounts),
            "active_accounts_details": active_users_list,
            "account_health_percentage": health_percentage,
            "note": "Account health shows percentage of active user accounts (excluding service/API-only accounts) with recent login activity (within 30 days). Service accounts are excluded because they use API tokens and don't login."
        },
        "account_lifecycle_monitoring": {
            "account_age_distribution": account_ages,
            "last_activity_distribution": last_activity_distribution,
            "note": "Demonstrates active monitoring of account lifecycle and user activity patterns"
        },
        "detected_users": detected_users
    }

    # Only add lifecycle activity if there's actual activity
    if lifecycle_activity:
        evidence["summary"]["lifecycle_activity"] = {
            "activities": lifecycle_activity,
            "note": "Recent account lifecycle events demonstrating automation in practice"
        }

    # Only add inactive accounts if there are any
    if inactive_summary:
        evidence["summary"]["inactive_account_monitoring"] = inactive_summary

    return evidence


def main() -> int:
    return run(collect, output_filename="okta_automated_account_management.json", logger_name="okta_automated_account_management")


if __name__ == "__main__":
    sys.exit(main())
