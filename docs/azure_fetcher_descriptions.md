# Azure fetcher descriptions

What each Azure fetcher collects, the access it needs, the calls it makes, and what each summary field means. Every entry uses the same layout. A few describe fetchers still in review; their Script paths appear on this branch once they merge.

## Index

| Area | Fetcher | Evidence set |
|---|---|---|
| Identity and access | [azure_entra_access_reviews](#azure_entra_access_reviews) | `EVD-AZURE-ENTRA-ACCESS-REVIEWS` |
| Identity and access | [azure_entra_app_registrations](#azure_entra_app_registrations) | `EVD-AZURE-ENTRA-APP-CREDS` |
| Identity and access | [azure_entra_authentication_policy](#azure_entra_authentication_policy) | `EVD-AZURE-ENTRA-AUTH-METHODS-POLICY` |
| Identity and access | [azure_entra_conditional_access_policies](#azure_entra_conditional_access_policies) | `EVD-AZURE-ENTRA-CA-POLICIES` |
| Identity and access | [azure_entra_dormant_identities](#azure_entra_dormant_identities) | `EVD-AZURE-ENTRA-DORMANT-IDENTITIES` |
| Identity and access | [azure_entra_groups](#azure_entra_groups) | `EVD-AZURE-ENTRA-GROUPS` |
| Identity and access | [azure_entra_mfa_status](#azure_entra_mfa_status) | `EVD-AZURE-ENTRA-MFA` |
| Identity and access | [azure_entra_pim_assignments](#azure_entra_pim_assignments) | `EVD-AZURE-ENTRA-PIM-ASSIGNMENTS` |
| Identity and access | [azure_entra_privileged_roles](#azure_entra_privileged_roles) | `EVD-AZURE-ENTRA-PRIV-ROLES` |
| Identity and access | [azure_entra_risky_users](#azure_entra_risky_users) | `EVD-AZURE-ENTRA-RISKY-USERS` |
| Identity and access | [azure_entra_service_principals](#azure_entra_service_principals) | `EVD-AZURE-ENTRA-SERVICE-PRINCIPALS` |
| Identity and access | [azure_entra_sign_ins](#azure_entra_sign_ins) | `EVD-AZURE-ENTRA-SIGN-INS` |
| Identity and access | [azure_managed_identity_configuration](#azure_managed_identity_configuration) | `EVD-AZURE-MANAGED-IDENTITY-CONFIG` |
| Identity and access | [azure_rbac_custom_roles](#azure_rbac_custom_roles) | `EVD-AZURE-RBAC-CUSTOM-ROLES` |
| Identity and access | [azure_rbac_role_assignments](#azure_rbac_role_assignments) | `EVD-AZURE-RBAC-ASSIGNMENTS` |
| Logging and monitoring | [azure_activity_log_alerts](#azure_activity_log_alerts) | `EVD-AZURE-ACTIVITY-ALERTS` |
| Logging and monitoring | [azure_alert_rules](#azure_alert_rules) | `EVD-AZURE-ALERT-RULES` |
| Logging and monitoring | [azure_change_provenance](#azure_change_provenance) | `EVD-AZURE-CHANGE-PROVENANCE` |
| Logging and monitoring | [azure_diagnostic_settings](#azure_diagnostic_settings) | `EVD-AZURE-DIAG-SETTINGS` |
| Logging and monitoring | [azure_entra_diagnostic_settings](#azure_entra_diagnostic_settings) | `EVD-AZURE-ENTRA-DIAGNOSTIC-SETTINGS` |
| Logging and monitoring | [azure_log_analytics_deletion_rights](#azure_log_analytics_deletion_rights) | `EVD-AZURE-LOG-ANALYTICS-DELETION-RIGHTS` |
| Logging and monitoring | [azure_log_analytics_query_audit](#azure_log_analytics_query_audit) | `EVD-AZURE-LOG-ANALYTICS-QUERY-AUDIT` |
| Logging and monitoring | [azure_log_analytics_workspaces](#azure_log_analytics_workspaces) | `EVD-AZURE-LOG-ANALYTICS` |
| Logging and monitoring | [azure_log_storage_immutability](#azure_log_storage_immutability) | `EVD-AZURE-LOG-STORAGE-IMMUTABILITY` |
| Logging and monitoring | [azure_monitor_fired_alerts](#azure_monitor_fired_alerts) | `EVD-AZURE-MONITOR-FIRED-ALERTS` |
| Logging and monitoring | [azure_network_flow_logs](#azure_network_flow_logs) | `EVD-AZURE-NETWORK-FLOW-LOGS` |
| Logging and monitoring | [azure_resource_diagnostic_settings](#azure_resource_diagnostic_settings) | `EVD-AZURE-RESOURCE-DIAG-SETTINGS` |
| Logging and monitoring | [azure_service_log_records](#azure_service_log_records) | `EVD-AZURE-SERVICE-LOG-RECORDS` |
| Microsoft Sentinel | [azure_sentinel_analytics_rules](#azure_sentinel_analytics_rules) | `EVD-AZURE-SENTINEL-ANALYTICS-RULES` |
| Microsoft Sentinel | [azure_sentinel_automation_rules](#azure_sentinel_automation_rules) | `EVD-AZURE-SENTINEL-AUTOMATION-RULES` |
| Microsoft Sentinel | [azure_sentinel_data_sources](#azure_sentinel_data_sources) | `EVD-AZURE-SENTINEL-DATA-SOURCES` |
| Microsoft Sentinel | [azure_sentinel_incidents](#azure_sentinel_incidents) | `EVD-AZURE-SENTINEL-INCIDENTS` |
| Microsoft Sentinel | [azure_sentinel_playbooks](#azure_sentinel_playbooks) | `EVD-AZURE-SENTINEL-PLAYBOOKS` |
| Security posture, policy and backup | [azure_app_service_backups](#azure_app_service_backups) | `EVD-AZURE-APPSVC-BACKUPS` |
| Security posture, policy and backup | [azure_backup_recovery_status](#azure_backup_recovery_status) | `EVD-AZURE-BACKUP-RECOVERY` |
| Security posture, policy and backup | [azure_defender_assessments](#azure_defender_assessments) | `EVD-AZURE-DEFENDER-ASSESSMENTS` |
| Security posture, policy and backup | [azure_defender_plans](#azure_defender_plans) | `EVD-AZURE-DEFENDER` |
| Security posture, policy and backup | [azure_defender_regulatory_compliance](#azure_defender_regulatory_compliance) | `EVD-AZURE-DEFENDER-REG-COMPLIANCE` |
| Security posture, policy and backup | [azure_disk_encryption_status](#azure_disk_encryption_status) | `EVD-AZURE-DISK-ENC` |
| Security posture, policy and backup | [azure_policy_assignments](#azure_policy_assignments) | `EVD-AZURE-POLICY-ASSIGN` |
| Security posture, policy and backup | [azure_policy_compliance](#azure_policy_compliance) | `EVD-AZURE-POLICY-COMPLIANCE` |
| Security posture, policy and backup | [azure_residual_resources](#azure_residual_resources) | `EVD-AZURE-RESIDUAL-RESOURCES` |
| Security posture, policy and backup | [azure_resource_inventory](#azure_resource_inventory) | `EVD-AZURE-RESOURCE-INVENTORY` |
| Security posture, policy and backup | [azure_vm_hardening_status](#azure_vm_hardening_status) | `EVD-AZURE-VM-HARDENING` |
| Network and edge | [azure_api_management_configuration](#azure_api_management_configuration) | `EVD-AZURE-API-MANAGEMENT-CONFIG` |
| Network and edge | [azure_app_gateway_backend_tls](#azure_app_gateway_backend_tls) | `EVD-AZURE-APPGW-BACKEND-TLS` |
| Network and edge | [azure_app_gateway_tls_listeners](#azure_app_gateway_tls_listeners) | `EVD-AZURE-APPGW-TLS-LISTENERS` |
| Network and edge | [azure_app_gateway_waf](#azure_app_gateway_waf) | `EVD-AZURE-APPGW-WAF` |
| Network and edge | [azure_ddos_protection](#azure_ddos_protection) | `EVD-AZURE-DDOS` |
| Network and edge | [azure_dns_configuration](#azure_dns_configuration) | `EVD-AZURE-DNS-CONFIG` |
| Network and edge | [azure_front_door_origins](#azure_front_door_origins) | `EVD-AZURE-FRONTDOOR-ORIGINS` |
| Network and edge | [azure_front_door_tls](#azure_front_door_tls) | `EVD-AZURE-FRONTDOOR-TLS` |
| Network and edge | [azure_front_door_waf_coverage](#azure_front_door_waf_coverage) | `EVD-AZURE-FRONTDOOR-WAF-COVERAGE` |
| Network and edge | [azure_front_door_waf_policies](#azure_front_door_waf_policies) | `EVD-AZURE-FRONTDOOR-WAF` |
| Network and edge | [azure_network_security_groups](#azure_network_security_groups) | `EVD-AZURE-NSG` |
| Network and edge | [azure_private_dns_zone_configuration](#azure_private_dns_zone_configuration) | `EVD-AZURE-PRIVATE-DNS-ZONE-CONFIG` |
| Network and edge | [azure_private_endpoint_configuration](#azure_private_endpoint_configuration) | `EVD-AZURE-PRIVATE-ENDPOINT-CONFIG` |
| Network and edge | [azure_virtual_wan_configuration](#azure_virtual_wan_configuration) | `EVD-AZURE-VIRTUAL-WAN-CONFIG` |
| Network and edge | [azure_vnet_egress_routing](#azure_vnet_egress_routing) | `EVD-AZURE-VNET-EGRESS` |
| Network and edge | [azure_vpn_gateway_configuration](#azure_vpn_gateway_configuration) | `EVD-AZURE-VPN-GATEWAY-CONFIG` |
| Compute, apps and AI | [azure_ai_hub_configuration](#azure_ai_hub_configuration) | `EVD-AZURE-AI-HUB-CONFIG` |
| Compute, apps and AI | [azure_ai_services_configuration](#azure_ai_services_configuration) | `EVD-AZURE-AI-SERVICES-CONFIG` |
| Compute, apps and AI | [azure_aks_cluster_configuration](#azure_aks_cluster_configuration) | `EVD-AZURE-AKS-CONFIG` |
| Compute, apps and AI | [azure_app_service_configuration](#azure_app_service_configuration) | `EVD-AZURE-APPSVC-CONFIG` |
| Compute, apps and AI | [azure_app_service_deployments](#azure_app_service_deployments) | `EVD-AZURE-APPSVC-DEPLOYMENTS` |
| Compute, apps and AI | [azure_app_service_plans](#azure_app_service_plans) | `EVD-AZURE-APPSVC-PLANS` |
| Compute, apps and AI | [azure_container_registry_configuration](#azure_container_registry_configuration) | `EVD-AZURE-ACR-CONFIG` |
| Compute, apps and AI | [azure_container_workloads_configuration](#azure_container_workloads_configuration) | `EVD-AZURE-CONTAINER-WORKLOADS-CONFIG` |
| Compute, apps and AI | [azure_databricks_workspace_configuration](#azure_databricks_workspace_configuration) | `EVD-AZURE-DBRICKS-CONFIG` |
| Compute, apps and AI | [azure_function_app_configuration](#azure_function_app_configuration) | `EVD-AZURE-FUNCAPP-CONFIG` |
| Data, keys and encryption | [azure_cosmosdb_configuration](#azure_cosmosdb_configuration) | `EVD-AZURE-COSMOSDB-CONFIG` |
| Data, keys and encryption | [azure_data_services_configuration](#azure_data_services_configuration) | `EVD-AZURE-DATA-SERVICES-CONFIG` |
| Data, keys and encryption | [azure_key_vault_configuration](#azure_key_vault_configuration) | `EVD-AZURE-KEYVAULT-CFG` |
| Data, keys and encryption | [azure_key_vault_key_rotation](#azure_key_vault_key_rotation) | `EVD-AZURE-KEYVAULT-ROTATION` |
| Data, keys and encryption | [azure_managed_redis_configuration](#azure_managed_redis_configuration) | `EVD-AZURE-MANAGED-REDIS-CONFIG` |
| Data, keys and encryption | [azure_mysql_configuration](#azure_mysql_configuration) | `EVD-AZURE-MYSQL-CONFIG` |
| Data, keys and encryption | [azure_postgresql_configuration](#azure_postgresql_configuration) | `EVD-AZURE-POSTGRESQL-CONFIG` |
| Data, keys and encryption | [azure_redis_cache_configuration](#azure_redis_cache_configuration) | `EVD-AZURE-REDIS-CACHE-CONFIG` |
| Data, keys and encryption | [azure_sql_encryption_status](#azure_sql_encryption_status) | `EVD-AZURE-SQL-ENC` |
| Data, keys and encryption | [azure_sql_managed_instance_backups](#azure_sql_managed_instance_backups) | `EVD-AZURE-SQLMI-BACKUPS` |
| Data, keys and encryption | [azure_sql_managed_instance_configuration](#azure_sql_managed_instance_configuration) | `EVD-AZURE-SQLMI-CONFIG` |
| Data, keys and encryption | [azure_sql_managed_instance_encryption](#azure_sql_managed_instance_encryption) | `EVD-AZURE-SQLMI-ENCRYPTION` |
| Data, keys and encryption | [azure_sql_server_configuration](#azure_sql_server_configuration) | `EVD-AZURE-SQL-CONFIG` |
| Data, keys and encryption | [azure_storage_encryption_status](#azure_storage_encryption_status) | `EVD-AZURE-STORAGE-ENC` |
| Azure DevOps and code scanning | [azure_devops_audit_streams](#azure_devops_audit_streams) | `EVD-AZURE-DEVOPS-AUDIT-STREAMS` |
| Azure DevOps and code scanning | [azure_devops_identities](#azure_devops_identities) | `EVD-AZURE-DEVOPS-IDENTITIES` |
| Azure DevOps and code scanning | [azure_devops_permissions](#azure_devops_permissions) | `EVD-AZURE-DEVOPS-PERMISSIONS` |
| Azure DevOps and code scanning | [azure_devops_pipelines](#azure_devops_pipelines) | `EVD-AZURE-DEVOPS-PIPELINES` |
| Azure DevOps and code scanning | [azure_devops_service_connections](#azure_devops_service_connections) | `EVD-AZURE-DEVOPS-SERVICE-CONNECTIONS` |
| Azure DevOps and code scanning | [checkov_bicep](#checkov_bicep) | `EVD-CHECKOV-BICEP` |

## Identity and access

### azure_entra_access_reviews
Short Description: Shows whether each Entra ID access review runs at least monthly, denies unanswered reviews and removes access automatically, and what its latest cycle decided and applied.

Script: fetchers/azure/entra_access_reviews/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph AccessReview.Read.All, in a tenant with Entra ID P2 or ID Governance. The application permission, with admin consent, is recommended. A delegated run (as a signed-in user) needs AccessReview.Read.All in the token and a user holding Security Reader or Identity Governance Administrator. A missing permission or role reads not_authorized. Optional: Organization.Read.All; without it, the tenant name reads null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /identityGovernance/accessReviews/definitions` — every review series and its settings
- Microsoft Graph `GET /identityGovernance/accessReviews/definitions/{id}/instances` (per series) — each run of the series and its status
- Microsoft Graph `GET /identityGovernance/accessReviews/definitions/{id}/instances/{id}/decisions` (per run in each active series' latest completed cycle; active means the series' status is not Completed, AutoReviewed or Applied, and the latest completed cycle is the most recent set of runs that started at the same time and have all ended, one run per group for a series over many groups) — what reviewers decided and whether it was applied

Output: `azure_entra_access_reviews_<tenant>.json` — every access review series with what it reviews, its schedule, default decision, auto-apply setting and reviewers, and the decisions of its latest completed cycle. Reviews of Azure resource roles aren't read: Azure Resource Manager keeps them, not Graph.

Summary fields:

**What was checked?**
- `access_reviews_available` — True if the tenant's access reviews were read; false if Graph refused the first read (the series list) because the tenant has no Entra ID P2 or ID Governance licence (error code AadPremiumLicenseRequired); null if a read failed, including a licence refusal of any later read
- `collection_complete` — True if every review series, its instances and the decisions of each active series' latest completed cycle were read; false if any read failed or was refused for the licence, and every other field except `access_reviews_available` is left out
- `review_definitions` — Number of access review series (definitions), active or ended
- `active_review_definitions` — Number of active review series
- `active_definitions_by_scope_type` — Number of active review series for each kind of access reviewed, read from the series' scope:
  - group_membership (members of one or more groups or Teams, including membership managed by PIM for Groups)
  - application (users and groups assigned to an app)
  - entra_role (holders of an Entra directory role)
  - access_package (access package assignments)
  - other (any other scope, such as every user in the tenant)

**Is every active review monthly, deny-by-default and applied automatically?**
- `active_definitions_recurring_at_least_monthly` — Number of active review series that recur every 31 days or more often
- `active_definitions_default_deny` — Number of active review series where a review left unanswered is denied (default decision enabled and set to Deny; a Recommendation default doesn't count)
- `active_definitions_auto_applying` — Number of active review series that apply their decisions automatically when a run ends, so denied access is removed without an admin
- `active_definitions_monthly_auto_removal` — Number of active review series with monthly auto-removal (monthly auto-removal means the series recurs at least monthly, denies unanswered reviews and applies decisions automatically; an active one-time review counts as not monthly, by design)
- `monthly_auto_removal_percentage` — Percentage of active review series with monthly auto-removal = `active_definitions_monthly_auto_removal` / `active_review_definitions` × 100 (a whole number, 0–100); 0 when `active_review_definitions` is 0
- `active_definitions_without_monthly_auto_removal` — List of active review series names without monthly auto-removal
- `all_active_definitions_monthly_auto_removal` — True if every active review series has monthly auto-removal; false if any doesn't, or none is active
- `all_active_definitions_auto_removal` — True if every active review series denies unanswered reviews and applies decisions automatically, however often it recurs; false if any doesn't, or none is active
- `max_active_recurrence_period_days` — Days: the longest recurrence period of any active review series (daily 1, weekly 7, monthly 30, yearly 365, times the interval), for a validator that sets its own cadence; null if none is active or any active series is one-time or has a pattern not listed here
- `active_self_review_definitions` — List of active review series names where users review their own access (no reviewers named on the series; for a multi-stage series, none named on any of its stages, since Graph then ignores the series' own list)

**Are the reviews running on schedule?**
- `active_recurring_definitions_without_completed_cycle` — List of active recurring review series names with no completed cycle yet (a cycle is completed when every run that started at the same time has ended: status Completing, Completed, AutoReviewing, AutoReviewed, Applying or Applied, with an end time)
- `max_days_since_last_completed_cycle` — Days: the longest time since any active recurring review series' latest completed cycle ended; null if none has completed a cycle

**What did the last cycle decide, and was it applied?**
- `last_cycle_decisions` — Number of review decisions in each active review series' latest completed cycle
- `last_cycle_decisions_by_result` — Number of latest-cycle review decisions of each result:
  - Approve (the reviewer kept the access)
  - Deny (the reviewer, or the default decision, chose to remove the access)
  - NotReviewed (no one answered and no default decision was applied)
  - DontKnow (the reviewer answered that they don't know)
  - any other value Graph sends, such as NotNotified (not in Graph's documented list), is counted under its own key, which is present only then
- `last_cycle_denied_decisions_applied` — Number of latest-cycle Deny decisions whose removal was applied (apply result AppliedSuccessfully, or AppliedSuccessfullyButObjectNotFound when the access was already gone)
- `last_cycle_denied_decisions_not_applied` — Number of latest-cycle Deny decisions not applied, either not yet or because applying failed (any other apply result, such as New, ApplyNotSupported or AppliedWithUnknownFailure)


### azure_entra_app_registrations
Short Description: Lists every app registration's client secrets and certificates with their expiry dates, showing which have expired, expire within 30 days or never expire.

Script: fetchers/azure/entra_app_registrations/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph application permission Application.Read.All (Directory.Read.All also covers it). Optional: Organization.Read.All; without it, the tenant's name and domain read null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /applications` — every app registration with its sign-in audience, client secrets and certificates

Output: `azure_entra_app_registrations_<tenant>.json` — each app registration with who can sign in to it and every client secret and certificate it holds, with its expiry date and whether it has expired, expires soon or never expires; credentials held on service principals are in `azure_entra_service_principals`.

Summary fields:

**What app registrations exist?**
- `total_app_registrations` — Number of app registrations in the tenant
- `apps_with_credentials` — Number of app registrations holding at least one client secret or certificate
- `apps_without_credentials` — Number of app registrations holding no client secret or certificate
- `multi_tenant_apps` — Number of app registrations that accounts outside this tenant can sign in to: the sign-in audience is anything but this organization only (AzureADMyOrg), such as other organizations or personal Microsoft accounts; an app with no audience recorded counts here too

**What credentials do the apps hold?**
- `total_credentials` — Number of client secrets and certificates held on app registrations
- `password_credentials` — Number of app registration credentials that are client secrets (passwords)
- `certificate_credentials` — Number of app registration credentials that are certificates

**Do credentials expire and get rotated?**
- `rotation_threshold_days` — Days before expiry at which a credential counts as expiring soon (30)
- `expired_credentials` — Number of credentials whose end date has passed
- `credentials_expiring_soon` — Number of credentials that haven't expired and expire within `rotation_threshold_days` days
- `credentials_without_expiry` — Number of credentials with no end date (or one that couldn't be read), which never show up as expiring
- `healthy_credentials` — Number of healthy credentials: they have an end date, haven't expired and don't expire within `rotation_threshold_days` days
- `credential_rotation_compliance_percentage` — Percentage of credentials that are healthy = `healthy_credentials` / `total_credentials` × 100 (a whole number, 0–100); 0 when `total_credentials` is 0. Credentials with no end date count in the total but not as healthy, so they lower it

**Which apps have a credential to fix?**
- `apps_with_expired_credentials` — Number of app registrations holding at least one expired credential
- `apps_with_credentials_expiring_soon` — Number of app registrations holding at least one credential that expires within `rotation_threshold_days` days
- `apps_with_credentials_without_expiry` — Number of app registrations holding at least one credential with no end date
- `apps_with_all_credentials_healthy` — Number of app registrations that hold at least one credential and whose every credential is healthy


### azure_entra_authentication_policy
Short Description: Shows which sign-in methods the tenant allows, flagging weak SMS and voice codes and phishing-resistant methods, plus security defaults and password protection settings.

Script: fetchers/azure/entra_authentication_policy/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph application permissions Policy.Read.All and Directory.Read.All.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /policies/authenticationMethodsPolicy` — each sign-in method's state, who it applies to and its settings, plus the registration campaign and migration state
- Microsoft Graph `GET /policies/identitySecurityDefaultsEnforcementPolicy` — whether security defaults are on
- Microsoft Graph `GET /groupSettings` and `GET /groupSettingTemplates/{Password Rule Settings id}` — the tenant's password protection settings, and Microsoft's defaults for any it never set
- Microsoft Graph `GET /subscribedSkus` — the tenant's licences, to tell Free, P1 and P2 apart

Output: `azure_entra_authentication_policy_<tenant>.json` — each sign-in method in the authentication methods policy with its state, who it applies to, its settings and whether it's weak or phishing-resistant, plus the registration campaign, security defaults, password protection settings and the tenant's licences; Windows Hello for Business is set through device management and isn't covered.

Summary fields:

**What was checked?**
- `authentication_methods_policy_readable` — True if the authentication methods policy was read; false if not, and every method field reads null
- `total_methods` — Number of sign-in methods in the policy, enabled or not; null if the policy couldn't be read
- `enabled_methods` — List of the methods whose state is enabled (for example fido2, microsoftAuthenticator, sms); null if the policy couldn't be read
- `enabled_method_count` — Number of enabled methods; null if the policy couldn't be read

**Does the tenant still allow weak methods?**
- `sms_enabled` — True if the SMS method is enabled for the users and groups it targets; false if it's disabled or not in the policy; null if the policy couldn't be read
- `voice_enabled` — True if the voice call method is enabled; false if it's disabled or not in the policy; null if the policy couldn't be read
- `weak_methods_enabled` — List of enabled weak methods: SMS and voice call, which send one-time codes over the phone network that can be intercepted or phished; null if the policy couldn't be read
- `weak_method_enabled` — True if SMS or voice call is enabled; false if neither is; null if the policy couldn't be read

**Does the tenant allow a phishing-resistant method?**
- `fido2_enabled` — True if the FIDO2 method (security keys and passkeys, which only work on the real site, so a look-alike can't relay them) is enabled; false if it's disabled or not in the policy; null if the policy couldn't be read
- `x509_certificate_enabled` — True if certificate-based sign-in (X.509) is enabled; false if it's disabled or not in the policy; null if the policy couldn't be read
- `x509_certificate_multi_factor` — True if certificate-based sign-in defaults to multi-factor, so a certificate alone satisfies MFA; false if it defaults to single-factor; null if the policy couldn't be read, has no X.509 entry or reports no default. Set whether or not the method is enabled
- `phishing_resistant_methods_enabled` — List of enabled phishing-resistant methods: FIDO2, and X.509 certificates only when `x509_certificate_multi_factor` is true (binding rules that raise particular certificates to multi-factor aren't evaluated); null if the policy couldn't be read
- `phishing_resistant_method_enabled` — True if at least one phishing-resistant method is enabled; false if none is; null if the policy couldn't be read

**Does this policy alone decide which methods work?**
- `policy_migration_state` — Whether the move from the legacy per-user MFA and self-service password reset (SSPR) policies to this policy is finished: preMigration, migrationInProgress or migrationComplete; null if the policy couldn't be read
- `legacy_method_policies_apply` — True if the migration isn't complete, so the legacy MFA and SSPR policies can still allow a method this policy disables; false if it's complete; null if the migration state couldn't be read

**Are users pushed to set up MFA?**
- `registration_campaign_state` — Whether the registration campaign, which prompts users at sign-in to set up a stronger method, is on: enabled, disabled or default (Microsoft decides); null if the policy has no campaign or couldn't be read
- `security_defaults_enabled` — True if security defaults are on (Microsoft's baseline that has every user register for MFA, prompts admins for MFA and blocks legacy authentication); false if they're off; null if the setting couldn't be read

**Are common passwords and password guessing blocked?**
- `entra_id_tier` — Whether the tenant has Entra ID P2, P1 or neither: p2, p1 or free, from the service plans of its active subscriptions (a lapsed one doesn't count); null if the licences couldn't be read
- `password_settings_source` — Whether the password protection values come from a setting the tenant saved (directory_setting) or, when it never saved one, Microsoft's defaults (template_defaults); null if neither could be read
- `custom_banned_password_check_enabled` — True if the custom banned-password check is switched on; false if it's off; null if the value couldn't be read
- `custom_banned_password_count` — Number of words on the custom banned-password list (the words aren't recorded); null if neither the tenant's setting nor Microsoft's defaults could be read
- `custom_banned_password_list_enforced` — True only if the custom check is on, the list has at least one word and the tenant has Entra ID P1 or P2; false if any of the three is missing; null if the check setting or the licence tier couldn't be read
- `lockout_threshold` — Number of failed sign-ins before smart lockout first locks an account; null if the value couldn't be read
- `lockout_duration_in_seconds` — Number of seconds an account stays locked after its first smart lockout (later lockouts last longer); null if the value couldn't be read


### azure_entra_conditional_access_policies
Short Description: Lists every Conditional Access policy with whether it's enforced, who and what it covers or excludes, and what it requires or blocks.

Script: fetchers/azure/entra_conditional_access_policies/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph application permission Policy.Read.All. Optional: Organization.Read.All; without it, the tenant's name and domain read null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /identity/conditionalAccess/policies` — every policy with its state, conditions, grant controls and session controls

Output: `azure_entra_conditional_access_policies_<tenant>.json` — each Conditional Access policy with its state, the users, groups, roles and apps it includes and excludes, its other conditions (client apps, risk levels, platforms, locations), what it grants or blocks, and its session controls.

Summary fields:

**What policies exist, and which are enforced?**
- `total_policies` — Number of Conditional Access policies in the tenant; also 0 when the tenant has no Entra ID P1 or P2 licence, since Graph then returns an empty list
- `enabled_policies` — Number of enforced policies: state enabled, so they apply at sign-in (report-only policies aren't counted). Every count named `enforced_policies_…` or `enforced_mfa_…` counts only enforced policies
- `disabled_policies` — Number of policies switched off; a policy whose state couldn't be read counts here
- `report_only_policies` — Number of report-only policies, which log what they would have done but enforce nothing
- `enforced_percentage` — Percentage of policies that are enforced = `enabled_policies` / `total_policies` × 100 (a whole number, 0–100); 0 when `total_policies` is 0. Disabled and report-only policies count in the total but not as enforced

**What do enforced policies require?**
- `enforced_policies_requiring_mfa` — Number of enforced policies that require MFA: the MFA grant control or an authentication strength is among their grant controls, even when the policy lets the user meet a different control instead
- `enforced_policies_blocking_access` — Number of enforced policies that block access
- `enforced_policies_requiring_compliant_device` — Number of enforced policies whose grant controls include a compliant device or a hybrid-joined device, even when the policy lets the user meet a different control instead
- `enforced_policies_with_authentication_strength` — Number of enforced policies that require an authentication strength (a named set of allowed sign-in methods, such as phishing-resistant MFA)
- `enforced_policies_with_session_controls` — Number of enforced policies with at least one session control: sign-in frequency, persistent browser session, app-enforced restrictions or Defender for Cloud Apps session control

**How widely do enforced policies apply?**
- `enforced_policies_targeting_all_users` — Number of enforced policies that include all users; a policy can still exclude users, groups or roles
- `enforced_policies_targeting_all_applications` — Number of enforced policies that include all cloud apps; a policy can still exclude apps
- `enforced_mfa_for_all_users_and_apps` — Number of enforced policies that require MFA for all users on all cloud apps, before any exclusions
- `enforced_policies_targeting_legacy_authentication` — Number of enforced policies whose conditions include legacy clients (Exchange ActiveSync or other older clients, which can't prompt for MFA), whether the policy blocks them or requires something else

**Do admin portals and Azure management require MFA?**
- `mfa_required_for_admin_portals` — True if at least one enforced policy requires MFA for all users on Microsoft Admin Portals (the Microsoft admin centers) or on all cloud apps; false if no enforced policy does. Excluded users, groups, roles and apps aren't checked
- `mfa_required_for_azure_management_api` — True if at least one enforced policy requires MFA for all users on Windows Azure Service Management API (the Azure portal, CLI and PowerShell) or on all cloud apps; false if no enforced policy does. Excluded users, groups, roles and apps aren't checked

**Who is left out?**
- `enforced_policies_with_exclusions` — Number of enforced policies that exclude at least one user, group or directory role
- `distinct_excluded_principals` — Number of distinct users, groups and directory roles excluded by at least one enforced policy


### azure_entra_dormant_identities
Short Description: Shows whether any dormant, never-used, guest or deleted user or service principal still holds an Entra directory role or an Azure role in the subscription.

Script: fetchers/azure/entra_dormant_identities/fetcher.py (uses the shared REST client fetchers/azure/_shared/azure_rest.py)

Access: Microsoft Graph Directory.Read.All (or the Directory Readers role) and AuditLog.Read.All with an Entra ID P1 or P2 licence, and Reader on the subscription. Without AuditLog.Read.All or the licence, the users holding a role and the guests are still listed, with their roles, and the dormancy fields read null. The service principal sign-in report exists only in Microsoft's global cloud, so in US Government and China clouds service principal dormancy reads null. The credential must sign in to the subscription's own tenant; if Microsoft Graph answers for another tenant, the run fails without reading the directory.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `GET /subscriptions/{id}` — the subscription's tenant, to tell this tenant's own apps from other tenants'
- Microsoft Graph `GET /organization` — the tenant Microsoft Graph is signed in to, which must be the subscription's
- Microsoft Graph `GET /users` with sign-in activity — every user, when it was created and when it last signed in (read again without sign-in activity if that read fails)
- Microsoft Graph `GET /applications` — when each of this tenant's app registrations was created, for the grace period of a service principal with no creation date of its own
- Microsoft Graph `GET /reports/servicePrincipalSignInActivities` on the beta endpoint — when each app or managed identity last signed in
- Microsoft Graph `GET /directoryRoles` and `GET /directoryRoles/{id}/members` (per role) — who holds each directory role now, tenant-wide; eligible (PIM) assignments and roles scoped to an administrative unit aren't read
- `GET Microsoft.Authorization/roleDefinitions` and `GET Microsoft.Authorization/roleAssignments` — every active Azure role assignment that applies in the subscription, including those inherited from management groups and made below it, with its role name; eligible (PIM) assignments aren't read
- Microsoft Graph `GET /groups/{id}/transitiveMembers` on the beta endpoint (per group holding a role) — who holds the role through the group; beta because v1.0 member reads are known to leave out service principals
- Microsoft Graph `POST /directoryObjects/getByIds` — the service principals holding a role, and which assigned principals no longer exist

Output: `azure_entra_dormant_identities_<subscription>.json` — each user holding a role, each dormant user and each guest, and each role-holding service principal, with its last sign-in and the roles it holds, plus each deleted principal that an Azure role assignment still names; the user counts come from every user, but other users are listed only when a role read failed and any of them may hold a role.

Summary fields:

**What was checked?**
- `dormant_after_days` — Days without a successful sign-in after which an enabled identity counts as dormant (90 unless `ENTRA_DORMANT_DAYS` sets it)
- `tenant_readable` — True if the subscription's tenant id and the tenant Microsoft Graph is signed in to were both read, and match; false if not, and every enabled service principal with no sign-in as a client reads unknown (on a mismatch nothing else is read and every count reads null)
- `users_readable` — True if the user list was read, with or without sign-in activity; false if both reads failed, and every user count reads null
- `applications_readable` — True if this tenant's app registrations were read; false if not, and a role-holding app of this tenant with no sign-in as a client and no creation date of its own reads unknown (see `service_principals_holding_roles_dormancy_unknown`)
- `user_sign_in_activity` — Whether users' sign-in activity was read: read, not_licensed (the tenant has no Entra ID P1 or P2) or not_read (refused or failed)
- `service_principal_sign_in_activity` — Whether the service principal sign-in activity report was read: read, not_licensed (the tenant has no Entra ID P1 or P2) or not_read (refused or failed)
- `directory_roles_readable` — True if every directory role, its members and the members of groups holding one were read; false if any read of directory roles, their members or group members failed
- `azure_roles_readable` — True if the subscription's Azure role assignments, role names and the members of groups holding one were read; false if any read of Azure role assignments, role names or group members failed
- `principal_lookup_readable` — True if the directory lookup of role-holding service principals and assigned principals succeeded; false if it failed, and the service principal and deleted-principal fields read null
- `users_checked` — Number of users in the tenant; null if the user list wasn't read
- `service_principals_holding_roles` — Number of service principals (apps and managed identities) holding a directory role or an Azure role in the subscription; null if the roles or the lookup weren't read

**Who holds a role?**
- `users_holding_roles` — Number of users holding a directory role or an Azure role in the subscription, directly or through a group; null if the users or the roles weren't read
- `users_holding_directory_roles` — Number of users holding a directory role, directly or through a role-assignable group; null if the users or the directory roles weren't read
- `users_holding_privileged_directory_roles` — Number of users holding a directory role that grants tenant-wide administrative power (the list shared with `azure_entra_privileged_roles`); null if the users or the directory roles weren't read
- `users_holding_azure_roles` — Number of users holding an Azure role that applies in the subscription, directly or through a group; null if the users or the Azure roles weren't read
- `service_principals_holding_directory_roles` — Number of service principals holding a directory role; null if the directory roles or the lookup weren't read
- `service_principals_holding_azure_roles` — Number of service principals holding an Azure role that applies in the subscription; null if the Azure roles or the lookup weren't read

**Are enabled accounts in use?**
- `enabled_users` — Number of users whose account is enabled; null if the user list wasn't read
- `guest_users` — Number of guest (external) users; null if the user list wasn't read
- `dormant_users` — Number of dormant users: enabled, with no successful sign-in in the last `dormant_after_days` days, or with none at all and created more than that many days ago; null if sign-in activity wasn't read
- `users_never_signed_in` — Number of users with no sign-in attempt on record, successful or not, including new and disabled accounts; null if sign-in activity wasn't read
- `dormant_service_principals_holding_roles` — Number of enabled role-holding service principals with no sign-in as a client (app-only or on behalf of a user) in the last `dormant_after_days` days, or with none on record and created more than that many days ago; the creation date comes from the service principal, else its app registration in this tenant; a principal with neither gets no grace, or reads unknown if the app registrations couldn't be read. One with no sign-in as a client on record counts only if it's an app registered in this tenant; the enabled rest are unknown. Null if the report, the roles or the lookup weren't read
- `service_principals_holding_roles_without_recorded_sign_in` — Number of role-holding service principals with no sign-in as a client in the report, including service principals whose dormancy is unknown; null if the report, the roles or the lookup weren't read
- `service_principals_holding_roles_dormancy_unknown` — Number of enabled role-holding service principals whose dormancy can't be judged: managed identities, other tenants' apps (Microsoft's included) and apps with no owner organization that have no sign-in as a client in the report, whether or not it lists them, since Microsoft doesn't document the report covering their client sign-ins; every one with no sign-in as a client when the tenant couldn't be read; and this tenant's own apps with no sign-in as a client and no creation date of their own when the app registrations couldn't be read; null if the report, the roles or the lookup weren't read

**Does any dormant, unused, guest or deleted identity hold a role?**
- `dormant_users_holding_roles` — Number of dormant users holding a directory role or an Azure role; null if sign-in activity or the roles weren't read
- `never_signed_in_users_holding_roles` — Number of enabled users with no sign-in attempt on record, created more than `dormant_after_days` days ago, holding a directory role or an Azure role; a new account that hasn't signed in yet isn't counted, nor is a disabled one (see `disabled_users_holding_roles`); null if sign-in activity or the roles weren't read
- `guest_users_holding_roles` — Number of guest users holding a directory role or an Azure role; null if the users or the roles weren't read
- `disabled_users_holding_roles` — Number of disabled users still holding a directory role or an Azure role; null if the users or the roles weren't read
- `disabled_service_principals_holding_roles` — Number of disabled service principals still holding a directory role or an Azure role; null if the roles or the lookup weren't read
- `deleted_principals_holding_azure_roles` — Number of principals an Azure role assignment still names that the directory no longer has (deleted users, groups or apps); partner-tenant groups aren't checked; null if the Azure roles or the lookup weren't read
- `azure_role_assignments_to_deleted_principals` — Number of Azure role assignments that name a deleted principal; null if the Azure roles or the lookup weren't read
- `no_dormant_guest_or_deleted_identity_holds_a_role` — True if no dormant user, never-signed-in user (enabled and created more than `dormant_after_days` days ago; disabled accounts are counted apart in `disabled_users_holding_roles`), guest user, dormant service principal or deleted principal holds a role; false if any does; null if none was found but sign-in activity, the roles or the lookup couldn't be read, or a role-holding service principal's dormancy is unknown. Only active assignments are judged: an identity eligible (PIM) for a role, holding a role scoped to an administrative unit, or holding one through a partner-tenant group isn't checked


### azure_entra_groups
Short Description: Shows every Entra ID group's members and owners, which groups can hold directory roles, and whether membership is set by a rule, by hand or synced from on-premises.

Script: fetchers/azure/entra_groups/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph GroupMember.Read.All, or Directory.Read.All (the Directory Readers role covers it), which also covers every optional permission here but Member.Read.Hidden. Optional: User.Read.All; without it, users come back as an id only, so `member_details_readable` and `owner_details_readable` read false and the guest, disabled-user and disabled-owner figures read null. Optional: Member.Read.Hidden; without it, the members of groups with hidden membership read unknown. Optional: Application.Read.All; without it, `groups_with_only_disabled_owners` reads null when any owner is an app or managed identity. Optional: Organization.Read.All; without it, no tenant name or domain is recorded.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /groups`, expanding members — every group, how its membership is managed, and its members
- Microsoft Graph `GET /groups`, expanding owners — who owns each group (Graph allows one expansion per request)
- Microsoft Graph `GET /groups/{id}/members` — a group's whole member list when the expansion stopped at its limit of 20 (beta, since v1.0 leaves out service principals)
- Microsoft Graph `GET /groups/{id}/owners` — a group's whole owner list when the expansion stopped at its limit of 20 (beta, as for members)

Output: `azure_entra_groups_<tenant>.json` — each group with its kind, whether it can hold directory roles, how its membership is managed, and its members and owners.

Summary fields:

**What was checked?**
- `total_groups` — Number of groups in the tenant; a group that is neither security- nor mail-enabled (rare) is in none of the four kind counts, so the four may not add up to the total
- `groups_readable` — True if the whole group list was read; false if any page failed, and every count reads null, since a partial list would pass for the whole tenant
- `members_readable` — True if every group's members were read, apart from `hidden_membership_groups_unread`; false if any member read failed, and the member fields read null
- `member_details_readable` — True if every user member came back with its guest status and account state; false if members couldn't be read or any one user came back without its guest status or account state (Graph returns users as an id only when User.Read.All isn't granted, and older accounts can have no guest status). A missing guest status nulls the guest fields for the whole tenant, and a missing account state nulls the disabled-user field
- `owners_readable` — True if every group's owners (the users or service principals who can manage the group) were read; false if any owner read failed, and the owner fields read null
- `owner_details_readable` — True if owners were read and every owner came back with its account state (enabled or disabled); false if not (User.Read.All or Application.Read.All isn't granted), and `groups_with_only_disabled_owners` reads null

**What kinds of groups exist?**
- `security_groups` — Number of security groups that aren't mail-enabled (used to grant access)
- `mail_enabled_security_groups` — Number of security groups that also have an email address
- `microsoft_365_groups` — Number of Microsoft 365 groups (shared mailbox, files and Teams)
- `distribution_groups` — Number of email distribution lists that aren't security groups

**Which groups can hold directory roles?**
- `role_assignable_groups` — Number of groups that can be assigned an Entra directory role (only Privileged Role Administrators and Global Administrators can change their membership)
- `role_assignable_groups_without_owner` — Number of role-assignable groups with no owner; null if owners couldn't be read
- `role_assignable_groups_with_guest_members` — Number of role-assignable groups with at least one guest user as a member; null if any user member's guest status couldn't be read
- `users_in_role_assignable_groups` — Number of distinct users who are direct members of a role-assignable group; null if members couldn't be read

**How is membership managed?**
- `dynamic_groups` — Number of groups whose membership is set by a rule on user or device attributes
- `dynamic_groups_paused` — Number of dynamic groups whose rule processing is paused, so membership no longer follows the rule
- `assigned_groups` — Number of groups whose membership isn't set by a rule: members are added and removed by hand, or, for synced groups (included here), managed in on-premises Active Directory
- `synced_groups` — Number of groups synced from on-premises Active Directory, and managed there
- `cloud_groups` — Number of groups created in Entra ID rather than synced
- `hidden_membership_groups` — Number of Microsoft 365 groups whose membership is hidden; their members are listed only with Member.Read.Hidden
- `hidden_membership_groups_unread` — Number of hidden-membership groups that came back with no members, which Graph also returns without Member.Read.Hidden, so their members read unknown and the member fields leave them out; null if members couldn't be read

**Who owns each group?**
- `groups_with_owners_not_in_graph` — Number of groups whose owners Microsoft Graph doesn't return: synced groups, distribution groups and mail-enabled security groups (created in Exchange); the owner fields leave them out
- `groups_without_owner` — Number of groups with no owner, among groups whose owners Graph returns; null if owners couldn't be read
- `cloud_groups_without_owner` — Number of groups created in Entra ID with no owner, among groups whose owners Graph returns; null if owners couldn't be read
- `groups_with_only_disabled_owners` — Number of groups whose every owner is a disabled account, among groups whose owners Graph returns; null if owners or their account state couldn't be read

**Who is in them?**
- `total_direct_memberships` — Number of direct member entries across all groups (a user in three groups counts three times); null if members couldn't be read
- `empty_groups` — Number of groups with no members; null if members couldn't be read
- `groups_with_guest_members` — Number of groups with at least one guest user as a member; null if any user member's guest status couldn't be read
- `groups_with_disabled_user_members` — Number of groups with at least one disabled user as a member; null if any user member's account state couldn't be read
- `groups_with_nested_groups` — Number of groups with another group as a direct member; null if members couldn't be read
- `groups_with_service_principal_members` — Number of groups with an app or managed identity as a direct member; null if members couldn't be read


### azure_entra_mfa_status
Short Description: Shows which users can sign in with MFA or passwordless methods, with coverage for enabled users, members and admins, and when each account last signed in.

Script: fetchers/azure/entra_mfa_status/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph application permissions Directory.Read.All (or User.Read.All, RoleManagement.Read.Directory and GroupMember.Read.All), Reports.Read.All and AuditLog.Read.All.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /users`, with sign-in activity — every user, whether the account is enabled, member or guest, and when it last signed in
- Microsoft Graph `GET /reports/authenticationMethods/userRegistrationDetails` — each user's registered methods and whether they can do MFA, passwordless sign-in and self-service password reset
- Microsoft Graph `GET /directoryRoles` — the directory roles activated in the tenant
- Microsoft Graph `GET /directoryRoles/{id}/members` (per privileged role) — who holds each admin role
- Microsoft Graph `GET /groups/{id}/transitiveMembers` (per group holding a privileged role) — the users who hold the role through the group, including nested groups

Output: `azure_entra_mfa_status_<tenant>.json` — every user with whether the account is enabled, member or guest, when it last signed in, the methods it has registered, whether it can do MFA and passwordless sign-in, and the admin roles it holds.

Summary fields:

**What was checked?**
- `total_users` — Number of users in the tenant, members and guests, enabled or not
- `enabled_users` — Number of users whose account is enabled and can sign in; a user whose account state Graph didn't return counts as enabled
- `disabled_users` — Number of users whose account is disabled
- `guest_users` — Number of guest users (invited from another organization), enabled or not
- `users_never_signed_in` — Number of users with no recorded interactive sign-in (successful or failed), enabled or not; a user whose sign-in activity Graph didn't return counts too

**Can every enabled user do MFA?**
- `mfa_capable_users` — Number of users, enabled or not, who are MFA-capable: the registration report says they've registered a method that can do MFA and the tenant's authentication methods policy allows it. A user with no row in the report counts as not capable
- `mfa_capable_enabled_users` — Number of enabled users who are MFA-capable
- `enabled_users_without_mfa` — Number of enabled users who aren't MFA-capable, including users with no row in the registration report
- `mfa_coverage_percentage` — Percentage of enabled users who are MFA-capable = `mfa_capable_enabled_users` / `enabled_users` × 100 (a whole number, 0–100); 0 when `enabled_users` is 0. Users with no row in the registration report count in the total but not as capable
- `mfa_coverage_percentage_all_users` — Percentage of all users, enabled or not, who are MFA-capable = `mfa_capable_users` / `total_users` × 100 (a whole number, 0–100); 0 when `total_users` is 0
- `mfa_registered_enabled_users` — Number of enabled users the registration report shows as registered for MFA, whether or not the tenant's policy allows the method they registered
- `sspr_registered_enabled_users` — Number of enabled users registered for self-service password reset (SSPR)
- `users_without_registration_details` — Number of users, enabled or not, with no row in the registration report; each counts as not MFA-capable, so this shows how much of the gap rests on a missing row

**Can enabled users sign in without a password?**
- `passwordless_capable_enabled_users` — Number of enabled users who are passwordless-capable: the registration report says they've registered a passwordless method the policy allows (a FIDO2 security key or passkey, Windows Hello for Business, or Microsoft Authenticator phone sign-in)
- `passwordless_coverage_percentage` — Percentage of enabled users who are passwordless-capable = `passwordless_capable_enabled_users` / `enabled_users` × 100 (a whole number, 0–100); 0 when `enabled_users` is 0

**Are enabled members covered, leaving guests aside?**
- `enabled_member_users` — Number of enabled users who aren't guests
- `mfa_capable_enabled_member_users` — Number of enabled non-guest users who are MFA-capable
- `member_mfa_coverage_percentage` — Percentage of enabled non-guest users who are MFA-capable = `mfa_capable_enabled_member_users` / `enabled_member_users` × 100 (a whole number, 0–100); 0 when `enabled_member_users` is 0

**Can every admin do MFA?**
- `admin_role_membership_readable` — True if the members of every activated privileged role, and of every group holding one, were read; false if any read failed, and every admin field reads null
- `admin_users` — Number of admins, enabled or not: users holding a privileged directory role (one of the 24 admin roles `azure_entra_privileged_roles` flags, such as Global Administrator, User Administrator or Security Reader) directly or through a group, plus users the registration report flags as admins. Only active role holders are seen, so a PIM-eligible admin who hasn't activated counts only through the report's flag; null if role membership couldn't be read
- `mfa_capable_admin_users` — Number of admins who are MFA-capable; null if role membership couldn't be read
- `admin_users_without_mfa` — Number of admins who aren't MFA-capable, including admins with no row in the registration report; null if role membership couldn't be read
- `admin_users_without_registration_details` — Number of admins with no row in the registration report; null if role membership couldn't be read
- `admin_mfa_coverage_percentage` — Percentage of admins who are MFA-capable = `mfa_capable_admin_users` / `admin_users` × 100 (a whole number, 0–100); 0 when `admin_users` is 0; null if role membership couldn't be read. Disabled admin accounts count in the total


### azure_entra_pim_assignments
Short Description: Shows who can activate each Entra ID admin role on demand, who holds one permanently, and whether activating a privileged role needs MFA, a reason, approval and a time limit.

Script: fetchers/azure/entra_pim_assignments/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph RoleManagement.Read.Directory, in a tenant with Entra ID P2 or ID Governance. Optional: Organization.Read.All; without it, the tenant name reads null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /roleManagement/directory/roleDefinitions` — the name of each directory role
- Microsoft Graph `GET /roleManagement/directory/roleEligibilityScheduleInstances`, expanding the principal — who is eligible to activate each role, and until when
- Microsoft Graph `GET /roleManagement/directory/roleAssignmentScheduleInstances`, expanding the principal — who holds each role now, and whether it was assigned or activated
- Microsoft Graph `GET /policies/roleManagementPolicyAssignments`, filtered to directory roles at tenant scope and expanding each policy's rules — each role's activation and assignment rules

Output: `azure_entra_pim_assignments_<tenant>.json` — every eligible and active directory role assignment with its user, group or app and how long it lasts, and the activation rules of each privileged role (one of the admin roles azure_entra_privileged_roles flags, such as Global Administrator or Privileged Role Administrator) and of each role with an assignment.

Summary fields:

**What was checked?**
- `pim_available` — True if the tenant has Privileged Identity Management; false if Graph refused the first PIM read (the eligible assignments) because the tenant has no Entra ID P2 or ID Governance licence (error code AadPremiumLicenseRequired; the role names stay in the results and the other PIM reads are skipped); null if a read failed, including a licence refusal of a later read (false wins when both happen)
- `collection_complete` — True if role names, eligible and active assignments and role policies were all read; false if any read failed or was refused for the licence, and every other field except `pim_available` is left out
- `privileged_role_policies` — Number of privileged roles whose tenant-wide PIM policy was read
- `privileged_roles_without_policy` — List of privileged role names held by someone (eligible or active, at any scope, directly or through a group) whose tenant-wide PIM policy didn't come back; when it isn't empty, the activation and assignment rule lists below and `max_privileged_activation_hours` read null, so a missing policy never reads as clean

**Who can activate a privileged role on demand?**
- `eligible_assignments` — Number of eligible assignments (a user, group or app that can activate a role when needed) across all directory roles. This and every assignment count below takes direct assignments only (memberType Direct), so a role held through a group counts once, as the group's; an assignment counts as privileged only when the privileged role is held tenant-wide, not scoped to an administrative unit, a single object or an app. A direct privileged assignment that comes back with no scope at all could be tenant-wide, so it makes the privileged counts of its kind null (eligible ones the five below; active ones the seven in the next section), and `privileged_assignments_scoped_below_tenant` null
- `eligible_privileged_assignments` — Number of eligible assignments to privileged roles
- `permanently_eligible_privileged_assignments` — Number of eligible assignments to privileged roles with no end date
- `principals_eligible_for_privileged_roles` — Number of distinct users, groups and apps eligible for at least one privileged role
- `privileged_roles_with_eligible_holders` — List of privileged role names with at least one eligible assignment
- `global_administrator_eligible` — Number of eligible assignments to Global Administrator, held tenant-wide as `global_administrator_permanent_active` counts them (Entra can't scope Global Administrator below the tenant, so this leaves nothing out)

**Who holds a privileged role right now, and for how long?**
- `active_assignments` — Number of active assignments (a role held now) across all directory roles, including activations of an eligible assignment
- `active_privileged_assignments` — Number of active assignments to privileged roles
- `active_privileged_by_standing` — Number of active privileged-role assignments for each kind:
  - permanent (assigned with no end date, so standing access; a group whose membership PIM for Groups manages also reads permanent when its role has no end date)
  - pim_activated (an eligible holder activated it, so it ends after the activation time)
  - time_bound (assigned directly with an end date)
- `permanent_active_privileged_assignments` — Number of active privileged-role assignments with no end date that were not activated through PIM
- `permanent_active_privileged_user_assignments` — Number of permanent active privileged-role assignments held by users (not groups or apps); null if a holder's type wasn't returned
- `principals_with_permanent_privileged_access` — Number of distinct users, groups and apps holding a privileged role permanently
- `privileged_roles_with_permanent_active_holders` — List of privileged role names held permanently by at least one user, group or app
- `global_administrator_permanent_active` — Number of permanent active Global Administrator assignments
- `privileged_assignments_scoped_below_tenant` — Number of eligible and active assignments of privileged roles scoped to an administrative unit, a single object or an app, which the privileged counts leave out; null if one came back with no scope at all

**Does activating a privileged role require MFA, a reason, approval and a time limit?**
- `privileged_roles_activation_without_mfa_or_auth_context` — List of privileged role names whose activation needs neither MFA nor a Conditional Access authentication context; null if `privileged_roles_without_policy` isn't empty or a privileged role's policy sets no authentication context and didn't say whether activation needs MFA
- `privileged_roles_activation_without_justification` — List of privileged role names whose activation doesn't ask for a reason; null if `privileged_roles_without_policy` isn't empty or a privileged role's policy didn't say whether activation needs one
- `privileged_roles_activation_without_approval` — List of privileged role names whose activation doesn't need someone's approval; null if `privileged_roles_without_policy` isn't empty or a privileged role's policy didn't say whether activation needs approval
- `max_privileged_activation_hours` — Hours: the longest maximum activation time set on any privileged role; null if `privileged_roles_without_policy` isn't empty, a privileged role's policy didn't give a maximum activation time, or no privileged role's policy was read
- `privileged_roles_allowing_permanent_active_assignment` — List of privileged role names whose policy lets an admin assign the role permanently as active, with no end date; null if `privileged_roles_without_policy` isn't empty or a privileged role's policy didn't say whether an active assignment needs an end date
- `privileged_roles_allowing_permanent_eligible_assignment` — List of privileged role names whose policy lets an admin make someone permanently eligible, with no end date; null if `privileged_roles_without_policy` isn't empty or a privileged role's policy didn't say whether an eligible assignment needs an end date


### azure_entra_privileged_roles
Short Description: Lists every activated directory role and who holds it, counting Global Administrators and the users, groups and apps holding privileged admin roles.

Script: fetchers/azure/entra_privileged_roles/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph application permission RoleManagement.Read.Directory (Directory.Read.All also covers it). Optional: Organization.Read.All; without it, the tenant's name and domain read null. Not yet verified: whether member names come back without Directory.Read.All; the ids and member types always do.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /directoryRoles` — the directory roles activated in the tenant
- Microsoft Graph `GET /directoryRoles/{id}/members` (per role) — who holds each role

Output: `azure_entra_privileged_roles_<tenant>.json` — each activated directory role, whether it's privileged or Global Administrator, and the users, groups and apps holding it, plus the list of role names counted as privileged.

Summary fields:

**What was checked?**
- `total_directory_roles_activated` — Number of directory roles activated in the tenant (a role is activated the first time anyone is assigned it; a role never assigned isn't listed and has no holders)
- `roles_with_no_members` — Number of activated roles nobody holds now (assigned once, then removed)
- `total_role_assignments` — Number of active role assignments across all activated roles, one per role per holder (user, group, app or other account); PIM-eligible holders who haven't activated aren't listed
- `distinct_principals_with_a_directory_role` — Number of distinct users, groups, apps and other accounts holding at least one directory role

**How many Global Administrators are there?**
- `global_administrator_count` — Number of users, groups and apps holding Global Administrator directly; a group counts once, not its members
- `global_administrator_role_activated` — True if the Global Administrator role is activated in the tenant; false if not, and `global_administrator_count` is 0

**Who holds privileged roles?**
- `privileged_roles_activated` — Number of activated privileged roles: the 24 built-in roles the fetcher treats as tenant-wide admin power, such as Global Administrator, Privileged Role Administrator, User Administrator, Security Administrator and Global Reader (the full list is in the output)
- `privileged_roles_with_members` — Number of privileged roles at least one user, group or app holds
- `privileged_role_names_assigned` — List of the privileged role names at least one user, group or app holds
- `privileged_role_assignments` — Number of assignments to privileged roles, one per role per holder
- `distinct_privileged_principals` — Number of distinct users, groups, apps and other accounts holding at least one privileged role
- `privileged_assignment_percentage` — Percentage of role assignments that are to privileged roles = `privileged_role_assignments` / `total_role_assignments` × 100 (a whole number, 0–100); 0 when `total_role_assignments` is 0

**What kind of account holds privileged power?**
- `users_in_privileged_roles` — Number of privileged-role assignments held by users; a user holding two privileged roles counts twice
- `groups_in_privileged_roles` — Number of privileged-role assignments held by groups; members of the group aren't counted
- `service_principals_in_privileged_roles` — Number of privileged-role assignments held by service principals (apps and managed identities)


### azure_entra_risky_users
Short Description: Shows which users Entra ID Protection flags as risky, which hold privileged roles, how each serious risk was handled, and whether an owned alert covers it.

Script: fetchers/azure/entra_risky_users/fetcher.py

Access: Microsoft Graph IdentityRiskyUser.Read.All, SecurityAlert.Read.All and RoleManagement.Read.Directory (or Directory.Read.All), plus an Entra ID P2 licence. Optional: User.Read.All (Directory.Read.All also covers it); without it, the account status of a privileged user at open risk reads unknown, which counts as enabled, and the run is not marked partial.

Commands Executed:
- Microsoft Graph `GET /identityProtection/riskyUsers` — risky users (a 403 saying the tenant isn't licensed means no P2)
- Microsoft Graph `GET /identityProtection/riskyUsers/{id}/history` (per user at open or high risk) — each change to the user's risk, what caused it and who started it
- Microsoft Graph `GET /security/alerts_v2` (Entra ID Protection alerts only) — the alerts naming each user at open or high risk, with owner, status and incident
- Microsoft Graph `GET /directoryRoles` — activated directory roles
- Microsoft Graph `GET /directoryRoles/{id}/members` — who holds each role
- Microsoft Graph `GET /users/{id}?$select=accountEnabled` (privileged users at open risk) — whether the account is enabled (a 403 means User.Read.All isn't granted, and the status reads unknown)

Output: `azure_entra_risky_users_<tenant>.json` — whether Identity Protection is available, and each risky user with their risk level, state and any privileged roles, plus the risk history and alerts of users at open or high risk.

Summary fields:

**Is Identity Protection available?**
- `identity_protection_available` — Whether Entra ID Identity Protection is available; false means the tenant has no Entra ID P2 licence, and no other field is written

**How many users are at risk, and for how long?**
- `risky_users_total` — Number of users Identity Protection lists as risky, in any state
- `by_risk_state` — Number of risky users in each risk state (for example, at risk, remediated or dismissed)
- `open_risk_users` — Number of users with open risk (still at risk, or confirmed compromised)
- `open_high_risk_users` — Number of users with open risk whose risk level is high
- `oldest_open_risk_days` — Days since the oldest open risk was last updated

**Are privileged accounts at risk?**
- `privileged_open_risk_users` — Number of users with open risk who hold a privileged admin role
- `privileged_open_risk_users_enabled` — Number of users with open risk who hold a privileged role and whose account isn't known to be disabled; an account reads unknown when User.Read.All isn't granted, and unknown counts as enabled
- `privileged_principals` — Number of users, groups or apps that directly hold at least one privileged role

**Did every serious risk raise an alert that someone owns?**
- `open_or_high_risk_users` — Number of risky users at open or high risk: risk still open (at risk, or confirmed compromised), or a high risk level in any state. Their risk history and alerts are read
- `risk_histories_read` — Number of users at open or high risk whose risk history was read; below `open_or_high_risk_users` only when a history read failed
- `identity_protection_alerts` — Number of Entra ID Protection alerts Microsoft Defender XDR lists for the tenant, whichever user they name; null if the alerts couldn't be read
- `alerts_for_open_or_high_risk_users` — Number of Entra ID Protection alerts whose user evidence names a user at open or high risk, matched on the user's object id or user principal name; null if the alerts couldn't be read
- `open_high_risk_users_without_alert` — Number of users with open risk and a high risk level whom no Entra ID Protection alert names; an alert past Defender XDR's retention is no longer listed, so a long-open risk can count here; null if the alerts couldn't be read
- `alerts_without_owner` — Number of alerts naming a user at open or high risk with nobody assigned; Defender XDR gives every alert in an incident the incident's owner when the incident is assigned, so this stands in for alerts whose incident has no owner; null if the alerts couldn't be read
- `alerts_without_incident` — Number of alerts naming a user at open or high risk that belong to no Defender XDR incident; null if the alerts couldn't be read


### azure_entra_service_principals
Short Description: Shows how each non-user account in Entra ID signs in, whether its credentials expire, who owns it, and which API permissions it holds, flagging privileged Microsoft Graph access.

Script: fetchers/azure/entra_service_principals/fetcher.py (uses the shared Graph helpers fetchers/azure/_shared/entra_graph.py)

Access: Microsoft Graph Application.Read.All, or the Directory Readers role. Optional: DelegatedPermissionGrant.Read.All (or Directory.Read.All; the Directory Readers role covers both); without it, the delegated grant fields read null. Optional: User.Read.All (or Directory.Read.All; the Directory Readers role covers it); without it, user owners come back as an id only, so their names and account state read null and `service_principals_with_only_disabled_owners` reads null. Optional: Organization.Read.All; without it, the tenant's name and domain read null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /servicePrincipals` — every service principal and the secrets and certificates it holds
- Microsoft Graph `GET /applications` — this tenant's app registrations with their secrets, certificates and federated credentials
- Microsoft Graph `GET /applications` and `GET /servicePrincipals`, expanding owners — who owns each app registration and service principal
- Microsoft Graph `GET /servicePrincipals`, expanding app role assignments — the application permissions each service principal holds
- Microsoft Graph `GET /applications/{id}/owners`, `GET /servicePrincipals/{id}/owners` and `GET /servicePrincipals/{id}/appRoleAssignments` (only when an expansion returned 20, its limit, or an assignment without its API) — the whole list
- Microsoft Graph `GET /servicePrincipals/{id}` (per API an assignment names) — the names of that API's app roles
- Microsoft Graph `GET /oauth2PermissionGrants` — delegated grants (a 403 means DelegatedPermissionGrant.Read.All isn't granted)

Output: `azure_entra_service_principals_<tenant>.json` — each service principal with its type, who owns it, the credentials it can sign in with and when they expire, and the API permissions it holds, plus app registrations that have no service principal.

Summary fields:

**What was checked?**
- `total_service_principals` — Number of service principals (apps, managed identities and other non-user accounts) in the tenant
- `disabled_service_principals` — Number of service principals that are disabled
- `owners_readable` — True if the owners (the users or service principals listed as able to manage an app registration or service principal) of every app registration and service principal were read; false if any owner read failed, and every count that needs owners reads null
- `owner_details_readable` — True if owners were read and every service principal that can have one (any service principal except Microsoft's own apps and managed identities), and every app registration with no service principal, either has an owner known to be enabled or has every owner's account state (enabled or disabled); false if not, and `service_principals_with_only_disabled_owners` reads null
- `application_permissions_readable` — True if every service principal's application permissions (app roles on an API, used with no user signed in) and their names were read; false if any read failed, and the application permission fields read null
- `delegated_grants_readable` — True if the delegated grants (permissions to call an API on behalf of a signed-in user) were read; false if they couldn't be (usually DelegatedPermissionGrant.Read.All isn't granted), and the delegated grant fields read null
- `delegated_grants_status` — Whether the delegated grants were read: ok; not_authorized (Graph answered 401 or 403, or with its Authorization_RequestDenied code, usually because DelegatedPermissionGrant.Read.All isn't granted; the run still succeeds); or failed (any other error, which fails the run, or the read was never reached)

**What kinds of non-user accounts exist?**
- `application_service_principals` — Number of service principals of type Application (the identity of an app)
- `managed_identities` — Number of managed identities (identities Azure creates and rotates for a resource)
- `system_assigned_managed_identities` — Number of managed identities tied to one resource and deleted with it
- `user_assigned_managed_identities` — Number of managed identities created on their own and attachable to several resources
- `legacy_service_principals` — Number of service principals of type Legacy (created before app registrations existed)
- `social_idp_service_principals` — Number of service principals of type SocialIdp (a social identity provider)

**Who registered the app behind each account?**
- `microsoft_first_party_service_principals` — Number of service principals for Microsoft's own apps (owned by Microsoft's tenants)
- `tenant_owned_service_principals` — Number of service principals for apps registered in this tenant
- `other_tenant_service_principals` — Number of service principals for apps registered in another organization's tenant
- `unknown_owner_service_principals` — Number of service principals, other than managed identities, with no owning organization recorded

**How do non-user accounts authenticate?**
- `federated_service_principals` — Number of service principals whose app has a federated credential (signs in with a token another identity provider issues, with no stored secret); a service principal can count in several of these fields
- `certificate_based_service_principals` — Number of service principals holding a certificate someone in the tenant manages
- `secret_based_service_principals` — Number of service principals holding a client secret (password)
- `tenant_owned_service_principals_without_credentials` — Number of service principals for apps registered in this tenant with no secret, certificate or federated credential, which can't sign in as themselves
- `federated_identity_credentials` — Number of federated credentials on apps that have a service principal

**Do stored credentials expire and get rotated?**
- `total_credentials` — Number of managed credentials: secrets and certificates someone in the tenant manages, held on service principals or on their apps. The certificate Azure issues and rotates for each managed identity isn't a managed credential and is left out
- `service_principal_held_credentials` — Number of managed credentials held on the service principal itself
- `application_held_credentials` — Number of managed credentials held on the app registration
- `password_credentials` — Number of managed credentials that are client secrets
- `certificate_credentials` — Number of managed credentials that are certificates
- `expired_credentials` — Number of managed credentials whose end date has passed
- `credentials_expiring_soon` — Number of managed credentials that expire within `rotation_threshold_days` days and haven't expired
- `credentials_without_expiry` — Number of managed credentials with no end date
- `healthy_credentials` — Number of managed credentials that have an end date, haven't expired and don't expire within `rotation_threshold_days` days
- `rotation_threshold_days` — Days before expiry at which a credential counts as expiring soon (30)
- `credential_rotation_compliance_percentage` — Percentage of managed credentials that are healthy = `healthy_credentials` / `total_credentials` × 100 (a whole number, 0–100); 0 when `total_credentials` is 0
- `platform_managed_credentials` — Number of certificates Azure issues and rotates for managed identities, which no one in the tenant can rotate or let lapse

**Are there app registrations with no service principal?**
- `tenant_applications_without_service_principal` — Number of app registrations in this tenant with no service principal here, which can't sign in to this tenant until one is created
- `federated_identity_credentials_on_applications_without_service_principal` — Number of federated credentials on app registrations with no service principal here
- `ownerless_applications_without_service_principal` — Number of app registrations with no service principal here and no owner; null if owners couldn't be read

**Does every app and service principal have a named owner?**
- `owner_eligible_service_principals` — Number of service principals that can have an owner: all except Microsoft's own apps and managed identities
- `service_principals_without_owner` — Number of service principals that can have an owner where neither the service principal nor its app registration in this tenant lists an owner; null if owners couldn't be read. Apps registered in another organization's tenant usually have no owner here (their owners are set in the publisher's tenant), so they make up most of this count
- `tenant_owned_service_principals_without_owner` — Number of service principals for apps registered in this tenant where neither the service principal nor its app registration lists an owner; null if owners couldn't be read
- `ownerless_service_principals_with_credentials` — Number of service principals that can have an owner, have no owner, and hold a secret, certificate or federated credential someone manages; null if owners couldn't be read
- `service_principals_with_only_disabled_owners` — Number of service principals that can have an owner, have at least one, and whose every owner (on the service principal or its app registration) is a disabled account; null if owners or their account state couldn't be read

**What API permissions do non-Microsoft accounts hold?**
- `service_principals_with_application_permissions` — Number of service principals, other than Microsoft's own apps, holding at least one application permission or default-access assignment (access to an API with no named app role); null if application permissions couldn't be read
- `application_permission_assignments` — Number of application permissions and default-access assignments held by service principals other than Microsoft's own apps; null if application permissions couldn't be read
- `unnamed_graph_application_permissions` — Number of Microsoft Graph application permissions (or ones whose API is unknown), held by service principals other than Microsoft's own apps, whose name couldn't be found in the API's app roles, so whether each is privileged is unknown; null if application permissions couldn't be read
- `unnamed_other_application_permissions` — Number of application permissions on APIs other than Microsoft Graph, held by service principals other than Microsoft's own apps and other than default-access assignments, whose name couldn't be found in the API's app roles; only Microsoft Graph permissions are judged, so each permission on another API, named or not, reads `privileged` null with `judged` false, and so does the holder's `has_privileged_permission` unless it holds a privileged Graph permission; null if application permissions couldn't be read
- `service_principals_with_delegated_grants` — Number of service principals, other than Microsoft's own apps, holding at least one delegated grant; null if delegated grants couldn't be read
- `delegated_permission_grants` — Number of delegated grants held by service principals other than Microsoft's own apps; null if delegated grants couldn't be read
- `admin_consented_delegated_grants` — Number of delegated grants, held by service principals other than Microsoft's own apps, that an admin consented to for every user; null if delegated grants couldn't be read

**Which accounts hold privileged Microsoft Graph permissions?**
- `service_principals_with_privileged_application_permissions` — Number of service principals, other than Microsoft's own apps, holding a privileged Microsoft Graph application permission: one on the list in `privileged_application_graph_permissions_checked`, which lets the holder grant itself more access, take over users' sign-in, change the tenant's security controls, or read or write tenant-wide data such as mail, files, sites and chats, or any whose name contains ReadWrite or FullControl (`privileged_application_graph_permission_substrings`), matched in any case. `azure_managed_identity_configuration` judges a managed identity's Graph permissions the same way; permissions that couldn't be named aren't included (see `unnamed_graph_application_permissions`); null if application permissions couldn't be read
- `managed_identities_with_privileged_application_permissions` — Number of managed identities holding a privileged Microsoft Graph application permission; permissions that couldn't be named aren't included (see `unnamed_graph_application_permissions`); null if application permissions couldn't be read
- `ownerless_service_principals_with_privileged_application_permissions` — Number of service principals that can have an owner, have no owner, and hold a privileged Microsoft Graph application permission; permissions that couldn't be named aren't included (see `unnamed_graph_application_permissions`); null if owners or application permissions couldn't be read
- `privileged_application_permissions_held` — List of the privileged Microsoft Graph application permissions held by service principals other than Microsoft's own apps; permissions that couldn't be named aren't included (see `unnamed_graph_application_permissions`); null if application permissions couldn't be read
- `service_principals_with_privileged_delegated_grants` — Number of service principals, other than Microsoft's own apps, with a delegated grant that includes a privileged Microsoft Graph permission: one on the list in `privileged_delegated_graph_permissions_checked`, which leaves out the tenant-wide data permissions because, delegated, they reach only what the signed-in user can already open; null if delegated grants couldn't be read
- `privileged_delegated_permissions_granted` — List of the privileged Microsoft Graph permissions in delegated grants to service principals other than Microsoft's own apps; null if delegated grants couldn't be read


### azure_entra_sign_ins
Short Description: Shows how users actually sign in: whether each sign-in required and passed MFA, which methods were used, whether Conditional Access applied, and which sign-ins Entra rated risky.

Script: fetchers/azure/entra_sign_ins/fetcher.py (uses the shared REST client fetchers/azure/_shared/azure_rest.py)

Access: Microsoft Graph AuditLog.Read.All and an Entra ID P1 or P2 licence. Optional: Policy.Read.ConditionalAccess (or Policy.Read.All); without it, Graph leaves out which Conditional Access policies applied to each sign-in and they read null. Optional: Organization.Read.All; without it, no tenant name or domain is recorded. Risk levels need Entra ID P2; without it the risky sign-in figures read null.

Commands Executed:
- Microsoft Graph `GET /organization` — the tenant's name and domain
- Microsoft Graph `GET /auditLogs/signIns` on the beta endpoint, from the start of the lookback — every interactive sign-in with its MFA requirement, methods, Conditional Access result and risk (beta because v1.0 has no MFA requirement or methods)

Output: `azure_entra_sign_ins_<tenant>.json` — sign-in counts per app, and per user for each user with a single-factor, no-Conditional-Access or risky sign-in, over the lookback, and those sign-ins listed one by one.

Summary fields:

**What was checked?**
- `sign_in_logs` — Whether the sign-in logs were read: read, not_licensed (Graph refused the first page because the tenant has no Entra ID P1 or P2, so there are no logs to read; the run still succeeds) or not_read (refused or failed before any sign-in was read)
- `lookback_days` — Days of sign-ins read, ending at the run (7 unless `ENTRA_SIGN_IN_LOOKBACK_DAYS` sets it, at most 30). It should be at least the interval between runs, or some sign-ins are never read
- `window_start` — Time of the lookback's start, in UTC
- `window_end` — Time of the lookback's end (the run), in UTC
- `sign_ins_complete` — True if every sign-in in the lookback was read; false if a read failed part-way or stopped at the limit of about 200,000, and the counts cover only the newest sign-ins read (`window_start` still shows the configured start)
- `sign_ins_truncated` — True if reading stopped at about 200,000 sign-ins (checked after each page of 1000); false otherwise
- `total_sign_ins` — Number of interactive sign-ins in the lookback: a user signing in themselves. Non-interactive sign-ins (a client refreshing a token for a user), service principal and managed identity sign-ins aren't read; null if the logs weren't read
- `successful_sign_ins` — Number of sign-ins that succeeded (error code 0); null if the logs weren't read
- `failed_sign_ins` — Number of sign-ins with a non-zero error code. That includes interrupted steps that are a normal part of a successful sign-in, such as the MFA prompt (50074) or keep me signed in (50140), so it isn't a count of failed attempts; null if the logs weren't read
- `users_signing_in` — Number of distinct users with at least one sign-in. A sign-in with no user id, such as an attempt at a name that doesn't exist, counts in the totals but not here; null if the logs weren't read
- `users_listed` — Number of users listed one by one in the evidence: those with at least one successful single-factor sign-in, successful sign-in no Conditional Access policy applied to, or risky sign-in. Every user figure here counts all users signing in, listed or not; null if the logs weren't read
- `apps_signed_in_to` — Number of distinct apps signed in to; null if the logs weren't read

**Did each sign-in require and pass MFA?**
- `successful_single_factor_sign_ins` — Number of successful sign-ins that required only one factor (a password alone, for example). This and `multi_factor_percentage` follow what Entra required for the sign-in (authenticationRequirement), not the method the user presented, so a passwordless sign-in that no policy required MFA for counts as single-factor; null if the logs weren't read
- `successful_multi_factor_sign_ins` — Number of successful sign-ins that required and passed MFA; null if the logs weren't read
- `successful_sign_ins_with_unknown_requirement` — Number of successful sign-ins whose MFA requirement Graph didn't report (null or unknownFutureValue). They count in `successful_sign_ins` but in neither single- nor multi-factor sign-ins, so they lower `multi_factor_percentage`; null if the logs weren't read
- `multi_factor_percentage` — Percentage of successful sign-ins that passed MFA = `successful_multi_factor_sign_ins` / `successful_sign_ins` × 100 (a whole number, 0–100), counting a sign-in with an unreported requirement as not MFA; null when `successful_sign_ins` is 0 or the logs weren't read
- `users_with_single_factor_sign_ins` — Number of users with at least one successful single-factor sign-in; null if the logs weren't read
- `apps_with_single_factor_sign_ins` — Number of apps with at least one successful single-factor sign-in; null if the logs weren't read
- `successful_legacy_authentication_sign_ins` — Number of successful sign-ins from legacy clients that can't do MFA: any client other than a browser, modern mobile and desktop apps or modern clients (Microsoft's own rule), such as IMAP, POP, SMTP or Exchange ActiveSync. A floor: only interactive sign-ins are read, and Microsoft's guidance is to check non-interactive sign-ins for legacy authentication too; null if the logs weren't read

**Which methods were used?**
- `methods_used` — Number of successful sign-ins that used each authentication method (Password, Authenticator App, SMS, FIDO2 security key and so on); a sign-in using two methods counts under both; null if the logs weren't read
- `successful_phishing_resistant_sign_ins` — Number of successful sign-ins that used a phishing-resistant method: a FIDO2 security key, a passkey, Windows Hello for Business, a platform credential, or a certificate that alone satisfied MFA (any other method beside it must be phishing-resistant too, and a reused earlier step rules it out). A step that reused an earlier authentication (Previously satisfied, Satisfied by token) never counts, so this is a floor when the earlier factor was phishing-resistant; null if the logs weren't read
- `users_using_phishing_resistant_methods` — Number of users with at least one successful phishing-resistant sign-in, a floor since a step that reused an earlier authentication never counts; null if the logs weren't read

**Did Conditional Access apply?**
- `successful_sign_ins_without_conditional_access` — Number of successful sign-ins that no Conditional Access policy applied to; null if the logs weren't read
- `users_with_sign_ins_without_conditional_access` — Number of users with at least one successful sign-in no Conditional Access policy applied to; null if the logs weren't read
- `conditional_access_failures` — Number of sign-ins a Conditional Access policy blocked or failed; null if the logs weren't read

**Which sign-ins did Entra rate risky?**
- `risk_levels_available` — True if Entra ID Protection rated the sign-ins (the tenant has Entra ID P2); false if every risk level read hidden; null if the logs weren't read or there were no sign-ins
- `risky_sign_ins` — Number of risky sign-ins: rated low, medium or high risk, or with a risk state of at risk or confirmed compromised; null if the logs weren't read or `risk_levels_available` is false (no Entra ID P2, so risk is unknown, not none)
- `risky_sign_ins_by_level` — Number of risky sign-ins at each risk level (low, medium, high, or none for one flagged only by its risk state); null if the logs weren't read or `risk_levels_available` is false
- `risky_sign_ins_by_state` — Number of risky sign-ins in each risk state (for example atRisk, remediated, dismissed); null if the logs weren't read or `risk_levels_available` is false
- `users_with_risky_sign_ins` — Number of users with at least one risky sign-in; null if the logs weren't read or `risk_levels_available` is false

**Which sign-ins are listed one by one?**
- `exception_sign_ins` — Number of exceptions: successful single-factor sign-ins, successful sign-ins no Conditional Access policy applied to, and risky sign-ins. Each listed sign-in names its reasons: single_factor, single_factor_phishing_resistant (a FIDO2 key, passkey or similar alone, with no policy requiring MFA), no_conditional_access and risky. When `risk_levels_available` is false no sign-in counts as risky, so one flagged only by its risk state isn't an exception; null if the logs weren't read
- `exception_sign_ins_listed` — Number of exceptions listed in the evidence, the newest first, at most 1000; null if the logs weren't read


### azure_managed_identity_configuration
Short Description: Lists every managed identity, what it is attached to, which outside systems can sign in as it, and what its Azure roles and Microsoft Graph permissions let it do.

Script: fetchers/azure/managed_identity_configuration/fetcher.py

Access: Reader on the subscription. Optional: permission to read service principals in Microsoft Graph (a signed-in member user has it by default; a service principal needs Application.Read.All); without it, `graph_access` reads not_authorized and every identity's Graph permissions read unknown.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.ManagedIdentity — tells an unregistered provider apart from no identities
- `user_assigned_identities.list_by_subscription()` — user-assigned identities
- `Resources | where isnotnull(identity)` (Resource Graph) — every resource's identity block: its system-assigned identity and the user-assigned identities attached to it
- `role_definitions.list()` at subscription scope — each role's name and the permissions it grants
- `role_assignments.list_for_subscription()` — every role assignment, matched to identities by principal id
- `GET {identity}/federatedIdentityCredentials` (per user-assigned identity) — outside systems trusted to sign in as the identity
- `GET /servicePrincipals/{id}/appRoleAssignments` (Microsoft Graph, per identity) — Graph application permissions granted to the identity
- `GET /servicePrincipals/{id}` (Microsoft Graph, per API the permissions belong to) — the permission names

Output: `azure_managed_identity_configuration_<subscription>.json` — each user-assigned identity with the resources it is attached to and its federated credentials, each resource's system-assigned identity, and every identity's role assignments and Graph permissions.

Summary fields:

**What managed identities exist?**
- `total_identities` — Number of managed identities, user-assigned and system-assigned
- `total_user_assigned_identities` — Number of user-assigned identities (standalone identities that resources can share)
- `total_system_assigned_identities` — Number of system-assigned identities (one tied to a single resource, deleted with it)
- `system_assigned_identities_by_resource_type` — Number of system-assigned identities for each Azure resource type that holds one, one key per type present (for example `microsoft.web/sites`)
- `provider_registration_status` — Whether Microsoft.ManagedIdentity is registered on the subscription: registered, not_registered or unknown

**Is every user-assigned identity attached to something?**
- `user_assigned_identities_no_resource_attached` — Number of user-assigned identities that no resource in this subscription names (a resource in another subscription, a deployment script or a federated workload may still use one; sign-in activity isn't read)
- `unattached_identities_with_roles` — Number of user-assigned identities that no resource in this subscription names but that still hold at least one role assignment (standing access with no visible owner)

**Which outside systems can sign in as an identity?**
- `user_assigned_identities_with_federated_credentials` — Number of user-assigned identities with at least one federated credential (trust that lets an outside system sign in as the identity without a secret)
- `total_federated_credentials` — Number of federated credentials across all user-assigned identities
- `federated_credentials_by_issuer_kind` — Number of federated credentials for each kind of outside system that issues the token (only kinds present appear):
  - github_actions (GitHub Actions workflows)
  - azure_devops (Azure DevOps pipelines)
  - aks_workload_identity (pods in an AKS cluster)
  - google (Google Cloud)
  - aws (Amazon Web Services)
  - other (any other issuer)
- `federated_credentials_broad_subject` — Number of federated credentials with a broad subject: any GitHub pull request can sign in, a wildcard claims-matching expression is set, or the subject contains a "*"
- `federated_credentials_nonstandard_audience` — Number of federated credentials with no audience, or an audience other than api://AzureADTokenExchange (or its government and China cloud variants)

**What can each identity do in Azure?**
- `identities_with_broad_role` — Number of identities holding Owner, Contributor, User Access Administrator or Role Based Access Control Administrator anywhere visible from this subscription
- `identities_with_subscription_or_higher_role` — Number of identities with a role assigned at subscription, management group or root scope
- `identities_full_control` — Number of identities holding a role whose permissions allow every action ("*")
- `identities_can_grant_access` — Number of identities holding a role whose permissions allow creating role assignments, so the identity can grant access to others
- `identities_can_read_keys` — Number of identities holding a role whose permissions allow reading a data-plane credential (storage, AI services, AI Search, Cosmos DB, Redis, Event Hubs and Service Bus keys, Foundry connection secrets, App Service settings or API Management subscription keys)
- `identities_full_data_access` — Number of identities holding a role whose data permissions are "_" or end in "/_", giving full access to a service's data
- `identities_without_role_assignments` — Number of identities with no role assignment visible from this subscription
- `identities_role_assignments_unknown` — Number of identities whose role assignments are unknown because the role assignment list couldn't be read
- `role_assignments_unresolved_role` — Number of role assignments to managed identities whose role definition isn't visible at subscription scope, so what the role allows is unknown

**What can each identity do in Microsoft Graph?**
- `graph_access` — Whether Microsoft Graph could be read: read; not_authorized (the credential can't read service principals, so every identity's Graph permissions are unknown); failed (the Graph client couldn't connect, with the same effect); or not_read (there were no identities to look up)
- `identities_with_graph_roles` — Number of identities granted at least one Graph application permission
- `identities_with_privileged_graph_roles` — Number of identities granted a privileged Graph application permission (any permission containing ReadWrite or FullControl, or Mail.Send or Mail.Send.Shared)
- `identities_graph_roles_unknown` — Number of identities whose Graph application permissions couldn't be read


### azure_rbac_custom_roles
Short Description: Lists every custom Azure role in the subscription with its permissions, flagging wildcards and permissions that let a holder grant itself more access.

Script: fetchers/azure/rbac_custom_roles/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Authorization — whether the provider is registered
- `role_definitions.list()` at the subscription — every built-in and custom role with its assignable scopes and permissions

Output: `azure_rbac_custom_roles_<subscription>.json` — each custom role with where it can be assigned, its management and data permissions, its wildcards, and whether it can grant itself more access, plus the escalation permissions checked.

Summary fields:

**What was checked?**
- `total_role_definitions` — Number of role definitions listed for the subscription, built-in and custom
- `builtin_role_definitions` — Number of built-in role definitions; above 0 shows the list was read even when there are no custom roles
- `custom_role_definitions` — Number of custom role definitions
- `provider_registration_status` — Whether Microsoft.Authorization is registered on the subscription: registered, not_registered or unknown

**Can a custom role grant its holder more access?**
- `custom_roles_with_privilege_escalation` — Number of custom roles that grant at least one escalation permission: writing role assignments, role definitions or deny assignments. A role grants a permission when one of its actions matches it, with `*` matching any text including `/` (so `*/write` and `Microsoft.Authorization/*` both match), and no notAction in the same permission block removes it; data actions aren't checked
- `custom_roles_that_can_assign_roles` — Number of custom roles that grant `Microsoft.Authorization/roleAssignments/write`, so a holder can assign any role, Owner included, to anyone
- `custom_roles_that_can_write_role_definitions` — Number of custom roles that grant `Microsoft.Authorization/roleDefinitions/write`, so a holder can rewrite a role it already holds
- `custom_roles_with_escalation_names` — List of the names of custom roles that grant an escalation permission

**How broad are custom roles?**
- `custom_roles_with_wildcard_actions` — Number of custom roles with `*` anywhere in an action or data action, such as `*`, `*/read` or `Microsoft.Compute/*`
- `custom_roles_with_all_actions_wildcard` — Number of custom roles with an action of exactly `*` (every management action)
- `owner_equivalent_custom_roles` — Number of custom roles with an action of `*` that still grant writing role assignments, which makes them equal to Owner
- `contributor_equivalent_custom_roles` — Number of custom roles with an action of `*` whose notActions remove writing role assignments, which makes them equal to Contributor
- `custom_roles_with_data_actions` — Number of custom roles with at least one data action (access to data inside resources, such as blobs or secrets)
- `custom_roles_with_not_actions` — Number of custom roles that subtract permissions with notActions or notDataActions
- `custom_roles_with_root_assignable_scope` — Number of custom roles assignable at the root scope (`/`), anywhere in the tenant
- `custom_roles_administering_resource_locks` — Number of custom roles that grant `Microsoft.Authorization/locks/delete`, so a holder can remove the locks that stop resources being deleted

**How many custom roles follow least privilege?**
- `least_privilege_custom_roles` — Number of least-privilege custom roles: no `*` in any action or data action, and no escalation permission
- `least_privilege_percentage` — Percentage of custom roles that are least-privilege = `least_privilege_custom_roles` / `custom_role_definitions` × 100 (a whole number, 0–100); 0 when `custom_role_definitions` is 0


### azure_rbac_role_assignments
Short Description: Lists who holds which Azure role at every scope of a subscription, flags over-broad and access-granting roles, and shows whether each grant is permanent or just-in-time through PIM.

Script: fetchers/azure/rbac_role_assignments/fetcher.py

Access: Reader on the subscription; a custom role also needs roleAssignmentScheduleInstances/read, roleEligibilityScheduleInstances/read and roleManagementPolicyAssignments/read under Microsoft.Authorization, or the run fails not_authorized. Optional: Entra ID P2 or ID Governance in the tenant for Privileged Identity Management (PIM); without it, nothing is eligible (eligible means a user, group or app can activate a role on demand through PIM) and every grant reads permanent (no end date).

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Authorization — tells an unregistered provider from no assignments
- `role_definitions.list()` — the name of each role a grant uses
- `role_assignments.list_for_subscription(filter="atScope()")` — grants made on the subscription or inherited from above it
- `role_assignments.list_for_subscription()` — every grant, including those on resource groups and single resources
- `role_assignment_schedule_instances.list_for_scope()` on the subscription, unfiltered — the PIM schedule behind each active grant at, above and below it
- `role_eligibility_schedule_instances.list_for_scope()` on the subscription, unfiltered — PIM-eligible assignments at, above and below it
- `role_management_policy_assignments.list_for_scope()` on the subscription — the subscription's PIM settings for the four over-broad roles (Owner, Contributor, User Access Administrator and Role Based Access Control Administrator)

Output: `azure_rbac_role_assignments_<subscription>.json` — every role assignment with its scope, user, group or app, role and flags, whether it is permanent, time-bound or activated through PIM, plus PIM-eligible assignments and the over-broad roles' PIM settings.

Summary fields:

**What was checked?**
- `provider_registration_status` — Whether Microsoft.Authorization is registered on the subscription: registered, not_registered or unknown
- `total_role_assignments` — Number of role assignments at subscription scope or above (made on the subscription, or inherited from a management group or the tenant root)
- `distinct_principals` — Number of distinct users, groups and apps with a role assignment at subscription scope or above
- `unresolved_role_definitions` — Number of role assignments at subscription scope or above whose role name couldn't be found (usually a custom role defined on a management group)
- `pim_available` — True if the tenant has PIM; false if Azure refused a PIM read because the tenant has no Entra ID P2 or ID Governance licence, even when another PIM read failed (the PIM reads that succeeded are kept); null if a PIM read failed for another reason and none was refused for the licence. Any PIM failure other than the licence refusal fails the run

**Who holds over-broad access at subscription scope or above?**
- `over_broad_builtin_assignments` — Number of role assignments at subscription scope or above that grant an over-broad built-in role (Owner, Contributor, User Access Administrator or Role Based Access Control Administrator)
- `distinct_principals_with_over_broad_roles` — Number of distinct users, groups and apps holding an over-broad role at subscription scope or above
- `over_broad_percentage` — Percentage of role assignments at subscription scope or above that grant an over-broad role = `over_broad_builtin_assignments` / `total_role_assignments` × 100 (a whole number, 0–100); 0 when `total_role_assignments` is 0
- `least_privilege_assignments` — Number of role assignments at subscription scope or above that don't grant an over-broad role
- `owner_assignments` — Number of Owner assignments at subscription scope or above
- `contributor_assignments` — Number of Contributor assignments at subscription scope or above
- `user_access_administrator_assignments` — Number of User Access Administrator assignments at subscription scope or above
- `rbac_administrator_assignments` — Number of Role Based Access Control Administrator assignments at subscription scope or above
- `role_granting_assignments` — Number of role assignments at subscription scope or above that let the holder grant access, including to itself (Owner, User Access Administrator or Role Based Access Control Administrator)
- `over_broad_at_subscription_scope_or_above` — Number of over-broad role assignments made on the subscription or inherited from a management group or the tenant root

**Where are the assignments at subscription scope or above made?**
- `assignments_at_root_scope` — Number of role assignments made at the tenant root and inherited by the subscription
- `assignments_at_management_group_scope` — Number of role assignments made on a management group above the subscription
- `assignments_at_subscription_scope` — Number of role assignments made on the subscription itself
- `assignments_at_resource_group_scope` — Number of role assignments in the subscription-and-above list that are made on a resource group (normally 0; resource group grants are counted in the below-subscription fields)
- `assignments_at_resource_scope` — Number of role assignments in the subscription-and-above list that are made on a single resource (normally 0; resource grants are counted in the below-subscription fields)
- `assignments_inherited_from_above_subscription` — Number of role assignments inherited from a management group or the tenant root

**What kinds of roles and principals are they?**
- `custom_role_assignments` — Number of role assignments at subscription scope or above that grant a custom role
- `builtin_role_assignments` — Number of role assignments at subscription scope or above that grant a built-in role whose name was found
- `assignments_by_principal_type` — Number of role assignments at subscription scope or above for each kind of principal:
  - User (a person's account)
  - Group (an Entra group)
  - ServicePrincipal (an app or managed identity)
  - Unknown (Azure doesn't say)
- `assignments_with_conditions` — Number of role assignments at subscription scope or above with an attribute-based condition that narrows what the role allows

**What is granted below the subscription?**
- `below_subscription_role_assignments` — Number of role assignments made on a resource group or a single resource
- `below_subscription_distinct_principals` — Number of distinct users, groups and apps with a role assignment on a resource group or a single resource
- `below_subscription_resource_group_assignments` — Number of role assignments made on a resource group
- `below_subscription_resource_assignments` — Number of role assignments made on a single resource
- `below_subscription_over_broad_builtin_assignments` — Number of over-broad role assignments made on a resource group or a single resource
- `below_subscription_role_granting_assignments` — Number of access-granting role assignments (Owner, User Access Administrator or Role Based Access Control Administrator) made on a resource group or a single resource
- `below_subscription_custom_role_assignments` — Number of custom role assignments made on a resource group or a single resource
- `below_subscription_unresolved_role_definitions` — Number of role assignments on a resource group or a single resource whose role name couldn't be found
- `below_subscription_assignments_by_principal_type` — Number of role assignments on a resource group or a single resource for each kind of principal:
  - User (a person's account)
  - Group (an Entra group)
  - ServicePrincipal (an app or managed identity)
  - Unknown (Azure doesn't say)

**What is granted at every scope together?**
- `all_scopes_total_role_assignments` — Number of role assignments at every scope: tenant root, management group, subscription, resource group and single resource
- `all_scopes_distinct_principals` — Number of distinct users, groups and apps with a role assignment at any scope
- `all_scopes_over_broad_builtin_assignments` — Number of over-broad role assignments at any scope
- `all_scopes_role_granting_assignments` — Number of access-granting role assignments at any scope
- `all_scopes_assignments_by_scope_level` — Number of role assignments at each scope level:
  - root (the tenant root)
  - management_group (a management group above the subscription)
  - subscription (the subscription itself)
  - resource_group (a resource group in the subscription)
  - resource (a single resource)
  - unknown (a scope the fetcher couldn't classify)

**Is privileged access permanent or just-in-time?**
- `assignments_by_standing` — Number of role assignments at any scope of each standing; null if the PIM schedules couldn't be read:
  - permanent (no end date: PIM lists a grant made outside it as assigned with no end date, and a grant PIM lists no schedule for also reads permanent; a grant to a group whose membership is just-in-time through PIM for Groups reads permanent although its members' access is not standing)
  - pim_activated (an eligible user, group or app activated it through PIM, so it ends when the activation does)
  - time_bound (assigned with an end date through PIM)
- `over_broad_assignments_by_standing` — Number of over-broad role assignments at any scope of each standing; null if the PIM schedules couldn't be read:
  - permanent (no end date)
  - pim_activated (activated through PIM, so it ends when the activation does)
  - time_bound (assigned through PIM with an end date)
- `permanent_over_broad_assignments` — Number of over-broad role assignments at any scope that are permanent; null if the PIM schedules couldn't be read
- `permanent_over_broad_user_assignments` — Number of permanent over-broad role assignments at any scope held by users (not groups or apps); null if the PIM schedules couldn't be read
- `principals_with_permanent_over_broad_access` — Number of distinct users, groups and apps holding an over-broad role permanently at any scope; null if the PIM schedules couldn't be read
- `assignments_without_pim_schedule` — Number of role assignments at any scope that PIM lists no schedule for; these read permanent; null if the PIM schedules couldn't be read

**Who can activate an over-broad role on demand?**
- `total_eligible_role_assignments` — Number of PIM-eligible assignments (a user, group or app that can activate a role when needed) at any scope; null if they couldn't be read
- `eligible_over_broad_assignments` — Number of PIM-eligible assignments to over-broad roles at any scope; null if they couldn't be read
- `permanently_eligible_over_broad_assignments` — Number of PIM-eligible assignments to over-broad roles with no end date; null if they couldn't be read
- `principals_eligible_for_over_broad_roles` — Number of distinct users, groups and apps eligible for an over-broad role; null if they couldn't be read

**Does activating an over-broad role require MFA, a reason, approval and a time limit?**
- `over_broad_role_policies_read` — List of over-broad role names whose PIM settings on the subscription were read; null if they couldn't be read or PIM isn't available. Only the subscription's settings are read: an eligibility on a management group or resource group follows that scope's own settings, which aren't read
- `over_broad_roles_activation_without_mfa_or_auth_context` — List of over-broad role names whose PIM activation on the subscription needs neither MFA nor a Conditional Access authentication context (only PIM's activation rule is read; MFA that Conditional Access requires at sign-in isn't checked). A role with no authentication-context rule is judged on MFA alone, so it's listed when MFA is off; null if any of the four over-broad roles' settings weren't read, if a role without an authentication context lacks the MFA rule, or if PIM isn't available
- `over_broad_roles_activation_without_justification` — List of over-broad role names whose PIM activation on the subscription doesn't ask for a reason; null if any of the four over-broad roles' settings weren't read or lack the rule this reads, or if PIM isn't available
- `over_broad_roles_activation_without_approval` — List of over-broad role names whose PIM activation on the subscription doesn't need someone's approval; null if any of the four over-broad roles' settings weren't read or lack the rule this reads, or if PIM isn't available
- `max_over_broad_activation_hours` — Hours: the longest maximum PIM activation time set on any over-broad role on the subscription; null if any of the four over-broad roles' settings weren't read, set no maximum or set one that doesn't parse as a duration, or if PIM isn't available
- `over_broad_roles_allowing_permanent_active_assignment` — List of over-broad role names whose PIM settings let an admin assign the role through PIM with no end date; null if any of the four over-broad roles' settings weren't read or lack the rule this reads, or if PIM isn't available
- `over_broad_roles_allowing_permanent_eligible_assignment` — List of over-broad role names whose PIM settings let an admin make someone eligible with no end date; null if any of the four over-broad roles' settings weren't read or lack the rule this reads, or if PIM isn't available


## Logging and monitoring

### azure_activity_log_alerts
Short Description: Shows which security-relevant control-plane operations and App Service changes are covered by an activity log alert that reaches a person.

Script: fetchers/azure/activity_log_alerts/fetcher.py

Access: Reader or Monitoring Reader on the subscription. Optional: Reader on other subscriptions whose action groups the alerts use; without it, those alerts' verdicts read unknown.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Insights and Microsoft.AlertsManagement — skips an unregistered provider
- `activity_log_alerts.list_by_subscription_id()` — activity log alert rules and their conditions
- `GET Microsoft.Insights/actionGroups` — action groups and their receivers
- `GET Microsoft.AlertsManagement/actionRules` — processing rules that suppress or add action groups
- `GET {action group id}` (groups in other subscriptions) — their receivers

Output: `azure_activity_log_alerts_<subscription>.json` — each activity log alert with the operations it fires on, who it notifies and whether it reaches a person, plus the security and App Service operations it's judged against.

Summary fields:

**What activity log alerts exist?**
- `total_activity_log_alerts` — Number of activity log alert rules
- `enabled_alerts` — Number of enabled alert rules
- `disabled_alerts` — Number of disabled alert rules
- `alerts_with_action_groups` — Number of alert rules with at least one action group of their own
- `alerts_without_action_groups` — Number of alert rules with no action group of their own
- `provider_registration_status` — Whether the Azure Monitor provider (Microsoft.Insights) is registered on the subscription: registered, not_registered or unknown

**Are security-relevant operations alerted on?**
- `monitored_operation_coverage` — For each security operation (create/update and delete of NSGs, NSG rules, public IPs, policy assignments, SQL firewall rules and security solutions): true if an enabled alert fires on it
- `monitored_operations_covered` — Number of security operations in monitored_operation_coverage that an enabled alert fires on
- `monitored_operations_total` — Number of security operations in monitored_operation_coverage
- `monitored_operation_percentage` — Percentage of the security operations that an enabled alert fires on = `monitored_operations_covered` / `monitored_operations_total` × 100 (a whole number, 0–100). The total is the fetcher's fixed list of 12 operations, so it is never 0
- `all_monitored_operations_covered` — True if an enabled alert fires on every security operation in monitored_operation_coverage
- `uncovered_monitored_operations` — List of security operations no enabled alert fires on
- `service_health_alert_configured` — True if an enabled alert fires on Service Health incidents

**Do the alerts reach a person?**
- `alerts_routing_to_enabled_receiver` — Number of enabled alerts that always notify an action group with at least one enabled receiver
- `alerts_routing_unknown` — Number of enabled alerts where it's unknown whether they notify anyone
- `alerts_suppressed` — Number of enabled alerts whose notifications an active suppression rule always switches off
- `alerts_possibly_suppressed` — Number of enabled alerts whose notifications a suppression rule might switch off
- `alerts_reaching_human` — Number of enabled alerts that notify a person and aren't suppressed
- `alerts_reaching_human_unknown` — Number of enabled alerts where it's unknown whether they reach a person
- `monitored_operation_coverage_reaching_human` — For each security operation in monitored_operation_coverage: true if an alert that reaches a person fires on it; null if only an alert that might reach a person does; false otherwise

**Does a person get alerted to App Service changes?**
- `change_operation_coverage` — For each App Service change (create/update, configuration change, deployment and slot swap, on apps and slots): true if an alert that reaches a person fires on it; null if only an alert that might reach a person does; false otherwise
- `change_operations_covered` — Number of App Service changes marked true in change_operation_coverage
- `change_operations_possibly_covered` — Number of App Service changes marked null (only possibly covered) in change_operation_coverage
- `change_operations_total` — Number of App Service changes in change_operation_coverage
- `all_change_operations_covered` — True if every App Service change is covered; false if any isn't; null if some are only possibly covered
- `uncovered_change_operations` — List of App Service changes marked false in change_operation_coverage (no alert that reaches, or might reach, a person)


### azure_alert_rules
Short Description: Shows every metric, log search and smart detector alert rule and whether each one actually reaches a person.

Script: fetchers/azure/alert_rules/fetcher.py

Access: Reader or Monitoring Reader on the subscription. Optional: Reader on other subscriptions whose action groups the rules use; without it, those rules' verdicts read unknown.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Insights and Microsoft.AlertsManagement — skips an unregistered provider
- `GET Microsoft.Insights/metricAlerts` — metric alert rules
- `GET Microsoft.Insights/scheduledQueryRules` — log search alert rules
- `GET Microsoft.AlertsManagement/smartDetectorAlertRules` — smart detector rules
- `GET Microsoft.Insights/actionGroups` — action groups and their receivers
- `GET Microsoft.AlertsManagement/actionRules` — processing rules that suppress or add action groups
- `GET {action group id}` (groups in other subscriptions) — their receivers

Output: `azure_alert_rules_<subscription>.json` — each alert rule with its condition, the receivers it notifies (phone numbers cut to the last 4 digits, webhooks to their host, Logic Apps and Functions to their resource id), any processing rules that suppress or add groups to it, and whether it reaches a person; mute durations are recorded but not evaluated, and activity log alerts are in `azure_activity_log_alerts`.

Summary fields:

**What alert rules exist?**
- `total_alert_rules` — Number of alert rules of all types
- `rules_by_type` — Number of alert rules of each type (metric, log_search, smart_detector); a type with no rules is left out
- `alerting_rules` — Number of alert rules that can send a notification (all except log rules that only produce metrics)
- `enabled_alerting_rules` — Number of alerting rules that are enabled
- `disabled_alerting_rules` — Number of alerting rules that are disabled
- `log_search_rules_enabled` — Number of enabled log search (KQL query) alert rules
- `provider_registration_status` — Whether Microsoft.Insights and Microsoft.AlertsManagement are registered on the subscription: registered, not_registered or unknown for each

**Do enabled rules notify anyone?**
- `enabled_rules_without_action_groups` — Number of enabled rules with no action group to notify, either their own or one added by a processing rule
- `enabled_rules_routing_to_enabled_receiver` — Number of enabled rules that always notify a deliverable action group: one that is enabled and has at least one enabled receiver (email and SMS receivers count only when their status is Enabled; other receiver types always count)
- `enabled_rules_routing_unknown` — Number of enabled rules where it's unknown whether they notify anyone: no action group is known to deliver on every notification, and one couldn't be read, or a deliverable one is added only some of the time
- `enabled_rules_routing_to_person` — Number of enabled rules that always notify a person (email, SMS, voice call, app push, Azure role or ITSM ticket)
- `action_groups` — Number of action groups in the subscription
- `deliverable_action_groups` — Number of deliverable action groups in the subscription
- `action_groups_notifying_people` — Number of deliverable action groups that notify a person

**Are notifications being suppressed?**
- `enabled_rules_suppressed` — Number of enabled rules whose notifications an active suppression rule always switches off
- `enabled_rules_possibly_suppressed` — Number of enabled rules whose notifications a suppression rule might switch off (it covers only part of the scope, has conditions, or has a schedule that can't be evaluated)
- `processing_rules` — Number of alert processing rules in the subscription
- `suppressing_processing_rules_active` — Number of enabled suppression rules that are active now, or whose schedule can't rule it out

**Does every enabled rule reach a person?**
- `enabled_rules_reaching_human` — Number of enabled rules that notify a person and aren't suppressed
- `enabled_rules_reaching_human_unknown` — Number of enabled rules where it's unknown whether they reach a person: they notify only webhooks, Logic Apps, Functions, runbooks or Event Hubs (code that may or may not tell anyone), an action group couldn't be read, one that notifies a person is added only some of the time, or a suppression rule might apply
- `enabled_rules_not_reaching_human` — Number of enabled rules that notify no deliverable action group, or that a suppression rule always switches off
- `reaching_human_percentage` — Percentage of enabled alerting rules that reach a person = `enabled_rules_reaching_human` / `enabled_alerting_rules` × 100 (a whole number, 0–100); 0 when `enabled_alerting_rules` is 0. Rules where reaching a person is unknown (`enabled_rules_reaching_human_unknown`) count in the total but not as reaching, so they lower it
- `all_enabled_rules_reach_human` — True if every enabled alerting rule reaches a person; false if any doesn't, or none is enabled; null if none fails but some are unknown


### azure_change_provenance
Short Description: Labels each change in a subscription over the last 14 days as made by a pipeline or deployment, by a deployment a person ran, or by a direct edit.

Script: fetchers/azure/change_provenance/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- Resource Graph `resourcechanges` query — every resource create, update and delete in the lookback window
- Resource Graph `resourcecontainerchanges` query — creates, updates and deletes of resource groups and the subscription itself
- `deployments.list_at_subscription_scope()` — subscription deployment history
- `resource_groups.list()` — the resource groups
- `deployments.list_by_resource_group()` (per group) — each group's deployment history, to match changes to deployments

Output: `azure_change_provenance_<subscription>.json` — every change in the lookback window labelled by origin (pipeline, deployment, manual deployment, direct edit, platform or unattributed), and the deployment history it was matched against.

Summary fields:

**How many changes were made, and how?**
- `total_changes` — Number of changes in the lookback period
- `changes_via_deployment` — Number of changes made by an ARM deployment run by an application, a managed identity or a listed pipeline account
- `changes_via_pipeline` — Number of changes a listed pipeline account made outside any deployment
- `manual_deployment_changes` — Number of changes made by a deployment a person ran (from the CLI as a user, from the Portal, or through a Portal wizard)
- `direct_changes` — Number of changes a named user or app made directly, outside any deployment or pipeline
- `platform_changes` — Number of changes Azure itself made (recorded as System)
- `unattributed_changes` — Number of changes with no recorded caller that couldn't be tied to a deployment

**Are changes made by redeploying rather than by editing in place?**
- `percent_redeployed` — Percentage of changes made by redeploying = (`changes_via_deployment` + `changes_via_pipeline`) / (`changes_via_deployment` + `changes_via_pipeline` + `manual_deployment_changes` + `direct_changes`) × 100 (a whole number, 0–100); 0 when the denominator is 0. Platform and unattributed changes are left out of both
- `percent_redeployed_conservative` — Percentage of changes made by redeploying, counting unattributed changes against it = (`changes_via_deployment` + `changes_via_pipeline`) / (`changes_via_deployment` + `changes_via_pipeline` + `manual_deployment_changes` + `direct_changes` + `unattributed_changes`) × 100 (a whole number, 0–100); 0 when the denominator is 0. Platform changes are left out of both

**Who made changes outside a pipeline, and with what?**
- `manual_deployment_changes_by_changed_by` — Number of manual-deployment changes made by each caller
- `direct_changes_by_changed_by_type` — Number of direct changes for each caller type (User, Application, ManagedIdentity…)
- `direct_changes_by_client_type` — Number of direct changes from each client (Portal, CLI, SDK…)
- `direct_changes_by_changed_by` — Number of direct changes made by each caller
- `direct_changes_by_resource_type` — Number of direct changes for each resource type

**How reliable is the attribution?**
- `attribution_by_method` — Number of changes tied to their origin by each method: `correlation_id` (matched to a deployment by its ID), `same_resource` (took the origin of the nearest identified change to the same resource) and `deployment_window` (made while a deployment was running)
- `direct_changes_in_deleted_resource_groups` — Number of direct changes in resource groups that have since been deleted, whose deployment history was deleted with them (null if the groups couldn't be listed)
- `deployments_in_history` — Number of deployments read from subscription and resource group history
- `deployments_matched_to_changes` — Number of deployments that at least one change was traced to
- `resource_groups_at_deployment_history_cap` — List of resource groups at ARM's 800-deployment history limit, where older deployments were deleted, so their changes look direct


### azure_diagnostic_settings
Short Description: Shows whether the subscription's Activity Log is exported by a diagnostic setting, where it goes, and whether the Administrative, Security, Alert and Policy categories are captured.

Script: fetchers/azure/diagnostic_settings/fetcher.py

Access: Reader or Monitoring Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Insights — tells "not registered" from "no settings"
- `diagnostic_settings.list()` on the subscription — the Activity Log's diagnostic settings, with their categories, category groups, retention and destinations

Output: `azure_diagnostic_settings_<subscription>.json` — each subscription-level diagnostic setting with the Activity Log categories and category groups it turns on, its legacy retention setting, and where it sends the records.

Summary fields:

**What was checked?**
- `total_diagnostic_settings` — Number of diagnostic settings on the subscription itself, which export the Activity Log; resource-level settings are in `azure_resource_diagnostic_settings`
- `provider_registration_status` — Whether the Azure Monitor provider (Microsoft.Insights) is registered on the subscription: registered, not_registered or unknown

**Is the Activity Log exported, and where to?**
- `activity_log_exported` — True if the subscription has at least one diagnostic setting, whatever categories it turns on; false if it has none, so the Activity Log is kept 90 days and then discarded
- `settings_with_storage_account` — Number of settings that send the Activity Log to a storage account
- `settings_with_log_analytics_workspace` — Number of settings that send the Activity Log to a Log Analytics workspace
- `settings_with_event_hub` — Number of settings that send the Activity Log to an event hub
- `settings_with_partner_solution` — Number of settings that send the Activity Log to a partner solution

**Which Activity Log categories are captured?**
- `log_category_coverage` — For each of the eight Activity Log categories, true if at least one setting captures it (by name, or through the allLogs group); false if none does. Other category groups aren't expanded, so a category turned on only through one reads false:
  - Administrative (create, update, delete and action operations on resources)
  - Security (Defender for Cloud alerts)
  - ServiceHealth (Azure service incidents)
  - Alert (Azure Monitor alerts firing)
  - Recommendation (Azure Advisor recommendations)
  - Policy (Azure Policy evaluations and effects)
  - Autoscale (autoscale engine events)
  - ResourceHealth (changes in a resource's health)
- `required_log_categories` — List of the four categories the fetcher requires for control-plane audit: Administrative, Security, Alert and Policy (CIS Azure 5.1.2)
- `covered_required_log_categories` — Number of the four required categories that at least one setting captures; different settings can capture different categories
- `required_log_category_percentage` — Percentage of the required categories captured = `covered_required_log_categories` / the number of `required_log_categories` (4) × 100 (a whole number: 0, 25, 50, 75 or 100); the denominator is always 4, never 0
- `all_required_log_categories_covered` — True if all four required categories are captured, by one setting or spread across several; false if any is missing
- `settings_capturing_required_categories` — Number of settings that on their own capture all four required categories, by name or through allLogs (the stricter, one-setting reading)

**Is the retired per-setting retention still set?**
- `settings_with_legacy_retention` — Number of settings with the legacy per-setting retention policy switched on for at least one category; Azure has retired it in favour of the destination's own retention


### azure_entra_diagnostic_settings
Short Description: Shows which Entra ID log categories the tenant exports and whether audit and sign-in logs reach a Sentinel workspace.

Script: fetchers/azure/entra_diagnostic_settings/fetcher.py

Access: Security Reader or Global Reader in Entra ID. Optional: Microsoft Sentinel Reader on the destination workspaces; without it, whether logs reach Sentinel reads as unknown.

Commands Executed:
- `GET /providers/microsoft.aadiam/diagnosticSettings` — the tenant's diagnostic settings
- `GET /providers/microsoft.aadiam/diagnosticSettingsCategories` — every category, so unexported ones show
- `GET Microsoft.SecurityInsights/onboardingStates` (per destination workspace) — whether it runs Sentinel

Output: `azure_entra_diagnostic_settings_<tenant>.json` — the tenant's diagnostic settings and, for each Entra log category, whether it's exported and whether it reaches Sentinel.

Summary fields:

**Are Entra ID logs exported?**
- `settings_total` — Number of Entra ID diagnostic settings in the tenant
- `categories_exported` — Number of Entra ID log categories that at least one setting exports
- `categories_not_exported` — List of Entra ID log categories no setting exports

**Do audit and sign-in logs reach Sentinel?**
- `key_categories_to_sentinel` — For audit logs (AuditLogs) and sign-in logs (SignInLogs): whether each reaches a Sentinel workspace (true, false, or null when unknown)
- `audit_and_signin_logs_to_sentinel` — True only if both audit and sign-in logs reach Sentinel; false if either doesn't; null if unknown


### azure_log_analytics_deletion_rights
Short Description: Shows who can delete or purge log data, or shorten its retention, in each Log Analytics workspace.

Script: fetchers/azure/log_analytics_deletion_rights/fetcher.py

Access: Reader on the subscription. Optional: Microsoft Graph Directory.Read.All to show principal names, and Entra ID P2 to include PIM-eligible assignments.

Commands Executed:
- `GET /subscriptions` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` — every workspace
- `GET Microsoft.SecurityInsights/onboardingStates` (per workspace) — whether Sentinel is on
- `GET Microsoft.Authorization/roleAssignments` (per workspace) — active role assignments
- `GET Microsoft.Authorization/roleEligibilityScheduleInstances` (per workspace) — PIM-eligible assignments
- `GET {roleDefinitionId}` (per role) — whether the role grants a deletion action
- Microsoft Graph `POST /directoryObjects/getByIds` — principal names

Output: `azure_log_analytics_deletion_rights_<subscription>.json` — for each workspace, its retention and every principal that can delete its data, with the role and scope that grants it.

Summary fields:

**Who can delete log data?**
- `workspaces_collected` — Number of Log Analytics workspaces read
- `max_principals_with_deletion_rights` — Highest number of distinct users, groups or apps that can delete data on any one workspace
- `workspaces_with_explicit_grants` — Number of workspaces where someone has a deletion permission by name (for example, through the Data Purger role), not only through a wildcard permission


### azure_log_analytics_query_audit
Short Description: Shows whether Log Analytics query auditing is on and how often people reviewed the logs each week.

Script: fetchers/azure/log_analytics_query_audit/fetcher.py

Access: Reader on the subscription, plus Log Analytics Reader on the workspace that receives the audit logs.

Commands Executed:
- `GET /subscriptions` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` — every workspace
- `GET Microsoft.SecurityInsights/onboardingStates` (per workspace) — whether Sentinel is on
- `GET Microsoft.Insights/diagnosticSettings` (per workspace) — whether query auditing is exported, and where
- `GET {destination workspace}` and `GET {destination}/tables/LAQueryLogs` — the audit table's retention
- KQL on `LAQueryLogs` — weekly human and application query counts, and queries per user

Output: `azure_log_analytics_query_audit_<subscription>.json` — for each workspace, whether query auditing is on and where the audit logs go, and weekly counts of human and application queries.

Summary fields:

**Are queries against the logs audited?**
- `workspaces_collected` — Number of Log Analytics workspaces read
- `workspaces_with_query_auditing` — Number of workspaces that export their query audit log (the Audit diagnostic category)
- `workspaces_without_query_auditing` — Number of workspaces whose diagnostic settings were read and don't export the query audit log
- `sentinel_workspaces` — Number of workspaces read that have Microsoft Sentinel turned on


### azure_log_analytics_workspaces
Short Description: Shows how long each Log Analytics workspace keeps its logs, who can reach and read them, where they are exported, and whether Microsoft Sentinel is onboarded.

Script: fetchers/azure/log_analytics_workspaces/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.OperationalInsights — tells "not in use" from "no workspaces"
- `workspaces.list()` — every workspace with its SKU, retention, daily cap, network access and access settings
- `tables.list_by_workspace()` (per workspace) — each table's plan and retention
- `data_exports.list_by_workspace()` (per workspace) — data export rules and their destinations
- `intelligence_packs.list()` (per workspace) — the solutions switched on, including Sentinel (SecurityInsights)

Output: `azure_log_analytics_workspaces_<subscription>.json` — each workspace with its SKU, retention and daily cap, public network access, access control mode and shared-key setting, table counts by plan and retention, the tables whose retention differs from the default or that are custom, its data export rules, and whether Sentinel is onboarded; no log data is read.

Summary fields:

**What was checked?**
- `total_workspaces` — Number of Log Analytics workspaces in the subscription
- `total_tables` — Number of tables, built-in and custom, across all workspaces whose tables were read
- `provider_registration_status` — Whether the Log Analytics provider (Microsoft.OperationalInsights) is registered on the subscription: registered, not_registered or unknown

**How long are logs kept, and can ingestion stop?**
- `min_workspace_retention_in_days` — Shortest workspace retention in days (how long a workspace keeps data available to query by default) across all workspaces; null when no workspace reports one
- `max_workspace_retention_in_days` — Longest workspace retention in days across all workspaces; null when no workspace reports one
- `min_table_total_retention_in_days` — Shortest total retention in days (query retention plus long-term retention) of any table, across all workspaces whose tables were read; null when no table reports one. A table's retention can be set apart from its workspace's
- `workspaces_with_daily_cap` — Number of workspaces with a daily ingestion cap (a daily quota other than -1, which means no cap); data arriving after the cap is reached is dropped for the rest of that day

**Who can reach and read the logs?**
- `workspaces_public_ingestion_enabled` — Number of workspaces that accept data from the public internet (public network access for ingestion is Enabled, or not set, which means Enabled)
- `workspaces_public_query_enabled` — Number of workspaces that can be queried from the public internet (public network access for query is Enabled, or not set, which means Enabled)
- `workspaces_resource_or_workspace_access_mode` — Number of workspaces in the "resource or workspace permissions" access mode: someone with read access to an Azure resource can read that resource's logs without any right on the workspace (the enableLogAccessUsingOnlyResourcePermissions setting is true, despite its name)
- `workspaces_workspace_only_access_mode` — Number of workspaces in the "workspace permissions" access mode: reading logs needs a right on the workspace itself (the setting is false or not set)
- `workspaces_local_auth_disabled` — Number of workspaces with shared-key (local) authentication turned off, so callers must sign in with Entra ID; not set means shared keys still work

**Are logs exported?**
- `workspaces_with_data_exports` — Number of workspaces with at least one data export rule, enabled or not
- `total_data_exports` — Number of data export rules across all workspaces, enabled or not

**Is Microsoft Sentinel onboarded?**
- `sentinel_onboarded_workspaces` — Number of workspaces with Microsoft Sentinel onboarded: the SecurityInsights solution is switched on in the workspace
- `sentinel_onboarded` — True if at least one workspace has Sentinel onboarded; false if none does, including when no workspace's solutions could be read (the run then fails)


### azure_log_storage_immutability
Short Description: Shows whether the storage containers holding Azure Monitor logs are protected from change or deletion.

Script: fetchers/azure/log_storage_immutability/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `GET /subscriptions` — picks a subscription when none is set
- `GET Microsoft.Storage/storageAccounts` — storage accounts
- `GET {account}/blobServices/default/containers` (per account) — Azure Monitor log containers and their immutability policies
- `GET {account}/blobServices/default` (accounts with log containers) — soft delete and versioning

Output: `azure_log_storage_immutability_<subscription>.json` — each storage account holding logs with its soft-delete and versioning settings, and each log container's immutability policy, retention and legal hold.

Summary fields:

**Which log storage was checked?**
- `storage_accounts_scanned` — Number of storage accounts checked
- `accounts_with_log_containers` — Number of storage accounts with at least one Azure Monitor log container
- `log_containers` — Number of Azure Monitor log containers found

**Can stored logs be changed or deleted?**
- `locked_policy` — Number of log containers with a locked retention policy, which nobody can shorten or remove
- `unlocked_policy_only` — Number of log containers with only an unlocked retention policy and no legal hold, which an admin can still shorten or remove
- `legal_hold` — Number of log containers under a legal hold
- `unprotected` — Number of log containers with neither a locked retention policy nor a legal hold
- `min_retention_days` — Shortest retention period, in days, among log containers that have a retention policy


### azure_monitor_fired_alerts
Short Description: Lists every Azure Monitor alert fired in the last 30 days, who acknowledged and closed it and when, and how often each alert rule fired.

Script: fetchers/azure/monitor_fired_alerts/fetcher.py

Access: Reader or Monitoring Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.AlertsManagement and Microsoft.Insights — skips an unregistered provider
- `GET Microsoft.AlertsManagement/alertsSummary` — Azure's own count of alerts in the 30 days, to prove none were missed
- `GET Microsoft.AlertsManagement/alerts` — every alert fired in the 30 days Azure keeps them
- `GET {alert id}/history` (per alert) — who acknowledged and closed it, when, and whether its action groups ran
- `GET Microsoft.Insights/metricAlerts` — metric alert rules, to count their fires
- `GET Microsoft.Insights/scheduledQueryRules` — log search alert rules, to count their fires
- `GET Microsoft.AlertsManagement/smartDetectorAlertRules` — smart detector alert rules, to count their fires
- `GET Microsoft.Insights/activityLogAlerts` — activity log alert rules, to count their fires

Output: `azure_monitor_fired_alerts_<subscription>.json` — each fired alert with its rule, severity, state, times and history, and each alert rule with how often and when it last fired. Descriptions and comments past 500 characters are cut and marked as truncated.

Summary fields:

**Were all fired alerts collected?**
- `window_days` — Number of days of fired alerts collected (30, all Azure keeps)
- `alerts_fired` — Number of alerts fired in the window; null if the alert list wasn't read
- `alerts_summary_total` — Number of alerts in the window by Azure's own alert summary; null if it couldn't be read or Microsoft.AlertsManagement isn't registered
- `all_alerts_listed` — True if at least `alerts_summary_total` alerts were listed; false if fewer were; null if the summary or the alert list couldn't be read, or Microsoft.AlertsManagement isn't registered
- `alert_histories_read` — Number of alerts whose state history was read; null if the alert list wasn't read
- `alert_histories_unread` — Number of alerts whose state history couldn't be read (deleted, refused or failed), so who acknowledged or closed them is unknown; when every history is refused the run fails as not authorized; null if the alert list wasn't read
- `provider_registration_status` — Whether Microsoft.AlertsManagement and Microsoft.Insights are registered on the subscription: registered, not_registered or unknown for each

**What fired?**
- `alerts_by_severity` — Number of alerts for each severity (Sev0 most severe to Sev4), or unknown when an alert has none; null if the alert list wasn't read
- `alerts_by_monitor_service` — Number of alerts for each source that raised them, such as Platform (metric alerts), Log Analytics or Azure Backup, or unknown when an alert has none; null if the alert list wasn't read
- `alerts_by_rule_type` — Number of alerts for each kind of rule that fired them (metric, log_search, smart_detector, activity_log, other); builtin for alerts raised by a built-in rule that has no rule resource, such as Azure Backup's and Service Health's; none for alerts with no rule; null if the alert list wasn't read
- `alerts_by_monitor_condition` — Number of alerts for each monitor condition: Fired (the condition still holds), Resolved (it cleared), or unknown when an alert has none; null if the alert list wasn't read

**Was each alert notified, reviewed and closed?**
- `alerts_with_notifications` — Number of alerts whose history shows an action group ran; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial count; null if the alert list wasn't read
- `alerts_with_failed_notifications` — Number of alerts whose history shows an action group failed; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial count; null if the alert list wasn't read
- `alerts_with_actions_suppressed` — Number of alerts whose notifications an alert processing rule suppressed; null if the alert list wasn't read
- `alerts_by_state` — Number of alerts for each review state: New, Acknowledged, Closed, or unknown when an alert has none; null if the alert list wasn't read
- `alerts_open` — Number of alerts not in the Closed state; null if the alert list wasn't read
- `alerts_acknowledged` — Number of alerts someone acknowledged, now or earlier in their history; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial count; null if the alert list wasn't read
- `alerts_closed` — Number of alerts in the Closed state; null if the alert list wasn't read
- `alerts_closed_by_person` — Number of closed alerts whose closing change (the last change to Closed; an earlier close on an alert that was reopened doesn't count) was made by any actor other than System, which includes service principals and automation acting through the API as well as people; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial count; null if the alert list wasn't read
- `median_hours_to_close` — Number of hours from an alert firing to its closing change, the median across closed alerts whose history shows the closing change; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial figure; null if no closed alert's history shows one, or the alert list wasn't read
- `max_hours_to_close` — Number of hours from an alert firing to its closing change, the longest across closed alerts whose history shows the closing change; null while any alert's history is unread (`alert_histories_unread` above 0), never a partial figure; null if no closed alert's history shows one, or the alert list wasn't read
- `oldest_open_alert_fired_at` — Time of firing of the oldest alert not in the Closed state; null if no alert is open, or the alert list wasn't read
- `max_open_alert_age_hours` — Number of hours from the oldest alert not in the Closed state (New or Acknowledged) firing to the run, so an alert acknowledged but left open for weeks shows; at most about 720, since Azure keeps alerts 30 days. The state comes from the alert list, so unread histories don't affect it. 0 if no alert is open; null if an open alert has no firing time, or the alert list wasn't read

**Does every rule fire?**
- `alert_rules_listed` — Number of listed alert rules: metric, log search, smart detector and activity log alert rules the subscription's rule lists return; null if a rule list failed, never a partial count
- `alert_rules_by_type` — Number of listed alert rules of each kind (metric, log_search, smart_detector, activity_log); null if a rule list failed
- `enabled_alert_rules` — Number of listed alert rules that are enabled; null if a rule list failed
- `rules_that_fired` — Number of alert rules, listed or not, with at least one alert in the window; built-in rules (rule type builtin) aren't counted; null if the alert list wasn't read (Microsoft.AlertsManagement not registered, or the list failed)
- `enabled_rules_never_fired` — Number of enabled listed alert rules with no alert in the window; null if the alert list wasn't read or a rule list failed
- `rules_fired_not_listed` — Number of alert rules that fired an alert in the window but aren't in the subscription's rule lists: in another subscription, deleted, a kind the fetcher doesn't list (such as Prometheus rule groups or classic alert rules), or its provider isn't registered; built-in rules (rule type builtin) aren't counted; null if the alert list wasn't read or a rule list failed


### azure_network_flow_logs
Short Description: Shows which virtual networks and subnets have their traffic recorded by an enabled flow log, where those records go and how long they are kept.

Script: fetchers/azure/network_flow_logs/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — tells an unregistered provider apart from no flow logs
- `network_watchers.list_all()` — Network Watchers and their regions
- `flow_logs.list()` (per Network Watcher) — flow logs, their targets, storage, retention and Traffic Analytics settings
- `virtual_networks.list_all()` — virtual networks and their subnets
- `network_security_groups.list_all()` (only when an NSG flow log exists) — whether each network security group is attached to a subnet or network interface

Output: `azure_network_flow_logs_<subscription>.json` — each Network Watcher, each flow log with its target, storage and retention, and each virtual network and subnet with whether its traffic is logged.

Summary fields:

**What was checked?**
- `total_network_watchers` — Number of Network Watchers in the subscription
- `virtual_networks_read` — True if the virtual network list was read; false if it couldn't be, in which case every virtual network, subnet and region field below is null (unknown, not "no networks")
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown

**Is there a Network Watcher in every region with networks?**
- `regions_with_virtual_networks` — List of regions that have at least one virtual network; null if the virtual network list couldn't be read
- `regions_with_virtual_networks_without_network_watcher` — List of regions that have a virtual network but no Network Watcher; empty if the Network Watcher list couldn't be read, null if the virtual network list couldn't be read
- `regions_without_network_watcher_count` — Number of regions that have a virtual network but no Network Watcher; null if the virtual network list couldn't be read

**What flow logs exist?**
- `total_flow_logs` — Number of flow logs across all Network Watchers
- `enabled_flow_logs` — Number of flow logs that are enabled
- `disabled_flow_logs` — Number of flow logs that are disabled
- `flow_logs_by_target_type` — Number of flow logs for each kind of target they log (only kinds present appear):
  - virtual_network (a VNet flow log on a whole virtual network)
  - subnet (a VNet flow log on one subnet)
  - network_interface (a flow log on one network interface)
  - network_security_group (a legacy NSG flow log, which Microsoft is retiring in favour of VNet flow logs)
  - unknown (the target's type couldn't be told from its id)
- `legacy_nsg_flow_logs` — Number of flow logs on a network security group (legacy NSG flow logs)
- `vnet_flow_logs` — Number of flow logs on a virtual network or subnet (VNet flow logs)
- `enabled_flow_logs_filtered` — Number of enabled flow logs with a filter, so they record only matching traffic

**Are enabled flow logs pointed at something that has traffic?**
- `enabled_flow_logs_on_unattached_targets` — Number of enabled flow logs whose target can't produce records: a network security group not attached to any subnet or network interface, or a virtual network or subnet that no longer exists
- `enabled_flow_logs_target_unknown` — Number of enabled flow logs where it's unknown whether the target can produce records: network interface targets (not checked), and targets whose network security group or virtual network list couldn't be read

**Are flow log records analysed and kept long enough?**
- `enabled_flow_logs_with_traffic_analytics` — Number of enabled flow logs with Traffic Analytics on, which sends their records to a Log Analytics workspace
- `enabled_flow_logs_traffic_analytics_every_10_minutes` — Number of enabled flow logs with Traffic Analytics on that process records every 10 minutes (rather than every 60)
- `enabled_flow_logs_retained_indefinitely` — Number of enabled flow logs that keep records indefinitely (no retention policy enabled, or one set to 0 days, so storage never deletes them)
- `minimum_retention_days` — Days of the shortest retention set on any enabled flow log; null if every enabled flow log keeps records indefinitely
- `enabled_flow_logs_retained_under_90_days` — Number of enabled flow logs whose retention policy deletes records in fewer than 90 days
- `enabled_flow_logs_retained_under_365_days` — Number of enabled flow logs whose retention policy deletes records in fewer than 365 days

**Is every virtual network's traffic logged?**
- `total_virtual_networks` — Number of virtual networks in the subscription; null if the list couldn't be read
- `virtual_networks_fully_covered` — Number of virtual networks whose subnets are all covered (each one logged by an enabled, unfiltered VNet flow log on the virtual network or subnet, or an enabled NSG flow log on the subnet's network security group); a virtual network with no subnets counts if an enabled flow log targets it
- `virtual_networks_partially_covered` — Number of virtual networks where at least one subnet is logged (covered, or logged only through a filter) but not every subnet is covered
- `virtual_networks_not_covered` — Number of virtual networks where no subnet is logged by any enabled flow log
- `virtual_networks_coverage_unknown` — Number of virtual networks with at least one subnet whose coverage is unknown (nothing read covers it, but the flow logs or Network Watcher for its region couldn't be read)

**Is every subnet's traffic logged?**
- `total_subnets` — Number of subnets across all virtual networks; null if the virtual network list couldn't be read
- `subnets_covered` — Number of subnets that are covered (logged by an enabled, unfiltered VNet flow log on the virtual network or subnet, or an enabled NSG flow log on the subnet's network security group); flow logs on network interfaces don't count
- `subnets_covered_percentage` — Percentage of subnets that are covered = `subnets_covered` / `total_subnets` × 100 (a whole number, 0–100); 0 when `total_subnets` is 0. Empty subnets count, and subnets with unknown coverage count in the total but not as covered
- `subnets_in_use` — Number of subnets that are in use (something is deployed in them: an IP configuration, private endpoint, service association or resource navigation link, or application gateway IP configuration)
- `subnets_in_use_covered` — Number of in-use subnets that are covered
- `subnets_in_use_covered_filtered` — Number of in-use subnets logged only by a filtered VNet flow log, which records only matching traffic
- `subnets_in_use_not_covered` — Number of in-use subnets that no enabled flow log logs
- `subnets_in_use_coverage_unknown` — Number of in-use subnets whose coverage is unknown (nothing read covers them, but their region's flow logs or Network Watcher couldn't be read)
- `subnets_in_use_covered_percentage` — Percentage of in-use subnets that are covered = `subnets_in_use_covered` / `subnets_in_use` × 100 (a whole number, 0–100); 0 when `subnets_in_use` is 0. Subnets logged only through a filter or with unknown coverage count in the total but not as covered
- `subnets_in_use_without_nsg` — Number of in-use subnets that could take a network security group but have none, so no NSG flow log can reach them (a VNet flow log still can)
- `subnets_in_use_nsg_not_supported` — Number of in-use subnets Azure doesn't let you attach a network security group to (GatewaySubnet, AzureFirewallSubnet, AzureFirewallManagementSubnet, RouteServerSubnet), so only a VNet flow log can cover them


### azure_resource_diagnostic_settings
Short Description: Shows which resources export their logs through a diagnostic setting, where those logs go, whether they actually arrive in Log Analytics, and which log categories nothing captures.

Script: fetchers/azure/resource_diagnostic_settings/fetcher.py

Access: Reader or Monitoring Reader on the subscription. Optional: Reader or Log Analytics Reader on destination workspaces (the Log Analytics workspaces diagnostic settings send logs to) in other subscriptions; without it, log arrival for resources sending there reads unknown (null).

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Insights")` — tells "not registered" from "no settings"
- Resource Graph `Resources` query — every resource; the run fails if the rows collected differ from Resource Graph's total
- `diagnostic_settings_category.list()` (per resource) — which log, audit and metric categories it emits; about 14 resources a second with 4 workers, so roughly 25 minutes per 20,000 resources. That is this pass alone; the destination queries below run after it within the same 3600-second timeout
- `diagnostic_settings.list()` (per log-emitting resource) — its settings and destinations
- `GET {workspace id}` and `GET {workspace id}/tables` (per destination workspace) — its query id, and which tables are on the Basic or Auxiliary plan
- KQL `union *` on each destination workspace (text in `results.ingestion_query`) — newest event time (TimeGenerated) and record count for each resource over the lookback. One query per workspace; it costs nothing on Analytics tables but scans them all, so a large workspace can take minutes. A query that hits a service limit fails the run. One that runs past the 600-second wait is retried up to 4 more times, and destinations are read one after another, so a slow destination can push the run past its 3600-second timeout. It leaves out tables written whatever a diagnostic setting says: AzureActivity, AzureMetrics, InsightsMetrics, Perf, Heartbeat, Syslog, Event and the Container Insights tables (ContainerLog, ContainerLogV2, ContainerInventory, ContainerNodeInventory, ContainerImageInventory, ContainerServiceLog and the Kube tables). Application Insights tables stay, since their rows are the component's own telemetry; a component whose linked workspace is also its destination reads arrived, whatever its setting does
- KQL on each Basic or Auxiliary table through the `/search` endpoint, since `/query` refuses these tables (text in `results.basic_table_query`), only when `basic_logs_lookback_hours` is above 0 — newest event time and record count over that many hours for the tables union * skips; off by default because these queries bill per GB scanned. Custom (_CL) tables and the left-out tables above are never queried, and a table whose query fails stays unqueried without failing the run

Output: `azure_resource_diagnostic_settings_<subscription>.json` — each resource with its diagnostic settings, where its logs go, which log and audit categories aren't exported, and per destination workspace whether its logs arrived (log_analytics_ingestion, last_ingested, ingested_in_window), plus each destination workspace's status, unqueried_tables and table_errors (the Basic or Auxiliary queries that failed) in log_analytics_destinations.

Summary fields:

**Was every resource found and checked?**
- `resources_enumerated` — Number of resources Resource Graph returned
- `resource_graph_total_records` — Number of resources Resource Graph reported in total; must equal `resources_enumerated`, and the run fails if they differ, which proves no resource was missed; null if Resource Graph gave no total
- `resource_graph_pages` — Number of Resource Graph result pages read
- `child_services_synthesized` — Number of storage blob, file, queue and table services added to the inventory (Resource Graph doesn't list them)
- `resources_evaluated` — Number of resources checked, including the added storage services
- `resources_assessed` — Number of resources whose diagnostic log categories were read
- `resources_unsupported` — Number of resources whose type doesn't support diagnostic settings
- `resources_not_found` — Number of resources deleted between being listed and being checked
- `resources_errored` — Number of resources that couldn't be read (any makes the run fail)
- `provider_registration_status` — Whether the Azure Monitor provider (Microsoft.Insights) is registered on the subscription: registered, not_registered or unknown

**Do resources export their logs?**
- `resources_emitting_logs` — Number of log-producing resources (resources whose type produces resource logs). A SQL server's master database counts like any database: its setting is where server-level auditing is exported, while the server itself has metrics only
- `resources_with_enabled_log_setting` — Number of log-producing resources that export logs: they have a diagnostic setting with at least one destination (an empty destination id counts as none) and at least one enabled log category or category group
- `resources_emitting_logs_without_setting` — Number of log-producing resources with no diagnostic setting exporting any log category
- `log_setting_coverage_percentage` — Percentage of log-producing resources that export their logs = `resources_with_enabled_log_setting` / `resources_emitting_logs` × 100 (a whole number, 0–100); 0 when `resources_emitting_logs` is 0
- `uncovered_by_type` — Number of log-producing resources that don't export logs, for each resource type
- `all_log_emitting_resources_covered` — True if every log-producing resource exports its logs and no resource read failed, including when there are none; false otherwise

**Do the logs go to Log Analytics?**
- `resources_sending_to_log_analytics` — Number of log-producing resources that export logs to a Log Analytics workspace
- `log_analytics_coverage_percentage` — Percentage of log-producing resources that export logs to Log Analytics = `resources_sending_to_log_analytics` / `resources_emitting_logs` × 100 (a whole number, 0–100); 0 when `resources_emitting_logs` is 0

**Were the destination workspaces read?**
- `ingestion_lookback_days` — Number of days of records the workspace query looks back over
- `basic_logs_lookback_hours` — Number of hours of records read from Basic and Auxiliary plan tables; 0, the default, when Basic and Auxiliary tables were skipped
- `log_analytics_destinations` — Number of distinct destination workspaces that diagnostic settings export logs to
- `log_analytics_destinations_queried` — Number of destination workspaces whose records were read
- `log_analytics_destinations_not_authorized` — Number of destination workspaces that refused the read (401 or 403, or in a subscription the caller can't see)
- `log_analytics_destinations_not_found` — Number of destination workspaces that no longer exist, so logs sent there go nowhere
- `log_analytics_destinations_errored` — Number of destination workspaces whose read failed for another reason (any makes the run fail)
- `log_analytics_destinations_with_unqueried_tables` — Number of queried destination workspaces with a Basic or Auxiliary table that could hold resource logs (not custom, not left out) and was not queried

**Are the logs actually arriving?**
- `resources_with_recent_ingestion` — Number of log-producing resources exporting to Log Analytics with recent ingestion: at least one record in a destination workspace, in a table that isn't left out, with an event time (TimeGenerated) in the lookback
- `resources_without_recent_ingestion` — Number of log-producing resources exporting to Log Analytics with no record in the lookback, where every destination workspace was read in full or no longer exists. Read in full means queried, with no unqueried Basic or Auxiliary table that could hold the resource's logs: a storage service's own StorageBlobLogs, StorageFileLogs, StorageQueueLogs or StorageTableLogs, or for any other resource a resource-specific table, unless every setting sending there is explicitly in AzureDiagnostics mode; an unset mode counts as resource-specific. No record is not proof of a broken setting: an idle resource writes nothing and counts here too, and `log_analytics_ingestion` shows what did arrive. With `basic_logs_lookback_hours` above 0, Basic and Auxiliary tables are read over that many hours only, so a resource whose only Basic or Auxiliary records are older counts here
- `resources_ingestion_unknown` — Number of log-producing resources exporting to Log Analytics with no record found, where a destination workspace refused the read, failed, or has an unqueried Basic or Auxiliary table that could hold the resource's logs
- `recent_ingestion_percentage` — Percentage of resources exporting to Log Analytics with recent ingestion = `resources_with_recent_ingestion` / `resources_sending_to_log_analytics` × 100 (a whole number, 0–100); 0 when `resources_sending_to_log_analytics` is 0. Resources counted in `resources_ingestion_unknown` are in the total but not the numerator
- `no_recent_ingestion_by_type` — Number of resources without recent ingestion, for each resource type
- `all_log_analytics_resources_ingesting` — True if every log-producing resource exporting to Log Analytics has recent ingestion; false if any has none (an idle resource included) or is unknown; true when none exports to Log Analytics

**Do logs go to an approved workspace?**
- `approved_workspaces_configured` — True if an approved workspace list (`approved_log_workspaces`) was set; false if not. A resource id on the list matches exactly; a bare name matches a workspace of that name in any subscription
- `settings_exporting_to_unapproved_workspace` — Number of diagnostic settings exporting logs to a workspace not on the approved list; null when no list is set
- `resources_sending_to_approved_workspace` — Number of log-producing resources with a diagnostic setting exporting logs to an approved workspace; null when no list is set
- `resources_exporting_to_unapproved_workspace` — Number of resources with a diagnostic setting exporting logs to a workspace not on the approved list; null when no list is set

**Are all audit logs captured?**
- `resources_with_audit_categories` — Number of log-producing resources whose type has audit log categories
- `resources_capturing_all_audit_categories` — Number of resources that export every audit log category their type has


### azure_service_log_records
Short Description: Shows whether App Service HTTP logs and SQL Managed Instance audit events actually reach Log Analytics, with their retention, the principals that connect and the services each app calls.

Script: fetchers/azure/service_log_records/fetcher.py

Access: Reader on the subscription. Optional: Reader or Log Analytics Reader on destination workspaces in other subscriptions; without it, arrival reads unknown for the apps and instances that send logs there.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `GET Microsoft.Web/sites` and `GET {site id}/slots` (per app) — every App Service app and deployment slot, with its state (running or stopped)
- `GET Microsoft.Sql/managedInstances` and `GET {instance id}/databases` (per instance) — every SQL managed instance and its databases
- `GET {resource id}/providers/Microsoft.Insights/diagnosticSettings` (per app, slot and instance) — which workspaces receive AppServiceHTTPLogs or SQLSecurityAuditEvents
- `GET {workspace id}` (per destination workspace) — the workspace's query id
- `GET {workspace id}/tables/{table}` for AppServiceHTTPLogs, AzureDiagnostics and AppDependencies — each table's plan and retention; a missing table has never received a record
- KQL on `AppServiceHTTPLogs` — records, last record, status classes, hosts, latest request and top client IPs per app
- KQL on `AzureDiagnostics` where Category is SQLSecurityAuditEvents — audit events per instance, database and action, and per principal
- KQL on `AppDependencies` — calls per app role, target and type, read only in destination workspaces; best-effort, a failure leaves only this table unread

Output: `azure_service_log_records_<subscription>.json` — each app and slot with its state, HTTP log export and arrival, each managed instance with its audit events, databases and principals, each app role's dependencies, and each destination workspace's tables, retention and any failed queries. When an app or instance sends to more than one workspace, its counts, last record and latest request all come from the one copy holding the most records.

Summary fields:

**What was checked?**
- `lookback_days` — Number of days of records summarized (`service_logs_lookback_days`, 7 by default)
- `apps` — Number of App Service apps and deployment slots in the subscription
- `managed_instances` — Number of SQL managed instances in the subscription
- `managed_databases` — Number of databases listed on the managed instances
- `log_workspaces` — Number of destination workspaces: Log Analytics workspaces that a diagnostic setting sends App Service HTTP logs or managed instance audit events to
- `log_workspaces_queried` — Number of destination workspaces read without a refusal or error: each table's plan was read and every Analytics table among them was queried (a workspace whose tables are all Basic, Auxiliary or missing counts too, and so does one whose only failure was the best-effort dependency query)
- `log_workspaces_not_authorized` — Number of destination workspaces that refused the read (401 or 403, or in a subscription the caller can't see)
- `log_workspaces_not_found` — Number of destination workspaces that no longer exist

**Do App Service HTTP logs arrive?**
- `apps_exporting_http_logs` — Number of exporting apps and slots: those with a diagnostic setting that sends AppServiceHTTPLogs, by name or through the allLogs group, to a Log Analytics workspace
- `apps_with_http_log_records` — Number of exporting apps and slots whose HTTP logs are arriving: at least one record reached a destination workspace in the lookback
- `apps_without_http_log_records` — Number of running exporting apps and slots with no HTTP log record in the lookback, where every destination workspace was queried, lacks the table, or no longer exists; stopped apps are left out (see `stopped_apps_exporting_http_logs`)
- `apps_http_logs_unknown` — Number of exporting apps and slots whose arrival is unknown: a destination workspace refused or failed the read, a query on the AppServiceHTTPLogs table failed there, or the workspace keeps the table on a Basic or Auxiliary plan, which is not queried because it bills per GB scanned
- `stopped_apps_exporting_http_logs` — Number of exporting apps and slots that are stopped; a stopped app serves no requests, so it has no HTTP logs to send
- `http_log_arrival_percentage` — Percentage of running exporting apps and slots whose HTTP logs are arriving = running apps with HTTP log records / (`apps_exporting_http_logs` − `stopped_apps_exporting_http_logs`) × 100 (a whole number, 0–100); 0 when `apps_exporting_http_logs` − `stopped_apps_exporting_http_logs` is 0 (no running app exports). Stopped apps are left out of both counts; apps whose arrival is unknown count in the total but not as arriving
- `http_log_records` — Number of HTTP log records that arrived for the subscription's apps and slots in the lookback, counted once when an app sends them to more than one workspace; apps whose records couldn't be read (apps counted in `apps_http_logs_unknown`, or apps whose diagnostic settings couldn't be read) aren't counted, nor are apps whose fullest copy failed a query on the table; their own `http_log_records` reads null
- `http_log_retention_days` — Number of days the AppServiceHTTPLogs table keeps records for queries (interactive retention), the shortest across the workspaces apps send HTTP logs to that have the table; null if none has it
- `http_log_total_retention_days` — Number of days the AppServiceHTTPLogs table keeps records in all, including long-term (archive) retention, the shortest across the workspaces apps send HTTP logs to that have the table; null if none has it

**Do SQL Managed Instance audit events arrive?**
- `instances_exporting_audit` — Number of exporting managed instances: those with a diagnostic setting that sends SQLSecurityAuditEvents, by name or through the audit or allLogs group, to a Log Analytics workspace
- `instances_with_audit_records` — Number of exporting managed instances whose audit events are arriving: at least one event reached a destination workspace in the lookback, which shows a T-SQL server audit is running
- `instances_without_audit_records` — Number of exporting managed instances with no audit event in the lookback, where every destination workspace was queried, lacks the table, or no longer exists
- `instances_audit_unknown` — Number of exporting managed instances whose arrival is unknown: a destination workspace refused or failed the read, a query on the audit events failed there, or the workspace keeps the table on a Basic or Auxiliary plan
- `audit_records` — Number of audit events that arrived for the subscription's managed instances in the lookback, counted once when an instance sends them to more than one workspace; instances whose events couldn't be read (instances counted in `instances_audit_unknown`, or instances whose diagnostic settings couldn't be read, or whose fullest copy failed one of the audit queries) aren't counted here or in the counts below, and their own counts read null
- `failed_audit_events` — Number of audit events recording an action that failed, such as a failed login
- `audit_actions` — Number of audit events for each action, such as LOGIN SUCCEEDED or LOGIN FAILED, or unknown when an event names none; instances whose events couldn't be read (see `audit_records`) are left out
- `managed_databases_with_audit_records` — Number of listed databases named in at least one audit event; events that name no database, such as server logins, don't count. A database name the instance doesn't list appears in the evidence only once an event on it succeeded, since a failed login names whatever database the client asked for
- `audit_log_retention_days` — Number of days the AzureDiagnostics table keeps audit events for queries (interactive retention), the shortest across the workspaces instances send audit events to that have the table; null if none has it
- `audit_log_total_retention_days` — Number of days the AzureDiagnostics table keeps audit events in all, including long-term (archive) retention, the shortest across the workspaces instances send audit events to that have the table; null if none has it

**Who connects to the managed instances?**
- `audit_principals` — Number of named principals (users, apps, managed identities and SQL logins) with at least one succeeded audit event, counted once per instance; a failed login carries whatever name the client sent, so names seen only in failed events are counted in `failed_only_principals` instead
- `entra_principals` — Number of Entra principals with at least one succeeded audit event, counted once per instance: names containing @, since Entra users sign in by user principal name and apps and managed identities as client id@tenant id
- `sql_login_principals` — Number of SQL logins with at least one succeeded audit event, counted once per instance: principal names without @, which includes Windows-style DOMAIN\name logins
- `failed_only_principals` — Number of principal names seen only in failed audit events, such as logins tried with a guessed or wrong user name, counted once per instance; their names are not listed
- `unnamed_principal_events` — Number of audit events with no principal name, such as failed logins that never identified a login

**What does each app call?**
- `app_roles_with_dependencies` — Number of Application Insights app roles (cloud role names) in the subscription that recorded dependency calls in a destination workspace in the lookback; only destination workspaces are read, so a component sending to any other workspace isn't counted and 0 can mean not looked at
- `dependency_targets` — Number of distinct targets (data stores and services) the app roles called, counted once per app role
- `dependency_types` — List of the kinds of dependency called, such as SQL, HTTP or Azure blob
- `dependency_query_failures` — Number of destination workspaces whose AppDependencies query failed, for example on the query API's row or size cap; the dependency read is best-effort, so neither a failure nor a refusal there fails the run or affects the other tables, and the app roles in a workspace whose dependency query failed aren't counted
- `dependency_retention_days` — Number of days the AppDependencies table keeps records for queries (interactive retention), the shortest across destination workspaces that have the table; null if none has it
- `dependency_total_retention_days` — Number of days the AppDependencies table keeps records in all, including long-term (archive) retention, the shortest across destination workspaces that have the table; null if none has it


## Microsoft Sentinel

### azure_sentinel_analytics_rules
Short Description: Lists each Sentinel workspace's detection rules with their queries, suppression and the log tables each reads, flagging arriving logs no enabled rule reads and rules with no recent logs.

Script: fetchers/azure/sentinel_analytics_rules/fetcher.py

Access: Microsoft Sentinel Reader and Log Analytics Reader on each Sentinel workspace.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` — the subscription's Log Analytics workspaces
- `GET Microsoft.SecurityInsights/onboardingStates` (per workspace) — finds the Sentinel workspaces
- `GET Microsoft.SecurityInsights/alertRules` (per workspace; stable and preview APIs) — every analytics rule with its query and suppression, including kinds only the preview returns, such as NRT
- `GET Microsoft.SecurityInsights/alertRuleTemplates` (per workspace, stable API) — templates available and in use, and the data types each template lists
- `GET Microsoft.SecurityInsights/alertRuleTemplates/{name}` (preview API, only for a template a rule uses that the stable listing lacks, such as an NRT rule's) — that template's data types
- `GET Microsoft.OperationalInsights/workspaces/tables` (per workspace) — the workspace's table and column names, to find the tables each query reads
- `GET Microsoft.OperationalInsights/workspaces/savedSearches` (per workspace) — the workspace's function names (parsers), so a name a query reads that is neither a listed table nor a function counts as a table the workspace never provisioned
- KQL `union *` summarized by table (per workspace) — each table's last ingestion time in the window
- KQL on `SecurityAlert` by product (per workspace) — which products sent alerts, for incident-creation rules (only when the workspace has one and `SecurityAlert` received data)
- `GET Microsoft.SecurityInsights/dataConnectors` (per workspace; stable and preview APIs, only when an enabled incident-creation rule's product sent no alert) — which data connections have alerts enabled, so a rule whose product is wired up but sent nothing reads as quiet; only the preview returns Defender XDR's connection

Output: `azure_sentinel_analytics_rules_<subscription>.json` — for each Sentinel workspace, every analytics rule with its query's SHA-256 and length (and its full query text as written, including any user names, IP addresses or file paths it names, only when `include_rule_query_text` is on), suppression, the tables it reads and which of them got no data, plus the arriving tables no enabled rule reads, the enabled incident-creation rules that are quiet, and, for each table enabled rules read, how many of those rules read it only through their template.

Summary fields:

**Which workspaces were checked?**
- `workspaces_collected` — Number of Sentinel workspaces read
- `workspaces_without_sentinel` — Number of workspaces skipped because Sentinel isn't turned on

**Is threat detection turned on?**
- `enabled_rules_total` — Number of enabled analytics rules across all Sentinel workspaces
- `min_enabled_rules` — Number of enabled analytics rules on the Sentinel workspace with the fewest; null if no workspace's rules could be read
- `workspaces_with_no_enabled_rules` — Number of Sentinel workspaces whose rules were read and have no enabled analytics rule
- `workspaces_with_fusion_enabled` — Number of Sentinel workspaces where the Fusion rule (multistage attack detection) is enabled; Fusion is turned off by design on workspaces onboarded to the Defender portal, where Defender XDR correlates alerts instead

**Do the enabled rules read the logs that arrive?**
- `ingesting_tables_not_read` — Number of tables, across all Sentinel workspaces, that received data in the window (default 14 days) but that no enabled analytics rule reads; null if the table list or the ingestion query failed on every workspace. A rule reads a table when its query names it, in code or as a string passed to `table()` or to a function the query defines; tables in other workspaces don't count. A name the workspace doesn't list counts as a table too where only a table can stand (the start of a query, a let, union, join, lookup or find in), unless it is one of the workspace's functions; names a query binds (mv-expand, as, withsource=) never count. When the query names none, the data types its template lists count instead, except for Fusion, ML and threat intelligence rules. Tables a query reads only through a parser function (such as `_Im_Dns`) aren't seen, so when the query also names a table directly, the parser's sources can show here. An incident-creation rule reads `SecurityAlert`. Workspace and Sentinel telemetry (Usage, Heartbeat, SecurityIncident and the like) and `SecurityAlert`, which also holds Sentinel's own alerts, are left out
- `ingesting_tables_read_only_by_templates` — Number of tables, across all Sentinel workspaces, that received data in the window and that enabled rules read only through their templates' data types, which list the sources a rule may read rather than ones its query is known to read (for example a parser rule whose template lists both CommonSecurityLog and Syslog); these count as read in `ingesting_tables_not_read`. Workspace and Sentinel telemetry and `SecurityAlert` are left out, as there; null if the table list or the ingestion query failed on every workspace
- `enabled_rules_missing_data` — Number of enabled analytics rules missing data, across all Sentinel workspaces; null if the table list or the ingestion query failed on every workspace. A rule is missing data when a table its query reads got nothing in the window (including a table the workspace never provisioned), when none of the data types its template lists got anything (a template's data types are alternative sources), or, for an incident-creation rule, when its product sent no alert
- `enabled_rules_quiet` — Number of the rules in `enabled_rules_missing_data` that are quiet incident-creation rules, across all Sentinel workspaces. A rule is quiet when the product it creates incidents for sent no alert in the window while a data connection that sends that product's alerts has alerts enabled: either the product's own connection or, for Entra ID Protection and Defender for Identity, Endpoint, Office 365 and Cloud Apps, Defender XDR's. No alert in the window is normal for a quiet rule, so `enabled_rules_missing_data` equal to `enabled_rules_quiet` means every rule missing data is quiet. A rule whose product has no connection with alerts enabled isn't quiet, since nothing sends its alerts; Defender XDR doesn't carry Defender for Cloud or Defender for IoT alerts, so a rule for either needs the product's own connection. Null when `enabled_rules_missing_data` is null, or when a workspace's data connectors couldn't be read and an incident-creation rule there missing data isn't quiet through the connections that were
- `enabled_rules_tables_unknown` — Number of enabled analytics rules whose tables can't be worked out (Fusion, ML and threat intelligence rules, and rules whose query reads only through parser functions or wildcards and whose template lists no data type other than a parser function; when the workspace's saved searches can't be read, also rules whose query reads only tables the workspace doesn't list and whose template lists none); null if no workspace's table list could be read


### azure_sentinel_automation_rules
Short Description: Shows each Sentinel workspace's automation rules, what triggers them and what actions they take.

Script: fetchers/azure/sentinel_automation_rules/fetcher.py

Access: Microsoft Sentinel Reader.

Commands Executed:
- `GET /subscriptions` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` and `onboardingStates` (per workspace) — finds the Sentinel workspaces
- `GET Microsoft.SecurityInsights/automationRules` — the automation rules

Output: `azure_sentinel_automation_rules_<subscription>.json` — for each Sentinel workspace, every automation rule with its trigger, conditions and actions, who last changed it, and the playbooks active rules run.

Summary fields:

**Which workspaces were checked?**
- `workspaces_collected` — Number of Sentinel workspaces read
- `workspaces_without_sentinel` — Number of workspaces skipped because Sentinel isn't turned on

**Is incident response automated?**
- `active_rules_total` — Number of active automation rules (enabled and not expired) across all Sentinel workspaces
- `workspaces_with_no_active_rules` — Number of Sentinel workspaces with no active automation rule
- `playbooks_run` — Number of distinct playbooks that active automation rules run


### azure_sentinel_data_sources
Short Description: Shows which log sources and data connectors sent data to each Sentinel workspace in the ingestion window (14 days by default), with each connector's last data received.

Script: fetchers/azure/sentinel_data_sources/fetcher.py

Access: Microsoft Sentinel Reader and Log Analytics Reader.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` and `onboardingStates` (per workspace) — finds the Sentinel workspaces
- `GET Microsoft.SecurityInsights/dataConnectors` (stable and preview APIs) — connections and their states, and the connector definitions installed from Content Hub
- `GET Microsoft.SecurityInsights/dataConnectorDefinitions` — codeless connector definitions
- `GET Microsoft.OperationalInsights/workspaces/tables` — each table's plan, since the query API can't read tables on the Basic or Auxiliary plan
- KQL `union *` summarized by table — each table's last ingestion time and record count
- KQL on `SecurityAlert` by product — which alert products feed the workspace
- KQL `union` of each connector data type's `lastDataReceivedQuery` — last data received per connector data type, as the Sentinel portal measures it
- KQL on `SentinelHealth` — each connector's latest health status (only when health monitoring sends data)

Output: `azure_sentinel_data_sources_<subscription>.json` — for each Sentinel workspace, its connectors with when each last received data, whether it sends only alerts and its latest health status, every table with when it last received data, and the Basic and Auxiliary tables that weren't measured.

Summary fields:

**Which workspaces were checked?**
- `workspaces_collected` — Number of Sentinel workspaces read
- `workspaces_without_sentinel` — Number of workspaces skipped because Sentinel isn't turned on

**Is Sentinel receiving data from enough sources?**
- `min_sources_ingesting` — Number of data sources sending data to the Sentinel workspace with the fewest, in the window (default 14 days); null if no workspace's ingestion could be read. A source is a table that received data, other than workspace and Sentinel telemetry (Usage, Operation, LAQueryLogs, SentinelHealth, SentinelAudit, SecurityIncident, watchlists, UEBA tables and Heartbeat), or a product other than Sentinel sending alerts to `SecurityAlert`. Tables on the Basic or Auxiliary plan aren't counted
- `workspaces_with_2plus_sources` — Number of Sentinel workspaces receiving data from at least two sources
- `workspaces_with_no_sources` — Number of Sentinel workspaces receiving data from no source
- `data_connectors_total` — Number of configured data connections across all Sentinel workspaces, including kinds only the preview API lists, such as Defender XDR; null if no workspace's connections could all be listed

**Is each connector actually delivering data?**
- `connectors_connected` — Number of connectors, across all Sentinel workspaces, that are connected. A connector is every connector definition installed in the workspace plus each built-in connection kind with no installed definition; it is connected when at least one of its data types received data in the window, measured with the definition's own last-data query (for a built-in connection kind, the fetcher's own query for it). Null if no workspace's connectors could all be listed and measured
- `connectors_not_connected` — Number of connectors, across all Sentinel workspaces, none of whose data types received data in the window. This includes an alert-only connector with no linked connection sending alerts (never connected, or its alerts turned off); a quiet one is counted under `connectors_quiet` instead. Connectors whose data couldn't be measured (such as a table on the Basic or Auxiliary plan), or that define no data types, aren't counted. Null if no workspace's connectors could all be listed and measured
- `connectors_quiet` — Number of alert-only connectors, across all Sentinel workspaces, that received no alert in the window although a linked connection (their own, or Defender XDR's for the products whose alerts it carries, which leaves out Defender for Cloud and Defender for IoT) has alerts enabled, which is normal for them. A quiet connector still reads connected: false. A connector is alert-only when all its data types are `SecurityAlert` queries, as for Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud, Defender for Cloud Apps (whose Cloud Discovery logs count only when its connection turns them on), Defender for IoT, Entra ID Protection and Insider Risk Management. Null if no workspace's connectors could all be listed and measured
- `connectors_configured_without_data` — Number of connectors, across all Sentinel workspaces, that have at least one connection (their own, or a linked one such as Defender XDR) but none of whose data types received data in the window, not counting quiet ones. An alert-only connector whose connection has alerts turned off is counted; a connector installed from Content Hub with no connection, which `connectors_not_connected` counts, isn't. Connectors whose data couldn't be measured, or that define no data types, aren't counted. Null if any workspace's connectors couldn't all be listed and measured, or there is no Sentinel workspace
- `workspaces_with_health_monitoring` — Number of Sentinel workspaces where Sentinel health monitoring sent data to the `SentinelHealth` table in the window
- `connectors_unhealthy` — Number of data connections, across all Sentinel workspaces, whose latest `SentinelHealth` status isn't Success; null if no workspace's `SentinelHealth` data was read (health monitoring off, or the query failed)


### azure_sentinel_incidents
Short Description: Shows each Sentinel workspace's recent and open incidents with their response timeline, entities and owner, plus monthly detection, acknowledgement and close times and the open backlog.

Script: fetchers/azure/sentinel_incidents/fetcher.py

Access: Microsoft Sentinel Reader and Log Analytics Reader on each Sentinel workspace.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` — the subscription's Log Analytics workspaces
- `GET Microsoft.SecurityInsights/onboardingStates` (per workspace) — finds the Sentinel workspaces
- `GET Microsoft.SecurityInsights/incidents` (per workspace) — every incident, with its Defender XDR id and link when it came from there
- KQL on `SecurityIncident`, latest row per incident (per workspace) — close times and tasks, which the incident list lacks
- KQL on `SecurityIncident`, every row in the lookback (per workspace) — status, owner and severity changes and who made them
- KQL on `SecurityAlert` for the alert ids `SecurityIncident` lists (per workspace) — the entities on each incident's alerts, up to 25 of each kind, with processes as image name and process id and URLs as scheme and host only
- `GET Microsoft.OperationalInsights/workspaces/tables/SecurityIncident` (per workspace) — whether the table exists, and its retention

Output: `azure_sentinel_incidents_<subscription>.json` — for each Sentinel workspace, every incident created in the lookback (default 90 days) plus older ones still open, with its severity, status, owner, response timeline and entities, and per month the mean time to detect (first activity, the earliest alert's event, to creation), acknowledge and close, and the open backlog at month end, which is null for month ends older than the `SecurityIncident` table's retention. Monthly detection, acknowledgement and close times cover the in-scope incidents only, while the backlog covers every incident, so an older incident closed in the lookback leaves the backlog without counting in that month's close time, and monthly MTTR may read low. In a workspace connected to Microsoft Defender XDR, analysts usually work incidents in the Defender portal, and `SecurityIncident` then shows mostly the XDR sync's updates, which aren't a person's, so those incidents read as not acknowledged, time to acknowledge has few or no values, and an open one can count in `open_unacknowledged` while someone works it. Their acknowledgement times would need Defender XDR's incident activity history, which neither `SecurityIncident` nor Graph's `security/incidents` (its current state and comments, but not when an incident was first activated or assigned) provides.

Summary fields:

**Which workspaces were checked?**
- `workspaces_collected` — Number of Sentinel workspaces collected, including any whose incidents couldn't be read. If the workspace list or a check for Sentinel fails, or a workspace named in `SENTINEL_WORKSPACES` isn't found, every incident count below is null rather than 0
- `workspaces_without_sentinel` — Number of workspaces skipped because Sentinel isn't turned on, or because the check for Sentinel failed

**Are incidents being worked and closed?**
- `incidents_in_scope` — Number of incidents created in the lookback, plus older incidents still open; null if any workspace's incidents couldn't be read
- `open_incidents` — Number of incidents still open (New or Active); null if any workspace's incidents couldn't be read
- `closed_incidents` — Number of in-scope incidents that are closed; null if any workspace's incidents couldn't be read
- `acknowledged_incidents` — Number of in-scope incidents with a known acknowledgement time; null if any workspace's incidents or `SecurityIncident` history couldn't be read. An incident is acknowledged at the first update by a person that moves it to Active or Closed or gives it an owner or a different one (by object id when both updates have one, so a renamed owner isn't a different one), up to its first close, so a reopen never counts and removing an owner doesn't either; a person creating it already Active or owned acknowledges it at creation. Updates with no modifier don't count, nor do updates by automation rules, playbooks, alert grouping, Fusion, incident creation or the Defender XDR sync, matched by the names Microsoft's docs and workbooks use, so incidents worked only in the Defender portal show none. Microsoft doesn't document what a person's update writes as the modifier, so any other modifier counts as a person, including an unlisted system such as a Logic App calling the API directly. Only an incident created in the lookback and within the `SecurityIncident` table's retention whose creation row was read can have a known time, and a later row missing doesn't undo one already found
- `open_unacknowledged` — Number of open incidents whose every update was read and that no person has acknowledged. Every update was read when the incident was created in the lookback and within the `SecurityIncident` table's retention, its creation row was read, and its latest row read matches its current status, owner and severity and is no older than a change made in the last hour; null if any workspace's incidents or `SecurityIncident` history couldn't be read. Open incidents whose updates weren't all read aren't counted, since their acknowledgement can't be known; `open_new_unowned_history_incomplete` counts the ones still New with no owner. Only updates up to the first close count, so an incident an automation rule closed and a person then reopened and worked counts as unacknowledged, while one a person acknowledged before an alert reopened it to New doesn't
- `open_new_unowned_history_incomplete` — Number of open incidents still New with no owner whose updates weren't all read: created before the `SecurityIncident` history read starts (the lookback or the table's retention, whichever is later), an update missing from it, its creation row not ingested yet, or its `SecurityIncident` history unreadable; null if any workspace's incidents couldn't be read. Taken from the incident list, and never overlapping `open_unacknowledged`, which counts only incidents whose every update was read
- `recurring_titles` — Number of incident titles shared by two or more incidents created in the lookback, counted per workspace and summed, so a title recurring in two workspaces counts twice; null if any workspace's incidents couldn't be read

**Can every close time be shown?**
- `closed_missing_close_time` — Number of closed incidents whose close time wasn't found in the `SecurityIncident` table, even though it should still be within the table's retention; null if any workspace's incidents or close times couldn't be read
- `closed_close_time_not_retained` — Number of closed incidents whose close record is older than the `SecurityIncident` table's retention, so the close time is gone; null if any workspace's incidents or close times couldn't be read

### azure_sentinel_playbooks
Short Description: Shows which Sentinel playbooks are live and whether they contain accounts, isolate devices, update incidents or notify people.

Script: fetchers/azure/sentinel_playbooks/fetcher.py

Access: Reader (or Logic App Reader) and Microsoft Sentinel Reader.

Commands Executed:
- `GET /subscriptions` — picks a subscription when none is set
- `GET Microsoft.OperationalInsights/workspaces` and `onboardingStates` (per workspace) — finds the Sentinel workspaces
- `GET Microsoft.SecurityInsights/automationRules` — which playbooks the rules run
- `GET Microsoft.Logic/workflows` — the Logic Apps
- `GET {workflow id}` (when a definition is missing) — the playbook's definition

Output: `azure_sentinel_playbooks_<subscription>.json` — each playbook with its triggers, connectors and capabilities, who it emails, the automation rules that run it, and whether it's live.

Summary fields:

**Which playbooks exist, and which are live?**
- `logic_apps_scanned` — Number of Logic Apps in the subscription
- `playbooks` — Number of Logic Apps that are Sentinel playbooks (triggered by Sentinel or run by an automation rule)
- `enabled_playbooks` — Number of playbooks that are enabled
- `run_by_active_automation_rule` — Number of live playbooks: enabled and run by an active automation rule
- `standard_playbooks` — Number of playbooks on the Standard (single-tenant) Logic Apps plan

**What do the live playbooks do?**
- `live_account_containment_playbooks` — Number of live playbooks that lock down a user account
- `live_notifying_playbooks` — Number of live playbooks that send email or Teams messages
- `notification_recipients` — List of fixed email addresses that live playbooks send to

**Could anything not be read?**
- `playbooks_without_definition` — List of playbooks whose definition couldn't be read
- `automation_rule_references_unresolved` — List of playbooks that automation rules point to but that couldn't be found


## Security posture, policy and backup

### azure_app_service_backups
Short Description: Shows whether each App Service web app has a recent restore point, how often its backups occur, and whether they meet the recovery point objective.

Script: fetchers/azure/app_service_backups/fetcher.py

Access: Reader on the subscription. Optional: Microsoft.Web/sites/config/list/action, to read custom backup settings; without it they read as unknown.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Web")` — tells "App Service not in use" from "no apps"
- `web_apps.list()` — every web app
- Resource Graph query on `microsoft.web/sites` and `sites/slots` — confirms the list is complete; finds function apps and slots to exclude
- `web_apps.get()` (per app only Resource Graph lists) — confirms it exists
- `web_apps.list_snapshots()` (per app) — automatic backups
- `web_apps.list_backups()` (per app) — custom backup history and restores
- `web_apps.get_backup_configuration()` (per app) — custom backup schedule and retention
- Resource Graph query on `microsoft.storage/storageaccounts` — the backup storage's region, replication and immutability

Output: `azure_app_service_backups_<subscription>.json` — each web app's automatic and custom backups, the age of its newest restore point and whether it meets the RPO, plus the apps left out and why.

Summary fields:

**Which web apps were checked?**
- `total_web_apps` — Number of web apps assessed (production sites only; function apps and slots are left out)
- `apps_by_plan_tier` — Number of web apps on each App Service plan tier
- `excluded_function_apps` — Number of function apps left out of the assessment
- `excluded_deployment_slots` — Number of deployment slots left out of the assessment
- `resource_graph_web_apps` — Number of web apps Resource Graph lists, used to check the app list is complete
- `web_apps_added_from_resource_graph` — Number of web apps Resource Graph found that the main app list missed
- `provider_registration_status` — Whether the App Service provider (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown

**Is every web app backed up?**
- `apps_on_tier_without_backups` — Number of web apps on the Free or Shared tier, which can't have backups
- `apps_with_automatic_backups` — Number of web apps with at least one automatic backup
- `apps_automatic_backups_unknown` — Number of web apps whose automatic backups couldn't be read
- `apps_backed_up` — Number of web apps with a restore point inside the restore-point window
- `apps_not_backed_up` — Number of web apps with no restore point inside the restore-point window, or on a tier without backups
- `apps_backed_up_unknown` — Number of web apps where a failed read means it's unknown whether they're backed up
- `backup_coverage_percentage` — Percentage of web apps that are backed up = `apps_backed_up` / `total_web_apps` × 100 (a whole number, 0–100); 0 when `total_web_apps` is 0. Apps whose backup state is unknown (`apps_backed_up_unknown`) count in the total but not as backed up, so they lower it
- `all_web_apps_backed_up` — True if every web app is backed up; false if any isn't; null if any is unknown or there are no apps
- `restore_point_window_hours` — Hours back the fetcher looks when deciding whether an app is backed up and measuring gaps between restore points (default 48)

**How often do backups happen?**
- `max_latest_restore_point_age_hours` — Hours since the newest restore point of the web app that's furthest behind
- `largest_restore_point_gap_hours` — Longest time, in hours, between two consecutive restore points in the window, across all web apps
- `longest_effective_backup_interval_hours` — Longest observed time between backups, in hours, across all web apps (for each app, the larger of its newest restore point's age and its largest gap)
- `longest_configured_backup_interval_hours` — Longest configured backup interval, in hours, across all web apps (automatic backups or a custom schedule)
- `apps_backup_interval_unknown` — Number of web apps that support backups but have too few restore points in the window to measure an interval

**Do backups meet the recovery point objective (RPO)?**
- `recovery_point_objective_hours` — The configured recovery point objective (RPO), in hours; null if none is set
- `apps_meeting_recovery_point_objective` — Number of web apps whose newest restore point age and backup interval are both within the RPO
- `apps_missing_recovery_point_objective` — Number of web apps that exceed the RPO
- `apps_recovery_point_objective_unknown` — Number of web apps where it's unknown whether they meet the RPO (null when no RPO is set)
- `all_web_apps_meet_recovery_point_objective` — True if every web app meets the RPO; false if any doesn't; null if any is unknown, there are no apps, or no RPO is set

**Are custom backups set up, succeeding and restore-tested?**
- `apps_with_custom_backup_configured` — Number of web apps with a custom backup set up to a storage container
- `apps_custom_backup_configuration_unknown` — Number of web apps whose custom backup setup couldn't be determined
- `apps_custom_backup_configuration_not_authorized` — Number of web apps whose custom backup setup couldn't be read because the optional permission isn't granted
- `apps_with_scheduled_custom_backup` — Number of web apps with an enabled custom backup schedule
- `apps_with_custom_backup_history` — Number of web apps with at least one custom backup taken
- `apps_latest_custom_backup_failed` — Number of web apps whose latest custom backup didn't fully succeed (Failed, TimedOut, PartiallySucceeded or Skipped)
- `apps_with_custom_backup_restore_in_window` — Number of web apps restored from a custom backup within the restore-test window (restore_test_window_days)

**Is custom backup storage protected against a regional outage?**
- `custom_backup_storage_accounts` — Number of distinct storage accounts that custom backups go to
- `custom_backup_storage_accounts_geo_redundant` — Number of custom backup storage accounts that replicate to a second region (GRS, RA-GRS, GZRS or RA-GZRS)
- `custom_backup_storage_accounts_unresolved` — Number of custom backup storage accounts not found in this subscription, or whose lookup failed


### azure_backup_recovery_status
Short Description: Shows whether each Recovery Services vault backs up its items successfully, keeps backups at least 30 days, and protects the backups themselves from deletion.

Script: fetchers/azure/backup_recovery_status/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.RecoveryServices")` — tells "Azure Backup not in use" from "no vaults"
- `vaults.list_by_subscription_id()` — every Recovery Services vault with its soft delete, immutability, cross-region restore and encryption settings
- `backup_policies.list()` (per vault) — each backup policy's schedule and retention
- `backup_protected_items.list()` (per vault) — each backed-up item with its policy, protection state and last backup

Output: `azure_backup_recovery_status_<subscription>.json` — each Recovery Services vault with its protection settings, its backup policies and their retention, and the items it backs up with their state and last backup.

Summary fields:

**What was checked?**
- `total_recovery_services_vaults` — Number of Recovery Services vaults in the subscription
- `vaults_with_protected_items` — Number of vaults that back up at least one item
- `vaults_without_protected_items` — Number of vaults that back up nothing
- `total_backup_policies` — Number of backup policies across all vaults
- `total_protected_items` — Number of protected items (VMs, file shares, databases and other workloads registered for backup) across all vaults
- `protected_items_by_workload_type` — Number of protected items for each workload type, keyed by Azure's name for the type; common keys:
  - VM (Azure virtual machine)
  - AzureFileShare (Azure Files share)
  - SQLDataBase (SQL Server database in a VM)
  - SAPHanaDatabase (SAP HANA database in a VM)
  - unknown (Azure reported no workload type)
- `provider_registration_status` — Whether the Recovery Services provider (Microsoft.RecoveryServices) is registered on the subscription: registered, not_registered or unknown

**Are backups kept long enough?**
- `retention_threshold_days` — Days of retention a backup policy must reach to meet the threshold (30)
- `policies_meeting_retention_threshold` — Number of backup policies that meet the retention threshold: the policy's longest retention, taken across its daily, weekly, monthly, yearly and flat retention and any per-database sub-policies and converted to days (a week as 7, a month as 30, a year as 365), is at least `retention_threshold_days`
- `policies_without_readable_retention` — Number of backup policies with no retention the fetcher could convert to days
- `protected_items_meeting_retention_threshold` — Number of protected items whose backup policy in the same vault meets the retention threshold; an item with no policy, or whose policy isn't found, doesn't count
- `retention_threshold_percentage` — Percentage of protected items whose policy meets the retention threshold = `protected_items_meeting_retention_threshold` / `total_protected_items` × 100 (a whole number, 0–100); 0 when `total_protected_items` is 0

**Are the backups themselves protected?**
- `soft_delete_enabled_vaults` — Number of vaults with soft delete Enabled or AlwaysON (on and can't be turned off), so deleted backups are kept for a recovery period
- `immutability_enabled_vaults` — Number of vaults with immutability Unlocked or Locked, so recovery points can't be deleted before they expire; only Locked can't be turned off
- `cross_region_restore_vaults` — Number of vaults with cross-region restore Enabled, so backups can be restored in the paired region

**Are protected items actually being backed up?**
- `protected_items_with_policy` — Number of protected items that have a backup policy assigned
- `protected_items_in_protected_state` — Number of protected items whose protection state is Protected (not stopped, paused, pending or in error)
- `protected_items_with_healthy_last_backup` — Number of protected items whose last backup status is Completed, Success, Succeeded or Healthy


### azure_defender_assessments
Short Description: Lists every Defender for Cloud check result on the subscription, showing which resources pass or fail which checks and how severe each failure is.

Script: fetchers/azure/defender_assessments/fetcher.py (uses the shared Resource Graph paging in fetchers/azure/_shared/resource_graph.py)

Access: Reader or Security Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `assessments.list()` on the subscription — every check result for every resource; a "not registered" answer means Defender for Cloud is not in use
- `assessments_metadata.list_by_subscription()` — each check's categories, threats, type and remediation effort, which the result list doesn't include, and a fallback severity
- Resource Graph `SecurityResources | where type =~ 'microsoft.security/assessments'` — each result's own severity, which the check catalogue can rate lower

Output: `azure_defender_assessments_<subscription>.json` — one record per resource and check, with its Healthy, Unhealthy or NotApplicable status, why, when it last changed, its severity and where that came from, and the check's remediation effort.

Summary fields:

**What was checked?**
- `provider_registration_status` — Whether Defender for Cloud's provider (Microsoft.Security) is registered on the subscription: registered, not_registered (Defender for Cloud is not in use, so no results are listed) or unknown (the read failed)
- `total_assessments` — Number of check results, one for each resource and check

**Which checks pass and fail?**
- `healthy_count` — Number of check results with status Healthy (the resource passes the check)
- `unhealthy_count` — Number of check results with status Unhealthy (the resource fails the check and needs fixing)
- `not_applicable_count` — Number of check results with status NotApplicable (the check doesn't apply to the resource)
- `healthy_percentage` — Percentage of check results that pass = `healthy_count` / `total_assessments` × 100 (a whole number, 0–100); 0 when `total_assessments` is 0. NotApplicable results count in the total but not as passing, so they lower it and 100 is unlikely

**How severe are the failures?**
- `unhealthy_by_severity` — Number of failing (Unhealthy) check results for each severity: the result's own severity from Resource Graph, or the check catalogue's when Resource Graph has none; a severity with no failures is left out, and failures with no severity at all are counted in `unhealthy_severity_unknown_count` instead:
  - High
  - Medium
  - Low
- `unhealthy_severity_from_catalogue_count` — Number of failing check results whose severity comes from the check catalogue because Resource Graph had none for them, so it may be lower than the result's own
- `unhealthy_severity_unknown_count` — Number of failing check results with no severity from Resource Graph or the check catalogue

**Does each result carry its own severity?**
- `severity_from_catalogue_count` — Number of check results of any status whose severity comes from the check catalogue because Resource Graph had none for them (its index lags, or the identity can't read that row)
- `severity_unknown_count` — Number of check results of any status with no severity from Resource Graph or the check catalogue


### azure_defender_plans
Short Description: Shows which Defender for Cloud plans are switched on for the subscription, with each plan's sub-plan, how much of the subscription it covers and whether it is deprecated or inherited.

Script: fetchers/azure/defender_plans/fetcher.py

Access: Reader or Security Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `pricings.list()` on the subscription — every Defender plan with its tier, sub-plan, enablement time, coverage, enforcement, deprecation, inheritance and extensions; a "not registered" answer means Defender for Cloud is not in use

Output: `azure_defender_plans_<subscription>.json` — each Defender for Cloud plan with its tier, sub-plan, when it was switched on (when Azure reports it), how much of the subscription it covers, whether it is deprecated or inherited, and its enabled extensions.

Summary fields:

**What was checked?**
- `provider_registration_status` — Whether Defender for Cloud's provider (Microsoft.Security) is registered on the subscription: registered, not_registered (Defender for Cloud is not in use, so no plans are listed) or unknown (the read failed)
- `total_plans` — Number of Defender plans Azure lists for the subscription, deprecated plans included

**Which plans are switched on?**
- `standard_tier_plans` — Number of plans on the Standard tier. A plan counts as enabled only on Standard, the paid tier that protects resources; Free is the default tier and protects nothing
- `free_tier_plans` — Number of plans on the Free tier, deprecated plans included
- `standard_tier_percentage` — Percentage of plans that are enabled = `standard_tier_plans` / `total_plans` × 100 (a whole number, 0–100); 0 when `total_plans` is 0. Deprecated plans count in the total, and few systems need every plan, so 100 is not expected
- `enabled_plans` — List of the names of the enabled (Standard) plans
- `plans_not_enabled` — List of the names of the Free-tier plans, deprecated plans left out. The fetcher doesn't judge which plans a system needs: VirtualMachines (Defender for Servers) is expected here on a system with no virtual machines
- `enabled_plan_sub_plans` — For each enabled plan, its sub-plan (for example P1 or P2 for VirtualMachines, DefenderForStorageV2 for StorageAccounts, PerKeyVault for KeyVaults); null for a plan that has no sub-plan
- `enabled_plan_enablement_times` — For each enabled plan, the time (UTC) it was last switched to Standard; null when Azure doesn't report it, which can happen for every plan, so every value can be null. Don't build a validator on it

**Which extra protections are switched on?**
- `plans_with_enabled_extensions` — Number of plans, on any tier, with at least one extension switched on (for example agentless VM scanning, malware scanning on upload, or container registry vulnerability assessment)
- `total_enabled_extensions` — Number of extensions switched on across all plans

**Does each enabled plan cover the whole subscription?**
- `enabled_plans_not_fully_covered` — For each enabled plan whose coverage status isn't FullyCovered, that status:
  - PartiallyCovered (some resources have their own setting that switches the plan off)
  - NotCovered (no resource is covered)
  - unknown (Azure gave the plan no coverage status, so it isn't counted as covered)
- `enforced_plans` — List of the names of the plans set to enforce, which stops a resource from overriding the subscription's setting

**Are any enabled plans out of date?**
- `deprecated_plans` — List of the names of the plans Azure marks as deprecated, on any tier
- `deprecated_plans_enabled` — For each deprecated plan still on Standard, the list of plans that replace it

**Is any plan's setting inherited?**
- `plans_reporting_inheritance` — Number of plans for which Azure says whether the setting is inherited. Azure documents this for resource-level settings only, so on a subscription it is usually 0, and the two lists below are then empty because nothing was reported, not because nothing is inherited
- `inherited_plans` — List of the names of the plans whose setting is inherited from a parent scope
- `plans_inherited_from_management_group` — List of the names of the inherited plans whose parent scope is a management group


### azure_defender_regulatory_compliance
Short Description: Shows which controls of each Defender for Cloud compliance standard, such as the Microsoft cloud security benchmark, the subscription passes or fails, and the assessments behind each control.

Script: fetchers/azure/defender_regulatory_compliance/fetcher.py

Access: Reader or Security Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `regulatory_compliance_standards.list()` — every compliance standard the subscription is graded against, with its state; a "not registered" answer means Defender for Cloud is not in use, and a "no standard pricing bundle" answer means regulatory compliance isn't offered because no Defender plan is on the Standard tier
- `regulatory_compliance_controls.list()` (per standard) — each control's state and assessment counts
- `regulatory_compliance_assessments.list()` (per control) — the assessments behind each control, with their state and passed, failed, skipped and unsupported resource counts

Output: `azure_defender_regulatory_compliance_<subscription>.json` — each compliance standard with its controls and the assessments behind each control, every level with its state and pass and fail counts, and whether regulatory compliance is in use at all.

Summary fields:

**What was checked?**
- `provider_registration_status` — Whether Defender for Cloud's provider (Microsoft.Security) is registered on the subscription, judged from the standards list's answer: registered, not_registered (Defender for Cloud is not in use, so no standards are listed) or unknown (the read failed)
- `regulatory_compliance_status` — Whether regulatory compliance answered, one of:
  - available (the standards were listed)
  - not_available_free_tier (no Defender plan is on the Standard tier, so Azure doesn't offer regulatory compliance and no standards are listed)
  - provider_not_registered (Microsoft.Security isn't registered, so Defender for Cloud is not in use)
  - unknown (the standards list failed, or there was no subscription or credential to read it with)
- `total_standards` — Number of compliance standards the subscription is graded against

**Does the subscription pass each compliance standard?**
- `standards_by_state` — Number of compliance standards in each state, as Defender for Cloud grades them; Passed, Failed, Skipped and Unsupported are always present, even at 0, and any other state Azure returns, or Unknown when it returns none, is added:
  - Passed (everything under it that Defender for Cloud can check passes)
  - Failed (at least one control, assessment or resource under it fails)
  - Skipped (Defender for Cloud marked it skipped rather than assessing it)
  - Unsupported (Defender for Cloud can't assess it automatically)
- `standards_failed` — List of the names of the compliance standards whose state is Failed

**Which controls fail?**
- `total_controls` — Number of controls listed across every compliance standard, a control counted once for each standard it sits in; a standard whose control list couldn't be read adds none, and the run reports a failure
- `controls_by_state` — Number of controls, across every compliance standard, in each state (Passed, Failed, Skipped, Unsupported, and any other, as in `standards_by_state`), counted from the controls listed rather than the standard's own totals
- `failed_controls` — Number of controls, across every compliance standard, whose state is Failed
- `control_pass_percentage` — Percentage of graded controls that pass = Passed controls in `controls_by_state` / (Passed + Failed controls in `controls_by_state`) × 100 (a whole number, 0–100); 0 when the sum of Passed and Failed controls is 0. Skipped and Unsupported controls are left out of both

**How many resources fail the assessments behind the controls?**
- `total_assessments` — Number of assessments listed under every control of every compliance standard, an assessment counted once for each control it sits under
- `assessments_by_state` — Number of assessments in each state (Passed, Failed, Skipped, Unsupported, and any other, as in `standards_by_state`)
- `failed_resources` — Number of resource failures: the failed-resource counts of every listed assessment added up, so a resource failing several assessments, or an assessment under several controls, counts each time

**Does the subscription pass the Microsoft cloud security benchmark?**
- `mcsb_standard_present` — True if the Microsoft cloud security benchmark, Defender for Cloud's default standard, is among the compliance standards; false if not
- `mcsb_state` — Whether the benchmark passes as a whole: its state (Passed, Failed, Skipped or Unsupported, as in `standards_by_state`); null if the benchmark isn't listed
- `mcsb_total_controls` — Number of the benchmark's controls listed
- `mcsb_passed_controls` — Number of the benchmark's controls whose state is Passed
- `mcsb_failed_controls` — Number of the benchmark's controls whose state is Failed
- `mcsb_control_pass_percentage` — Percentage of the benchmark's graded controls that pass = `mcsb_passed_controls` / (`mcsb_passed_controls` + `mcsb_failed_controls`) × 100 (a whole number, 0–100); 0 when `mcsb_passed_controls` + `mcsb_failed_controls` is 0, including when the benchmark isn't listed. Skipped and Unsupported controls are left out of both
- `mcsb_failed_control_names` — List of the names of the benchmark's controls whose state is Failed


### azure_disk_encryption_status
Short Description: Shows whether each managed disk, attached or unattached, is encrypted with a customer-managed key rather than Microsoft's platform key, and whether exporting it is restricted.

Script: fetchers/azure/disk_encryption_status/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Compute")` — tells "Compute not in use" from "no disks"
- `disks.list()` — every managed disk with its encryption type, disk encryption set, Azure Disk Encryption settings, attachment and network access policy

Output: `azure_disk_encryption_status_<subscription>.json` — each managed disk's encryption type and key, its Azure Disk Encryption settings (Key Vault ids only, no key URLs), the VMs it is attached to, and its export settings.

Summary fields:

**What was checked?**
- `total_disks` — Number of managed disks in the subscription (every managed disk is encrypted at rest; what varies is the key)
- `os_disks` — Number of disks that report an operating system type (OS disks)
- `data_disks` — Number of disks with no operating system type (data disks)
- `provider_registration_status` — Whether the Compute provider (Microsoft.Compute) is registered on the subscription: registered, not_registered or unknown

**Which key encrypts each disk?**
- `customer_managed_key_disks` — Number of disks encrypted with a customer-managed key: an encryption type other than the platform key (EncryptionAtRestWithCustomerKey or EncryptionAtRestWithPlatformAndCustomerKeys)
- `platform_managed_key_disks` — Number of disks encrypted only with Microsoft's platform key, or with no encryption type reported
- `cmk_percentage` — Percentage of disks with a customer-managed key = `customer_managed_key_disks` / `total_disks` × 100 (a whole number, 0–100); 0 when `total_disks` is 0
- `double_encryption_disks` — Number of disks with double encryption: the platform key and a customer-managed key together (EncryptionAtRestWithPlatformAndCustomerKeys)
- `disk_encryption_set_disks` — Number of disks linked to a disk encryption set, the resource that holds a customer-managed key

**Are attached disks encrypted with a customer-managed key?**
- `attached_total_disks` — Number of disks attached to at least one VM (a shared disk can be attached to several)
- `attached_customer_managed_key_disks` — Number of attached disks encrypted with a customer-managed key
- `attached_platform_managed_key_disks` — Number of attached disks encrypted only with the platform key, or with no encryption type reported
- `attached_cmk_percentage` — Percentage of attached disks with a customer-managed key = `attached_customer_managed_key_disks` / `attached_total_disks` × 100 (a whole number, 0–100); 0 when `attached_total_disks` is 0

**Are unattached disks encrypted with a customer-managed key?**
- `unattached_total_disks` — Number of disks attached to no VM, which still hold the data of the VM they came from
- `unattached_customer_managed_key_disks` — Number of unattached disks encrypted with a customer-managed key
- `unattached_platform_managed_key_disks` — Number of unattached disks encrypted only with the platform key, or with no encryption type reported
- `unattached_cmk_percentage` — Percentage of unattached disks with a customer-managed key = `unattached_customer_managed_key_disks` / `unattached_total_disks` × 100 (a whole number, 0–100); 0 when `unattached_total_disks` is 0

**Is the guest volume encrypted, and is export restricted?**
- `azure_disk_encryption_disks` — Number of disks with Azure Disk Encryption on, which also encrypts the volume inside the VM (BitLocker on Windows, dm-crypt on Linux)
- `network_access_restricted_disks` — Number of disks whose network access policy is DenyAll or AllowPrivate, so a download (SAS) link for the disk can't be used from the internet; AllowAll doesn't count


### azure_policy_assignments
Short Description: Lists every Azure Policy assignment in effect on the subscription and shows which ones actually enforce their policies and which only audit.

Script: fetchers/azure/policy_assignments/fetcher.py

Access: Reader on the subscription. Optional: Reader on the management groups that hold custom policy definitions; without it, those definitions and their effects read as unavailable.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Authorization")` — tells "no policy assigned" from an unregistered provider
- `policy_assignments.list()` — every assignment on the subscription and those inherited from management groups
- `policy_definitions` / `policy_set_definitions` `get_built_in()`, `get()` or `get_at_management_group()` (per distinct definition) — display name, built-in or custom, and the policy effect
- `policy_definitions.list_built_in()` (once, when an initiative is assigned) — the effect of each built-in member policy

Output: `azure_policy_assignments_<subscription>.json` — each policy assignment with its scope, exclusions, parameters, enforcement mode and policy definition, the effect of each policy it applies, and whether it actually enforces.

Summary fields:

**What policy assignments exist?**
- `total_policy_assignments` — Number of policy assignments in effect on the subscription, its own and inherited
- `initiative_assignments` — Number of assignments of an initiative (a policy set bundling many policies)
- `single_definition_assignments` — Number of assignments of a single policy definition
- `built_in_definition_assignments` — Number of assignments whose definition or initiative is built in by Microsoft
- `custom_definition_assignments` — Number of assignments whose definition or initiative is custom
- `unresolved_definition_assignments` — Number of assignments whose definition or initiative couldn't be read
- `provider_registration_status` — Whether the policy provider (Microsoft.Authorization) is registered on the subscription: registered, not_registered or unknown

**Where do the assignments apply?**
- `subscription_scoped_assignments` — Number of assignments made on the subscription itself
- `resource_group_scoped_assignments` — Number of assignments made on one resource group
- `inherited_assignments` — Number of assignments made on a management group above the subscription
- `assignments_with_excluded_scopes` — Number of assignments that exclude at least one scope (notScopes)
- `assignments_with_parameters` — Number of assignments that set at least one parameter

**Is enforcement switched on?**
- `enforced_assignments` — Number of assignments with enforcement mode Default, where the policy's effect is applied
- `audit_only_assignments` — Number of assignments with enforcement mode DoNotEnforce (the portal's "Disabled"), which are evaluated but change nothing
- `enforced_percentage` — Percentage of assignments with enforcement on = `enforced_assignments` / `total_policy_assignments` × 100 (a whole number, 0–100); 0 when `total_policy_assignments` is 0
- `security_center_builtin_assigned` — True if Defender for Cloud's own assignment (SecurityCenterBuiltIn) is present; false if not
- `security_center_builtin_enforced` — True if the SecurityCenterBuiltIn assignment is present with enforcement mode Default; false if not

**Do the assignments actually enforce, or only audit?**
- `actually_enforcing_assignments` — Number of assignments that actually enforce: at least one policy with an enforcing effect (deny, denyAction, modify, deployIfNotExists, append, mutate, addToNetworkGroup or enforceSetting, which block, change or remediate a resource) under enforcement mode Default
- `actually_enforcing_percentage` — Percentage of assignments that actually enforce = `actually_enforcing_assignments` / `total_policy_assignments` × 100 (a whole number, 0–100); 0 when `total_policy_assignments` is 0. Assignments whose effects couldn't be resolved (`unresolved_effect_assignments`) count in the total but not as enforcing, so they lower it
- `audit_effect_only_assignments` — Number of assignments whose policies only report (audit, auditAction, auditIfNotExists or manual), or whose enforcing effects are held back by enforcement mode DoNotEnforce
- `disabled_effect_assignments` — Number of assignments whose every policy has the disabled effect
- `unresolved_effect_assignments` — Number of assignments where no policy's effect could be resolved (the definition couldn't be read, the effect is an expression, or its value isn't a known effect)
- `assignments_by_effect_class` — Number of assignments in each effect class:
  - enforcing (actually enforces)
  - audit_only (only reports, or held back by DoNotEnforce)
  - disabled (every policy disabled)
  - unresolved (no effect resolved, or only disabled resolved with some policies unresolved)
- `enforcing_effects_not_enforced_assignments` — Number of assignments with enforcement mode DoNotEnforce that contain at least one policy with an enforcing effect

**Was every policy's effect resolved?**
- `member_policy_effect_counts` — Number of policies with each effect across every assignment, counting each policy of an initiative (an initiative assigned twice counts twice), plus unresolved for policies whose effect couldn't be resolved
- `unresolved_member_policies` — Number of policies across every assignment whose effect couldn't be resolved, counting the unresolved policies inside partly resolved initiatives, which are classed by their resolved policies alone
- `unresolved_member_policies_not_enforced` — Number of policies whose effect couldn't be resolved inside assignments with enforcement mode DoNotEnforce, where an enforcing effect may be held back unseen


### azure_policy_compliance
Short Description: Shows what the assigned Azure Policies found: which resources are non-compliant and why, whether remediation fixed them, and which non-compliance keeps coming back.

Script: fetchers/azure/policy_compliance/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.PolicyInsights")` — tells "Azure Policy not in use" from "nothing non-compliant"
- `policy_states.summarize_for_subscription("latest")` — the service's own compliance counts, subscription-wide and per assignment
- `policy_states.list_query_results_for_subscription("latest")` filtered to NonCompliant — the non-compliant (resource, policy) records, up to a limit
- `policy_states.list_query_results_for_resource("latest")` expanded with evaluation details (per listed resource, up to a limit) — the values each policy compared
- `policy_states.list_query_results_for_subscription("default")` grouped per resource, policy and state, and a count of the groups — 30 days of evaluation history, checked to be complete
- `policy_states.list_query_results_for_subscription("default")` for one pair, ordered by time (per part-time non-compliant pair, up to a limit) — counts its separate non-compliant episodes
- `remediations.list_for_subscription()` — remediation tasks and their deployment counts
- `remediations.list_deployments_at_subscription()`, `_at_resource_group()`, `_at_management_group()` or `_at_resource()` (per task) — each resource a task remediated
- `policy_states.list_query_results_for_subscription("latest")` filtered to the task's policy and remediated resources (per task) — whether each remediated resource is compliant now, and when that was evaluated

Output: `azure_policy_compliance_<subscription>.json` — the subscription's and each assignment's compliance, the non-compliant resources with the values that failed, the remediation tasks and what each one fixed, and the policies that keep falling out of compliance.

Summary fields:

**What was evaluated?**
- `resources_evaluated` — Number of resources with a compliance state in the service's evaluation window (the last day); 0 means nothing was evaluated, not that everything passed
- `resources_by_compliance_state` — Number of resources in each compliance state (for example Compliant, NonCompliant, Exempt)
- `policies_by_compliance_state` — Number of policies in each compliance state
- `assignments_evaluated` — Number of policy assignments the service summarized
- `provider_registration_status` — Whether the policy compliance provider (Microsoft.PolicyInsights) is registered on the subscription: registered, not_registered or unknown

**How compliant is the subscription?**
- `non_compliant_resources` — Number of resources non-compliant with at least one policy, as the service counts them
- `non_compliant_policies` — Number of policies with at least one non-compliant resource, as the service counts them
- `compliant_resources` — Number of resources compliant with every policy that applies to them
- `resource_compliance_percentage` — Percentage of evaluated resources that are compliant = `compliant_resources` / (`compliant_resources` + the NonCompliant count in `resources_by_compliance_state`) × 100 (a whole number, 0–100); 0 when that sum is 0. Resources in other states (exempt, unknown, conflicting) are left out of both
- `non_compliant_assignments` — Number of policy assignments with at least one non-compliant resource
- `compliant_assignments` — Number of policy assignments with no non-compliant resource

**Which resources are non-compliant?**
- `listed_non_compliant_states` — Number of non-compliant (resource, policy) records listed in the evidence (at most the `max_non_compliant_resources` setting, default 1000)
- `listed_distinct_non_compliant_resources` — Number of distinct resources among the listed non-compliant records
- `non_compliant_states_truncated` — True if there were more non-compliant records than the list holds; false if every one is listed, or `max_non_compliant_resources` is 0 and the list is skipped

**Why did they fail?**
- `evaluation_details_eligible_resources` — Number of distinct resources among the listed non-compliant records whose evaluation details can be read (subscriptions and resource groups can't be)
- `evaluation_details_resources_queried` — Number of readable non-compliant resources whose evaluation details were requested, refused and failed reads included, at most the `max_evaluation_detail_resources` setting (default 100), the resources with the most listed records first
- `evaluation_details_truncated` — True if some readable resources were not requested because of the `max_evaluation_detail_resources` limit; false if every readable resource was requested, or the limit is 0 and the details are skipped
- `evaluation_details_not_authorized_resources` — Number of requested resources whose evaluation-details read Policy Insights refused (a 403 or an AuthorizationFailed error). A refused read is retried once, at most 3 times a run and not after a retry is refused again; a refusal that persists marks the resource's records not_authorized and doesn't fail the run
- `non_compliant_states_with_evaluation_details` — Number of listed non-compliant records that carry the values the policy compared: the field path, the operator, the resource's actual value and the policy's target value
- `non_compliant_states_by_evaluation_details_status` — Number of listed non-compliant records in each evaluation-details status:
  - collected (the compared values are in the record)
  - not_returned (the resource was read and the service returned the record, but without compared values, as it does for policies on Key Vault keys and secrets)
  - not_in_detail_result (the resource was read, but the service no longer reported this record as non-compliant, for example after a re-evaluation in between)
  - not_requested (the resource was past the read limit)
  - unsupported_scope (the record is for a subscription or resource group)
  - not_authorized (Policy Insights refused the read for the resource)
  - failed (the read for the resource failed)

**Do remediation tasks fix what they target?**
- `remediation_tasks` — Number of remediation tasks on the subscription
- `remediation_tasks_by_provisioning_state` — Number of remediation tasks in each state (for example Succeeded, Failed, Evaluating)
- `remediation_successful_deployments` — Number of remediation deployments that succeeded, as the tasks report them
- `remediation_failed_deployments` — Number of remediation deployments that failed, as the tasks report them
- `remediation_deployments_listed` — Number of per-resource remediation deployments listed in the evidence (at most the `max_remediation_deployments` setting, default 1000)
- `remediation_deployments_truncated` — True if some deployments were not listed because of the `max_remediation_deployments` limit; false if every one is listed, or the limit is 0 and the deployments are skipped
- `remediation_deployments_by_status` — Number of listed remediation deployments in each status (for example Succeeded, Failed)
- `remediated_resources_listed` — Number of distinct resources among the listed remediation deployments (remediated resources). A resource deployed to more than once is judged by its newest deployment, against the policy of that deployment's task, so `remediated_resources_now_compliant`, `remediated_resources_now_non_compliant`, `remediated_resources_not_yet_reevaluated` and `remediated_resources_compliance_unknown` add up to it
- `remediated_resources_now_compliant` — Number of remediated resources whose current compliance state for the task's policy is Compliant and wasn't evaluated before their newest deployment
- `remediated_resources_now_non_compliant` — Number of remediated resources whose current compliance state for the task's policy is NonCompliant and wasn't evaluated before their newest deployment, including resources fixed and later drifted back
- `succeeded_remediations_now_non_compliant` — Number of remediated resources whose newest deployment succeeded but which are non-compliant with the task's policy now, so the fix didn't hold
- `remediated_resources_not_yet_reevaluated` — Number of remediated resources whose current compliance state was evaluated before their newest deployment last changed, so it doesn't yet show whether the fix worked (Azure re-evaluates every 24 hours)
- `remediated_resources_compliance_unknown` — Number of remediated resources with no current Compliant or NonCompliant state for the task's policy (not evaluated in the last day, exempt, deleted, or the state read failed); resources not yet re-evaluated are counted apart

**Does non-compliance keep coming back?**
- `recurrence_window_days` — Days of evaluation history read (30)
- `history_collected` — True if the evaluation history was read; false if the read failed or didn't run (for example, Microsoft.PolicyInsights isn't registered), and then the history, recurrence-pair and episode counts are null rather than 0
- `history_non_compliant_pairs` — Number of (resource, policy) pairs non-compliant at least once in the history window; null if `history_collected` is false
- `history_persistently_non_compliant_pairs` — Number of (resource, policy) pairs non-compliant at every evaluation in the window; null if `history_collected` is false
- `history_intermittently_non_compliant_pairs` — Number of (resource, policy) pairs evaluated both compliant and non-compliant in the window; null if `history_collected` is false
- `history_truncated` — True if the history had more rows than the fetcher reads (50,000), or the service returned fewer (resource, policy, state) groups than its own group count says, so the pair counts are a lower bound; false if all of it was read; null if `history_collected` is false
- `recurrence_pairs_read` — Number of intermittently non-compliant pairs whose evaluations were read in time order, at most the `max_recurrence_pairs` setting (default 100), the most often non-compliant first; null if `history_collected` is false
- `recurrence_pairs_truncated` — True if some intermittently non-compliant pairs were not read because of the `max_recurrence_pairs` limit; false if every one was read, or the limit is 0 and none are read; null if `history_collected` is false
- `recurring_non_compliant_pairs` — Number of read pairs with more than one separate non-compliant episode (a run of non-compliant evaluations with a compliant one between runs); null if `history_collected` is false
- `max_non_compliant_episodes` — Number of separate non-compliant episodes of the (resource, policy) pair with the most in the window; 1 for a pair non-compliant throughout, 0 when no pair was non-compliant; null if `history_collected` is false


### azure_residual_resources
Short Description: Lists leftover resources nothing uses any more, such as detached disks and network resources, empty resource groups, unused identities, stale slots and role assignments to deleted principals.

Script: fetchers/azure/residual_resources/fetcher.py

Access: Reader on the subscription, plus Microsoft Graph Directory.Read.All when it runs as a service principal or managed identity (a signed-in user needs nothing extra).

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- Resource Graph `Resources | where type =~ '<type>'` queries, one per orphan kind — unattached disks, NICs, NSGs, public IPs and NAT gateways, disconnected private endpoints, unlinked private DNS zones and empty App Service plans
- Resource Graph `ResourceContainers` and `Resources` queries — empty resource groups
- Resource Graph `Resources | where type =~ 'microsoft.web/sites/slots'` — stale slots
- Resource Graph `Resources | where type =~ 'microsoft.managedidentity/userassignedidentities'`, plus a query for what references each identity — unused identities
- ARM `GET …/federatedIdentityCredentials` (unused identities only) — federated credentials, which Resource Graph doesn't index
- Resource Graph `authorizationresources` query and `role_definitions.list()` — role assignments and role names
- Resource Graph subscription query and Microsoft Graph `GET /organization` — confirms Graph is signed in to the subscription's tenant
- Microsoft Graph `POST /directoryObjects/getByIds` — which principals still exist

Output: `azure_residual_resources_<subscription>.json` — each leftover resource and why it counts as unused, and every role assignment with whether its principal still exists.

Summary fields:

**How many leftovers are there?**
- `total_orphans` — Number of leftover items found: orphaned resources plus role assignments to deleted users, groups or apps
- `orphans_by_kind` — Number of leftover items of each kind (for example, unattached disks, empty resource groups, role assignments to deleted principals)
- `orphaned_resources` — Number of orphaned resources, not counting role assignments

**Do role assignments point to deleted users, groups or apps?**
- `role_assignments_checked` — Number of role assignments read
- `deleted_principal_assignments` — Number of role assignments whose user, group or app no longer exists in Entra ID
- `principals_checked` — Number of distinct users, groups and apps (principals) the role assignments point to
- `principals_missing` — Number of distinct principals that no longer exist in Entra ID
- `foreign_principal_assignments` — Number of role assignments to groups from another tenant, which aren't looked up or flagged
- `principal_check` — Whether the deleted-principal check ran: `complete`; `failed` (reading role assignments, checking the tenant or the Graph lookup failed, so the run fails); or `not_run` (no subscription or credential)

**How many identities and slots were checked, and when is a slot stale?**
- `identities_checked` — Number of user-assigned managed identities read
- `slots_checked` — Number of deployment slots read
- `stale_slot_days` — Days without changes after which a deployment slot counts as stale (default 90); a stopped slot also counts as stale


### azure_resource_inventory
Short Description: Lists every resource in the subscription and shows which ones Defender for Cloud assesses and Azure Policy evaluates, and which ones neither covers.

Script: fetchers/azure/resource_inventory/fetcher.py (uses the shared Resource Graph paging in fetchers/azure/_shared/resource_graph.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- Resource Graph `Resources` — every resource with its type, location, resource group, tags, SKU and kind
- Resource Graph `SecurityResources | where type =~ 'microsoft.security/assessments'` — every Defender for Cloud assessment, its status and severity
- Resource Graph `PolicyResources | where type =~ 'microsoft.policyinsights/policystates'` — every Azure Policy state and its compliance

Output: `azure_resource_inventory_<subscription>.json` — each resource with its details, how many Defender assessments and Policy evaluations cover it, and how many of them fail.

Summary fields:

**What resources exist?**
- `total_resources` — Number of resources in the subscription (resource groups and the subscription itself are not counted)
- `resource_type_count` — Number of different resource types
- `resources_by_type` — Number of resources of each type
- `location_count` — Number of different locations (regions, plus global)
- `resources_by_location` — Number of resources in each location
- `resource_group_count` — Number of resource groups that hold at least one resource

**Are resources tagged?**
- `untagged_resources` — Number of resources with no tags at all
- `tagged_resources` — Number of resources with at least one tag

**Was coverage read completely?**
- `defender_coverage_collected` — True if every page of Defender assessments was read; false if the query failed, came back truncated or short, or never ran because the `Resources` query failed, and then every Defender field below is null
- `policy_coverage_collected` — True if every page of Policy states was read; false if the query failed, came back truncated or short, or never ran because the `Resources` query failed, and then every Policy field below is null
- `defender_assessments_total` — Number of Defender for Cloud assessments in the subscription that came back Healthy or Unhealthy (an assessment that ran); NotApplicable and other statuses are counted apart
- `defender_not_applicable_total` — Number of Defender assessments in the subscription with status NotApplicable (the check didn't run on the resource, for example because a policy turned it off); these never count as coverage
- `defender_unknown_status_total` — Number of Defender assessments in the subscription with a missing or unexpected status (not Healthy, Unhealthy or NotApplicable); these never count as coverage. With `defender_assessments_total` and `defender_not_applicable_total` this makes every assessment read
- `defender_assessments_outside_inventory` — Number of Healthy or Unhealthy Defender assessments about something that is not an inventoried resource or a child of one (the subscription itself, a resource that no longer exists, or an AWS, GCP or on-premises machine, even when its id sits under an inventoried connector)
- `policy_evaluations_total` — Number of Azure Policy states in the subscription, one for each resource, policy assignment and policy
- `policy_evaluations_outside_inventory` — Number of Policy states about something that is not an inventoried resource or a child of one (a resource group, the subscription, or a resource that no longer exists)

**Does Defender for Cloud assess every resource it can?**
- `resources_assessed_by_defender` — Number of resources with at least one Healthy or Unhealthy Defender assessment, on the resource or on a child of it (a subnet counts for its virtual network); NotApplicable assessments and assessments of AWS, GCP or on-premises machines don't count
- `defender_assessable_resources` — Number of assessable resources: resources of a type that Defender assessed on at least one resource in the subscription
- `defender_assessed_percentage` — Percentage of assessable resources that Defender assessed = `resources_assessed_by_defender` / `defender_assessable_resources` × 100 (a whole number, 0–100); 0 when `defender_assessable_resources` is 0, which also happens when Defender assessed nothing; null if `defender_coverage_collected` is false
- `resources_without_defender_assessment` — List of the ids of the assessable resources with no Defender assessment
- `resources_without_defender_assessment_count` — Number of assessable resources with no Defender assessment
- `types_without_defender_assessment` — Number of resources of each type that Defender assessed on no resource in the subscription. These are not counted as missing: Defender has no recommendations for many types (action groups, managed identities, DNS zones), and a type can also land here when no plan or policy covers it
- `all_assessable_resources_assessed_by_defender` — True if every assessable resource has a Defender assessment; false if any doesn't, or if Defender assessed no resource at all, an empty inventory included; null if the query failed

**Do Defender assessments find serious problems?**
- `resources_with_unhealthy_high_severity` — Number of resources with at least one unhealthy Defender assessment of High or Critical severity
- `unhealthy_high_severity_assessments` — Number of unhealthy Defender assessments of High or Critical severity on inventoried resources and their children; assessments about the subscription or anything else not inventoried are not counted here
- `unhealthy_assessments_without_severity` — Number of unhealthy Defender assessments on inventoried resources that carry no severity, so they can't be counted as High or not
- `defender_unhealthy_outside_inventory` — Number of unhealthy Defender assessments about something not inventoried (the subscription itself, a resource that no longer exists, or an AWS, GCP or on-premises machine), of any severity. Together with the unhealthy assessments on inventoried resources this makes every unhealthy assessment in the subscription
- `defender_unhealthy_high_severity_outside_inventory` — Number of unhealthy Defender assessments of High or Critical severity about something not inventoried. With `unhealthy_high_severity_assessments` this makes every unhealthy High or Critical assessment in the subscription
- `defender_unhealthy_without_severity_outside_inventory` — Number of unhealthy Defender assessments with no severity about something not inventoried

**Does Azure Policy evaluate every resource it can?**
- `resources_evaluated_by_policy` — Number of resources with at least one Policy state of any compliance, on the resource or on a child of it
- `policy_evaluable_resources` — Number of evaluable resources: resources of a type that Policy evaluated on at least one resource in the subscription
- `policy_evaluated_percentage` — Percentage of evaluable resources that Policy evaluated = `resources_evaluated_by_policy` / `policy_evaluable_resources` × 100 (a whole number, 0–100); 0 when `policy_evaluable_resources` is 0, which also happens when Policy evaluated nothing; null if `policy_coverage_collected` is false
- `resources_without_policy_evaluation` — List of the ids of the evaluable resources with no Policy state
- `resources_without_policy_evaluation_count` — Number of evaluable resources with no Policy state
- `types_without_policy_evaluation` — Number of resources of each type that Policy evaluated on no resource in the subscription, which means no assigned policy applies to that type. These are not counted as missing
- `all_evaluable_resources_evaluated_by_policy` — True if every evaluable resource has a Policy state; false if any doesn't, or if Policy evaluated no resource at all, an empty inventory included; null if the query failed

**Is anything non-compliant?**
- `resources_with_non_compliant_policy` — Number of resources with at least one non-compliant Policy state
- `non_compliant_policy_evaluations` — Number of non-compliant Policy states on inventoried resources and their children; states about the subscription, a resource group or anything else not inventoried are not counted here
- `policy_non_compliant_outside_inventory` — Number of non-compliant Policy states about something not inventoried (the subscription, a resource group, or a resource that no longer exists). `non_compliant_policy_evaluations` plus this is every non-compliant state in the subscription

**What does nothing cover?**
- `resources_covered_by_neither_by_type` — Number of resources of each type that have neither a Defender assessment nor a Policy state. It counts every such resource, so it holds both the missing resources listed above and the types neither service covers on any resource; null if either query failed


### azure_vm_hardening_status
Short Description: Shows whether each virtual machine and scale set boots with Trusted Launch, whether VMs use only managed disks, and whether Linux VMs allow only SSH-key sign-in.

Script: fetchers/azure/vm_hardening_status/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Compute")` — tells "Compute not in use" from "no VMs"
- `virtual_machines.list_all()` — every VM with its security profile, disks, source image and Linux sign-in settings
- `virtual_machine_extensions.list()` (per VM) — the guest extensions (agents) installed on it
- `virtual_machine_scale_sets.list_all()` — every scale set with its VM template's security profile, sign-in settings, image and load balancer pools
- `virtual_machine_scale_set_vms.list()` (per scale set) — its instances

Output: `azure_vm_hardening_status_<subscription>.json` — each VM's Trusted Launch and encryption-at-host settings, disks, source image, Linux password setting and installed extensions, and each scale set's template settings, load balancer pools and instances.

Summary fields:

**What was checked?**
- `total_virtual_machines` — Number of virtual machines in the subscription
- `linux_vms` — Number of VMs with Linux sign-in settings (a Linux OS profile); a Linux VM built from an existing disk has no OS profile and isn't counted
- `vms_in_scale_sets` — Number of VMs that belong to a scale set
- `total_scale_sets` — Number of virtual machine scale sets in the subscription
- `total_scale_set_instances` — Number of instances across all scale sets
- `empty_scale_sets` — Number of scale sets with no instances listed, including any whose instance list couldn't be read
- `provider_registration_status` — Whether the Compute provider (Microsoft.Compute) is registered on the subscription: registered, not_registered or unknown

**Do machines boot only verified software (Trusted Launch)?**
- `trusted_launch_vms` — Number of VMs with Trusted Launch: security type TrustedLaunch with both secure boot and the virtual TPM on; confidential VMs don't count
- `trusted_launch_percentage` — Percentage of VMs with Trusted Launch = `trusted_launch_vms` / `total_virtual_machines` × 100 (a whole number, 0–100); 0 when `total_virtual_machines` is 0. Generation 1 VMs can't use Trusted Launch, so 100 may be impossible
- `secure_boot_vms` — Number of VMs with UEFI secure boot on, which lets only signed boot loaders and kernels start
- `vtpm_vms` — Number of VMs with a virtual TPM (vTPM), which records measurements of the boot so it can be checked
- `confidential_vms` — Number of confidential VMs (security type ConfidentialVM), which also encrypt memory in hardware
- `trusted_launch_scale_sets` — Number of scale sets whose VM template has Trusted Launch (security type TrustedLaunch with secure boot and the virtual TPM on)

**Are disks managed and encrypted at the host?**
- `managed_disk_vms` — Number of VMs whose OS disk and every data disk are managed disks
- `managed_disk_percentage` — Percentage of VMs using only managed disks = `managed_disk_vms` / `total_virtual_machines` × 100 (a whole number, 0–100); 0 when `total_virtual_machines` is 0
- `unmanaged_disk_vms` — Number of VMs with at least one unmanaged disk (a VHD file in a storage account), or with no disk information returned
- `encryption_at_host_vms` — Number of VMs with encryption at host on, which also encrypts temporary disks and disk caches on the host server

**Do Linux VMs require SSH keys?**
- `linux_ssh_key_only_vms` — Number of Linux VMs with password sign-in disabled, so only SSH keys work
- `linux_ssh_key_only_percentage` — Percentage of Linux VMs that allow only SSH keys = `linux_ssh_key_only_vms` / `linux_vms` × 100 (a whole number, 0–100); 0 when `linux_vms` is 0. Windows VMs are left out of both numbers

**Are guest agents installed and scale sets load balanced?**
- `vms_with_extensions` — Number of VMs with at least one guest extension (agent) installed, in any provisioning state
- `total_extensions` — Number of guest extensions across all VMs
- `scale_sets_with_load_balancer` — Number of scale sets whose VM template places instances in a load balancer backend pool


## Network and edge

### azure_api_management_configuration
Short Description: Shows how each API Management service is exposed, which TLS versions and ciphers it accepts, whether its APIs stop callers without a key, and how backends and secrets are protected.

Script: fetchers/azure/api_management_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.ApiManagement — tells an unregistered provider apart from no services
- `api_management_service.list()` — services with their network, TLS, cipher, hostname and portal settings
- `sign_up_settings.get()` (per service) — whether anyone can sign up on the developer portal
- `policy.get()` (per service) — which security elements the global policy contains
- `product.list_by_service()`, `product_policy.get()` and `product_api.list_by_product()` (per service and product) — products, their policies and the APIs in each
- `api.list_by_service()`, `api_policy.get()`, `api_operation.list_by_api()` and `api_operation_policy.get()` (per service, API and operation) — APIs, operations and their policies
- `policy_fragment.list_by_service()` and `policy_fragment.get()` (per service and fragment) — reusable policy fragments
- `subscription.list()` (per service) — API Management subscriptions (key holders), their scope, state and tracing
- `backend.list_by_service()` (per service) — backends, their URL, certificate checks and whether they authenticate
- `identity_provider.list_by_service()` (per service) — developer portal sign-in providers
- `named_value.list_by_service()` (per service) — named values and whether secret ones live in Key Vault
- `certificate.list_by_service()` (per service) — uploaded certificates and their expiry
- `logger.list_by_service()` (per service) — where the service sends request logs
- `diagnostic_settings.list()` (per service) — whether gateway logs are exported

Output: `azure_api_management_configuration_<subscription>.json` — each API Management service with its network exposure, TLS and cipher settings, certificates, developer portal, policies, APIs, products, subscriptions, backends, named values and logging, without any policy text, keys or secret values.

Summary fields:

**What was checked?**
- `total_services` — Number of API Management services in the subscription
- `provider_registration_status` — Whether Microsoft.ApiManagement is registered on the subscription: registered, not_registered or unknown

**Can the services be reached from the internet?**
- `services_with_public_network_access` — Number of services with public network access not disabled (unset counts as on)
- `services_in_virtual_network` — Number of services deployed into a virtual network, in External or Internal mode
- `services_with_private_endpoints` — Number of services with at least one private endpoint connection

**Does the gateway accept only strong TLS?**
- `services_with_legacy_tls_or_ssl_enabled` — Number of services where TLS 1.0, TLS 1.1 or SSL 3.0 is on for clients or backends (set on, or unset on a service created on or before 1 April 2018, where Azure defaults it on)
- `services_with_weak_ciphers_enabled` — Number of services with at least one weak cipher suite on (a CBC-mode suite, one without forward secrecy, or 3DES); Azure leaves the CBC and RSA key-exchange suites on until they are set to off
- `services_minimum_api_version_enforced` — Number of services that block management API versions older than 2019-12-01, which can read secrets back

**Is the developer portal open to sign-ups?**
- `services_developer_portal_enabled` — Number of services with the developer portal enabled
- `services_developer_portal_sign_up_enabled` — Number of services where anyone can sign up for an account on the developer portal

**Are gateway logs exported?**
- `services_with_diagnostic_settings` — Number of services with at least one diagnostic setting
- `services_audit_logs_exported` — Number of services with gateway logs exported (a diagnostic setting that has a destination enables GatewayLogs or the audit or allLogs category group)
- `services_audit_logs_unknown` — Number of services whose diagnostic settings couldn't be read, so whether gateway logs are exported is unknown

**Do APIs stop callers without a key or token?**
- `total_apis` — Number of APIs across all services (0 proves nothing about protection: there is nothing to protect yet)
- `apis_accepting_http` — Number of APIs that accept plain HTTP or unencrypted WebSocket (ws) calls
- `apis_without_access_control` — Number of APIs without access control: a call without a subscription key isn't stopped, because the API doesn't require a key, has no OAuth 2.0 or OpenID Connect server, and no validate-jwt or validate-azure-ad-token policy applies at global or API level, in an open product (one needing no subscription) containing the API, or on every operation; a keyed product's policy never runs for a keyless call, so only open products count
- `apis_access_control_unknown` — Number of APIs where access control is unknown: nothing found protects them, but a policy that could (global, API, operation, or an open or unread product) couldn't be read
- `total_products` — Number of products across all services
- `published_products_without_subscription` — Number of published products that need no subscription, so anyone can call their APIs without a key

**Who holds keys to the APIs?**
- `total_subscriptions` — Number of API Management subscriptions (sets of keys callers use, not Azure subscriptions) across all services
- `active_all_apis_subscriptions` — Number of active API Management subscriptions whose keys work for every API on their service, including the built-in all-access one
- `subscriptions_with_tracing_allowed` — Number of API Management subscriptions whose callers may request traces, which can include request data

**Are backends reached securely?**
- `total_backends` — Number of backends across all services
- `backends_using_http` — Number of backends whose URL is plain HTTP
- `backends_without_certificate_validation` — Number of backends set not to check the backend certificate's chain or its host name
- `backends_without_auth` — Number of backends with no credential configured (header, query, authorization or certificate) that aren't an Azure resource

**Are secrets and certificates looked after?**
- `secret_named_values_not_in_key_vault` — Number of secret named values stored in API Management rather than referenced from Key Vault
- `certificates_expired` — Number of uploaded and hostname certificates that had expired at collection time
- `certificates_expiring_within_30_days` — Number of uploaded and hostname certificates that expire within 30 days of collection


### azure_app_gateway_backend_tls
Short Description: Shows whether Application Gateway traffic to its backends is encrypted and whether the backend certificate and SNI are validated.

Script: fetchers/azure/app_gateway_backend_tls/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `application_gateways.list_all()` — every gateway's backend settings, health probes, trusted root certificates and routing rules
- Resource Graph count of `microsoft.network/applicationgateways` — proves the gateway list is complete

Output: `azure_app_gateway_backend_tls_<subscription>.json` — each backend setting with its protocol, whether certificate and SNI validation are on, and whether a routing rule uses it.

Summary fields:

**Which gateways and backend settings were checked?**
- `total_application_gateways` — Number of Application Gateways in the subscription
- `total_backend_settings` — Number of backend settings (how a gateway connects to its backend servers), both web and TCP/TLS
- `in_use_backend_settings` — Number of backend settings that a routing rule actually uses
- `completeness_match` — True if the gateway list matches Resource Graph's independent count; null if either count couldn't be read
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown

**Is traffic to the backends encrypted?**
- `encrypted_in_use` — Number of in-use backend settings that connect over HTTPS or TLS
- `plaintext_in_use` — Number of in-use backend settings that connect unencrypted (HTTP or TCP)
- `plaintext_probes_in_use` — Number of in-use backend settings whose health probe is unencrypted (HTTP or TCP)

**Does the gateway verify backend certificates?**
- `certificate_validation_disabled_in_use` — Number of in-use backend settings with the backend certificate check (chain and expiry) turned off
- `sni_validation_disabled_in_use` — Number of in-use backend settings that don't check the backend certificate's host name (SNI)
- `insecure_backend_settings_in_use` — Number of in-use backend settings that are unencrypted or skip the certificate or SNI check


### azure_app_gateway_tls_listeners
Short Description: Shows whether every Application Gateway listener accepts only encrypted traffic and the minimum TLS version it enforces.

Script: fetchers/azure/app_gateway_tls_listeners/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `application_gateways.list_all()` — every gateway's listeners, rules, redirects and TLS settings
- Resource Graph count of `microsoft.network/applicationgateways` — proves the gateway list is complete

Output: `azure_app_gateway_tls_listeners_<subscription>.json` — each gateway listener with its protocol, whether it's public, whether plain HTTP only redirects to HTTPS, and its minimum TLS version.

Summary fields:

**Which gateways and listeners were checked?**
- `total_application_gateways` — Number of Application Gateways in the subscription
- `running_application_gateways` — Number of Application Gateways that are running
- `total_listeners` — Number of listeners, both web (HTTP/HTTPS) and TCP/TLS
- `l7_listeners` — Number of web listeners (HTTP or HTTPS)
- `l4_listeners` — Number of TCP or TLS listeners
- `completeness_match` — True if the gateway list matches Resource Graph's independent count; null if either count couldn't be read
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown

**Do listeners accept only encrypted traffic?**
- `encrypted_listeners` — Number of listeners that accept only encrypted traffic (HTTPS or TLS)
- `http_redirect_only_listeners` — Number of HTTP listeners that only redirect visitors to HTTPS
- `plaintext_listeners` — Number of listeners that accept unencrypted traffic: HTTP listeners that don't only redirect to HTTPS, and all TCP listeners
- `public_plaintext_listeners` — Number of unencrypted listeners reachable from the Internet (on a public frontend IP)

**Do encrypted listeners require TLS 1.2 or later?**
- `listeners_below_tls12` — Number of encrypted listeners that still allow TLS 1.0 or 1.1
- `listeners_tls_version_unknown` — Number of encrypted listeners whose minimum TLS version couldn't be determined

**Is FIPS mode on?**
- `gateways_fips_enabled` — Number of Application Gateways with FIPS mode on
- `gateways_fips_disabled` — Number of Application Gateways with FIPS mode off
- `gateways_fips_not_reported` — Number of Application Gateways where Azure doesn't report FIPS mode


### azure_app_gateway_waf
Short Description: Shows which web application firewall policy protects each Application Gateway listener and whether it blocks attacks in Prevention mode.

Script: fetchers/azure/app_gateway_waf/fetcher.py

Access: Reader on the subscription. Optional: Reader on another subscription holding a WAF policy the gateway uses; without it, that policy reads as unreadable.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `application_gateways.list_all()` — every gateway's listeners, path rules and WAF associations
- Resource Graph count of `microsoft.network/applicationgateways` — proves the gateway list is complete
- `web_application_firewall_policies.list_all()` — every WAF policy
- `web_application_firewall_policies.get()` (policies held elsewhere) — associated policies the list missed

Output: `azure_app_gateway_waf_<subscription>.json` — each HTTP(S) listener with the WAF policy that applies and whether it enforces, plus each WAF policy's mode, disabled rules, exclusions and custom rules.

Summary fields:

**Which gateways and listeners were checked?**
- `total_application_gateways` — Number of Application Gateways in the subscription
- `waf_tier_gateways` — Number of Application Gateways on a WAF tier
- `total_http_listeners` — Number of web listeners (HTTP/HTTPS); WAF doesn't apply to TCP/TLS listeners
- `completeness_match` — True if the gateway list matches Resource Graph's independent count; null if either count couldn't be read
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown

**Is every web listener protected by a WAF that blocks attacks?**
- `listeners_waf_enforcing` — Number of web listeners whose WAF blocks attacks (enabled in Prevention mode), including any path-specific WAF policies
- `listeners_waf_detection_only` — Number of web listeners whose WAF only logs attacks (Detection mode)
- `listeners_waf_disabled` — Number of web listeners whose WAF is turned off
- `listeners_without_waf` — Number of web listeners with no WAF at all
- `public_listeners_not_enforcing` — Number of Internet-facing web listeners whose WAF isn't confirmed to be blocking

**How are the WAF policies configured?**
- `total_waf_policies` — Number of WAF policies in the subscription, plus any linked policy read from another subscription
- `unresolved_waf_policies` — Number of linked WAF policies that couldn't be read
- `unreadable_waf_policies` — Number of linked WAF policies that couldn't be read because access was refused (401/403) or they don't exist (404)
- `policies_prevention` — Number of WAF policies enabled in Prevention (blocking) mode
- `policies_detection` — Number of WAF policies enabled in Detection (logging only) mode
- `policies_disabled` — Number of WAF policies that are turned off
- `disabled_managed_rules` — Number of Microsoft-managed WAF rules switched off, across all policies
- `rate_limit_rules` — Number of enabled rate-limiting custom rules, across all policies


### azure_ddos_protection
Short Description: Shows whether each Internet-facing public IP address is covered by Azure DDoS Protection.

Script: fetchers/azure/ddos_protection/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `ddos_protection_plans.list()` — DDoS protection plans
- `virtual_networks.list_all()` — each VNet's plan
- `public_ip_addresses.list_all()` — each public IP's attachment and protection setting
- `network_interfaces.list_all()` and `load_balancers.list_all()` — which VNet an attached IP belongs to

Output: `azure_ddos_protection_<subscription>.json` — each public IP with what it's attached to and whether DDoS Protection covers it, plus the DDoS plans and the VNets that use them.

Summary fields:

**Which virtual networks have a DDoS plan?**
- `total_ddos_protection_plans` — Number of DDoS protection plans in the subscription
- `total_virtual_networks` — Number of virtual networks (VNets)
- `virtual_networks_with_ddos_plan` — Number of VNets with DDoS protection turned on and a plan linked
- `virtual_networks_with_attached_public_ips` — Number of VNets with at least one public IP attached to a resource in them
- `virtual_networks_with_attached_public_ips_without_plan` — Number of VNets with at least one attached public IP but no DDoS plan
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown

**Is every Internet-facing public IP protected?**
- `total_public_ips` — Number of public IPs, attached or not
- `attached_public_ips` — Number of public IPs attached to a resource (reachable from the Internet)
- `attached_public_ips_by_effective_protection` — Number of attached public IPs with each protection result:
	- network_protection (covered by its VNet's DDoS plan)
	- ip_protection (covered by its own DDoS IP Protection)
	- none (no plan on its VNet and no IP Protection)
	- disabled (protection turned off on the IP)
	- not_supported (attached to a NAT gateway, which DDoS Protection can't cover)
	- unknown (its VNet couldn't be determined)
- `attached_public_ips_unprotected` — Number of attached public IPs with no DDoS protection (none or disabled)


### azure_dns_configuration
Short Description: Shows the targets, TTL and failover method of each in-scope public DNS record, whether each public zone is DNSSEC-signed, and which virtual networks each private zone links to.

Script: fetchers/azure/dns_configuration/fetcher.py (uses the shared helper fetchers/azure/_shared/scope_exclusions.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — tells "not registered" apart from "no zones"
- `zones.list()` — every public DNS zone
- `GET {zone id}/dnssecConfigs/default` (per public zone) — the zone's DNSSEC state and signing keys, through the DNSSEC preview API because the SDK has no DNSSEC call
- `record_sets.list_all_by_dns_zone()` (per public zone) — every record set with its type, TTL and values, and for an alias record its alias target (the Azure resource or record set in the zone it follows)
- `private_zones.list()` — every private DNS zone
- `virtual_network_links.list()` (per private zone) — the virtual networks linked to the zone and whether they auto-register records

Output: `azure_dns_configuration_<subscription>.json` — each public zone with its DNSSEC state, signing keys and in-scope record sets, each private zone with its virtual network links, and the public record sets left out of scope with the pattern each matched.

Summary fields:

**What was checked?**
- `total_public_zones` — Number of public DNS zones in the subscription
- `total_private_zones` — Number of private DNS zones in the subscription
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown

**Which public record sets are left out of scope?**
- `scope_exclusion_patterns` — List of the patterns in the fetcher's `scope_exclusions` setting, in the order given: case-insensitive globs (`*` matches any run of characters, dots included; `?` matches one character) that must match a whole name, tried against each public record set's relative name (`www`, or `@` for the zone apex) and its FQDN, with or without the trailing dot. A relative name matches in every public zone; an FQDN picks out one zone's record. A record set a pattern matches is out of scope: it is listed in the evidence's excluded list with its zone, type and the pattern, and left out of every other count; every other record set is in scope. Zones, their DNSSEC state and private zones are never taken out. A pattern with a prefix such as `route:` fails the run. Empty when no patterns are set, so every record set is in scope
- `scope_exclusion_patterns_unmatched` — List of configured patterns that matched no public record set's relative name or FQDN, such as a mistyped name
- `excluded_record_sets` — Number of public record sets out of scope because a pattern matches their relative name or FQDN
- `in_scope_record_sets` — Number of public record sets read and in scope (equal to `total_public_record_sets`); 0 means the patterns took out every record set, which a check can catch by requiring more than 0

**Are public zones signed with DNSSEC?**
- `dnssec_enabled_public_zones` — Number of public zones with DNSSEC enabled: a DNSSEC configuration exists, its provisioning state is Succeeded and it has at least one signing key
- `dnssec_disabled_public_zones` — Number of public zones without DNSSEC enabled (no DNSSEC configuration, or one that hasn't succeeded or has no signing key)
- `dnssec_unknown_public_zones` — Number of public zones whose DNSSEC configuration couldn't be read; the run fails when this is above 0
- `dnssec_percentage` — Percentage of public zones with DNSSEC enabled = `dnssec_enabled_public_zones` / `total_public_zones` × 100 (a whole number, 0–100); 0 when `total_public_zones` is 0. Zones with unknown DNSSEC (`dnssec_unknown_public_zones`) count in the total but not as enabled, so they lower it

**What records do the public zones publish?**
- `total_public_record_sets` — Number of in-scope record sets across all public zones (a record set is every record of one type at one name)
- `public_zones_record_sets_unread` — Number of public zones whose record sets couldn't be read; the run fails when this is above 0
- `public_record_sets_by_type` — Number of in-scope public record sets of each type, such as A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA and PTR; DS, TLSA and NAPTR record sets are counted, but the SDK has no fields for their values, so their targets are empty
- `public_alias_record_sets` — Number of in-scope public record sets that are aliases: instead of a fixed value they follow an Azure resource or another record set in the zone. Each record set's `alias_target_type` says which: front_door (a Front Door endpoint), traffic_manager (a Traffic Manager profile), cdn_endpoint (an Azure CDN endpoint, whose failover method reads cdn), public_ip (a public IP address), record_set (another record set in the zone) or other

**How does each public endpoint fail over?**
- `public_endpoint_record_sets` — Number of in-scope public endpoint record sets (A, AAAA and CNAME, the records that send clients to a server)
- `public_endpoint_record_sets_empty` — Number of in-scope public endpoint record sets with no value and no alias target, so they answer nothing. Dangling records aren't detected: an alias whose target resource was deleted, or a CNAME to a host that no longer exists, isn't counted here
- `public_endpoint_record_sets_by_failover_method` — Number of in-scope public endpoint record sets for each failover method, the way traffic moves to another region (each record set's `failover_method`; it is null for other record types and for empty record sets, which are left out here). A record that points at another record set in the zone, through an alias or a CNAME to a name in the zone, takes that record set's own method, even when that record set is out of scope; only one link is followed:
  - front_door (an alias to a Front Door endpoint or a CNAME to an azurefd.net host; Front Door moves traffic between its origins. Only azurefd.net host names are recognised)
  - traffic_manager (an alias to a Traffic Manager profile or a CNAME to a trafficmanager.net or usgovtrafficmanager.net host; Traffic Manager answers with a healthy endpoint)
  - cdn (an alias to an Azure CDN endpoint or a CNAME to an azureedge.net host; the CDN endpoint's origins decide)
  - record_update (a fixed address or host name, or an alias to another resource such as a public IP; moving traffic means changing the record, and resolvers can keep the old answer for up to its TTL)

**Which networks resolve the private zones?**
- `total_private_zone_virtual_network_links` — Number of virtual network links across all private zones
- `private_zones_without_links` — Number of private zones linked to no virtual network (a zone whose links couldn't be read also counts here, and the run fails)
- `auto_registration_links` — Number of virtual network links with auto-registration on, so virtual machines in the network get DNS records in the zone automatically

### azure_front_door_origins
Short Description: Shows whether Front Door's in-scope back ends span two healthy, serving regions, are reached securely, accept traffic only through their own profile, and have a regional twin with enough capacity.

Script: fetchers/azure/front_door_origins/fetcher.py (uses the shared Front Door helpers fetchers/azure/_shared/frontdoor.py and fetchers/azure/_shared/scope_exclusions.py)

Access: Reader on the subscription. Optional: Reader on other subscriptions holding origin apps; without it, those origins read as not visible and not locked.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Cdn — notes an unregistered provider
- `profiles.list()` — Front Door Standard/Premium profiles
- `profiles.get()` (per profile) — the profile's Front Door id, which Front Door sends as the X-Azure-FDID header
- `afd_origin_groups.list_by_profile()` and `afd_origins.list_by_origin_group()` — origin groups, origins, probes and origin authentication
- `afd_endpoints.list_by_profile()` and `routes.list_by_endpoint()` — which routes send traffic to each group, and over which protocol
- `afd_custom_domains.list_by_profile()` (per profile) — each custom domain's host name, to match against the scope exclusion patterns and count the hosts in scope
- `rule_sets.list_by_profile()` and `rules.list_by_rule_set()` — rules that override a route's origin group or protocol
- `Resources | where id in~ (…)` — the region of each origin's target resource
- `Resources | where type =~ 'microsoft.web/sites'` — every App Service app in the subscription, and each origin's app or slot, with its public network access and plan
- `Resources | where type =~ 'microsoft.web/serverfarms'` — each app's plan capacity and zone redundancy
- `web_apps.get_configuration()` or `get_configuration_slot()` (per app an in-scope origin group reaches) — the access restrictions of the app and of its Kudu (scm) site
- `metrics.list()` for OriginHealthPercentage and OriginRequestCount (per profile) — hourly health and request count of each origin over the lookback window

Output: `azure_front_door_origins_<subscription>.json` — each in-scope origin group with its origins, regions and connection settings, its measured health and traffic per region, each App Service origin with whether only its Front Door profile can reach it, each in-scope app with its regional twin, and the custom domains, endpoints, routes, origin groups and apps left out of scope with the pattern or reason that took each out.

Summary fields:

**What was checked?**
- `total_front_door_profiles` — Number of Front Door Standard and Premium profiles
- `premium_profiles` — Number of Front Door Premium profiles
- `standard_profiles` — Number of Front Door Standard profiles
- `skipped_profiles_by_sku` — Number of classic CDN profiles skipped, for each SKU
- `total_origin_groups` — Number of in-scope origin groups across all profiles (a group is in scope unless the scope exclusion patterns take out every route reaching it, as `excluded_origin_groups` describes)
- `serving_origin_groups` — Number of origin groups that serve traffic: in-scope groups that an enabled in-scope route on an enabled endpoint sends requests to, directly or through a rule-set override
- `unused_origin_groups` — Number of in-scope origin groups that no serving route reaches
- `total_origins` — Number of origins across all in-scope groups
- `enabled_origins` — Number of origins in in-scope groups that are enabled (an origin with no state set counts as enabled)
- `private_link_origins` — Number of origins in in-scope groups that Front Door reaches over private link
- `origins_by_region_source` — Number of origins in in-scope groups for each way their region was found:
  - azure_origin (the Azure resource the origin names)
  - private_link_target (the resource its private link points at)
  - host_name (the App Service app or storage account owning its host name)
  - None (region not found)
- `origin_api_version` — What the fetcher reads origins and origin groups with: the Front Door API version
- `provider_registration_status` — Whether Microsoft.Cdn is registered on the subscription: registered, not_registered or unknown

**Which parts of Front Door are left out of scope?**
- `scope_exclusion_patterns` — List of the patterns in the fetcher's `scope_exclusions` setting, in the order given: case-insensitive globs (`*` matches any run of characters, dots included; `?` matches one character) that must match a whole name. A plain pattern matches the host name of a custom domain or of an endpoint (the endpoint's own `*.azurefd.net` name); a pattern starting `route:` (such as `route:qa-*`) matches route names instead, and a plain pattern never matches a route's name. A pattern with any other prefix, or with nothing after `route:`, fails the run. Whatever a pattern takes out is out of scope: it is listed in the evidence's excluded list with the pattern (or the reason, when it went out because of something else) and left out of every verdict and count; everything else is in scope. Empty when no patterns are set, so everything is in scope
- `scope_exclusion_patterns_unmatched` — List of configured patterns that matched no custom-domain host name, endpoint host name or route name, such as a mistyped name
- `excluded_custom_domains` — Number of custom domains out of scope because their host name matches a pattern
- `excluded_endpoints` — Number of endpoints whose own `*.azurefd.net` host name matches a pattern
- `excluded_routes` — Number of routes out of scope: a `route:` pattern matches the route's name, or every host the route serves (its custom domains, plus the endpoint's own host name when the route links it) is out of scope. A route that serves no host goes out only by name
- `excluded_origin_groups` — Number of origin groups out of scope: at least one route reaches the group, directly or through a rule-set override, and every route reaching it is out of scope. A group no route reaches stays in scope, and an in-scope group is judged only on its in-scope routes. An out-of-scope group's origins, App Service origins and health are left out of every count
- `excluded_apps` — Number of production apps out of scope because every origin pointing at them sits in an out-of-scope origin group; an app no origin points at stays in scope
- `in_scope_hosts` — Number of custom domains and endpoints whose host name no pattern matches; 0 means the patterns took out every host, which a check can catch by requiring more than 0
- `in_scope_custom_domains` — Number of custom domains whose host name no pattern matches
- `in_scope_endpoints` — Number of endpoints whose own host name no pattern matches
- `in_scope_routes` — Number of routes in scope
- `in_scope_origin_groups` — Number of origin groups in scope (equal to `total_origin_groups`)
- `in_scope_apps` — Number of production apps in scope (`production_web_apps` plus `production_function_apps`)

**Does more than one region serve traffic?**
- `serving_regions` — List of regions holding an active origin in a serving group (active = enabled at the group's best priority)
- `serving_groups_multi_region_active_active` — Number of serving groups whose active origins span two or more regions
- `serving_groups_multi_region_failover` — Number of serving groups whose enabled origins span two or more regions, so a second region can take over
- `serving_groups_single_enabled_origin` — Number of serving groups with exactly one enabled origin
- `serving_groups_without_enabled_origin` — Number of serving groups where every origin is disabled
- `serving_groups_region_unresolved` — Number of serving groups with an enabled origin whose region wasn't found
- `serving_groups_multi_origin_without_health_probe` — Number of serving groups with more than one enabled origin and no health probe to detect a failed one
- `serving_groups_http_health_probe` — Number of serving groups whose health probe uses plain HTTP

**Are the regions healthy and serving, and when did traffic move?**
- `metrics_lookback_days` — Days of hourly metrics read (the configured lookback, 1 to 30)
- `metrics_window_start` — Time of the start of the metrics window (UTC)
- `metrics_window_end` — Time of the end of the metrics window, the last whole hour (UTC)
- `serving_groups_with_health_data` — Number of serving groups with health-probe results in the window (a group without a health probe has none)
- `serving_groups_with_traffic` — Number of serving groups whose origins received requests in the window
- `serving_groups_without_traffic` — Number of serving groups whose origins received no requests in the window
- `serving_groups_all_regions_healthy_last_hour` — Number of serving groups where every region holding an enabled origin has health data in the last health hour and was healthy then. The last health hour is the newest hour in which any origin of the group's profile has health data, and it counts only when it is one of the window's last 3 hours; otherwise no group of that profile is judged. A region with no health data that hour keeps the group out of this count. A region is healthy in an hour when one of its origins passed at least the share of health probes the group's load-balancing settings require (3 of 4, so 75%, by default)
- `serving_groups_region_unhealthy_last_hour` — Number of serving groups where a region holding an enabled origin has health data in the last health hour and was not healthy then
- `serving_multi_region_groups` — Number of serving groups whose enabled origins span two or more regions
- `serving_multi_region_groups_all_regions_healthy_last_hour` — Number of serving multi-region groups where every region holding an enabled origin has health data in the last health hour and was healthy then
- `serving_multi_region_groups_all_regions_serving_last_hour` — Number of serving multi-region groups where every region holding an enabled origin received requests in the last request hour: the newest hour in which any origin of the group's profile received requests, counted only when it is one of the window's last 3 hours, otherwise no group of that profile is counted. Requests and health each use their own newest hour, because Azure Monitor can deliver one metric later than the other
- `serving_multi_region_groups_with_traffic_shift` — Number of serving multi-region groups where the set of regions receiving requests changed at least once in the window
- `regions_serving_traffic` — List of regions whose origins in serving groups received requests in the window
- `origin_metric_series_unmatched` — Number of metric series whose origin matched no origin in the profile, in any origin group in scope or out (such as an origin deleted during the window)

**Does Front Door reach its origins securely?**
- `serving_groups_connection_protected` — Number of serving groups reached securely: at least one enabled origin, only HTTPS to the origins, certificate name checks on, and private link on every enabled origin or managed-identity authentication on the group
- `serving_groups_connection_unprotected` — Number of serving groups not reached securely
- `serving_groups_http_to_origin` — Number of serving groups where an in-scope route can forward plain HTTP to the origins
- `serving_groups_certificate_name_check_disabled` — Number of serving groups with an enabled origin that skips checking the origin certificate's name
- `serving_groups_without_private_link_or_origin_auth` — Number of serving groups where not every enabled origin uses private link and the group has no managed-identity authentication
- `serving_groups_all_private_link` — Number of serving groups where every enabled origin uses private link
- `serving_groups_origin_authentication` — Number of serving groups that authenticate to their origins with a managed identity

**Does each App Service origin accept traffic only through its own Front Door profile?**
- `app_service_origins` — Number of origins in in-scope groups that are App Service apps or slots, found by the origin's Azure resource, its private-link target, or the app owning its host name
- `serving_app_service_origins` — Number of App Service origins that are enabled and in a serving group
- `serving_app_service_origins_locked_to_front_door` — Number of serving App Service origins locked to Front Door: the app's public network access is off, or its access restrictions turn away every public caller except Front Door requests whose X-Azure-FDID header carries the Front Door id of the origin's own profile, or of another profile in the subscription that also serves the app through an enabled origin in an in-scope serving group, and its Kudu (scm) site doesn't let every public caller in
- `serving_app_service_origins_not_locked` — Number of serving App Service origins not locked to Front Door
- `serving_app_service_origins_public_network_access_disabled` — Number of serving App Service origins whose app has public network access turned off
- `serving_app_service_origins_public_access_unrestricted` — Number of serving App Service origins whose app lets any public caller in, through an "Allow all" rule, an allow default, or no rules
- `serving_app_service_origins_non_front_door_allow_rule` — Number of serving App Service origins whose app allows a public caller other than Front Door, such as an IP range or subnet
- `serving_app_service_origins_front_door_rule_without_fdid` — Number of serving App Service origins whose app allows the Front Door service tag without an X-Azure-FDID header, so any customer's Front Door can reach it
- `serving_app_service_origins_unknown_front_door_id_allowed` — Number of serving App Service origins whose app allows a Front Door id that no profile in the subscription has
- `serving_app_service_origins_other_front_door_id_allowed` — Number of serving App Service origins whose app allows the Front Door id of another profile in the subscription that doesn't serve the app through an in-scope serving group, so requests through that profile skip the serving profile's WAF
- `serving_app_service_origins_profile_front_door_id_not_allowed` — Number of serving App Service origins reached over the public internet whose app's rules don't admit the origin's own profile
- `serving_app_service_origins_profile_front_door_id_unknown` — Number of serving App Service origins reached over the public internet whose profile's Front Door id couldn't be read
- `serving_app_service_origins_scm_public_access_unrestricted` — Number of serving App Service origins whose app's Kudu (scm) site, the deployment and console endpoint, uses its own access restrictions rather than the main site's, and they let any public caller in (an "Allow all" rule, an allow default, or no rules)
- `serving_app_service_origins_access_restrictions_unread` — Number of serving App Service origins whose app's access restrictions couldn't be read
- `serving_app_service_origins_site_not_found` — Number of serving App Service origins pointing at an app that no longer exists in the subscription
- `serving_app_service_origins_site_not_visible` — Number of serving App Service origins pointing at an app in another subscription the credential can't read

**Does each production app have a regional twin with enough capacity?**
- `production_tag` — The configured tag that marks production apps, set per target; null when every app in the subscription counts as production
- `production_web_apps` — Number of in-scope production web apps (apps, not slots, whose kind isn't a function app)
- `production_web_apps_behind_front_door` — Number of production web apps reached by an enabled origin in a serving group
- `production_web_apps_not_behind_front_door` — Number of production web apps that no enabled origin in a serving group reaches
- `production_web_apps_regional_twin_ready` — Number of production web apps behind Front Door with a twin (another enabled origin in the same group, on a different app, in a different region) whose plan is platform-scaled or has at least as many instances
- `production_web_apps_without_regional_twin` — Number of production web apps behind Front Door with no twin in another region, including apps whose possible twin's region wasn't found
- `production_web_apps_twin_capacity_short` — Number of production web apps whose every twin's plan has fewer instances than the app's own plan
- `production_web_apps_twin_capacity_unknown` — Number of production web apps with a twin whose capacity can't be compared (a plan wasn't found, or the twin isn't an App Service app)
- `production_function_apps` — Number of in-scope production function apps (apps whose kind contains functionapp)
- `production_function_apps_behind_front_door` — Number of production function apps reached by an enabled origin in a serving group
- `production_function_apps_not_behind_front_door` — Number of production function apps that no enabled origin in a serving group reaches
- `production_function_apps_regional_twin_ready` — Number of production function apps behind Front Door with a twin in another region whose plan is platform-scaled or has at least as many instances
- `production_function_apps_without_regional_twin` — Number of production function apps behind Front Door with no twin in another region, including apps whose possible twin's region wasn't found
- `production_function_apps_twin_capacity_short` — Number of production function apps whose every twin's plan has fewer instances than the app's own plan
- `production_function_apps_twin_capacity_unknown` — Number of production function apps with a twin whose capacity can't be compared

### azure_front_door_tls
Short Description: Shows whether every in-scope serving Front Door route accepts only HTTPS and whether every in-scope custom domain it serves enforces TLS 1.2 or higher with an in-date certificate.

Script: fetchers/azure/front_door_tls/fetcher.py (uses the shared Front Door helpers fetchers/azure/_shared/frontdoor.py and fetchers/azure/_shared/scope_exclusions.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Cdn — notes an unregistered provider
- `profiles.list()` — Front Door Standard and Premium profiles; other CDN profiles are counted and skipped
- `afd_endpoints.list_by_profile()` and `routes.list_by_endpoint()` (per profile) — endpoints, their routes, and the protocols and HTTPS redirect each route has
- `afd_custom_domains.list_by_profile()` (per profile) — custom domains with their host name, cipher suite set, minimum TLS version and validation state
- `secrets.list_by_profile()` (per profile) — the certificates the domains use, with issuer and expiry (no private keys)
- `rule_sets.list_by_profile()` and `rules.list_by_rule_set()` (per profile) — rules that redirect HTTP to HTTPS

Output: `azure_front_door_tls_<subscription>.json` — each in-scope route with the protocols it accepts and whether it accepts only HTTPS, each in-scope custom domain with its TLS floor, certificate type, issuer and expiry, and whether a serving route uses it, and the custom domains, endpoints, routes and secrets left out of scope with the pattern or reason that took each out.

Summary fields:

**What was checked?**
- `total_front_door_profiles` — Number of Front Door Standard and Premium profiles
- `premium_profiles` — Number of Front Door Premium profiles
- `standard_profiles` — Number of Front Door Standard profiles
- `skipped_profiles_by_sku` — Number of other Azure CDN profiles skipped, for each SKU
- `total_routes` — Number of in-scope routes across all endpoints, enabled or not (a route is in scope unless the scope exclusion patterns take it out, as `excluded_routes` describes)
- `serving_routes` — Number of serving routes: in-scope routes where the route and its endpoint are both enabled
- `total_custom_domains` — Number of in-scope custom domains across all profiles (custom domains whose host name no scope exclusion pattern matches)
- `served_custom_domains` — Number of served custom domains: in-scope custom domains listed by an enabled route on an enabled endpoint; a route out of scope still counts here, so a domain is never left out because of its route
- `unrouted_custom_domains` — Number of in-scope custom domains that no route lists, enabled or not, in scope or not
- `provider_registration_status` — Whether the Front Door and CDN provider (Microsoft.Cdn) is registered on the subscription: registered, not_registered or unknown

**Which parts of Front Door are left out of scope?**
- `scope_exclusion_patterns` — List of the patterns in the fetcher's `scope_exclusions` setting, in the order given: case-insensitive globs (`*` matches any run of characters, dots included; `?` matches one character) that must match a whole name. A plain pattern matches the host name of a custom domain or of an endpoint (the endpoint's own `*.azurefd.net` name); a pattern starting `route:` (such as `route:qa-*`) matches route names instead, and a plain pattern never matches a route's name. A pattern with any other prefix, or with nothing after `route:`, fails the run. Whatever a pattern takes out is out of scope: it is listed in the evidence's excluded list with the pattern (or the reason, when it went out because of something else) and left out of every other count; everything else is in scope. Empty when no patterns are set, so everything is in scope
- `scope_exclusion_patterns_unmatched` — List of configured patterns that matched no custom-domain host name, endpoint host name or route name, such as a mistyped name
- `excluded_custom_domains` — Number of custom domains out of scope because their host name matches a pattern
- `excluded_endpoints` — Number of endpoints whose own `*.azurefd.net` host name matches a pattern; an in-scope route on such an endpoint lists only its in-scope hosts and doesn't count as serving the endpoint's own domain
- `excluded_routes` — Number of routes out of scope: a `route:` pattern matches the route's name, or every host the route serves (its custom domains, plus the endpoint's own host name when the route links it) is out of scope. A route that serves no host goes out only by name
- `excluded_secrets` — Number of profile secrets out of scope because every custom domain that uses them is out of scope
- `in_scope_hosts` — Number of custom domains and endpoints whose host name no pattern matches; 0 means the patterns took out every host, which a check can catch by requiring more than 0
- `in_scope_custom_domains` — Number of custom domains whose host name no pattern matches (equal to `total_custom_domains`)
- `in_scope_endpoints` — Number of endpoints whose own host name no pattern matches
- `in_scope_routes` — Number of routes in scope (equal to `total_routes`)
- `in_scope_secrets` — Number of profile secrets in scope, of every type (certificates, and any other secret a profile holds, such as a URL signing key); a secret no custom domain uses stays in scope

**Does every serving route accept only HTTPS?**
- `serving_routes_https_only` — Number of serving routes that accept only HTTPS: HTTP isn't among the route's protocols, or HTTP requests are redirected to HTTPS by the route's HTTPS redirect setting or by a rule-set rule (a redirect to HTTPS with no condition, or with only a request-scheme condition matching HTTP, reached before any rule that stops evaluation). A route with no protocols set accepts HTTP and HTTPS, and a route with no redirect set doesn't redirect
- `serving_routes_accepting_plain_http` — Number of serving routes that still answer plain HTTP: HTTP is among their protocols and nothing redirects it to HTTPS
- `serving_routes_https_only_protocols` — Number of serving routes that accept only HTTPS because HTTP isn't among their protocols
- `serving_routes_https_redirect` — Number of serving routes that accept HTTP but redirect it to HTTPS through the route's own HTTPS redirect setting
- `serving_routes_rule_set_redirect` — Number of serving routes that accept HTTP, have the route's HTTPS redirect off, and redirect every HTTP request to HTTPS through a rule-set rule
- `serving_routes_on_endpoint_default_domain` — Number of serving routes that also serve the endpoint's own `*.azurefd.net` domain while that host name is in scope; its TLS follows Front Door's platform policy rather than any setting in the profile

**Does every served domain enforce TLS 1.2 or higher?**
- `served_domains_below_tls12` — Number of served custom domains whose TLS floor is below TLS 1.2 (TLS 1.0). The TLS floor is the lowest TLS version a domain accepts: its minimum TLS version when its cipher suite set is Customized; otherwise the floor its predefined cipher suite set implies (TLS10_2019 gives TLS 1.0, TLS12_2022 and TLS12_2023 give TLS 1.2); otherwise its minimum TLS version when no set is stored
- `served_domains_minimum_tls13` — Number of served custom domains whose TLS floor is TLS 1.3
- `served_domains_tls_floor_unknown` — Number of served custom domains whose TLS floor couldn't be worked out: an unrecognised cipher suite set, neither a set nor a minimum version stored, or a version other than TLS 1.0, 1.2 or 1.3
- `domains_by_cipher_suite_set` — Number of in-scope custom domains, served or not, for each cipher suite set:
  - TLS10_2019 (predefined, TLS 1.0 floor)
  - TLS12_2022 (predefined, TLS 1.2 floor)
  - TLS12_2023 (predefined, TLS 1.2 floor)
  - Customized (cipher suites and minimum TLS version chosen by hand)
  - None (no cipher suite set stored)

**Is every served domain validated, with an in-date certificate?**
- `served_domains_validation_not_approved` — Number of served custom domains whose domain ownership validation state isn't Approved (for example Pending, Rejected or TimedOut)
- `served_domains_certificate_missing` — Number of served custom domains whose certificate wasn't found: it isn't a Front Door managed certificate, and no secret in the profile matches the domain's certificate reference
- `served_domains_managed_certificate_without_secret` — Number of served custom domains on a Front Door managed certificate that has no secret in the profile, so its expiry can't be read; Front Door renews these certificates itself
- `served_domains_certificate_expired` — Number of served custom domains whose certificate expired at or before the time of the run
- `served_domains_certificate_expiring_soon` — Number of served custom domains whose certificate hasn't expired but expires within `expiry_warning_days` days
- `served_domains_certificate_expiry_unknown` — Number of served custom domains with no readable certificate expiry (a missing certificate, a managed certificate without a secret, or an unreadable date); these count as neither expired nor valid
- `expiry_warning_days` — Days before expiry at which a certificate counts as expiring soon (30, fixed in the fetcher)
- `domains_by_certificate_type` — Number of in-scope custom domains, served or not, for each certificate type:
  - CustomerCertificate (the customer's own certificate, held in Key Vault)
  - ManagedCertificate (issued and renewed by Front Door)
  - AzureFirstPartyManagedCertificate (issued by Azure, for Microsoft's own first-party domains)
  - None (no certificate type stored)
- `certificate_secrets` — Number of in-scope certificate secrets across all profiles (customer, Front Door managed and Azure first-party managed certificates), whether or not a domain uses them

### azure_front_door_waf_coverage
Short Description: Shows whether every in-scope host a Front Door route serves is behind a web application firewall that blocks attacks on every path, and whether each profile exports its WAF log.

Script: fetchers/azure/front_door_waf_coverage/fetcher.py (uses the shared Front Door helpers fetchers/azure/_shared/frontdoor.py and fetchers/azure/_shared/scope_exclusions.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Cdn — notes an unregistered provider
- `profiles.list()` — Front Door Standard and Premium profiles; other CDN profiles are counted and skipped
- `afd_endpoints.list_by_profile()` and `routes.list_by_endpoint()` (per profile) — endpoints, their routes and the hosts each route serves
- `afd_custom_domains.list_by_profile()` (per profile) — custom domains and their host names, to find the ones no route serves and match them against the scope exclusion patterns
- `security_policies.list_by_profile()` (per profile) — which WAF policy applies to which routes, domains or the whole profile, and on which paths
- `policies.list_by_subscription()` — Front Door WAF policies with their mode, rule sets, overrides and custom rules
- `managed_rule_sets.list()` — Microsoft's managed rule set definitions, to work out which rules are on
- `diagnostic_settings_category.list()` and `diagnostic_settings.list()` (per profile) — whether the WAF log and access log are exported, and where

Output: `azure_front_door_waf_coverage_<subscription>.json` — each in-scope host on each in-scope route with the WAF policy that applies to it and whether it is protected (and why not), plus in-scope endpoints with no routes, in-scope custom domains no route serves, the security policies, where each profile exports its WAF log, and the custom domains, endpoints, routes and host-routes left out of scope with the pattern or reason that took each out.

Summary fields:

**What was checked?**
- `total_front_door_profiles` — Number of Front Door Standard and Premium profiles
- `premium_profiles` — Number of Front Door Premium profiles
- `standard_profiles` — Number of Front Door Standard profiles
- `skipped_profiles_by_sku` — Number of other Azure CDN profiles skipped, for each SKU
- `total_endpoints` — Number of endpoints across all profiles, enabled or not, whose own host name is in scope or that carry at least one in-scope route (an endpoint is in scope unless a scope exclusion pattern matches its host name, as `excluded_endpoints` describes)
- `endpoints_without_routes` — Number of endpoints with no routes whose own host name is in scope
- `total_routes` — Number of in-scope routes across all endpoints, enabled or not (a route is in scope unless the scope exclusion patterns take it out, as `excluded_routes` describes)
- `total_custom_domains` — Number of in-scope custom domains across all profiles (custom domains whose host name no scope exclusion pattern matches)
- `unrouted_custom_domains` — Number of in-scope custom domains that no route lists, enabled or not, in scope or not
- `total_security_policies` — Number of security policies across all profiles, of any type; scope exclusions don't apply to security policies
- `total_host_routes` — Number of in-scope host-routes: each host a route serves (each custom domain the route lists, plus the endpoint's own `*.azurefd.net` domain when the route links it), counted once per route, enabled or not, leaving out any whose host or route is out of scope
- `serving_host_routes` — Number of serving host-routes: in-scope host-routes where the route and its endpoint are both enabled; only serving host-routes are judged in the groups below
- `security_policies_api_version` — What the fetcher reads security policies with: the Front Door API version it pins, the first that reports which routes a policy covers and whether it covers the whole profile
- `provider_registration_status` — Whether the Front Door and CDN provider (Microsoft.Cdn) is registered on the subscription: registered, not_registered or unknown

**Which parts of Front Door are left out of scope?**
- `scope_exclusion_patterns` — List of the patterns in the fetcher's `scope_exclusions` setting, in the order given: case-insensitive globs (`*` matches any run of characters, dots included; `?` matches one character) that must match a whole name. A plain pattern matches the host name of a custom domain or of an endpoint (the endpoint's own `*.azurefd.net` name); a pattern starting `route:` (such as `route:qa-*`) matches route names instead, and a plain pattern never matches a route's name. A pattern with any other prefix, or with nothing after `route:`, fails the run. Whatever a pattern takes out is out of scope: it is listed in the evidence's excluded list with the pattern (or the reason, when it went out because of something else) and left out of every verdict and count; everything else is in scope. Empty when no patterns are set, so everything is in scope
- `scope_exclusion_patterns_unmatched` — List of configured patterns that matched no custom-domain host name, endpoint host name or route name, such as a mistyped name
- `excluded_custom_domains` — Number of custom domains out of scope because their host name matches a pattern
- `excluded_endpoints` — Number of endpoints whose own `*.azurefd.net` host name matches a pattern; their own domain's host-routes go out, but routes on them that serve an in-scope custom domain stay
- `excluded_routes` — Number of routes out of scope: a `route:` pattern matches the route's name, or every host the route serves (its custom domains, plus the endpoint's own host name when the route links it) is out of scope. A route that serves no host goes out only by name
- `excluded_host_routes` — Number of host-routes out of scope because the host's name matches a pattern or the host's route is out of scope
- `in_scope_hosts` — Number of custom domains and endpoints whose host name no pattern matches; 0 means the patterns took out every host, which a check can catch by requiring more than 0
- `in_scope_custom_domains` — Number of custom domains whose host name no pattern matches (equal to `total_custom_domains`)
- `in_scope_endpoints` — Number of endpoints whose own host name no pattern matches; unlike `total_endpoints`, an endpoint whose host name matches doesn't count even when it carries in-scope routes
- `in_scope_routes` — Number of routes in scope (equal to `total_routes`)
- `in_scope_host_routes` — Number of host-routes in scope (equal to `total_host_routes`)

**Which WAF applies to each serving host?**
- `host_routes_route_scope` — Number of serving host-routes whose WAF comes from a WAF security policy naming the route (and, when it also names domains, naming this host); route level wins over domain and profile level
- `host_routes_domain_scope` — Number of serving host-routes whose WAF comes from a WAF security policy naming the host's domain and no routes, with no route-level match
- `host_routes_profile_scope` — Number of serving host-routes whose WAF comes from a WAF security policy applied to the whole profile, with no route- or domain-level match
- `host_routes_none_scope` — Number of serving host-routes with no WAF security policy at route, domain or profile level

**Is every serving host behind a WAF that blocks attacks?**
- `protected_host_routes` — Number of protected serving host-routes: a WAF applies, its policy was found in the subscription, the policy blocks attacks, it covers every path (`/*`), and neither the route nor the WAF association marks the host inactive. A policy blocks attacks when it is enabled, in Prevention mode, runs a Default Rule Set that blocks with a blocking rule left in every group that blocks by default, and has no custom rule allowing every request (the full test is in `azure_front_door_waf_policies`)
- `unprotected_host_routes` — Number of serving host-routes that aren't protected; a host-route can fail for more than one reason, so the reason counts below can add up to more than this
- `protected_host_route_percentage` — Percentage of serving host-routes that are protected = `protected_host_routes` / `serving_host_routes` × 100 (a whole number, 0–100); 0 when `serving_host_routes` is 0

**Why is a serving host unprotected?**
- `host_routes_without_waf` — Number of serving host-routes with no WAF security policy at any level; always equal to `host_routes_none_scope`
- `host_routes_waf_not_blocking` — Number of serving host-routes whose WAF policy doesn't block attacks (for example it is disabled, in Detection mode, or has a rule group switched off)
- `host_routes_waf_unresolved` — Number of serving host-routes whose security policy names a WAF policy not found among the subscription's Front Door WAF policies (held in another subscription, deleted, or the policy list couldn't be read)
- `host_routes_partial_path_coverage` — Number of serving host-routes whose WAF association lists path patterns without `/*`, so some paths reach the origin unfiltered
- `host_routes_reference_inactive` — Number of serving host-routes whose host is marked inactive on the route or in the WAF association

**Does every profile with a WAF export its WAF log?**
- `profiles_with_waf_in_use` — Number of profiles where at least one serving host-route has a WAF security policy, blocking or not
- `profiles_waf_log_exported` — Number of profiles, with or without a WAF in use, whose WAF log (FrontDoorWebApplicationFirewallLog) is exported: a diagnostic setting with a destination (Log Analytics workspace, storage account, event hub or partner solution) turns the log on by name, through allLogs, or through a category group the log belongs to
- `profiles_with_waf_in_use_without_waf_log_export` — Number of profiles with a WAF in use whose WAF log isn't exported

### azure_front_door_waf_policies
Short Description: Shows each Front Door web application firewall policy's mode and managed rules, whether it actually blocks attacks and why not, and whether any Front Door uses it.

Script: fetchers/azure/front_door_waf_policies/fetcher.py (uses the shared Front Door helpers fetchers/azure/_shared/frontdoor.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — notes an unregistered provider
- `policies.list_by_subscription()` — every Front Door WAF policy with its settings, managed rule sets, overrides, exclusions and custom rules
- `managed_rule_sets.list()` — Microsoft's managed rule set definitions, to work out which rules are on and the newest version of each

Output: `azure_front_door_waf_policies_<subscription>.json` — each Front Door Standard or Premium WAF policy with its mode, managed rule sets and the rules switched off or set to log or allow, its custom rules, whether it blocks attacks and why not, and whether a Front Door security policy uses it.

Summary fields:

**What was checked?**
- `total_waf_policies` — Number of Front Door Standard and Premium WAF policies in the subscription
- `premium_waf_policies` — Number of Front Door Premium WAF policies
- `standard_waf_policies` — Number of Front Door Standard WAF policies
- `skipped_policies_by_sku` — Number of other Front Door WAF policies skipped (classic Front Door), for each SKU
- `provider_registration_status` — Whether the networking provider (Microsoft.Network), which holds Front Door WAF policies, is registered on the subscription: registered, not_registered or unknown

**Is each WAF policy used by a Front Door?**
- `associated_waf_policies` — Number of associated WAF policies: at least one Front Door security policy uses the policy (which hosts it covers is in `azure_front_door_waf_coverage`)
- `unassociated_waf_policies` — Number of WAF policies that no Front Door security policy uses

**Does each policy block attacks?**
- `blocking_waf_policies` — Number of WAF policies that block attacks: enabled (no state set counts as enabled), in Prevention mode, with a Default Rule Set (DefaultRuleSet or Microsoft_DefaultRuleSet) whose action is Block or Redirect (no action set counts as Block), whose rule definition was found, and in which every rule group that blocks by default still has an enabled rule that blocks (action Block, Redirect or AnomalyScoring), and with no enabled custom rule that allows every request. Groups Microsoft ships with no rule blocking by default (such as the threat-intelligence groups) don't count against a policy while left off
- `waf_policies_not_blocking` — Number of WAF policies that don't block attacks
- `associated_waf_policies_not_blocking` — Number of associated WAF policies that don't block attacks

**Why doesn't a policy block attacks?**
- `policies_disabled` — Number of WAF policies that are turned off
- `policies_in_detection_mode` — Number of WAF policies in Detection mode, which logs attacks but doesn't block them
- `policies_mode_unset` — Number of WAF policies with no mode set, counted as not blocking because Azure documents no default mode
- `policies_without_default_rule_set` — Number of WAF policies with no Default Rule Set
- `policies_default_rule_set_log_only` — Number of WAF policies whose Default Rule Set action is neither Block nor Redirect (such as Log), so matches are logged, not blocked
- `policies_rule_groups_not_blocking` — Number of WAF policies whose Default Rule Set has a rule group that blocks by default but has no enabled blocking rule left, because overrides switch the group or its rules off or set them to Log or Allow
- `policies_rule_definition_not_found` — Number of WAF policies whose Default Rule Set type and version has no definition in Microsoft's managed rule set list, so the rules that are on can't be counted
- `policies_with_allow_all_custom_rule` — Number of WAF policies with an enabled custom match rule that allows every request (every condition matches any request, or any IP address through 0.0.0.0/0 or ::/0); custom rules run before managed rules, so it lets every request past them

**How much of the managed rule set is switched off, and is it current?**
- `total_disabled_managed_rules` — Number of managed rules switched off one by one through a rule override, across all policies and rule sets; rules in a group switched off as a whole aren't included
- `total_disabled_managed_rule_groups` — Number of managed rule groups switched off as a whole (a group override that lists no rules), across all policies and rule sets
- `policies_with_fully_disabled_rule_groups` — Number of WAF policies whose Default Rule Set has a rule group that blocks by default with every rule now switched off
- `associated_policies_with_fully_disabled_rule_groups` — Number of associated WAF policies whose Default Rule Set has a rule group that blocks by default with every rule now switched off
- `policies_on_older_default_rule_set` — Number of WAF policies whose Default Rule Set version is older than the newest version Microsoft publishes for that rule set type

**Do policies limit request rates?**
- `waf_policies_with_rate_limit_rules` — Number of WAF policies with at least one enabled rate-limit custom rule


### azure_network_security_groups
Short Description: Shows NSG rules that expose SSH, RDP or unrestricted Internet egress, NSG coverage of subnets and network interfaces, and east-west segmentation between subnets.

Script: fetchers/azure/network_security_groups/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `network_security_groups.list_all()` — every NSG and its rules
- `virtual_networks.list_all()` — subnets, their NSGs and address ranges
- `network_interfaces.list_all()` — each NIC's NSG coverage

Output: `azure_network_security_groups_<subscription>.json` — every NSG with its rules, which subnets and network interfaces each one covers, and each subnet's east-west segmentation verdict.

Summary fields:

**Are SSH, RDP or other ports open to the Internet?**
- `total_network_security_groups` — Number of network security groups (NSGs)
- `total_security_rules` — Number of custom (user-written) rules across all NSGs
- `inbound_allow_rules` — Number of custom rules that allow inbound traffic
- `internet_sourced_allow_rules` — Number of custom rules that allow inbound traffic from anywhere on the Internet (source Internet, * or 0.0.0.0/0)
- `ssh_open_to_internet_groups` — Number of NSGs with a custom rule that allows SSH (port 22) from the Internet
- `rdp_open_to_internet_groups` — Number of NSGs with a custom rule that allows RDP (port 3389) from the Internet

**Is outbound Internet traffic restricted?**
- `outbound_allow_rules` — Number of custom rules that allow outbound traffic
- `outbound_deny_rules` — Number of custom rules that deny outbound traffic
- `internet_destined_allow_rules` — Number of custom rules that allow outbound traffic to anywhere on the Internet (destination Internet, * or 0.0.0.0/0)
- `unrestricted_internet_outbound_groups` — Number of NSGs that allow all outbound Internet traffic: their highest-priority rule covering all Internet traffic is an Allow (an NSG with no custom catch-all Internet rule counts, because of Azure's default AllowInternetOutBound rule)
- `restricted_internet_outbound_groups` — Number of NSGs whose highest-priority rule covering all Internet traffic is a Deny

**Is every subnet and network interface covered by an NSG?**
- `total_subnets` — Number of subnets
- `subnets_with_nsg` — Number of subnets with an NSG attached
- `subnets_without_nsg` — Number of subnets with no NSG attached
- `subnet_nsg_coverage_percentage` — Percentage of subnets with an NSG attached = `subnets_with_nsg` / `total_subnets` × 100 (a whole number, 0–100); 0 when `total_subnets` is 0. Every subnet counts, including Azure platform subnets such as GatewaySubnet and AzureFirewallSubnet that don't support an NSG, so 100 may be out of reach
- `total_network_interfaces` — Number of network interfaces (NICs)
- `nics_with_nic_nsg` — Number of NICs with their own NSG
- `nics_protected_by_subnet_nsg_only` — Number of NICs protected only by their subnet's NSG
- `nics_without_any_nsg` — Number of NICs with no NSG on the NIC or its subnet
- `nic_nsg_coverage_percentage` — Percentage of NICs protected by any NSG = (`total_network_interfaces` − `nics_without_any_nsg`) / `total_network_interfaces` × 100 (a whole number, 0–100); 0 when `total_network_interfaces` is 0. A NIC counts as protected by its own NSG or its subnet's

**Are subnets segmented from each other?**
- `workload_subnets_by_east_west_segmentation` — Number of workload subnets with each segmentation result, based on whether other subnets in the same VNet can reach it on every port:
	- segmented (no other subnet in the VNet can)
	- partial (some other subnets can)
	- unsegmented (every other subnet can)
	- undetermined (the deciding rule uses an application security group, or an NSG is in another subscription)
	- no_peer_subnets (it's the only subnet in its VNet)
- `east_west_subnet_pairs` — Number of subnet pairs within the same VNet that were checked
- `open_east_west_subnet_pairs` — Number of checked subnet pairs where one subnet can reach the other on every port

**Are virtual networks DDoS-protected?**
- `total_virtual_networks` — Number of virtual networks (VNets)
- `ddos_protected_virtual_networks` — Number of VNets with DDoS protection turned on
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown


### azure_private_dns_zone_configuration
Short Description: Shows which virtual networks each private DNS zone serves and whether every privatelink record still points at a live private endpoint serving that name.

Script: fetchers/azure/private_dns_zone_configuration/fetcher.py

Access: Reader on the subscription. Optional: Reader on other subscriptions whose virtual networks the zones link to or whose private endpoints the records point at; without it, those links read as unreadable and those records as unverified.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — records whether the provider is registered
- `private_zones.list()` — private DNS zones in the subscription
- `virtual_network_links.list()` (per zone) — the virtual networks each zone is linked to
- `record_sets.list()` (per zone) — the zone's records, except SOA
- `Resources | where type =~ 'microsoft.network/networkinterfaces'` (private endpoint network interfaces, across every readable subscription) — which private endpoint holds each private IP, the names it serves and the virtual network it sits in
- `Resources | where type =~ 'microsoft.network/privateendpoints'` (across every readable subscription) — each private endpoint's connection statuses, so only an Approved endpoint backs a record
- `Resources | where type =~ 'microsoft.network/networkinterfaces'` (other network interfaces) and `…/loadbalancers` (across every readable subscription) — private IPs held by something other than a private endpoint, such as an internal load balancer
- `Resources | where type =~ 'microsoft.network/virtualnetworks' and id in~ (…)` (the zones' linked virtual networks, then the networks peered with a privatelink zone's linked networks) — address ranges, peerings, and each subnet's ranges and the resource groups of the network interfaces in it
- `Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand properties.virtualNetworkPeerings` (a privatelink zone's linked virtual networks the credential can't read) — the readable networks peered with them
- `subscriptions.list()` and `ResourceContainers` resource groups — which subscriptions and resource groups are readable, to tell a deleted virtual network from an unreadable one
- `private_dns_zone_groups.list()` (per private endpoint holding a privatelink A record's IP, in the endpoint's own subscription) — the zones, names and IPs the endpoint registers through its own private DNS zone group
- `Resources | where type =~ 'microsoft.network/privatednszones'` and `…/virtualnetworklinks` (across every readable subscription) — zones with the same name elsewhere, and the virtual networks they serve

Output: `azure_private_dns_zone_configuration_<subscription>.json` — each private DNS zone with its virtual network links, its records, and for each privatelink record whether a live private endpoint backs it and what proves it (a match in the zone's virtual networks or the endpoint's own DNS zone group).

Summary fields:

**What was checked?**
- `total_zones` — Number of private DNS zones in the subscription
- `privatelink_zones` — Number of private DNS zones with a privatelink or privatelink-… label anywhere in the name (the zones Azure services use for private endpoints, such as privatelink.blob.core.windows.net, AKS zones with privatelink in the middle of the name, or Azure Virtual Desktop's privatelink-global.wvd.microsoft.com)
- `custom_zones` — Number of private DNS zones with no privatelink or privatelink-… label in the name
- `zones_links_unknown` — Number of private DNS zones whose virtual network links couldn't be listed, so whether they're linked is unknown (never counted as unlinked)
- `zones_records_unknown` — Number of private DNS zones whose records couldn't be listed, so their records are unknown (never counted as having none)
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown

**Which virtual networks does each zone serve?**
- `zones_without_virtual_network_links` — Number of private DNS zones linked to no virtual network, so no network resolves their names
- `total_virtual_network_links` — Number of virtual network links across all zones in the subscription
- `links_with_auto_registration` — Number of virtual network links that automatically register the linked network's virtual machines in the zone
- `links_with_nxdomain_redirect` — Number of virtual network links whose resolution policy is NxDomainRedirect, so names missing from the zone fall back to public DNS
- `links_not_completed` — Number of virtual network links whose link state isn't Completed
- `links_to_deleted_virtual_networks` — Number of virtual network links whose virtual network is deleted (the credential can read the network's resource group and the network isn't there)
- `links_to_unreadable_virtual_networks` — Number of virtual network links whose virtual network is unreadable (its subscription or resource group isn't readable by the credential; a deleted resource group also counts here)
- `links_virtual_network_unknown` — Number of virtual network links whose virtual network lookup failed, so whether it exists is unknown
- `duplicate_zone_names` — List of zone names in this subscription that exist more than once, each with the ids of every zone carrying the name and the virtual networks linked to any copy; Azure blocks linking one network to two zones of the same name, so a duplicated name resolves differently in different networks
- `duplicate_zone_names_scope` — Whether duplicate zone names were looked for across readable subscriptions or only this one: readable_subscriptions (every subscription the credential can read), target_subscription (only this subscription, because the cross-subscription query failed) or null when the subscription has no zones

**Does every privatelink record point at a live private endpoint?**
- `privatelink_a_records` — Number of privatelink A records (A records in a privatelink zone, other than the zone apex). Each IP is checked only within the virtual networks the zone resolves for: its linked virtual networks and the networks with a Connected peering to a linked network, seen from either side and one hop only, because the same private IP can be reused in unrelated networks. A private endpoint serves the record's name when one of its names is the record's full name or the record's name under the zone's public suffix (the zone name without its privatelink label; Key Vault's privatelink.vaultcore.azure.net maps to vault.azure.net, and likewise in Azure Government and Azure China); an endpoint that publishes no names is matched by IP alone
- `privatelink_records_backed` — Number of privatelink A records whose every IP is backed. An IP is backed when an Approved private endpoint (every connection Approved) holds it in a virtual network the zone resolves for and serves the record's name, or when an Approved private endpoint whose network interface holds every IP of the record registers exactly this zone, name and IPs through its own private DNS zone group (Azure keeps that record for the endpoint, so this works in any network layout) and the zone's own virtual networks show no other endpoint, unapproved endpoint or other resource holding the IP
- `privatelink_records_partially_backed` — Number of privatelink A records with at least one backed IP and at least one IP that isn't backed, so a dead IP next to a live one stays visible
- `privatelink_records_ip_mismatch` — Number of privatelink A records with no backed IP and at least one IP held, in a virtual network the zone resolves for, by a private endpoint that serves a different name
- `privatelink_records_endpoint_not_approved` — Number of privatelink A records with no backed or mismatched IP and at least one IP held by a private endpoint that serves the record's name but isn't approved (not every connection is Approved: Pending, Rejected or Disconnected)
- `privatelink_records_stale` — Number of privatelink A records with no backed, mismatched or unapproved-endpoint IP and at least one stale IP: nothing holds it, it lies in a subnet of a readable virtual network the zone resolves for, and every resource group with a network interface in that subnet is readable, so it was most likely left behind by a deleted endpoint
- `privatelink_records_unknown` — Number of privatelink A records with no backed, mismatched, unapproved-endpoint or stale IP and at least one IP whose check depends on a query that failed: the zone's link list, the private endpoint, approval, other-IP-holder, virtual network or peering lookups, the readable-scope listing, or the zone group read of an endpoint that could have registered the record (an IP that would otherwise read stale reads unknown then)
- `privatelink_records_unverified` — Number of privatelink A records with no backed, mismatched, unapproved-endpoint, stale or unknown IP and at least one IP that can't be checked: no readable virtual network the zone resolves for holds or contains it (the zone has no links, its links point only at unreadable networks, the endpoint sits in a subscription the credential can't read, or it sits more than one peering hop away, as with Virtual WAN or spoke to spoke, and no zone group registers the record), a network interface in its subnet is in a resource group the credential can't read, or it lies in overlapping virtual networks that disagree
- `privatelink_records_platform_managed` — Number of privatelink A records whose every IP is held, in a virtual network the zone resolves for, by a network interface or internal load balancer frontend that isn't a private endpoint (for example an AKS private cluster's API server)
- `privatelink_records_no_addresses` — Number of privatelink A records with no IP address
- `privatelink_records_backed_percentage` — Percentage of privatelink A records that are fully backed = `privatelink_records_backed` / `privatelink_a_records` × 100 (a whole number, 0–100); 0 when `privatelink_a_records` is 0. Partially backed, mismatched, unapproved-endpoint, stale, unknown, unverified, platform-managed and no-address records count in the total but not as backed, so 100 is out of reach while any platform-managed record (such as an AKS API server's) exists

### azure_private_endpoint_configuration
Short Description: Shows whether each private endpoint is approved and published in private DNS, whether the service behind it is closed to public access, and whether its subnet's NSG filters endpoint traffic.

Script: fetchers/azure/private_endpoint_configuration/fetcher.py

Access: Reader on the subscription. Optional: Reader on other subscriptions holding the endpoints' target resources or virtual networks; without it, those targets read not_visible and their public access, and those subnets' settings, go unchecked.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — records whether the provider is registered
- `private_endpoints.list_by_subscription()` — private endpoints, their connections, subnet and network interfaces
- `private_dns_zone_groups.list()` (per endpoint) — the private DNS zones that publish the endpoint's records
- `Resources | where id in~ (…)` (target resources and endpoint network interfaces, across every readable subscription) — each target's public network access and firewall default, and each endpoint's private IPs
- `Resources | where id in~ (…) | mv-expand properties.subnets` (the endpoints' virtual networks) — each endpoint subnet's private endpoint network policy, NSG and route table
- `subscriptions.list()` and `ResourceContainers` resource groups — which subscriptions and resource groups are readable, to tell a deleted target from an unreadable one

Output: `azure_private_endpoint_configuration_<subscription>.json` — each private endpoint with its connections and their approval, the resource each one reaches and whether that resource is open to the internet, its subnet's filtering, its private IPs (unknown when one of its network interfaces couldn't be read) and its private DNS zones.

Summary fields:

**What was checked?**
- `total_private_endpoints` — Number of private endpoints in the subscription
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown
- `connections_by_target_type` — Number of private link connections for each target resource type, keyed by the lowercased type (for example microsoft.storage/storageaccounts), or unknown when the target id has no type

**Are the endpoints approved and published in DNS?**
- `approved_endpoints` — Number of private endpoints that are approved (every connection, automatic or manual, has the status Approved)
- `not_approved_endpoints` — Number of private endpoints that are not approved (at least one connection is Pending, Rejected or Disconnected, or the endpoint has no connection)
- `approved_percentage` — Percentage of private endpoints that are approved = `approved_endpoints` / `total_private_endpoints` × 100 (a whole number, 0–100); 0 when `total_private_endpoints` is 0
- `endpoints_by_connection_status` — Number of private endpoints with each connection status; Approved, Pending, Rejected and Disconnected are always present, Mixed and None only when they occur
  - Approved (the target's owner accepted the connection)
  - Pending (waiting for the target's owner to approve it)
  - Rejected (the target's owner refused it)
  - Disconnected (the connection was removed, usually because the target resource was deleted)
  - Mixed (the endpoint's connections have different statuses)
  - None (the endpoint has no connection)
- `endpoints_with_private_dns_zone_group` — Number of private endpoints published in private DNS (a private DNS zone group on the endpoint names at least one private DNS zone, so Azure keeps the endpoint's records in that zone)
- `endpoints_without_private_dns_zone_group` — Number of private endpoints not known to be published in private DNS: no zone group on the endpoint names a private DNS zone, or the endpoint's zone groups couldn't be listed, so an unread endpoint never counts as published
- `endpoints_private_dns_zone_group_unknown` — Number of private endpoints whose private DNS zone groups couldn't be listed, so whether they're published is unknown

**Could the resources behind the endpoints be read?**
- `total_target_resources` — Number of distinct target resources the endpoints connect to (an App Service slot, reached through its parent site, counts as the slot)
- `target_resources_found` — Number of target resources that Resource Graph returned
- `target_resources_not_found` — Number of target resources not found (the credential can read the resource group the target belongs in, and the target isn't there, so it was most likely deleted)
- `target_resources_not_visible` — Number of target resources not visible (their subscription or resource group isn't readable by the credential; a deleted resource group also counts here)
- `target_resources_lookup_unknown` — Number of target resources whose lookup failed, so whether they exist is unknown

**Are the resources behind the endpoints closed to the internet?**
- `target_resources_public_access_disabled` — Number of found target resources whose public network access is Disabled or SecuredByPerimeter (behind a network security perimeter)
- `target_resources_public_access_not_disabled` — Number of found target resources whose public network access is anything other than Disabled or SecuredByPerimeter, including no value
- `target_resources_public_access_enabled` — Number of found target resources whose public network access is set to a value other than Disabled or SecuredByPerimeter (for example Enabled)
- `target_resources_public_access_unset` — Number of found target resources with no public network access value; its meaning depends on the service (a storage account without it allows public traffic subject to its firewall)
- `target_resources_public_access_firewall_deny_default` — Number of found target resources whose public network access isn't Disabled or SecuredByPerimeter but whose firewall default action is Deny, so only allow-listed networks can reach them
- `target_public_access_disabled_percentage` — Percentage of found target resources with public network access Disabled or SecuredByPerimeter = `target_resources_public_access_disabled` / `target_resources_found` × 100 (a whole number, 0–100); 0 when `target_resources_found` is 0. Targets not found, not visible or unknown are left out of both

**Does the subnet's NSG filter endpoint traffic?**
- `total_endpoint_subnets` — Number of distinct subnets that hold private endpoints
- `endpoints_subnet_lookup_not_read` — Number of private endpoints whose subnet couldn't be read (its virtual network wasn't found, isn't readable, or the lookup failed)
- `endpoints_subnet_policies_disabled` — Number of private endpoints in a read subnet whose private endpoint network policy is Disabled, so Azure applies neither the subnet's NSG nor its route table to endpoint traffic
- `endpoints_nsg_enforced` — Number of private endpoints whose subnet NSG filters their traffic (the subnet's private endpoint network policy is Enabled or NetworkSecurityGroupEnabled and an NSG is attached); it shows the NSG is in the path, not what its rules allow
- `endpoint_subnets_nsg_applies` — Number of read endpoint subnets whose private endpoint network policy makes Azure apply an NSG to endpoint traffic (Enabled or NetworkSecurityGroupEnabled)
- `endpoint_subnets_with_nsg` — Number of read endpoint subnets with an NSG attached
- `endpoint_subnets_with_nsg_not_applied` — Number of read endpoint subnets with an NSG attached that Azure doesn't apply to private endpoint traffic, because the policy isn't Enabled or NetworkSecurityGroupEnabled (for example Disabled or RouteTableEnabled)

### azure_virtual_wan_configuration
Short Description: Shows whether Virtual WAN hubs are secured by a firewall and whether each site-to-site VPN link uses encryption, IKEv2 and strong IPsec algorithms.

Script: fetchers/azure/virtual_wan_configuration/fetcher.py (shared helper: fetchers/azure/_shared/vpn_crypto.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — tells "not registered" apart from "no Virtual WANs"
- `virtual_wans.list()` — every Virtual WAN and whether VPN encryption is turned off
- `virtual_hubs.list()` — every hub and its Azure Firewall or security partner provider
- `vpn_gateways.list()` — hub site-to-site VPN gateways with their connections and site links, including IKE version, IPsec policies and status (shared keys are never recorded)
- `vpn_sites.list()` — the branch sites the hubs connect to
- `p2_svpn_gateways.list()` — hub point-to-site (client) VPN gateways
- `vpn_server_configurations.list()` — client VPN protocols, sign-in types and IPsec policies

Output: `azure_virtual_wan_configuration_<subscription>.json` — each Virtual WAN, hub, VPN gateway with its connections and site links, branch site, client VPN gateway and VPN server configuration.

Summary fields:

**What was checked?**
- `total_virtual_wans` — Number of Virtual WANs in the subscription
- `total_virtual_hubs` — Number of virtual hubs in the subscription
- `total_vpn_gateways` — Number of hub site-to-site VPN gateways
- `total_vpn_connections` — Number of connections from hub VPN gateways to branch sites
- `total_vpn_link_connections` — Number of site-link connections (one tunnel per branch site link) across all VPN connections
- `total_vpn_sites` — Number of VPN sites (branch locations)
- `total_p2s_vpn_gateways` — Number of hub point-to-site (client) VPN gateways
- `total_vpn_server_configurations` — Number of VPN server configurations for point-to-site clients
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown

**Is VPN traffic encrypted and are hubs secured?**
- `vpn_encryption_disabled_wans` — Number of Virtual WANs with VPN encryption turned off; should be 0
- `secured_hubs` — Number of secured hubs: hubs with an Azure Firewall or a security partner provider
- `secured_hub_percentage` — Percentage of hubs that are secured = `secured_hubs` / `total_virtual_hubs` × 100 (a whole number, 0–100); 0 when `total_virtual_hubs` is 0

**Do site links use IKEv2?**
- `ikev2_link_connections` — Number of site-link connections whose protocol is IKEv2
- `ikev1_link_connections` — Number of site-link connections whose protocol is IKEv1
- `ike_version_unknown_link_connections` — Number of site-link connections where Azure returned no protocol, so the IKE version is unknown

**Do site links avoid weak IPsec algorithms?**
- `explicit_ipsec_policy_link_connections` — Number of site-link connections with a custom IPsec/IKE policy
- `azure_default_ipsec_policy_link_connections` — Number of site-link connections with no custom policy, so Virtual WAN's default IPsec/IKE policy applies
- `weak_ipsec_policy_link_connections` — Number of site-link connections with at least one weak algorithm (DES, 3DES, MD5, SHA1, DH group 1 or 2, PFS group 1 or 2, or None) in their custom policy; a link on the default policy always counts, because that default offers DH group 2, SHA1 and PFS None (listed per link with an "(azure_default)" suffix)

**Are the site links up?**
- `connected_link_connections` — Number of site-link connections whose status is Connected


### azure_vnet_egress_routing
Short Description: Shows where each subnet's and network interface's Internet-bound traffic goes and which routes bypass the firewall.

Script: fetchers/azure/vnet_egress_routing/fetcher.py

Access: Reader on the subscription. Optional: Reader on another subscription holding a Virtual WAN hub or parent firewall policy; without it, those read as unresolved.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set, and finds others for the hub search
- `providers.get("Microsoft.Network")` — tells "networking not in use" from "nothing there"
- `virtual_networks.list_all()` — VNets and subnets
- `virtual_network_peerings.list()` (per VNet) — peerings and Virtual WAN spokes
- `route_tables.list_all()` — routes and the subnets they apply to
- `network_interfaces.list_all()` — NICs, and what holds an appliance's next-hop IP
- `azure_firewalls.list_all()` — lists all firewalls
- `firewall_policies.list_all()` — threat-intelligence mode and parent policies
- `virtual_hubs.list()`, `routing_intent.list()`, `hub_virtual_network_connections.list()` and `hub_route_tables.list()` — the default route a Virtual WAN hub pushes to its spokes (searches up to 50 other subscriptions when the hub isn't here)

Output: `azure_vnet_egress_routing_<subscription>.json` — each subnet's and network interface's Internet egress path and any routes that skip the firewall, plus the VNets, route tables, firewalls and Virtual WAN hubs behind them.

Summary fields:

**Which networks were checked?**
- `total_virtual_networks` — Number of virtual networks (VNets) in the subscription
- `total_subnets` — Number of subnets
- `workload_subnets` — Number of subnets that hold workloads (all except Azure platform subnets such as GatewaySubnet and AzureFirewallSubnet)
- `platform_subnets` — Number of Azure platform subnets, whose routing Azure manages
- `total_route_tables` — Number of route tables
- `unassociated_route_tables` — Number of route tables attached to no subnet
- `provider_registration_status` — Whether the networking provider (Microsoft.Network) is registered on the subscription: registered, not_registered or unknown

**Where does each subnet's Internet traffic go?**
- `workload_subnets_by_egress_path` — Number of workload subnets for each Internet egress path: appliance (a firewall or network appliance), blackhole (dropped), gateway (VPN or ExpressRoute), nat_gateway, default_outbound (Azure's implicit outbound access), none, other and virtual_hub_unresolved
- `workload_subnets_appliance_azure_firewall` — Number of workload subnets whose default route leads to an Azure Firewall, directly or through a Virtual WAN hub
- `workload_subnets_via_virtual_hub` — Number of workload subnets whose default route comes from a Virtual WAN hub
- `workload_subnets_appliance_not_in_subscription` — Number of firewall-routed workload subnets whose next-hop IP doesn't belong to anything visible in this subscription

**Can traffic reach the Internet without passing the firewall?**
- `workload_subnets_default_outbound_effective` — Number of workload subnets that still allow Azure's default outbound Internet access (the setting is unset or true)
- `workload_subnets_appliance_with_default_outbound_fallback` — Number of firewall-routed workload subnets that would reach the Internet directly if their route were removed
- `workload_subnets_with_internet_bypass_routes` — Number of workload subnets routed through a firewall, black hole, gateway or other next hop that still have a route sending some addresses straight to the Internet
- `workload_subnets_with_service_endpoints` — Number of workload subnets with service endpoints, whose traffic to the Azure services behind the endpoints ignores route tables
- `workload_subnets_with_unrouted_internal_prefixes` — Number of workload subnets where traffic to part of their own VNet skips the firewall
- `workload_subnets_with_unrouted_peered_prefixes` — Number of workload subnets where traffic to part of a peered VNet skips the firewall

**Where does each network interface's Internet traffic go?**
- `total_network_interfaces` — Number of network interfaces (NICs)
- `network_interfaces_by_egress_path` — Number of NICs for each egress path: the paths in workload_subnets_by_egress_path, plus platform_managed, public_ip (the NIC has its own public IP on a subnet with default outbound access or no egress) and mixed (its subnets have different paths)
- `network_interfaces_default_outbound_connectivity_enabled` — Number of NICs Azure reports as having default outbound Internet access

**Which networks route through a Virtual WAN hub?**
- `total_virtual_hubs` — Number of Virtual WAN hubs in this subscription, plus any in other subscriptions that this subscription's VNets connect to
- `virtual_hub_spokes` — Number of VNets connected to a Virtual WAN hub
- `virtual_hub_spokes_unresolved` — Number of hub-connected VNets whose hub couldn't be read

**Are the firewalls in use and blocking known threats?**
- `total_azure_firewalls` — Number of Azure Firewalls
- `azure_firewalls_by_effective_threat_intel_mode` — Number of Azure Firewalls in each threat-intelligence mode (Deny, Alert or Off), using the strictest mode across the firewall's policy and its parent policies
- `azure_firewalls_with_no_routed_subnet` — Number of Azure Firewalls that no workload subnet sends traffic to


### azure_vpn_gateway_configuration
Short Description: Shows whether each site-to-site VPN tunnel uses IKEv2 and strong IPsec algorithms, and whether it is connected, alongside the gateways and on-premises endpoints it joins.

Script: fetchers/azure/vpn_gateway_configuration/fetcher.py (shared helper: fetchers/azure/_shared/vpn_crypto.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Network — tells "not registered" apart from "no gateways"
- `resource_groups.list()` — the gateway calls below only work one resource group at a time
- `virtual_network_gateways.list()` (per resource group) — VPN and ExpressRoute gateways with their SKU, active-active and point-to-site settings
- `virtual_network_gateway_connections.list()` (per resource group) — connections with their IKE version and custom IPsec policies (shared keys are never recorded)
- `virtual_network_gateway_connections.get()` (per connection) — the connection status, which the list call leaves empty
- `local_network_gateways.list()` (per resource group) — the on-premises VPN endpoints

Output: `azure_vpn_gateway_configuration_<subscription>.json` — each virtual network gateway, each connection with its IKE version, IPsec policy, weak algorithms and status, and each local network gateway.

Summary fields:

**What was checked?**
- `total_gateways` — Number of virtual network gateways of any type (VPN and ExpressRoute)
- `vpn_gateways` — Number of virtual network gateways of type Vpn
- `active_active_gateways` — Number of virtual network gateways running active-active (two instances, each with its own tunnel)
- `p2s_enabled_gateways` — Number of virtual network gateways with point-to-site (client) VPN set up, meaning a client address pool is configured
- `total_connections` — Number of gateway connections of any type (IPsec, VNet-to-VNet, ExpressRoute and others)
- `ipsec_connections` — Number of IPsec tunnels: connections of type IPsec (site-to-site) or Vnet2Vnet
- `total_local_network_gateways` — Number of local network gateways (on-premises VPN endpoints)
- `provider_registration_status` — Whether Microsoft.Network is registered on the subscription: registered, not_registered or unknown

**Do tunnels use IKEv2?**
- `ikev2_connections` — Number of IPsec tunnels whose connection protocol is IKEv2
- `ikev1_connections` — Number of IPsec tunnels whose connection protocol is IKEv1
- `ike_version_unknown_connections` — Number of IPsec tunnels where Azure returned no connection protocol, so the IKE version is unknown
- `ikev2_percentage` — Percentage of IPsec tunnels using IKEv2 = `ikev2_connections` / `ipsec_connections` × 100 (a whole number, 0–100); 0 when `ipsec_connections` is 0. Tunnels with an unknown IKE version (`ike_version_unknown_connections`) count in the total but not as IKEv2, so they lower it

**Do tunnels avoid weak IPsec algorithms?**
- `explicit_ipsec_policy_connections` — Number of IPsec tunnels with a custom IPsec/IKE policy
- `azure_default_ipsec_policy_connections` — Number of IPsec tunnels with no custom policy, so Azure's default IPsec/IKE policy applies
- `weak_ipsec_policy_connections` — Number of IPsec tunnels with at least one weak algorithm (DES, 3DES, MD5, SHA1, DH group 1 or 2, PFS group 1 or 2, or None) in their custom policy; a tunnel on Azure's default policy always counts, because that default offers DH group 2 (listed per tunnel with an "(azure_default)" suffix)

**Are the tunnels up?**
- `connected_connections` — Number of gateway connections of any type whose status is Connected (a connection whose status couldn't be read doesn't count, and the run fails)


## Compute, apps and AI

### azure_ai_hub_configuration
Short Description: Shows how exposed each Azure AI hub, project and Machine Learning workspace is, and whether its data, endpoints, compute and connections avoid stored keys.

Script: fetchers/azure/ai_hub_configuration/fetcher.py (shared helpers: _shared/arm_rest.py, _shared/foundry_connections.py, _shared/diagnostics.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.MachineLearningServices — reports whether the provider is registered
- `GET Microsoft.MachineLearningServices/workspaces` — every hub, project and classic workspace with its network, encryption and identity settings
- `GET {workspace}/connections` (per workspace) — connections to other services and how each authenticates
- `GET {workspace}/datastores` (per workspace) — datastores and the credential type used to reach each
- `GET {workspace}/onlineEndpoints` and `GET {workspace}/serverlessEndpoints` (per workspace) — model endpoints with their authentication mode and public access
- `GET {workspace}/computes` (per workspace) — compute with its public IP and SSH settings
- `diagnostic_settings.list()` (per workspace) — whether diagnostic logs are exported

Output: `azure_ai_hub_configuration_<subscription>.json` — each workspace with its network exposure, managed network, encryption, datastores, endpoints, compute, connections and log export settings.

Summary fields:

**What was checked?**
- `total_workspaces` — Number of Machine Learning workspaces of every kind (hubs, projects, classic workspaces and feature stores)
- `workspaces_by_kind` — Number of workspaces of each kind, keyed by the kind Azure reports:
  - Hub (an AI hub that shares resources and connections with its projects)
  - Project (an AI project under a hub)
  - Default (a classic Machine Learning workspace; also used when no kind is set)
  - FeatureStore (a feature store workspace)
- `hubs` — Number of workspaces of kind Hub
- `projects` — Number of workspaces of kind Project
- `projects_without_hub` — Number of Project workspaces that name no hub
- `provider_registration_status` — Whether Microsoft.MachineLearningServices is registered on the subscription: registered, not_registered or unknown

**Can the workspaces be reached from the internet?**
- `workspaces_open_to_all_networks` — Number of workspaces whose network exposure is open: public network access is on (Azure treats unset as on) and no IP allow-list is set
- `workspaces_network_restricted` — Number of workspaces whose network exposure is restricted: public network access is on but an IP allow-list limits who can connect
- `workspaces_private_only` — Number of workspaces whose network exposure is private: public network access is Disabled
- `workspaces_with_private_endpoint_but_public_access` — Number of workspaces that have a private endpoint but whose network exposure is still open or restricted

**Is outbound traffic from workspace compute controlled?**
- `workspaces_managed_network_disabled` — Number of workspaces with no managed virtual network (isolation mode Disabled, the default), so compute uses the public network
- `workspaces_managed_network_internet_outbound` — Number of workspaces with a managed virtual network that may reach any internet address (isolation mode AllowInternetOutbound)
- `workspaces_outbound_restricted` — Number of workspaces whose outbound traffic is restricted: the managed virtual network allows only approved outbound rules (isolation mode AllowOnlyApprovedOutbound)

**Is workspace data protected?**
- `workspaces_hbi` — Number of workspaces marked high business impact, which reduces the diagnostic data Microsoft collects
- `workspaces_customer_managed_key` — Number of workspaces encrypted with a customer-managed key (encryption status Enabled and a Key Vault key identifier set)
- `workspaces_identity_based_datastore_access` — Number of workspaces whose system datastores are reached with an identity or user delegation SAS rather than the storage account key (Azure's default when unset)
- `workspaces_data_isolation_enabled` — Number of workspaces with data isolation turned on
- `workspaces_v1_legacy_mode` — Number of workspaces in v1 legacy mode
- `workspaces_without_managed_identity` — Number of workspaces with no managed identity (identity type None or unset)

**Are workspace logs exported?**
- `workspaces_diagnostic_logs_exported` — Number of workspaces with diagnostic logs exported: a diagnostic setting that sends to a destination (storage account, Log Analytics, event hub or partner solution) enables at least one log category or category group
- `workspaces_diagnostic_logs_not_exported` — Number of workspaces whose diagnostic settings were read and export no log category or category group to a destination
- `workspaces_diagnostic_logs_unknown` — Number of workspaces whose diagnostic settings couldn't be read

**Do datastores keep stored credentials?**
- `total_datastores` — Number of datastores across all workspaces whose datastores could be read
- `datastores_with_stored_credentials` — Number of datastores with stored credentials: the workspace reaches the store with a secret it keeps (account key, SAS token, service principal, certificate, Kerberos keytab or Kerberos password), even when the workspace's system datastores use an identity
- `datastores_credentials_unknown` — Number of datastores whose credential type is missing or not one the fetcher recognises, so whether a credential is stored is unknown (identity-based access, type None, counts as no stored credential)
- `workspaces_datastores_unknown` — Number of workspaces whose datastores couldn't be read

**Who can call the model endpoints?**
- `total_endpoints` — Number of online (managed) and serverless (pay-as-you-go) model endpoints across all workspaces whose endpoints could be read
- `endpoints_key_auth` — Number of model endpoints that authenticate callers with a key (auth mode Key) rather than an Azure ML or Entra ID token
- `endpoints_public` — Number of model endpoints reachable from the public network: online endpoints whose public network access isn't Disabled (unset means on), and every serverless endpoint, which has no public network access setting
- `endpoints_public_with_key_auth` — Number of model endpoints that are both public and use key authentication, so anyone holding the key can call the model from anywhere
- `workspaces_endpoints_unknown` — Number of workspaces whose online or serverless endpoints couldn't be read

**Is workspace compute exposed?**
- `total_computes` — Number of compute resources across all workspaces whose compute could be read
- `computes_public_ip` — Number of compute resources whose nodes get a public IP address (enableNodePublicIp true, or unset on an AmlCompute cluster, where it defaults to true)
- `computes_ssh_public` — Number of compute resources with public SSH access: a compute instance's sshPublicAccess or an AmlCompute cluster's remoteLoginPortPublicAccess is Enabled
- `workspaces_computes_unknown` — Number of workspaces whose compute couldn't be read

**Do connections to other services keep stored secrets?**
- `total_connections` — Number of connection listings across all workspaces, including each project's repeat of a connection it inherits from its hub
- `connections_using_stored_secrets` — Number of connection listings whose auth type keeps a credential in the connection (API key, custom keys, personal access token, username and password, access key, SAS, account key, service principal or OAuth2), as opposed to Entra ID or managed identity types
- `connections_unauthenticated` — Number of connection listings with auth type None (no authentication to the target service)
- `connections_auth_type_unrecognized` — Number of connection listings whose auth type the fetcher doesn't recognise, so whether they keep a secret is unknown
- `connections_shared_to_all` — Number of connection listings shared with every user of the workspace (isSharedToAll true)
- `distinct_connections` — Number of distinct connections: every connection listing except a project's repeat of its hub's connection (repeats_hub_connection is true when the project's hub is in the subscription and has a connection with the same name), so each hub's connections and each project's own are counted once, and two hubs with identical connections count as two
- `distinct_connections_using_stored_secrets` — Number of distinct connections whose auth type keeps a credential in the connection
- `workspaces_connections_unknown` — Number of workspaces whose connections couldn't be read


### azure_ai_services_configuration
Short Description: Shows how each AI services account and AI Search service is reached, signed into, encrypted and logged, and which models, content filters and outbound connections Foundry uses.

Script: fetchers/azure/ai_services_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.CognitiveServices — tells an unregistered provider apart from no accounts
- `accounts.list()` — AI services accounts with their network, key, encryption and identity settings
- `deployments.list()` (per Foundry or OpenAI account) — model deployments, publishers and content filter policy names
- `rai_policies.list()` (per Foundry or OpenAI account) — content filter policies and their filters
- `projects.list()` (per Foundry or OpenAI account) — Foundry projects
- `GET {account}/connections` and `GET {project}/connections` (per account and project) — connections agents use to reach other systems, and how they sign in
- `GET Microsoft.Search/searchServices` — AI Search services with their network, key and encryption settings
- `diagnostic_settings.list()` (per account and search service) — whether audit logs are sent anywhere

Output: `azure_ai_services_configuration_<subscription>.json` — each AI services account with its network, sign-in, encryption and logging settings, its model deployments, content filter policies, projects and connections, and each AI Search service with the same settings.

Summary fields:

**What was checked?**
- `total_accounts` — Number of AI services accounts in the subscription
- `accounts_by_kind` — Number of AI services accounts of each kind, one key per kind present as Azure reports it, for example:
  - AIServices (Azure AI Foundry)
  - OpenAI (Azure OpenAI)
  - other kinds such as TextAnalytics, SpeechServices or FormRecognizer
- `total_search_services` — Number of AI Search services in the subscription
- `provider_registration_status` — Whether Microsoft.CognitiveServices is registered on the subscription: registered, not_registered or unknown

**Can the AI endpoints be reached from the internet?**
- `accounts_open_to_all_networks` — Number of accounts that are open (public network access isn't disabled and the network rules don't default to deny; Azure treats unset values as open)
- `accounts_network_restricted` — Number of accounts that are restricted (public network access is on, but the network rules default to deny, so only listed IP ranges and virtual networks get in)
- `accounts_private_only` — Number of accounts with public network access disabled, reachable only through a private endpoint
- `accounts_with_private_endpoints` — Number of accounts with at least one private endpoint connection
- `accounts_with_private_endpoint_but_public_access` — Number of accounts with a private endpoint that are still open or restricted rather than private only
- `accounts_with_outbound_restricted` — Number of accounts set to restrict outbound network access to an allowed list of host names
- `search_services_open_to_all_networks` — Number of AI Search services with public network access on and no IP rules

**Do callers have to sign in with Microsoft Entra ID?**
- `accounts_with_api_keys_enabled` — Number of accounts where API keys still work (local authentication isn't disabled; it is on by default)
- `accounts_entra_only` — Number of accounts with API keys disabled, so every caller must sign in with Microsoft Entra ID
- `accounts_entra_only_percentage` — Percentage of accounts that accept only Microsoft Entra ID sign-in = `accounts_entra_only` / `total_accounts` × 100 (a whole number, 0–100); 0 when `total_accounts` is 0
- `accounts_without_managed_identity` — Number of accounts with no managed identity (system- or user-assigned) to sign in to other Azure services with
- `search_services_with_api_keys_enabled` — Number of AI Search services where API keys still work

**Is AI data encrypted with the organisation's own key?**
- `accounts_with_customer_managed_key` — Number of accounts encrypted with a customer-managed key (key source set to anything other than Microsoft-managed)
- `search_services_cmk_enforced` — Number of AI Search services with customer-managed key enforcement enabled

**Are audit logs exported?**
- `accounts_with_diagnostic_settings` — Number of accounts with at least one diagnostic setting
- `accounts_audit_logs_exported` — Number of accounts with audit logs exported (a diagnostic setting that has a destination enables the Audit category or the audit or allLogs category group)
- `accounts_audit_logs_unknown` — Number of accounts whose diagnostic settings couldn't be read, so whether audit logs are exported is unknown
- `search_services_audit_logs_exported` — Number of AI Search services with audit logs exported

**Which models are deployed, and where may they process data?**
- `total_deployments` — Number of model deployments across Foundry and OpenAI accounts whose deployments could be read
- `deployments_global_processing` — Number of model deployments of a Global type, which may process data in any Azure region
- `deployments_data_zone_processing` — Number of model deployments of a DataZone type, which process data within one geography
- `deployments_regional_processing` — Number of model deployments of a regional type (Standard, ProvisionedManaged or Batch), which process data in the account's region
- `deployments_processing_scope_unknown` — Number of model deployments whose type doesn't say where they process data
- `deployments_third_party_publisher` — Number of model deployments whose model comes from a publisher other than OpenAI or Microsoft
- `deployments_by_model_publisher` — Number of model deployments for each model publisher, one key per publisher present (for example OpenAI, Microsoft or a third party), plus:
  - unknown (the deployment names no publisher)
- `deployments_with_automatic_version_upgrade` — Number of model deployments set to move to a new model version automatically (when a new default version is available, or when the current one expires)

**Are model deployments protected by content filters?**
- `deployments_content_filter_blocking` — Number of model deployments whose content filter policy has the hate, sexual, violence and self-harm filters all present, enabled and blocking
- `deployments_content_filter_non_blocking` — Number of model deployments whose content filter policy leaves at least one of the hate, sexual, violence and self-harm filters missing, off or annotate-only
- `deployments_content_filter_none` — Number of model deployments that name no content filter policy
- `deployments_content_filter_missing` — Number of model deployments that name a content filter policy not found on their account
- `deployments_content_filter_unknown` — Number of model deployments whose account's content filter policies couldn't be read
- `deployments_jailbreak_protection` — Number of model deployments whose content filter policy has the Prompt Shields jailbreak filter enabled and blocking
- `deployments_indirect_attack_protection` — Number of model deployments whose content filter policy has the Prompt Shields indirect-attack filter enabled and blocking (Microsoft's default policy doesn't turn this on)
- `deployments_asynchronous_filtering` — Number of model deployments whose content filter policy lets output stream before filtering finishes
- `content_filter_policies_custom` — Number of content filter policies that are custom (user-managed rather than system-managed)
- `content_filter_policies_weaker_than_default` — Number of custom content filter policies that are weaker than default: they don't block all four harm categories and jailbreaks, or set any harm filter's severity threshold to High (the threshold is the lowest severity blocked, so High blocks less than Microsoft's default of Medium)
- `content_filter_policies_weaker_unknown` — Number of custom content filter policies where it's unknown whether they are weaker than default (they block every harm category and jailbreaks, but a harm filter's severity threshold is missing or unrecognised)
- `content_filter_policies_custom_unused` — Number of custom content filter policies that no model deployment on their account uses

**What can Foundry agents connect to, and how do they sign in?**
- `total_projects` — Number of Foundry projects across Foundry and OpenAI accounts
- `total_connections` — Number of connections at account and project level; a project's connection that the account list repeats is counted once
- `connections_using_stored_secrets` — Number of connections whose sign-in type keeps a credential in the connection (API key, custom keys, PAT, username and password, access key, SAS, account key, service principal or OAuth2)
- `connections_unauthenticated` — Number of connections with sign-in type None, so they send no credential
- `connections_auth_type_unrecognized` — Number of connections whose sign-in type the fetcher doesn't recognise as stored secret or keyless (Microsoft Entra ID or managed identity)
- `connections_unknown_accounts` — Number of Foundry or OpenAI accounts whose connections (account or project level) couldn't be read
- `remote_tool_connections` — Number of connections of category RemoteTool (tools and MCP servers agents can call)
- `grounding_with_bing_connections` — Number of Grounding with Bing Search connections, which send queries to Bing outside the Azure compliance boundary


### azure_aks_cluster_configuration
Short Description: Shows whether each AKS cluster's API server is private or IP-restricted, whether it enforces RBAC and network policy, and whether it auto-upgrades and is monitored.

Script: fetchers/azure/aks_cluster_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.ContainerService")` — tells "AKS not in use" from "no clusters"
- `managed_clusters.list()` — every AKS cluster with its API server, sign-in, network, upgrade and monitoring settings and its node pools

Output: `azure_aks_cluster_configuration_<subscription>.json` — each AKS cluster's API server exposure, sign-in and authorization settings, network policy, Kubernetes versions and upgrade channels, Defender and Azure Monitor settings, and its node pools.

Summary fields:

**What was checked?**
- `total_clusters` — Number of AKS clusters in the subscription, including clusters still provisioning or in a failed state
- `total_agent_pools` — Number of node pools (agent pools) across all clusters
- `kubernetes_versions` — List of the distinct Kubernetes versions the clusters are set to run (the requested version, which an upgrade in progress may not have reached yet), sorted
- `provider_registration_status` — Whether the AKS provider (Microsoft.ContainerService) is registered on the subscription: registered, not_registered or unknown

**Is the API server kept off the internet?**
- `private_clusters` — Number of private clusters, whose API server has only a private address inside the virtual network
- `private_cluster_percentage` — Percentage of clusters that are private = `private_clusters` / `total_clusters` × 100 (a whole number, 0–100); 0 when `total_clusters` is 0
- `clusters_with_authorized_ip_ranges` — Number of clusters whose API server accepts connections only from a list of authorized IP ranges
- `api_server_access_restricted_clusters` — Number of clusters with restricted API server access: a private cluster, or a public one with authorized IP ranges set
- `api_server_access_restricted_percentage` — Percentage of clusters with restricted API server access = `api_server_access_restricted_clusters` / `total_clusters` × 100 (a whole number, 0–100); 0 when `total_clusters` is 0
- `clusters_with_public_node_ips` — Number of clusters with at least one node pool that gives its nodes public IP addresses

**Who can sign in, and what can they do?**
- `rbac_enabled_clusters` — Number of clusters with Kubernetes role-based access control (RBAC) turned on
- `azure_rbac_enabled_clusters` — Number of clusters that authorize Kubernetes actions with Azure RBAC (Entra ID role assignments) instead of in-cluster role bindings alone
- `local_accounts_disabled_clusters` — Number of clusters with local accounts turned off, so the shared certificate-based admin credential can't be downloaded and every sign-in goes through Entra ID
- `workload_identity_clusters` — Number of clusters with workload identity turned on, so pods sign in to Azure as an Entra ID app or managed identity instead of with stored secrets

**Is traffic between pods restricted?**
- `network_policy_clusters` — Number of clusters with a network policy engine set (azure, calico or cilium), which lets Kubernetes network policies limit pod-to-pod traffic; any value counts, including none

**Are clusters kept up to date?**
- `auto_upgrade_clusters` — Number of clusters with an automatic upgrade channel set (patch, stable, rapid or node-image); none or no channel doesn't count

**Are clusters monitored?**
- `defender_enabled_clusters` — Number of clusters with Microsoft Defender for Containers security monitoring turned on in the cluster's security profile
- `azure_monitor_enabled_clusters` — Number of clusters sending metrics to Azure Monitor managed Prometheus; Container Insights logging isn't checked


### azure_app_service_configuration
Short Description: Shows how each App Service web app is hardened: TLS and cipher suites, basic-auth publishing, identity, access restrictions, logging, Key Vault references, runtime support and, opt-in, literal secrets.

Script: fetchers/azure/app_service_configuration/fetcher.py

Access: Reader on the subscription. Optional: `Microsoft.Web/sites/config/list/action`, used only when `scan_literal_secrets` is on to look for literal secrets (credentials typed into app settings or connection strings instead of Key Vault or App Configuration references); without it, each app's literal-secret scan reads not_authorized, the scan counts leave those apps out, and a Windows app's Node version stays unread.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Web")` — tells "App Service not in use" from "no apps"
- `web_apps.list()` — every web app's production site (function apps and deployment slots, which carry their own TLS, basic-auth and settings, are left out)
- `web_apps.get_configuration()` (per app) — TLS, FTP, runtime versions and access restrictions
- `web_apps.get_auth_settings_v2_without_secrets()` (per app) — App Service Authentication (Easy Auth)
- `web_apps.get_scm_allowed()` and `get_ftp_allowed()` (per app) — whether basic-auth publishing is allowed
- `web_apps.get_app_settings_key_vault_references()` and `get_site_connection_string_key_vault_references()` (per app) — which settings resolve from Key Vault, without reading values
- `web_apps.list_application_settings()` and `list_connection_strings()` (per app, only when `scan_literal_secrets` is on) — finds settings holding a literal secret, and a Windows app's Node version; no other value is written, and the Node version only when it is a version number
- `provider.get_web_app_stacks()` — App Service's runtime list with end-of-life dates
- `diagnostic_settings.list()` (per app) — which log categories are exported

Output: `azure_app_service_configuration_<subscription>.json` — each web app's transport, publishing, identity, network, logging, Key Vault and runtime settings, with a verdict on whether its runtimes are still supported and, when the scan is on, the names of settings holding a literal secret.

Summary fields:

**Which web apps were checked?**
- `total_web_apps` — Number of web apps checked (function apps are left out)
- `provider_registration_status` — Whether the App Service provider (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown

**Is traffic encrypted with modern TLS?**
- `https_only_apps` — Number of web apps that redirect HTTP to HTTPS
- `https_only_percentage` — Percentage of web apps that are HTTPS-only = `https_only_apps` / `total_web_apps` × 100 (a whole number, 0–100); 0 when `total_web_apps` is 0
- `minimum_tls_1_2_apps` — Number of web apps whose minimum TLS version is 1.2 or 1.3
- `scm_minimum_tls_1_2_apps` — Number of web apps whose deployment (SCM) site's minimum TLS version is 1.2 or 1.3
- `min_tls_cipher_suite_set_apps` — Number of web apps with a minimum TLS cipher suite set (without one, every suite App Service offers stays allowed)
- `cbc_cipher_suites_allowed_apps` — Number of web apps that still allow a CBC-mode cipher suite, read from App Service's fixed suite order cut at the app's minimum suite; a minimum TLS version of 1.3 allows only the two TLS 1.3 suites, and an app whose minimum suite isn't in that order isn't counted
- `non_forward_secret_cipher_suites_allowed_apps` — Number of web apps that still allow a static-RSA (TLS_RSA_*) cipher suite, which has no forward secrecy, worked out from the suite order the way `cbc_cipher_suites_allowed_apps` is
- `http2_enabled_apps` — Number of web apps with HTTP/2 switched on

**Are deployment endpoints locked down?**
- `ftp_deployment_disabled_apps` — Number of web apps with FTP and FTPS deployment switched off
- `ftp_encrypted_or_disabled_apps` — Number of web apps that allow only FTPS, or no FTP at all
- `scm_basic_auth_allowed_apps` — Number of web apps that accept a publishing user name and password (basic auth) on the deployment (SCM) site
- `ftp_basic_auth_allowed_apps` — Number of web apps that accept basic auth on the FTP endpoint
- `basic_auth_publishing_disabled_apps` — Number of web apps where basic auth is switched off on both the SCM site and FTP
- `basic_auth_publishing_unknown_apps` — Number of web apps where a policy read failed and neither read showed basic auth switched on
- `remote_debugging_enabled_apps` — Number of web apps with remote debugging switched on

**Who can call the app, and as whom does it run?**
- `auth_enabled_apps` — Number of web apps with App Service Authentication (Easy Auth) switched on
- `client_cert_required_apps` — Number of web apps that require a client certificate, using the mode the portal shows rather than the stale raw field
- `managed_identity_apps` — Number of web apps with a system- or user-assigned managed identity
- `managed_identity_percentage` — Percentage of web apps with a managed identity = `managed_identity_apps` / `total_web_apps` × 100 (a whole number, 0–100); 0 when `total_web_apps` is 0

**Is the app reachable only from where it should be?**
- `vnet_integrated_apps` — Number of web apps with outbound VNet integration
- `public_network_access_disabled_apps` — Number of web apps with public network access switched off
- `main_site_allows_all_traffic_apps` — Number of web apps whose main site's access restrictions let every caller through (rules are read in priority order, and the default action applies when no rule matches everyone)
- `scm_site_allows_all_traffic_apps` — Number of web apps whose deployment (SCM) site's access restrictions let every caller through, using the main site's rules when the SCM site inherits them
- `any_site_allows_all_traffic_apps` — Number of web apps where the main site or the SCM site lets every caller through
- `scm_uses_main_site_restrictions_apps` — Number of web apps whose SCM site uses the main site's access restrictions

**Are secrets kept in Key Vault?**
- `apps_with_key_vault_references` — Number of web apps with at least one app setting or connection string that is a Key Vault reference
- `key_vault_references` — Number of Key Vault references across all web apps' app settings and connection strings
- `unresolved_key_vault_references` — Number of Key Vault references whose status is anything other than Resolved
- `apps_with_unresolved_key_vault_references` — Number of web apps with at least one Key Vault reference that doesn't resolve

**Do any settings hold a literal secret (opt-in scan)?**
- `literal_secret_scan_enabled` — True if `scan_literal_secrets` is on; false if it is off
- `apps_scanned_for_literal_secrets` — Number of web apps whose app settings and connection strings were read; null if the scan is off
- `apps_literal_secret_scan_not_authorized` — Number of web apps whose settings could not be read because `Microsoft.Web/sites/config/list/action` is not granted; null if the scan is off
- `apps_literal_secret_scan_not_read` — Number of web apps the scan skipped without a failure: a ReadOnly lock refused config/list (409 ScopeLocked), or the app's id has no resource group; null if the scan is off
- `apps_with_literal_secrets` — Number of scanned web apps with at least one setting holding a literal secret; null if the scan is off, or if there are web apps and none could be scanned. A setting counts when it is not a Key Vault or App Configuration reference and either its value carries a credential (a key ending in Password, Pwd, AccountKey, SharedAccessKey, SharedAccessSignature, AccessKey, Secret, ApiKey or SubscriptionKey followed by = and a value other than true or false, such as ClientSecret= or DbPassword=; a SAS sig= parameter; a private key; or a password in a URL), or it is an app setting whose name contains password, passwd, secret, API key, access key, account key, private key or credential, or has the word key, token, pwd or sas, unless the name also has id, name, uri, url, endpoint, vault, version, header, enabled, path, file, lifetime, expiry, expiration or type, and whose value is a single word of 8 or more characters that is not a URL, a boolean or made wholly of key=value; pairs. Application Insights' instrumentation key and connection string never count. This is a heuristic, so 0 doesn't prove there are no literal secrets
- `literal_secret_settings` — Number of app settings and connection strings holding a literal secret across the scanned web apps; null if the scan is off, or if there are web apps and none could be scanned

**Are the runtimes still supported?**
- `apps_with_declared_runtime` — Number of web apps whose configuration names at least one language runtime version
- `apps_with_runtime_past_end_of_support` — Number of web apps with at least one declared runtime past end of support (matched by its spelling to App Service's runtime list, and marked deprecated there or past its end-of-life date). On Windows a Node app's version is the `WEBSITE_NODE_DEFAULT_VERSION` app setting, read only when `scan_literal_secrets` is on and matched to the Node stack only, as written or as ~major or major.minor; without it, the .NET Framework v4.0 every such Windows app carries reads as unknown rather than as its runtime. The portal and Visual Studio templates long added that setting to every Windows app, so it may be a stale default on a non-Node app; both runtimes are then judged
- `apps_with_runtime_support_unknown` — Number of web apps with no runtime past end of support where support is unknown: nothing declared, a custom container, a runtime not in App Service's list, a Windows app on .NET Framework v4.0 whose Node setting wasn't read, or a failed read

**Is the app logging?**
- `always_on_apps` — Number of web apps with Always On switched on
- `http_logging_enabled_apps` — Number of web apps writing web server (HTTP) logs
- `apps_with_diagnostic_settings` — Number of web apps with at least one diagnostic setting
- `apps_with_enabled_logs` — Number of web apps exporting at least one switched-on log category


### azure_app_service_deployments
Short Description: Shows how each App Service web app and slot is deployed: recorded deployments, slot swaps and publishing-credential retrievals with who and when, deployment source, and slot drift from production.

Script: fetchers/azure/app_service_deployments/fetcher.py (uses the shared helper fetchers/azure/_shared/app_service.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Web")` — tells "App Service not in use" from "no apps"
- `web_apps.list()` — every web app (function apps and other sites that aren't web apps are left out)
- `web_apps.list_deployments()` and `list_deployments_slot()` (per app and slot) — the deployments App Service (Kudu) records
- `web_apps.get_source_control()` and `get_source_control_slot()` (per app and slot) — the repository and branch it deploys from
- `web_apps.list_slots()` (per app) — its deployment slots
- `web_apps.get_configuration()` and `get_configuration_slot()` (per app with slots, and per slot) — the settings compared between each slot and production
- `activity_logs.list()` (Microsoft.Web events over the last activity_log_days, 90 by default) — slot swaps, publishing-credential retrievals and package deployments, with who requested each

Output: `azure_app_service_deployments_<subscription>.json` — each web app's and slot's recorded deployments and deployment events with who and when, its deployment source, how each slot differs from production, and what the evidence cannot attribute; each deployment event carries its Activity Log correlation id to trace it back; a Kudu author, deployer or message past 500 characters is cut and marked as truncated; all times are ISO 8601 UTC.

Summary fields:

**Which web apps and slots were checked?**
- `total_web_apps` — Number of web apps checked
- `total_deployment_slots` — Number of deployment slots across all web apps
- `apps_with_slots` — Number of web apps with at least one deployment slot
- `excluded_function_apps` — Number of function apps and other sites that aren't web apps (kind not starting with app) left out
- `provider_registration_status` — Whether the App Service provider (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown
- `activity_log_days` — Days of Activity Log requested (`activity_log_days`, 1 to 90; 90 is all the Activity Log keeps). The window is that many days back from the run; at 90 it starts an hour inside the 90-day limit, so its oldest edge is still kept when a long paged read reaches it
- `activity_log_complete` — True if every page of the window was read; false if the read failed or stopped at 200,000 events, keeping the newest (results.activity_log.oldest_event_time shows how far back the read reached)

**Where do the apps deploy from?**
- `apps_with_source_control` — Number of web apps with a source repository set up for deployment
- `apps_deploying_from_github_actions` — Number of web apps whose source is set up to deploy through GitHub Actions
- `slots_with_source_control` — Number of deployment slots with a source repository set up for deployment
- `apps_source_control_unknown` — Number of web apps whose deployment source couldn't be read
- `slots_source_control_unknown` — Number of deployment slots whose deployment source couldn't be read

**What does App Service's own deployment record (Kudu) show?**
- `apps_with_kudu_deployment_records` — Number of web apps with at least one Kudu deployment record on the app or one of its slots
- `apps_without_kudu_deployment_records` — Number of web apps with no Kudu deployment record where every read succeeded (Web Deploy, FTP, run-from-package URLs and slot swaps create none, so this is not "no deployments")
- `apps_kudu_deployment_records_unknown` — Number of web apps with no Kudu deployment record where a read failed
- `kudu_deployment_records` — Number of Kudu deployment records across all web apps and slots
- `failed_kudu_deployment_records` — Number of Kudu deployment records whose status is Failed
- `kudu_deployments_by_deployer` — Number of Kudu deployment records for each deploying tool, as App Service names it (unknown when a record names none)
- `latest_kudu_deployment_time` — Time of the newest Kudu deployment record across all web apps and slots; null if there is none

**Who released what, and when (Activity Log)?**
- `slot_swaps` — Number of slot swap requests in the window on a listed web app or slot, the events sharing one correlation id counted once per app even when logged on both the slot and production, on the site of the event that names the requester (a template deployment or pipeline run that swaps several apps under one correlation id counts once on each); null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `failed_slot_swaps` — Number of slot swap requests in the window that failed: the events naming the requester end Failed, or, when they never reach Succeeded or Failed, any event under the request's correlation id has status Failed (a platform row with no requester can reuse an unrelated correlation id, so it can't turn a request that succeeded into a failure); null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `apps_with_slot_swaps` — Number of web apps with at least one slot swap request in the window, on the app or a slot; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `latest_slot_swap_time` — Time of the newest slot swap request in the window (ISO 8601 UTC); null if there is none or the Activity Log couldn't be read
- `publish_profile_downloads` — Number of publish profile download requests (publishxml, the Web Deploy and FTP credentials Visual Studio uses) in the window on a listed web app or slot, one per correlation id; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `apps_with_publish_profile_downloads` — Number of web apps whose publish profile was downloaded in the window, for the app or a slot; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `publishing_credential_reads` — Number of requests reading a web app's or slot's publishing credentials through config/publishingcredentials/list (the Kudu and FTP user name and password that pipelines and the portal fetch) in the window on a listed web app or slot, one per correlation id; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `apps_with_publishing_credential_reads` — Number of web apps whose publishing credentials were read in the window, for the app or a slot; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `package_deployments` — Number of MSDeploy, OneDeploy or ZipDeploy deployment requests made through Azure Resource Manager in the window on a listed web app or slot, one per correlation id; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `apps_with_package_deployments` — Number of web apps with at least one package deployment through Azure Resource Manager in the window, on the app or a slot; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false
- `deployment_activity_by_caller_type` — Number of slot swap, publish profile download, publishing credential read and package deployment requests on listed web apps and slots, for each kind of requester (null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false):
  - user (a person: the token's identity type is user, or the caller is a user name containing @)
  - app (a service principal or managed identity: the token's identity type is app)
  - unknown (the log names neither)
- `deployment_activity_on_unlisted_sites` — Number of slot swap, publish profile download, publishing credential read and package deployment requests on a site this run didn't list (a deleted app or slot, a function app or other site that isn't a web app, or a slot whose list couldn't be read), counted here instead of on an app; null if the Activity Log couldn't be read, a lower bound if `activity_log_complete` is false

**Is there any trace of how each app is deployed?**
- `apps_with_deployment_evidence` — Number of web apps with deployment evidence: a Kudu deployment record, slot swap, publish profile download, publishing credential read or package deployment on the app or a slot. When the Activity Log couldn't be read, only Kudu records count
- `apps_without_deployment_evidence` — Number of web apps with no deployment evidence on the app or any slot, where the slot list and every Kudu read succeeded; null if the Activity Log window wasn't read in full (the read failed or stopped at 200,000 events)
- `apps_deployment_evidence_unknown` — Number of web apps with no deployment evidence found where it can't be ruled out: a slot list or Kudu read failed, or the Activity Log window wasn't read in full. With `apps_with_deployment_evidence` and `apps_without_deployment_evidence` it adds up to `total_web_apps` (counting a null as 0)

**Do the slots match production?**
- `slots_matching_production` — Number of deployment slots whose compared settings all match production. Compared: minimum TLS version and cipher suite, the SCM (deployment) site's minimum TLS version, FTPS state, HTTP/2, remote debugging, runtime versions, the main and SCM sites' access restrictions (rules in priority order, names ignored, and default actions), whether SCM uses the main site's rules, HTTPS-only, client certificates and public network access. Microsoft lists runtime versions as swapped; HTTPS-only, TLS, client certificates and access restrictions stay with the slot, so a match is posture parity between slot and production, and a slot locked down differently on purpose reads as differing. An unset FTPS state reads as AllAllowed (Microsoft: "No configuration is necessary to enable FTP or FTPS app deployment", learn.microsoft.com/azure/app-service/deploy-ftp), and an unset default action as what App Service applies (Allow with no rules of the site's own, Deny with one), so neither differs from that value set explicitly. An unset public network access differs from an explicit Enabled, since with a private endpoint unset can mean disabled
- `slots_differing_from_production` — Number of deployment slots with at least one compared setting that differs from production
- `slots_comparison_unknown` — Number of deployment slots not compared because the slot's or production's settings couldn't be read


### azure_app_service_plans
Short Description: Shows whether each App Service plan, and the web and function apps on it, would survive losing an instance or an availability zone.

Script: fetchers/azure/app_service_plans/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Web")` — tells "App Service not in use" from "no plans"
- `app_service_plans.list()` — every plan with its tier, instance count, zone redundancy and scaling settings
- `web_apps.list()` — every web app and function app, matched to the plan it runs on

Output: `azure_app_service_plans_<subscription>.json` — each App Service plan with its pricing tier, instance count, zone redundancy and scaling settings, and the web and function apps running on it.

Summary fields:

**What was checked?**
- `total_app_service_plans` — Number of App Service plans in the subscription
- `empty_plans` — Number of plans with no web app or function app on them
- `total_sites` — Number of web apps and function apps running on the subscription's plans
- `provider_registration_status` — Whether the App Service provider (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown

**Does each plan carry an uptime SLA?**
- `no_sla_tier_plans` — Number of plans on the Free or Shared tier, which run on shared infrastructure with no uptime SLA

**Does each plan survive losing an instance?**
- `multi_instance_plans` — Number of plans with more than one provisioned instance (the instance count set on the plan's SKU)
- `single_instance_plans` — Number of plans with a fixed instance count of 1 or less, or none reported, where losing that instance is an outage; platform-scaled plans are left out
- `platform_scaled_plans` — Number of platform-scaled plans (Consumption, Flex Consumption or Elastic Premium tier), where Azure adds and removes instances itself, so the instance count isn't a fixed number
- `sites_on_multi_instance_plans` — Number of web apps and function apps on a plan with more than one provisioned instance

**Does each plan survive losing an availability zone?**
- `zone_redundant_plans` — Number of plans that are zone redundant, spreading their instances across availability zones
- `zone_redundant_percentage` — Percentage of plans that are zone redundant = `zone_redundant_plans` / `total_app_service_plans` × 100 (a whole number, 0–100); 0 when `total_app_service_plans` is 0. Free, Shared, Basic and Standard plans can't be zone redundant, so 100 may be impossible
- `sites_on_zone_redundant_plans` — Number of web apps and function apps on a zone-redundant plan


### azure_container_registry_configuration
Short Description: Shows whether each container registry blocks the shared admin account and anonymous pulls, is reachable only privately, and sends its audit logs somewhere.

Script: fetchers/azure/container_registry_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.ContainerRegistry")` — tells "Container Registry not in use" from "no registries"
- `registries.list()` — every registry with its sign-in, network, encryption and image policy settings
- `diagnostic_settings.list()` (per registry) — where the registry sends its logs

Output: `azure_container_registry_configuration_<subscription>.json` — each container registry's admin account and anonymous pull settings, network access and private endpoints, encryption, content trust, quarantine and retention policies, and the diagnostic settings that send its logs.

Summary fields:

**What was checked?**
- `total_registries` — Number of container registries in the subscription
- `premium_sku_registries` — Number of registries on the Premium tier, the only tier that supports private endpoints, network rules, customer-managed keys and content trust
- `provider_registration_status` — Whether the Container Registry provider (Microsoft.ContainerRegistry) is registered on the subscription: registered, not_registered or unknown

**Who can pull and push images?**
- `admin_user_enabled_registries` — Number of registries with the shared admin account enabled: one username and password that bypasses Entra ID, so pulls and pushes through it can't be traced to a person
- `admin_user_disabled_percentage` — Percentage of registries with the admin account disabled = (`total_registries` − `admin_user_enabled_registries`) / `total_registries` × 100 (a whole number, 0–100); 0 when `total_registries` is 0
- `anonymous_pull_enabled_registries` — Number of registries that let anyone pull images without signing in

**Is each registry reachable only privately?**
- `public_network_access_registries` — Number of registries with public network access not Disabled (Enabled, or not returned, which Azure treats as Enabled)
- `private_network_access_registries` — Number of registries with public network access Disabled
- `private_network_access_percentage` — Percentage of registries with public network access Disabled = `private_network_access_registries` / `total_registries` × 100 (a whole number, 0–100); 0 when `total_registries` is 0. Only Premium registries can turn public access off, so 100 may be impossible
- `network_rules_default_deny_registries` — Number of registries whose network rules deny by default, so only the listed IP ranges can reach the public endpoint
- `private_link_registries` — Number of registries with at least one private endpoint connection, in any approval state (pending and rejected connections count too)

**Are images and stored data protected?**
- `customer_managed_key_registries` — Number of registries encrypted with a customer-managed key
- `content_trust_registries` — Number of registries with content trust enabled, so signed images can be required
- `quarantine_policy_registries` — Number of registries with the quarantine policy enabled, which holds new images back until a scanner marks them safe
- `retention_policy_registries` — Number of registries with a retention policy enabled, which deletes untagged manifests after a set number of days

**Are registry audit logs kept?**
- `registries_with_diagnostic_settings` — Number of registries with at least one diagnostic setting
- `registries_with_enabled_logs` — Number of registries with at least one diagnostic setting that has a log category turned on (such as login and repository events); a setting with every log category off doesn't count


### azure_container_workloads_configuration
Short Description: Shows whether Container Apps and Container Instances are exposed to the internet, require sign-in, keep secrets out of their configuration, pin their images and export their logs.

Script: fetchers/azure/container_workloads_configuration/fetcher.py (shared helper: _shared/diagnostics.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.App and Microsoft.ContainerInstance — reports whether each provider is registered
- `managed_environments.list_by_subscription()` — Container Apps environments with their network, encryption and log settings
- `container_apps.list_by_subscription()` — Container Apps with their ingress, secrets, registries and containers
- `container_apps_auth_configs.list_by_container_app()` (per app) — the app's built-in authentication (Easy Auth) settings
- `jobs.list_by_subscription()` — Container Apps jobs with their secrets, registries and containers
- `container_groups.list()` — Container Instances groups with their IP address, registry credentials, volumes and containers
- `diagnostic_settings.list()` (per environment and container group) — whether logs are exported

Output: `azure_container_workloads_configuration_<subscription>.json` — each Container Apps environment, app and job and each container group with its exposure, authentication, secret handling, images and log export.

Summary fields:

**What was checked?**
- `total_environments` — Number of Container Apps environments
- `total_container_apps` — Number of Container Apps
- `total_jobs` — Number of Container Apps jobs
- `total_container_groups` — Number of Container Instances container groups
- `total_containers` — Number of containers, including init containers, across all Container Apps, jobs and container groups
- `provider_registration_status_container_apps` — Whether Microsoft.App is registered on the subscription: registered, not_registered or unknown
- `provider_registration_status_container_instances` — Whether Microsoft.ContainerInstance is registered on the subscription: registered, not_registered or unknown

**Are Container Apps environments isolated and encrypted?**
- `environments_internal_only` — Number of environments whose network exposure is internal: the environment's virtual network configuration is internal, so it has no public endpoint
- `environments_private` — Number of environments whose network exposure is private: not internal, but public network access is Disabled
- `environments_public` — Number of environments whose network exposure is public: not internal and public network access is on (Azure treats unset as on)
- `environments_without_vnet` — Number of environments not placed in a virtual network subnet of the customer's
- `environments_mtls_enabled` — Number of environments with mutual TLS between apps turned on (off by default)
- `environments_peer_traffic_encryption_enabled` — Number of environments that encrypt traffic between apps inside the environment (off by default)
- `environments_zone_redundant` — Number of environments spread across availability zones

**Are Container Apps environment logs exported?**
- `environments_without_log_destination` — Number of environments whose app log destination is none or unset
- `environments_audit_logs_exported` — Number of environments with logs exported: the app log destination is log-analytics (the environment sends logs to the workspace itself), or it is azure-monitor and a diagnostic setting that sends to a destination enables ContainerAppSystemLogs, ContainerAppConsoleLogs or the audit or allLogs category group
- `environments_audit_logs_unknown` — Number of environments whose app log destination is azure-monitor and whose diagnostic settings couldn't be read

**Are Container Apps open to the internet without sign-in?**
- `container_apps_internet_facing` — Number of internet-facing Container Apps: ingress is external and the app's environment isn't internal-only (an environment missing from the subscription's list counts as not internal-only)
- `container_apps_allow_insecure` — Number of Container Apps whose ingress also accepts plain HTTP
- `container_apps_without_ip_restrictions` — Number of internet-facing Container Apps with no client IP restriction rules on their ingress
- `container_apps_internet_facing_without_auth` — Number of internet-facing Container Apps where sign-in isn't required, so the container itself must authenticate callers. Sign-in is required (auth_required) when Easy Auth is on and redirects or rejects callers who aren't signed in (RedirectToLoginPage, Return401 or Return403); it isn't when Easy Auth is off or set to AllowAnonymous, which lets every caller through
- `container_apps_allow_anonymous` — Number of Container Apps with Easy Auth on but set to AllowAnonymous, so it doesn't stop callers who aren't signed in
- `container_apps_auth_unknown` — Number of Container Apps where it's unknown whether sign-in is required: the auth settings couldn't be read, or Easy Auth is on with no action set for callers who aren't signed in

**Do apps and jobs keep secrets out of their configuration?**
- `workloads_with_secrets_stored_in_app` — Number of Container Apps and jobs with at least one secret held in the app's own configuration rather than as a Key Vault reference
- `workloads_registries_password_based` — Number of Container Apps and jobs that pull images from at least one registry with a password secret instead of a managed identity
- `workloads_plain_env_vars_with_secret_like_names` — Number of Container Apps and jobs with at least one environment variable set as a plain value (not a secret reference) whose name contains secret, password, passwd, pwd, apikey, token, connectionstring, connstr, accesskey, privatekey, credential, sastoken or clientsecret; a name match means review it, not that a secret is confirmed
- `workloads_without_managed_identity` — Number of Container Apps and jobs with no managed identity (identity type None or unset)

**Are container images pinned to a known source?**
- `containers_with_mutable_image_tag` — Number of containers whose image has no tag or the tag latest and no digest, so what runs can change without a deployment
- `containers_image_pinned_by_digest` — Number of containers whose image is pinned by an @sha256 digest
- `image_registries` — List of every registry host images are pulled from (the first part of the image name when it looks like a host, otherwise `docker.io`), for comparison with an approved list; the fetcher doesn't judge registries

**Are Container Instances exposed or holding secrets?**
- `container_groups_public_ip` — Number of container groups with a public IP address
- `container_groups_in_vnet` — Number of container groups that run in a virtual network subnet
- `container_groups_registries_password_based` — Number of container groups with at least one image registry credential that has a username and no managed identity
- `container_groups_plain_env_vars_with_secret_like_names` — Number of container groups with at least one environment variable set as a plain value rather than a secure value whose name contains secret, password, passwd, pwd, apikey, token, connectionstring, connstr, accesskey, privatekey, credential, sastoken or clientsecret
- `container_groups_without_managed_identity` — Number of container groups with no managed identity (identity type None or unset)
- `container_groups_customer_managed_key` — Number of container groups with encryption properties set (a customer-managed key)
- `container_groups_confidential_compute` — Number of container groups with a confidential compute policy set
- `container_groups_azure_file_volumes` — Number of container groups with at least one Azure Files volume, whose storage account key is stored in the container group definition

**Are Container Instances logs exported?**
- `container_groups_logs_exported` — Number of container groups with logs exported: a diagnostic setting that sends to a destination enables ContainerInstanceLog, ContainerEvent or the audit or allLogs category group
- `container_groups_logs_unknown` — Number of container groups whose diagnostic settings couldn't be read


### azure_databricks_workspace_configuration
Short Description: Shows whether each Databricks workspace blocks public access, runs clusters without public IPs in its own virtual network, and encrypts managed disks with a customer-managed key.

Script: fetchers/azure/databricks_workspace_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Databricks — tells “not registered” apart from “no workspaces”
- `workspaces.list_by_subscription()` — every workspace with its SKU, network settings and managed-disk encryption (no call is made into the workspaces themselves)

Output: `azure_databricks_workspace_configuration_<subscription>.json` — each Databricks workspace with its SKU, public network access, secure cluster connectivity, virtual network and the key that encrypts its managed disks.

Summary fields:

**What was checked?**
- `total_workspaces` — Number of Azure Databricks workspaces in the subscription
- `premium_sku_workspaces` — Number of workspaces on the Premium SKU, the tier needed for private connectivity and customer-managed keys
- `provider_registration_status` — Whether Microsoft.Databricks is registered on the subscription: registered, not_registered or unknown

**Is the workspace cut off from the public internet?**
- `public_network_access_disabled_workspaces` — Number of workspaces with public network access Disabled, so the workspace UI and API are reached only through private endpoints
- `publicly_accessible_workspaces` — Number of workspaces whose public network access is Enabled or not returned
- `no_public_ip_workspaces` — Number of workspaces with secure cluster connectivity (no public IP) on, so cluster nodes get no public IP addresses; a setting Azure didn't return counts as off
- `vnet_injected_workspaces` — Number of workspaces deployed into a customer-managed virtual network (VNet injection) instead of one Azure manages
- `network_isolated_workspaces` — Number of workspaces that are network isolated: public network access Disabled and secure cluster connectivity on (VNet injection isn't required)
- `network_isolated_percentage` — Percentage of workspaces that are network isolated = `network_isolated_workspaces` / `total_workspaces` × 100 (a whole number, 0–100); 0 when `total_workspaces` is 0

**Are managed disks encrypted with a customer-managed key?**
- `customer_managed_key_workspaces` — Number of workspaces whose cluster managed disks are encrypted with a customer-managed key (a Key Vault URI is set, or the key source is Microsoft.Keyvault); the disks are always encrypted, so what varies is whose key
- `platform_managed_key_workspaces` — Number of workspaces whose managed disks use the Microsoft-managed key
- `cmk_percentage` — Percentage of workspaces whose managed disks use a customer-managed key = `customer_managed_key_workspaces` / `total_workspaces` × 100 (a whole number, 0–100); 0 when `total_workspaces` is 0
- `key_rotation_enabled_workspaces` — Number of workspaces set to move their managed disks to the newest key version automatically; a setting Azure didn't return counts as off


### azure_function_app_configuration
Short Description: Shows whether each function app enforces HTTPS and TLS 1.2 or later, blocks public network access, uses a managed identity, and sends telemetry to Application Insights.

Script: fetchers/azure/function_app_configuration/fetcher.py

Access: Reader on the subscription. Optional: Microsoft.Web/sites/host/listkeys/action and Microsoft.Web/sites/config/list/Action; without them, each app's access keys and app settings read not_authorized.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Web")` — tells "App Service not in use" from "no function apps"
- `web_apps.list()` — every site, keeping function apps with their HTTPS, public access, VNet and identity settings
- `web_apps.get_configuration()` (per app) — runtime, TLS, FTP and remote debugging settings
- `web_apps.list_host_keys()` (per app) — the names of its access keys (key values are dropped)
- `web_apps.list_application_settings()` (per app) — the names of its app settings (values are dropped)

Output: `azure_function_app_configuration_<subscription>.json` — each function app's network exposure, HTTPS, TLS and FTP settings, runtime, managed identity, and the names (never the values) of its access keys and app settings.

Summary fields:

**What was checked?**
- `total_function_apps` — Number of function apps in the subscription (sites whose kind starts with functionapp; web apps are left out)
- `provider_registration_status` — Whether the App Service provider (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown

**Is each app reachable only privately?**
- `publicly_accessible_apps` — Number of function apps with public network access not Disabled (Enabled, or not returned, which Azure treats as Enabled)
- `public_network_access_disabled_apps` — Number of function apps with public network access Disabled
- `vnet_integrated_apps` — Number of function apps connected to a virtual network subnet for their outbound traffic (VNet integration)

**Is traffic to each app encrypted?**
- `https_only_apps` — Number of function apps with HTTPS only on, so plain HTTP requests are redirected to HTTPS
- `https_only_percentage` — Percentage of function apps with HTTPS only on = `https_only_apps` / `total_function_apps` × 100 (a whole number, 0–100); 0 when `total_function_apps` is 0
- `minimum_tls_1_2_apps` — Number of function apps whose minimum TLS version is 1.2 or 1.3; an app whose configuration couldn't be read doesn't count
- `ftp_deployment_disabled_apps` — Number of function apps with FTP deployment Disabled, so neither FTP nor FTPS is accepted
- `ftp_encrypted_or_disabled_apps` — Number of function apps whose FTP state is FtpsOnly or Disabled, so unencrypted FTP is refused
- `remote_debugging_enabled_apps` — Number of function apps with remote debugging turned on

**How do apps sign in, and are their keys readable?**
- `managed_identity_apps` — Number of function apps with a managed identity (system-assigned, user-assigned or both)
- `managed_identity_percentage` — Percentage of function apps with a managed identity = `managed_identity_apps` / `total_function_apps` × 100 (a whole number, 0–100); 0 when `total_function_apps` is 0
- `access_keys_configured_apps` — Number of function apps with at least one host-level function key (Azure creates one named default on new apps); an app whose keys couldn't be read doesn't count
- `access_keys_not_authorized_apps` — Number of function apps whose access keys couldn't be read because the run lacks Microsoft.Web/sites/host/listkeys/action or a read-only resource lock blocks the call

**Is each app's runtime declared and monitoring set up?**
- `apps_with_declared_runtime` — Number of function apps whose configuration names a runtime stack (a Linux runtime, a Windows runtime or a .NET Framework version)
- `functions_extension_version_configured_apps` — Number of function apps with the FUNCTIONS_EXTENSION_VERSION app setting, which pins the Functions host version (its value isn't recorded)
- `application_insights_configured_apps` — Number of function apps with an Application Insights app setting (APPINSIGHTS_INSTRUMENTATIONKEY or APPLICATIONINSIGHTS_CONNECTION_STRING), so they send telemetry to Application Insights
- `application_settings_not_authorized_apps` — Number of function apps whose app settings couldn't be read because the run lacks Microsoft.Web/sites/config/list/Action or a read-only resource lock blocks the call


## Data, keys and encryption

### azure_cosmosdb_configuration
Short Description: Shows whether each Cosmos DB account uses a customer-managed key, Entra-only sign-in, private network access and TLS 1.2, and can fail over and restore to a point in time.

Script: fetchers/azure/cosmosdb_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.DocumentDB — tells “not registered” apart from “no accounts”
- `database_accounts.list()` — every Cosmos DB account with its encryption key, sign-in, network, TLS, failover and backup settings (account keys are never requested)

Output: `azure_cosmosdb_configuration_<subscription>.json` — each Cosmos DB account with its API kind, encryption key, sign-in setting, network exposure (virtual network and IP allow-lists, private endpoints), minimum TLS version, failover settings and backup policy.

Summary fields:

**What was checked?**
- `total_cosmosdb_accounts` — Number of Cosmos DB accounts in the subscription
- `accounts_by_kind` — Number of accounts of each API kind Azure reports; a kind with no accounts is left out:
  - GlobalDocumentDB (the NoSQL API; Table, Cassandra and Gremlin accounts also report this kind)
  - MongoDB (the API for MongoDB)
  - Parse (the Parse Server kind)
  - unknown (no kind returned)
- `provider_registration_status` — Whether Microsoft.DocumentDB is registered on the subscription: registered, not_registered or unknown

**Is data encrypted with a customer-managed key?**
- `customer_managed_key_accounts` — Number of accounts encrypted with a customer-managed key (a Key Vault key URI is set); Cosmos DB always encrypts data at rest, so what varies is whose key
- `platform_managed_key_accounts` — Number of accounts encrypted with the Microsoft-managed key (no Key Vault key URI)
- `cmk_percentage` — Percentage of accounts encrypted with a customer-managed key = `customer_managed_key_accounts` / `total_cosmosdb_accounts` × 100 (a whole number, 0–100); 0 when `total_cosmosdb_accounts` is 0

**Is sign-in limited to Entra ID?**
- `local_auth_disabled_accounts` — Number of accounts with key-based (local) authentication disabled, so data can be reached only with Microsoft Entra ID sign-in and role assignments; a setting Azure didn't return counts as enabled

**Is the account kept off the public internet?**
- `public_network_access_disabled_accounts` — Number of accounts with public network access Disabled or SecuredByPerimeter (behind a Network Security Perimeter)
- `virtual_network_filter_accounts` — Number of accounts with the virtual network firewall on, so only the listed virtual networks and IP ranges can connect; a setting Azure didn't return counts as off
- `private_endpoint_accounts` — Number of accounts with at least one private endpoint connection, in any state

**Do connections use TLS 1.2 or later?**
- `recommended_minimal_tls_accounts` — Number of accounts whose minimum TLS version is 1.2 or 1.3 (no setting means TLS 1.0 is accepted, so it doesn't count)

**Will the account survive a region loss and restore to a point in time?**
- `automatic_failover_accounts` — Number of accounts with automatic (service-managed) failover to another region on; a setting Azure didn't return counts as off
- `multiple_write_location_accounts` — Number of accounts that accept writes in more than one region; a setting Azure didn't return counts as off
- `continuous_backup_accounts` — Number of accounts on the Continuous backup policy, which can restore to any point in time; accounts on Periodic backup (scheduled snapshots) or with no policy returned don't count


### azure_data_services_configuration
Short Description: Shows whether MongoDB vCore clusters, Data Explorer clusters and Event Hubs namespaces limit network access, avoid shared keys, restrict admin rights, use customer-managed keys and export audit logs.

Script: fetchers/azure/data_services_configuration/fetcher.py (shared helpers: _shared/ip_ranges.py, _shared/diagnostics.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.DocumentDB, Microsoft.Kusto and Microsoft.EventHub — reports whether each provider is registered
- `mongo_clusters.list()` — MongoDB vCore clusters with their public access, authentication, high availability and encryption settings
- `firewall_rules.list_by_mongo_cluster()` (per cluster) — the IP ranges each cluster's firewall admits
- `clusters.list()` — Data Explorer clusters with their network, encryption and tenant trust settings
- `cluster_principal_assignments.list()` (per cluster) — who holds which role on the cluster
- `databases.list_by_cluster()` and `database_principal_assignments.list()` (per cluster and database) — databases, their retention and who holds which role on each
- `clusters.list_callout_policies()` (per cluster) — which external services queries may call out to
- `namespaces.list()` — Event Hubs namespaces with their TLS, local authentication, redundancy and encryption settings
- `namespaces.get_network_rule_set()` (per namespace) — the namespace's default network action and IP and virtual network rules
- `namespaces.list_authorization_rules()` (per namespace) — shared access policies and their rights
- `event_hubs.list_by_namespace()` and `event_hubs.list_authorization_rules()` (per namespace and event hub) — event hubs with their retention and capture, and each hub's shared access policies
- `diagnostic_settings.list()` (per cluster and namespace) — whether audit logs are exported

Output: `azure_data_services_configuration_<subscription>.json` — each MongoDB vCore cluster, Data Explorer cluster and Event Hubs namespace with its network access, authentication, access rights, encryption and audit log export.

Summary fields:

**What was checked?**
- `total_mongo_clusters` — Number of Azure DocumentDB (MongoDB vCore) clusters
- `total_data_explorer_clusters` — Number of Azure Data Explorer clusters
- `total_event_hub_namespaces` — Number of Event Hubs namespaces
- `total_event_hubs` — Number of event hubs across all namespaces whose event hubs could be read
- `provider_registration_status_mongo_clusters` — Whether Microsoft.DocumentDB is registered on the subscription: registered, not_registered or unknown
- `provider_registration_status_data_explorer` — Whether Microsoft.Kusto is registered on the subscription: registered, not_registered or unknown
- `provider_registration_status_event_hubs` — Whether Microsoft.EventHub is registered on the subscription: registered, not_registered or unknown

**Can MongoDB clusters be reached from the internet?**
- `mongo_clusters_public_access_disabled` — Number of MongoDB clusters whose public access is disabled (public network access is Disabled). Otherwise public access is judged on the distinct IPv4 addresses all firewall rules admit together, overlaps merged and the 0.0.0.0–0.0.0.0 "allow Azure services" rule left out: allow_all, broad, restricted, or no_rules when there are no rules (nothing public can connect; not counted in the summary)
- `mongo_clusters_firewall_allow_all` — Number of MongoDB clusters whose public access is allow_all: the firewall rules together admit every IPv4 address, even when split across several ranges
- `mongo_clusters_firewall_broad` — Number of MongoDB clusters whose public access is broad: the firewall rules together admit more addresses than a /8 (16,777,216) but not every IPv4 address
- `mongo_clusters_firewall_restricted` — Number of MongoDB clusters whose public access is restricted: the firewall rules together admit a /8 or fewer addresses
- `mongo_clusters_public_access_unknown` — Number of MongoDB clusters whose firewall rules couldn't be read
- `mongo_clusters_with_private_endpoints` — Number of MongoDB clusters with at least one private endpoint connection

**Are MongoDB clusters configured securely?**
- `mongo_clusters_native_auth_enabled` — Number of MongoDB clusters that allow native username and password sign-in
- `mongo_clusters_entra_auth_enabled` — Number of MongoDB clusters that allow Microsoft Entra ID sign-in
- `mongo_clusters_high_availability_enabled` — Number of MongoDB clusters with a high availability mode other than Disabled
- `mongo_clusters_customer_managed_key` — Number of MongoDB clusters encrypted with a customer-managed key
- `mongo_clusters_data_api_enabled` — Number of MongoDB clusters with the Data API (HTTP access to the cluster) turned on
- `mongo_clusters_audit_logs_exported` — Number of MongoDB clusters with audit logs exported: a diagnostic setting that sends to a destination (storage account, Log Analytics, event hub or partner solution) enables vCoreMongoRequests or the audit or allLogs category group
- `mongo_clusters_audit_logs_unknown` — Number of MongoDB clusters whose diagnostic settings couldn't be read

**Can Data Explorer clusters be reached, and what can they reach?**
- `data_explorer_clusters_open_to_all_networks` — Number of Data Explorer clusters whose network exposure is open: public network access is on and no allowed IP range is set
- `data_explorer_clusters_network_restricted` — Number of Data Explorer clusters whose network exposure is restricted: public network access is on but allowed IP ranges limit who can connect
- `data_explorer_clusters_private_only` — Number of Data Explorer clusters whose network exposure is private: public network access is Disabled
- `data_explorer_clusters_vnet_injected` — Number of Data Explorer clusters deployed into a virtual network
- `data_explorer_clusters_outbound_restricted` — Number of Data Explorer clusters with outbound network access restricted (restrictOutboundNetworkAccess Enabled)
- `data_explorer_callout_policies_allowed` — Number of callout policies, across all Data Explorer clusters, that allow queries to call out to an external service (SQL, web APIs, storage)
- `data_explorer_clusters_callout_policies_unknown` — Number of Data Explorer clusters whose callout policies couldn't be read

**Is Data Explorer data protected?**
- `data_explorer_clusters_disk_encryption_enabled` — Number of Data Explorer clusters with disk encryption turned on
- `data_explorer_clusters_double_encryption_enabled` — Number of Data Explorer clusters with double encryption turned on
- `data_explorer_clusters_customer_managed_key` — Number of Data Explorer clusters encrypted with a customer-managed key (Key Vault properties set)
- `data_explorer_clusters_purge_enabled` — Number of Data Explorer clusters that allow purge (hard deletion of records)
- `data_explorer_clusters_audit_logs_exported` — Number of Data Explorer clusters with audit logs exported: a diagnostic setting that sends to a destination enables Command, Query, Journal or the audit or allLogs category group
- `data_explorer_clusters_audit_logs_unknown` — Number of Data Explorer clusters whose diagnostic settings couldn't be read

**Who has access to Data Explorer?**
- `data_explorer_clusters_trusting_any_tenant` — Number of Data Explorer clusters whose trusted external tenants include "*", so users, groups or apps from any Entra tenant can be granted access
- `data_explorer_principal_assignments` — Number of role assignments to users, groups or apps on Data Explorer clusters and their databases
- `data_explorer_admin_assignments` — Number of Data Explorer role assignments with an admin role (AllDatabasesAdmin or Admin), which can change data or grant access
- `data_explorer_admin_user_assignments` — Number of Data Explorer admin role assignments held by individual users rather than groups or apps
- `data_explorer_clusters_principals_unknown` — Number of Data Explorer clusters whose cluster role assignments, or the role assignments of any of its databases, couldn't be read

**Can Event Hubs namespaces be reached from the internet?**
- `event_hub_namespaces_open_to_all_networks` — Number of Event Hubs namespaces whose network exposure is open: public network access is on and the network rule set's default action is Allow (or unset)
- `event_hub_namespaces_network_restricted` — Number of Event Hubs namespaces whose network exposure is restricted: public network access is on but the network rule set's default action is Deny, so only its IP and virtual network rules get in
- `event_hub_namespaces_private_only` — Number of Event Hubs namespaces whose network exposure is private: the namespace or its network rule set sets public network access to Disabled
- `event_hub_namespaces_network_exposure_unknown` — Number of Event Hubs namespaces whose network rule set couldn't be read and that don't disable public network access themselves

**Are Event Hubs namespaces configured securely?**
- `event_hub_namespaces_tls_below_1_2` — Number of Event Hubs namespaces whose minimum TLS version is below 1.2 (1.0 or 1.1)
- `event_hub_namespaces_local_auth_enabled` — Number of Event Hubs namespaces where shared access keys still work (disableLocalAuth isn't true; it defaults to false)
- `event_hub_namespaces_shared_key_full_control` — Number of Event Hubs namespaces where one shared key gives full control: local authentication is on and a namespace shared access policy has Manage rights
- `event_hub_namespaces_customer_managed_key` — Number of Event Hubs namespaces encrypted with a customer-managed key (key source Microsoft.KeyVault)
- `event_hub_namespaces_zone_redundant` — Number of Event Hubs namespaces spread across availability zones
- `event_hub_namespaces_geo_replicated` — Number of Event Hubs namespaces replicated to at least one region besides the primary
- `event_hub_namespaces_audit_logs_exported` — Number of Event Hubs namespaces with audit logs exported: a diagnostic setting that sends to a destination enables RuntimeAuditLogs or the audit or allLogs category group
- `event_hub_namespaces_audit_logs_unknown` — Number of Event Hubs namespaces whose diagnostic settings couldn't be read

**Are individual event hubs protected and retained?**
- `event_hubs_with_capture` — Number of event hubs with Capture turned on (events copied to storage)
- `event_hubs_with_manage_rights_rules` — Number of event hubs with at least one of their own shared access policies granting Manage rights
- `event_hubs_authorization_rules_unknown` — Number of event hubs whose shared access policies couldn't be read
- `event_hubs_minimum_retention_days` — Days of message retention on the event hub with the shortest retention; null when no event hub reports a retention in days


### azure_key_vault_configuration
Short Description: Shows how each key vault grants access, whether deleted vaults and secrets can be recovered, how it's exposed to the network, and whether its audit events are logged.

Script: fetchers/azure/key_vault_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.KeyVault — whether the provider is registered
- `vaults.list_by_subscription()` — every key vault with its access model, access policies, recovery, network and SKU settings
- `diagnostic_settings.list()` (per vault) — where the vault's logs go, and whether audit events are among them

Output: `azure_key_vault_configuration_<subscription>.json` — each key vault with its access model and access policies, soft delete and purge protection, public access, firewall rules and private endpoints, SKU, the Azure services allowed to read it, and its diagnostic settings; no key, secret or certificate is read.

Summary fields:

**What was checked?**
- `total_key_vaults` — Number of key vaults in the subscription
- `provider_registration_status` — Whether Microsoft.KeyVault is registered on the subscription: registered, not_registered or unknown

**How is access to the vaults granted?**
- `rbac_authorization_vaults` — Number of vaults that use Azure RBAC role assignments for access to keys, secrets and certificates (the role assignments aren't in this evidence)
- `access_policy_vaults` — Number of vaults that use the older vault access policies instead of Azure RBAC
- `rbac_authorization_percentage` — Percentage of vaults that use Azure RBAC = `rbac_authorization_vaults` / `total_key_vaults` × 100 (a whole number, 0–100); 0 when `total_key_vaults` is 0
- `total_access_policies` — Number of access policy entries across all vaults, each giving a user, group or app permissions on a vault's keys, secrets, certificates or storage accounts

**Can a deleted vault or secret be recovered?**
- `soft_delete_vaults` — Number of vaults with soft delete on, so deleted vaults, keys and secrets are kept for the retention period and can be restored; a vault that doesn't report the setting counts as off
- `purge_protection_vaults` — Number of vaults with purge protection on, so nobody can permanently delete the vault or its contents before the retention period ends
- `recoverable_vaults` — Number of recoverable vaults: both soft delete and purge protection on
- `recoverable_percentage` — Percentage of vaults that are recoverable = `recoverable_vaults` / `total_key_vaults` × 100 (a whole number, 0–100); 0 when `total_key_vaults` is 0

**Is network access restricted?**
- `public_network_access_disabled_vaults` — Number of vaults with public network access disabled, reachable only through private endpoints; a vault that doesn't report the setting counts as enabled
- `network_acl_default_deny_vaults` — Number of vaults whose firewall denies by default, letting in only listed IP ranges and virtual networks (and trusted Azure services when allowed); a vault with no firewall settings counts as allowing all
- `private_endpoint_vaults` — Number of vaults with at least one private endpoint connection, in any state (pending and rejected connections count)

**Are keys protected by hardware?**
- `premium_sku_vaults` — Number of vaults on the Premium tier, which can hold keys in hardware security modules (HSMs); whether each key is HSM-backed isn't checked

**Is every operation on keys and secrets logged?**
- `vaults_with_diagnostic_settings` — Number of vaults with at least one diagnostic setting, whatever it exports
- `vaults_with_audit_logging` — Number of vaults with audit logging: a diagnostic setting that exports the AuditEvent category (directly, or through the audit or allLogs group) to a storage account, Log Analytics workspace, event hub or partner solution. AuditEvent records every read or change of a key, secret or certificate
- `vaults_without_audit_logging` — Number of vaults whose diagnostic settings were read and include no audit logging
- `vaults_audit_logging_unknown` — Number of vaults whose diagnostic settings couldn't be read
- `audit_logging_percentage` — Percentage of vaults with audit logging = `vaults_with_audit_logging` / `total_key_vaults` × 100 (a whole number, 0–100); 0 when `total_key_vaults` is 0. Vaults whose settings couldn't be read count in the total but not as logged


### azure_key_vault_key_rotation
Short Description: Shows whether Key Vault keys rotate, whether keys and secrets have an expiry and when certificates expire, whether certificates renew themselves, and where each App Service certificate comes from.

Script: fetchers/azure/key_vault_key_rotation/fetcher.py

Access: Reader on the subscription. Optional: Key Vault Reader on each vault (RBAC vaults) or an access policy with key and certificate list and get (access-policy vaults); without it, that vault's certificates read not_authorized and key rotation comes from the management plane only. An access policy with certificate list but not get lists the certificates with their auto-renew unknown. A vault firewall or private endpoint that blocks the collector also answers 403, so that vault reads not_authorized and inaccessible even with the role in place.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.KeyVault and Microsoft.Web — tells "not in use" from "none there"; a failure fails the run
- `vaults.list_by_subscription()` — every key vault
- `keys.list()` and `keys.get()` (per key) — keys, their dates and rotation policy
- `secrets.list()` (per vault) — secret names and expiry dates, never values
- `KeyClient.list_properties_of_keys()` and `get_key_rotation_policy()` (per vault, per key) — rotation policies on the data plane
- `CertificateClient.list_properties_of_certificates()` and `get_certificate_policy()` (per vault, per certificate) — certificate expiry and renewal policy; certificates not yet issued (still pending) are not listed; on the list, a 401 or 403 is that vault's not_authorized answer and any other error fails the run; on a policy read, a 401, 403 or 404 leaves that one certificate with policy_readable false and auto_renew_enabled null, and any other error fails the run
- `certificates.list()` (App Service) — App Service certificates, their expiry and source; a failure fails the run

Output: `azure_key_vault_key_rotation_<subscription>.json` — every key vault's keys with their rotation policies, secrets with their expiry, and certificates with their expiry and renewal policy, plus every App Service certificate with its expiry and where it comes from; no key material, secret value, certificate body or PFX password is read.

Summary fields:

**What was checked?**
- `total_key_vaults` — Number of key vaults in the subscription
- `data_plane_accessible_vaults` — Number of key vaults whose keys this credential could list on the data plane
- `data_plane_inaccessible_vaults` — Number of key vaults whose data-plane key list answered this credential with an HTTP error (most often no role or access policy, or a vault firewall); a permission or network gap, not a failed run
- `rbac_authorization_vaults` — Number of key vaults that use Azure RBAC rather than access policies for data-plane permissions
- `certificate_accessible_vaults` — Number of key vaults whose certificates this credential could list
- `certificate_not_authorized_vaults` — Number of key vaults that refused to list their certificates (HTTP 401 or 403, read as not_authorized); their certificates are unknown, not zero. Vaults whose certificate list failed, or that had no data-plane address, are in neither this count nor `certificate_accessible_vaults`
- `provider_registration_status` — Whether Key Vault (Microsoft.KeyVault) is registered on the subscription: registered, not_registered or unknown
- `web_provider_registration_status` — Whether App Service (Microsoft.Web) is registered on the subscription: registered, not_registered or unknown; not_registered means no App Service in use rather than zero certificates

**Do keys rotate?**
- `total_keys` — Number of keys across all key vaults
- `enabled_keys` — Number of keys that are enabled
- `keys_with_readable_rotation_policy` — Number of keys whose rotation policy could be read on either plane ("readable": the plane answered with a policy or with "there is none")
- `keys_with_rotation_policy` — Number of keys with a rotation policy
- `keys_with_rotation_enabled` — Number of keys whose rotation policy has a rotate action
- `rotation_enabled_percentage` — Percentage of keys with a readable rotation policy that rotate = `keys_with_rotation_enabled` / `keys_with_readable_rotation_policy` × 100 (a whole number, 0–100); 0 when `keys_with_readable_rotation_policy` is 0. Keys whose policy couldn't be read are left out of both

**Do keys and secrets expire?**
- `keys_with_expiration` — Number of keys with an expiration date set
- `key_expiration_percentage` — Percentage of keys with an expiration date = `keys_with_expiration` / `total_keys` × 100 (a whole number, 0–100); 0 when `total_keys` is 0
- `total_secrets` — Number of secrets across all key vaults
- `enabled_secrets` — Number of secrets that are enabled
- `secrets_with_expiration` — Number of secrets with an expiration date set
- `secret_expiration_percentage` — Percentage of secrets with an expiration date = `secrets_with_expiration` / `total_secrets` × 100 (a whole number, 0–100); 0 when `total_secrets` is 0

**Do Key Vault certificates renew themselves?**
- `total_certificates` — Number of certificates in the key vaults whose certificates could be listed
- `certificates_with_readable_policy` — Number of Key Vault certificates whose policy could be read
- `certificates_with_auto_renew` — Number of Key Vault certificates whose policy has an AutoRenew lifetime action; Key Vault renews only self-signed and integrated-CA (DigiCert, GlobalSign) certificates, and each certificate's policy.issuer_name says which (Unknown means a CA Key Vault does not integrate with, so nothing renews it)
- `certificate_auto_renew_percentage` — Percentage of Key Vault certificates with a readable policy that auto-renew = `certificates_with_auto_renew` / `certificates_with_readable_policy` × 100 (a whole number, 0–100); 0 when `certificates_with_readable_policy` is 0. Certificates whose policy couldn't be read, and vaults that refused the list, are left out of both

**Are certificates expired or about to expire?**
- `expired_certificates` — Number of Key Vault certificates past their expiry date when the fetcher ran
- `certificates_expiring_within_30_days` — Number of Key Vault certificates not yet expired that expire within 30 days (0 to 30 whole days left, with part days dropped, so 30 days 23 hours counts)
- `expired_app_service_certificates` — Number of App Service certificates past their expiry date when the fetcher ran
- `app_service_certificates_expiring_within_30_days` — Number of App Service certificates not yet expired that expire within 30 days

**Where do App Service certificates come from?**
- `total_app_service_certificates` — Number of App Service certificates in the subscription
- `app_service_certificates_by_source` — Number of App Service certificates from each source, with every source listed and 0 when it has none:
  - key_vault (synced from a Key Vault secret; the record's key_vault_certificate_auto_renew is that vault certificate's auto-renew, or null when the vault's certificates or that certificate's policy couldn't be read, the vault is not in this subscription, or it holds no certificate of that name, as for an App Service Certificate order)
  - managed (an App Service managed certificate, recognised by its canonical name or domain validation method; App Service renews it)
  - uploaded (an uploaded PFX file that nobody renews)
- `app_service_certificates_key_vault_sync_failing` — Number of Key Vault-backed App Service certificates whose last sync from the vault failed (an error status such as KeyVaultSecretDoesNotExist); Succeeded, pending (Initialized, WaitingOnCertificateOrder) and unknown statuses are not counted


### azure_managed_redis_configuration
Short Description: Shows whether each Azure Managed Redis cluster and database accepts only TLS connections, uses Entra ID instead of access keys, and is reachable only privately.

Script: fetchers/azure/managed_redis_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Cache — tells "not registered" apart from "no clusters"
- `redis_enterprise.list()` — every Managed Redis cluster with its TLS floor, network access and encryption
- `databases.list_by_cluster()` (per cluster) — each database's client protocol, access-key setting, persistence and geo-replication

Output: `azure_managed_redis_configuration_<subscription>.json` — each Managed Redis cluster with its TLS, network and encryption settings and the databases on it.

Summary fields:

**What was checked?**
- `total_clusters` — Number of Azure Managed Redis clusters in the subscription (classic Azure Cache for Redis is not included)
- `total_databases` — Number of databases across all clusters whose database list could be read
- `databases_unread_clusters` — Number of clusters whose database list couldn't be read; their TLS-only verdict is unknown
- `provider_registration_status` — Whether Microsoft.Cache is registered on the subscription: registered, not_registered or unknown

**Do clusters accept only TLS connections?**
- `tls_only_clusters` — Number of clusters that are TLS only: minimum TLS version 1.2 or 1.3, at least one database, and every database's client protocol Encrypted (TLS only) rather than Plaintext
- `tls_only_percentage` — Percentage of clusters that are TLS only = `tls_only_clusters` / `total_clusters` × 100 (a whole number, 0–100); 0 when `total_clusters` is 0. Clusters whose databases couldn't be read (`databases_unread_clusters`) count in the total but not as TLS only, so they lower it
- `recommended_minimum_tls_clusters` — Number of clusters whose minimum TLS version is 1.2 or 1.3
- `encrypted_protocol_databases` — Number of databases whose client protocol is Encrypted (TLS only)
- `plaintext_protocol_databases` — Number of databases whose client protocol is not Encrypted (Plaintext, which accepts non-TLS connections, or not returned)

**Is access limited to Entra ID?**
- `access_keys_disabled_databases` — Number of databases with access-key authentication Disabled, so only Microsoft Entra ID sign-in works
- `access_keys_enabled_databases` — Number of databases where access-key authentication is not Disabled (Enabled, or not returned, which is treated as the older default, Enabled)

**Are clusters reachable only privately and encrypted with their own key?**
- `public_network_access_disabled_clusters` — Number of clusters with public network access Disabled
- `public_network_access_unset_clusters` — Number of clusters where Azure returned no public network access setting (older clusters); these count as not disabled
- `private_only_clusters` — Number of clusters that are private only: public network access Disabled and at least one Approved private endpoint connection
- `customer_managed_key_clusters` — Number of clusters encrypted with a customer-managed key (a Key Vault key URL is set)


### azure_mysql_configuration
Short Description: Shows whether each MySQL flexible server requires TLS 1.2 or later, records connections in its audit log, blocks public access, and keeps geo-redundant backups and a standby.

Script: fetchers/azure/mysql_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.DBforMySQL — tells “not registered” apart from “no servers”
- `servers.list()` — every MySQL flexible server with its version, network, backup and high-availability settings
- `configurations.list_by_server()` (per server) — every server parameter, including the TLS and audit log ones

Output: `azure_mysql_configuration_<subscription>.json` — each MySQL flexible server with its transport encryption, audit logging, network, backup and high-availability settings, plus the name and value of every server parameter.

Summary fields:

**What was checked?**
- `total_mysql_servers` — Number of Azure Database for MySQL flexible servers in the subscription
- `total_configuration_parameters` — Number of server parameters read, added up across all servers; a server whose parameters couldn't be read adds 0, and its secure transport, TLS version and audit log settings all count as off
- `provider_registration_status` — Whether Microsoft.DBforMySQL is registered on the subscription: registered, not_registered or unknown

**Are connections encrypted with a current TLS version?**
- `require_secure_transport_servers` — Number of servers with the require_secure_transport parameter ON, so unencrypted connections are refused
- `require_secure_transport_percentage` — Percentage of servers that refuse unencrypted connections = `require_secure_transport_servers` / `total_mysql_servers` × 100 (a whole number, 0–100); 0 when `total_mysql_servers` is 0. Servers whose parameters couldn't be read count in the total but not as refusing, so they lower it
- `tls_version_compliant_servers` — Number of servers whose tls_version parameter lists no version older than TLS 1.2 (for example TLSv1.2,TLSv1.3); the parameter lists every version the server accepts rather than a minimum, so a list that still includes TLSv1 or TLSv1.1 doesn't count, and nor does an empty or missing one

**Are connections recorded in the audit log?**
- `audit_log_enabled_servers` — Number of servers with the audit_log_enabled parameter ON
- `audit_log_connection_event_servers` — Number of servers whose audit_log_events parameter includes the CONNECTION class, which records who connected and when; counted whether or not audit_log_enabled is ON

**Is the server kept off the public internet?**
- `public_network_access_disabled_servers` — Number of servers with public network access Disabled, so they're reached only through a virtual network or private endpoint

**Will the server survive a zone or region loss?**
- `geo_redundant_backup_servers` — Number of servers whose backups are geo-redundant (also stored in the paired region)
- `high_availability_servers` — Number of servers with a standby server: high-availability mode ZoneRedundant (standby in another zone) or SameZone (standby in the same zone); Disabled or no mode doesn't count


### azure_postgresql_configuration
Short Description: Shows whether each PostgreSQL flexible server requires encrypted connections, uses Entra ID sign-in, logs connections, keeps its firewall closed, and has geo-redundant backups and a standby.

Script: fetchers/azure/postgresql_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.DBforPostgreSQL — tells “not registered” apart from “no servers”
- `servers.list_by_subscription()` — every PostgreSQL flexible server with its sign-in, network, backup and high-availability settings
- `configurations.get()` (per server, six parameters) — require_secure_transport, log_checkpoints, log_connections, log_disconnections, connection_throttle.enable and logfiles.retention_days
- `firewall_rules.list_by_server()` (per server) — the IP ranges allowed to connect
- `administrators_microsoft_entra.list_by_server()` (per server) — the Entra users, groups or apps set as administrators

Output: `azure_postgresql_configuration_<subscription>.json` — each PostgreSQL flexible server with its secure transport, sign-in and logging settings, Entra administrators, firewall rules, and backup and high-availability settings.

Summary fields:

**What was checked?**
- `total_postgresql_servers` — Number of Azure Database for PostgreSQL flexible servers in the subscription
- `provider_registration_status` — Whether Microsoft.DBforPostgreSQL is registered on the subscription: registered, not_registered or unknown

**Are connections encrypted?**
- `require_secure_transport_servers` — Number of servers with the require_secure_transport parameter ON, so unencrypted connections are refused
- `require_secure_transport_percentage` — Percentage of servers that refuse unencrypted connections = `require_secure_transport_servers` / `total_postgresql_servers` × 100 (a whole number, 0–100); 0 when `total_postgresql_servers` is 0. Servers whose parameter couldn't be read count in the total but not as refusing, so they lower it

**Can people sign in with Entra ID?**
- `entra_id_authentication_servers` — Number of servers with Microsoft Entra ID authentication enabled
- `entra_id_authentication_configured_servers` — Number of servers with Entra ID authentication enabled and at least one Entra administrator assigned
- `total_entra_id_admins` — Number of Entra ID administrators (users, groups or apps) across all servers

**Is server activity logged?**
- `log_checkpoints_servers` — Number of servers with log_checkpoints ON, which writes each checkpoint to the server log
- `log_connections_servers` — Number of servers with log_connections ON, which logs each connection attempt
- `log_disconnections_servers` — Number of servers with log_disconnections ON, which logs the end and length of each session
- `connection_throttling_servers` — Number of servers with connection throttling (connection_throttle.enable) ON, which slows sign-in attempts from an IP address after repeated failures; the parameter was removed in PostgreSQL 16, so servers on 16 or later never count
- `log_retention_compliant_servers` — Number of servers that keep server logs (logfiles.retention_days) for 4 to 7 days: more than 3, and no more than Azure's maximum of 7, since a larger value means the setting never took effect; a server with server logs off has no retention parameter and doesn't count

**Is the server kept off the public internet?**
- `public_network_access_disabled_servers` — Number of servers with public network access Disabled, so they're reached only through a virtual network or private endpoint
- `servers_allowing_all_azure_services` — Number of servers with the 0.0.0.0–0.0.0.0 firewall rule (“allow public access from any Azure service”), which admits compute in any Azure customer's subscription, not only the organization's own
- `servers_allowing_entire_internet` — Number of servers with a firewall rule for every IPv4 address (exactly 0.0.0.0–255.255.255.255; split or overlapping rules that add up to it aren't detected)
- `total_firewall_rules` — Number of firewall rules across all servers

**Will the server survive a zone or region loss?**
- `geo_redundant_backup_servers` — Number of servers whose backups are geo-redundant (also stored in the paired region)
- `high_availability_servers` — Number of servers with a standby server: high-availability mode ZoneRedundant (standby in another zone) or SameZone (standby in the same zone); Disabled or no mode doesn't count


### azure_redis_cache_configuration
Short Description: Shows whether each classic Azure Cache for Redis accepts only TLS, requires Entra ID sign-in, stays off the public internet, exports audit logs and survives a node or zone failure.

Script: fetchers/azure/redis_cache_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Cache — tells "not registered" apart from "no caches"
- `redis.list_by_subscription()` — every cache with its TLS, authentication, network and resilience settings (access keys are never requested)
- `firewall_rules.list()` (per cache) — IP ranges allowed to connect
- `access_policy.list()` and `access_policy_assignment.list()` (per cache) — data-access policies and the Entra users, groups or apps granted them
- `patch_schedules.list_by_redis_resource()` (per cache) — the maintenance (patch) window
- `linked_server.list()` (per cache) — geo-replication links
- `diagnostic_settings.list()` (per cache) — whether connection and Entra sign-in audit logs are exported

Output: `azure_redis_cache_configuration_<subscription>.json` — each Redis cache with its transport, sign-in, network, audit logging, patching and resilience settings.

Summary fields:

**What was checked?**
- `total_caches` — Number of classic Azure Cache for Redis caches in the subscription (Azure Managed Redis is not included)
- `caches_by_sku` — Number of caches on each SKU (Basic, Standard, Premium; unknown when not returned)
- `caches_by_redis_version` — Number of caches on each Redis version (unknown when not returned)
- `provider_registration_status` — Whether Microsoft.Cache is registered on the subscription: registered, not_registered or unknown

**Do caches accept only TLS connections?**
- `tls_only_caches` — Number of caches that are TLS only: minimum TLS version 1.2 or 1.3 and the non-TLS port (6379) disabled
- `tls_only_percentage` — Percentage of caches that are TLS only = `tls_only_caches` / `total_caches` × 100 (a whole number, 0–100); 0 when `total_caches` is 0
- `recommended_minimum_tls_caches` — Number of caches whose minimum TLS version is 1.2 or 1.3 (no setting means TLS 1.0 is accepted, so it doesn't count)
- `non_ssl_port_enabled_caches` — Number of caches with the non-TLS port (6379) enabled

**Who can sign in, and how?**
- `auth_not_required_caches` — Number of caches that accept connections with no authentication at all (authnotrequired set to true)
- `access_keys_disabled_caches` — Number of caches with access-key authentication disabled, so only Microsoft Entra ID sign-in works
- `entra_auth_enabled_caches` — Number of caches with Microsoft Entra ID sign-in enabled
- `access_policy_assignments` — Number of Entra data-access policy assignments (a user, group or app granted a policy) across all caches; they only take effect on caches with Entra sign-in enabled

**Are caches kept off the public internet?**
- `public_network_access_disabled_caches` — Number of caches with public network access Disabled
- `public_network_access_unset_caches` — Number of caches where Azure returned no public network access setting; these count as not disabled
- `private_only_caches` — Number of caches that are private only: public network access Disabled and either an Approved private endpoint or deployment into a VNet subnet
- `vnet_injected_caches` — Number of caches deployed into a VNet subnet
- `firewall_allows_all_ips_caches` — Number of caches whose firewall rules together admit every IPv4 address (overlapping or split rules are merged first, so two halves count)

**Are activity and patching under control?**
- `audit_logging_enabled_caches` — Number of caches with a diagnostic setting that sends connection (ConnectedClientList) or Entra sign-in (MSEntraAuthenticationAuditLog) logs to a storage account, Log Analytics workspace, event hub or partner solution, directly or through the audit or allLogs group
- `maintenance_window_caches` — Number of caches with a patch schedule set (without one, Azure picks the maintenance time)

**Will caches survive a failure?**
- `replicated_caches` — Number of caches with a replica, meaning any SKU except Basic (a single node with no SLA)
- `zone_redundant_caches` — Number of caches spread across availability zones: more than one zone listed, or zonal allocation policy Automatic
- `geo_replicated_caches` — Number of caches with at least one linked server (a geo-replication link to another cache)
- `persistence_enabled_caches` — Number of caches saving data to disk with RDB snapshots or AOF logging

**Which caches need a closer look?**
- `exceptions` — For each failed expectation, a list of the names of the caches that fail it, so a reviewer can sample them:
  - not_tls_only (not TLS only)
  - non_ssl_port_enabled (non-TLS port 6379 enabled)
  - auth_not_required (no authentication required)
  - access_keys_enabled (access-key authentication still enabled)
  - public_network_access_not_disabled (public network access Enabled or not returned)
  - firewall_allows_all_ips (firewall rules together admit every IPv4 address)
  - no_audit_logging (diagnostic settings read, but no connection or Entra sign-in audit log exported)
  - no_maintenance_window (no patch schedule)
  - not_replicated (Basic SKU)
  - unknown_state (at least one per-cache read failed: firewall rules, access policies, access policy assignments, patch schedule, geo-replication links or diagnostic settings; those settings read as unknown and the run fails)


### azure_sql_encryption_status
Short Description: Shows whether each Azure SQL server's transparent data encryption uses a customer-managed Key Vault key and whether every user database on it has encryption turned on.

Script: fetchers/azure/sql_encryption_status/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Sql — tells “not registered” apart from “no servers”
- `servers.list()` — every logical server
- `encryption_protectors.get()` (per server) — the TDE protector's key type, key name, Key Vault URI and auto-rotation setting
- `databases.list_by_server()` (per server) — the databases on each server
- `transparent_data_encryptions.get()` (per database) — whether transparent data encryption (TDE) is on

Output: `azure_sql_encryption_status_<subscription>.json` — each Azure SQL logical server with the key that protects its transparent data encryption and the encryption state of every database on it; the master database is kept but marked as a system database.

Summary fields:

**What was checked?**
- `total_sql_servers` — Number of Azure SQL logical servers in the subscription
- `total_databases` — Number of databases across all servers, including master; a server whose database list couldn't be read adds 0
- `total_user_databases` — Number of user databases across all servers: every database except master, which Azure creates and manages
- `provider_registration_status` — Whether Microsoft.Sql is registered on the subscription: registered, not_registered or unknown

**Is the encryption key customer-managed?**
- `customer_managed_key_servers` — Number of servers whose TDE protector is a customer-managed Key Vault key (server key type AzureKeyVault)
- `service_managed_key_servers` — Number of servers not counted in `customer_managed_key_servers`: the protector is the Microsoft-managed (ServiceManaged) key, or the protector couldn't be read
- `cmk_percentage` — Percentage of servers whose TDE protector is a customer-managed key = `customer_managed_key_servers` / `total_sql_servers` × 100 (a whole number, 0–100); 0 when `total_sql_servers` is 0. Servers whose protector couldn't be read count in the total but not as customer-managed. TDE is on by default, so the key source is what varies
- `key_auto_rotation_servers` — Number of servers with key auto-rotation on, so the protector moves to the newest key version in Key Vault automatically

**Is every user database encrypted?**
- `tde_enabled_user_databases` — Number of user databases with TDE Enabled
- `tde_disabled_user_databases` — Number of user databases with TDE Disabled, for example a database restored or switched off under a server with a customer-managed key
- `tde_unknown_user_databases` — Number of user databases whose TDE state couldn't be read
- `tde_percentage` — Percentage of user databases with TDE on = `tde_enabled_user_databases` / `total_user_databases` × 100 (a whole number, 0–100); 0 when `total_user_databases` is 0. Databases whose state is unknown (`tde_unknown_user_databases`) count in the total but not as encrypted, so they lower it
- `servers_with_a_tde_disabled_user_database` — Number of servers with at least one user database whose TDE is Disabled


### azure_sql_managed_instance_backups
Short Description: Shows whether each SQL Managed Instance database keeps at least 7 days of point-in-time restore and long-term backups, and whether backups and the instance survive a zone or region loss.

Script: fetchers/azure/sql_managed_instance_backups/fetcher.py (shared helper: fetchers/azure/_shared/sql_managed_instance.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Sql — tells “not registered” apart from “no instances”
- `managed_instances.list()` — every managed instance with its state, backup storage redundancy and zone redundancy
- `instance_failover_groups.list_by_location()` (per resource group and region holding an instance) — the failover groups, their instance pairs and failover policy
- `managed_databases.list_by_instance()` (per instance) — the databases and their earliest restore points
- `managed_backup_short_term_retention_policies.get()` (per user database) — point-in-time restore retention in days
- `managed_instance_long_term_retention_policies.get()` (per user database) — weekly, monthly and yearly long-term retention

Output: `azure_sql_managed_instance_backups_<subscription>.json` — each SQL Managed Instance with its state, backup storage redundancy, zone redundancy and failover groups, and each database's earliest restore point and short- and long-term retention; system databases are kept but not counted.

Summary fields:

**What was checked?**
- `total_managed_instances` — Number of SQL Managed Instances in the subscription
- `total_user_databases` — Number of user databases across all instances (master, model, msdb and tempdb are left out); null if any instance's database list couldn't be read
- `instances_stopped` — Number of instances in the Stopped state; Azure takes no backups while an instance is stopped
- `provider_registration_status` — Whether Microsoft.Sql is registered on the subscription: registered, not_registered or unknown

**Does every user database keep at least 7 days of point-in-time restore?**
- `databases_retention_at_least_7_days` — Number of user databases whose short-term (point-in-time restore) retention is 7 days or more
- `databases_retention_below_7_days` — Number of user databases with a short-term retention policy set below 7 days
- `databases_missing_retention_policy` — Number of user databases with no short-term retention policy (Azure answered not found)
- `databases_retention_unknown` — Number of user databases whose short-term retention couldn't be read; `databases_retention_at_least_7_days`, `databases_retention_below_7_days`, `databases_missing_retention_policy` and this count add up to `total_user_databases` when it isn't null

**Are long-term backups kept?**
- `databases_with_long_term_retention` — Number of user databases whose long-term retention policy keeps at least one of the weekly, monthly or yearly backups (a duration other than zero)
- `databases_long_term_retention_unknown` — Number of user databases whose long-term retention policy couldn't be read

**Do backups and the instance survive a zone or region loss?**
- `instances_by_current_backup_storage_redundancy` — Number of instances on each backup storage redundancy now in effect; a value with no instances is left out:
  - Local (copies in one datacenter)
  - Zone (copies across availability zones in one region)
  - Geo (also copied to the paired region; the copies in the primary region sit in one zone)
  - GeoZone (across zones in the primary region and copied to the paired region)
  - unknown (not returned)
- `instances_backup_storage_zone_redundant` — Number of instances whose current backup storage is Zone or GeoZone (Geo doesn't count, as its copies in the primary region sit in one zone)
- `instances_zone_redundant` — Number of instances with compute zone redundancy on (replicas spread across availability zones), a separate setting from backup storage; a setting Azure didn't return counts as off
- `instances_in_failover_group` — Number of instances in an instance failover group, as the primary or the partner of one of its instance pairs
- `instances_failover_group_unknown` — Number of instances whose failover group membership is unknown: the failover group list for their resource group and region couldn't be read, and no other region's list showed them in a group
- `total_instance_failover_groups` — Number of instance failover groups found in the resource groups and regions holding an instance, each counted once although Azure lists a group from every region it spans; null if any failover group list couldn't be read
- `failover_groups_manual_policy` — Number of instance failover groups whose failover policy is Manual, so a person has to start a failover (Automatic fails over on its own); null if any failover group list couldn't be read


### azure_sql_managed_instance_configuration
Short Description: Shows whether each SQL Managed Instance is closed to the public internet, requires TLS 1.2, uses Entra ID sign-in, and has a diagnostic setting exporting SQL audit events.

Script: fetchers/azure/sql_managed_instance_configuration/fetcher.py (shared helper: fetchers/azure/_shared/sql_managed_instance.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Sql — tells “not registered” apart from “no instances”
- `managed_instances.list()` — every managed instance with its public data endpoint, connection type, minimum TLS version and private endpoints
- `managed_instance_administrators.list_by_instance()` (per instance) — the Entra ID administrator
- `managed_instance_azure_ad_only_authentications.list_by_instance()` (per instance) — whether only Entra ID sign-in is allowed
- `diagnostic_settings.list()` (per instance) — where the instance's logs are exported, and which log categories

Output: `azure_sql_managed_instance_configuration_<subscription>.json` — each SQL Managed Instance with its public data endpoint, connection type, minimum TLS version, private endpoints, Entra administrators, Entra-only setting and diagnostic settings; an exported audit log shows a route out of the instance, not that auditing is switched on inside it.

Summary fields:

**What was checked?**
- `total_managed_instances` — Number of SQL Managed Instances in the subscription
- `provider_registration_status` — Whether Microsoft.Sql is registered on the subscription: registered, not_registered or unknown

**Is the instance closed to the public internet?**
- `instances_public_data_endpoint_enabled` — Number of instances with the public data endpoint enabled, the only way to reach an instance from outside its virtual network
- `instances_private_access_only` — Number of instances with the public data endpoint explicitly disabled, so they're reachable only inside their virtual network or through private endpoints; an instance where Azure didn't return the setting counts in neither this field nor `instances_public_data_endpoint_enabled`
- `instances_with_approved_private_endpoint` — Number of instances with at least one Approved private endpoint connection

**Do connections use TLS 1.2 or later?**
- `instances_minimal_tls_recommended` — Number of instances whose minimum TLS version is 1.2 or 1.3 (None, 1.0, 1.1 or no setting doesn't count)

**Who can sign in, and how?**
- `instances_entra_administrator` — Number of instances with a Microsoft Entra ID administrator set; an instance whose administrator list couldn't be read doesn't count
- `instances_entra_only_authentication` — Number of instances that accept only Entra ID sign-in (Entra-only authentication on, so SQL logins with passwords are refused); an instance whose setting couldn't be read doesn't count

**Are SQL audit events exported?**
- `instances_audit_logs_exported` — Number of instances with a diagnostic setting that sends the SQLSecurityAuditEvents log, on its own or through the audit or allLogs category group, to a Log Analytics workspace, storage account or event hub; an instance whose diagnostic settings couldn't be read doesn't count. This proves a route out, not that auditing is on: Managed Instance auditing is started in T-SQL, which no Azure management call can read


### azure_sql_managed_instance_encryption
Short Description: Shows whether each SQL Managed Instance encrypts its databases with Transparent Data Encryption and whether its encryption key is customer-managed and rotated automatically.

Script: fetchers/azure/sql_managed_instance_encryption/fetcher.py (shared reads in fetchers/azure/_shared/sql_managed_instance.py)

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Sql")` — tells "Azure SQL not in use" from "no instances"
- `managed_instances.list()` — every SQL Managed Instance
- `managed_instance_encryption_protectors.get()` (per instance) — the key that protects its TDE keys (service-managed or Key Vault) and whether it auto-rotates
- `managed_databases.list_by_instance()` (per instance) — its databases
- `managed_database_transparent_data_encryption.get()` (per user database) — whether Transparent Data Encryption (TDE) is on

Output: `azure_sql_managed_instance_encryption_<subscription>.json` — each SQL Managed Instance's TDE protector (key type, Key Vault key URI and auto-rotation) and the TDE state of each of its databases.

Summary fields:

**What was checked?**
- `total_managed_instances` — Number of SQL Managed Instances in the subscription
- `total_user_databases` — Number of user databases across all instances (the system databases master, model, msdb and tempdb are left out); null if any instance's database list couldn't be read
- `provider_registration_status` — Whether the Azure SQL provider (Microsoft.Sql) is registered on the subscription: registered, not_registered or unknown

**Who holds the encryption key?**
- `instances_customer_managed_key` — Number of instances whose TDE protector is a customer-managed key in Azure Key Vault (server key type AzureKeyVault) rather than a service-managed key
- `instances_key_auto_rotation` — Number of instances with automatic key rotation on for the TDE protector, so a new key version in Key Vault is picked up without manual action

**Is every user database encrypted?**
- `tde_enabled_user_databases` — Number of user databases with TDE state Enabled
- `tde_disabled_user_databases` — Number of user databases whose TDE state is Disabled (any state other than Enabled)
- `tde_unknown_user_databases` — Number of user databases whose TDE state couldn't be read


### azure_sql_server_configuration
Short Description: Shows whether each Azure SQL server is closed to the public internet, requires TLS 1.2, uses Entra ID sign-in, audits activity, and runs Defender for SQL and vulnerability scans.

Script: fetchers/azure/sql_server_configuration/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get()` for Microsoft.Sql — tells “not registered” apart from “no servers”
- `servers.list()` — every logical server with its public access, minimum TLS version and Entra administrator
- `firewall_rules.list_by_server()` (per server) — the IP ranges allowed to connect
- `server_blob_auditing_policies.list_by_server()` (per server) — whether auditing is on and how long records are kept
- `server_security_alert_policies.get()` (per server) — whether Microsoft Defender for SQL threat detection is on
- `server_vulnerability_assessments.get()` (per server) — where scan results go, and whether recurring scans run and email admins

Output: `azure_sql_server_configuration_<subscription>.json` — each Azure SQL logical server with its network exposure, firewall rules, Entra administrator, auditing policies, Defender for SQL alert policy and vulnerability assessment settings.

Summary fields:

**What was checked?**
- `total_sql_servers` — Number of Azure SQL logical servers in the subscription (SQL Managed Instances aren't included)
- `provider_registration_status` — Whether Microsoft.Sql is registered on the subscription: registered, not_registered or unknown

**Is the server closed to the public internet?**
- `public_network_access_disabled_servers` — Number of servers with public network access Disabled or SecuredByPerimeter (behind a Network Security Perimeter), so they're reached only through private endpoints
- `servers_allowing_all_azure_services` — Number of servers with the 0.0.0.0–0.0.0.0 firewall rule (“allow Azure services and resources to access this server”), which admits compute in any Azure customer's subscription, not only the organization's own
- `servers_allowing_entire_internet` — Number of servers with a firewall rule for every IPv4 address (exactly 0.0.0.0–255.255.255.255; split or overlapping rules that add up to it aren't detected)
- `total_firewall_rules` — Number of server-level firewall rules across all servers (database-level rules aren't read)

**Do connections use TLS 1.2 or later?**
- `recommended_minimal_tls_servers` — Number of servers whose minimum TLS version is 1.2 or 1.3 (None, 1.0, 1.1 or no setting doesn't count)

**Who can sign in, and how?**
- `entra_administrator_servers` — Number of servers with a Microsoft Entra ID administrator set
- `entra_only_authentication_servers` — Number of servers that accept only Entra ID sign-in (Entra-only authentication on, so SQL logins with passwords are refused)

**Is activity audited and kept long enough?**
- `auditing_enabled_servers` — Number of servers with at least one server auditing policy Enabled
- `auditing_percentage` — Percentage of servers with auditing on = `auditing_enabled_servers` / `total_sql_servers` × 100 (a whole number, 0–100); 0 when `total_sql_servers` is 0
- `auditing_retention_over_90_days_servers` — Number of servers with an enabled auditing policy that keeps records more than 90 days, or whose retention is 0, which Azure reads as keep forever (exactly 90 days doesn't count); retention is the storage account setting, so a policy that sends only to Log Analytics or an event hub and is left at 0 also counts

**Are threats and vulnerabilities watched?**
- `defender_for_sql_enabled_servers` — Number of servers whose security alert policy (Microsoft Defender for SQL threat detection) is Enabled; a server with no policy, or whose policy couldn't be read, counts as off
- `vulnerability_assessment_enabled_servers` — Number of servers with vulnerability assessment set up, counted only when a storage container for scan results is set
- `vulnerability_assessment_recurring_scan_servers` — Number of servers with recurring (weekly) vulnerability scans on, counted whether or not a storage container is set
- `vulnerability_assessment_admin_notification_servers` — Number of servers whose recurring scan results are emailed to the subscription admins, counted whether or not recurring scans are on


### azure_storage_encryption_status
Short Description: Shows how each storage account is encrypted and exposed, how old its access keys are, whether it replicates to a healthy second region, which containers are public, and its owner.

Script: fetchers/azure/storage_encryption_status/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- `subscriptions.list()` — picks a subscription when none is set
- `providers.get("Microsoft.Storage")` — tells "storage not in use" from "no accounts"
- `storage_accounts.list()` — every account with its encryption, network, key policy, key creation times, regions and tags; access keys are never listed (no listKeys or SAS calls)
- `blob_services.get_service_properties()` and `file_services.get_service_properties()` (per account) — versioning and soft delete
- `storage_accounts.get_properties(expand="geoReplicationStats")` (per geo-redundant account) — replication health and last sync time; LastSyncTimeUnavailable reads as unavailable, any other error fails the run
- `blob_containers.list()` (per account) — each container's access level and immutability; an account kind with no Blob service reads not_supported, any other error fails the run

Output: `azure_storage_encryption_status_<subscription>.json` — every storage account's encryption, network exposure, access-key age, replication to a second region, blob containers (with metadata keys only, never values, and null when the list returns no metadata) and tags.

Summary fields:

**What was checked?**
- `total_storage_accounts` — Number of storage accounts in the subscription
- `provider_registration_status` — Whether Azure Storage (Microsoft.Storage) is registered on the subscription: registered, not_registered or unknown

**Who holds the encryption keys?**
- `customer_managed_key_storage` — Number of storage accounts encrypted with a customer-managed key held in Key Vault
- `platform_managed_key_storage` — Number of storage accounts encrypted with Microsoft's platform-managed key
- `cmk_percentage` — Percentage of storage accounts using a customer-managed key = `customer_managed_key_storage` / `total_storage_accounts` × 100 (a whole number, 0–100); 0 when `total_storage_accounts` is 0
- `infrastructure_encryption_accounts` — Number of storage accounts with infrastructure (double) encryption on

**Is data encrypted in transit?**
- `https_only_accounts` — Number of storage accounts that accept HTTPS only
- `minimum_tls_1_2_accounts` — Number of storage accounts whose minimum TLS version is 1.2 or 1.3

**Is storage reachable from the network?**
- `public_blob_access_accounts` — Number of storage accounts that allow anonymous (public) access to blobs; an account that omits the setting allows it
- `private_endpoint_accounts` — Number of storage accounts with at least one private endpoint connection

**Are access keys controlled?**
- `shared_key_access_accounts` — Number of storage accounts that accept access-key (shared key) authorization; an account that omits the setting allows it
- `key_expiration_policy_accounts` — Number of storage accounts with an access-key expiry policy (a maximum key age in days)
- `access_key_age_known_accounts` — Number of storage accounts whose two access keys both have a known creation time
- `access_key_max_age_days` — Days since the oldest access key in the subscription was created or last rotated; null when there are no storage accounts or any key's creation time is unknown (older accounts whose keys have not been rotated since Azure began recording it)
- `accounts_with_access_key_older_than_90_days` — Number of storage accounts with an access key created or last rotated more than 90 days ago; null when a key whose creation time is unknown leaves an account undecided
- `accounts_with_access_key_beyond_expiration_period` — Number of storage accounts with an access key older than the account's own key expiry policy; accounts with no policy are never counted; null when an account with a policy has a key of unknown age and no key known to be past it

**Is data replicated to a healthy second region?**
- `geo_redundant_accounts` — Number of storage accounts that replicate to a second region (GRS, RA-GRS, GZRS or RA-GZRS)
- `read_access_geo_redundant_accounts` — Number of storage accounts whose second-region copy can be read (RA-GRS or RA-GZRS)
- `geo_replication_stats_collected_accounts` — Number of geo-redundant storage accounts whose replication status was read
- `geo_replication_live_accounts` — Number of geo-redundant storage accounts whose replication status is Live (replicating normally)
- `geo_replication_max_sync_lag_minutes` — Number of minutes the second-region copy furthest behind trails its primary: the time since it last synced, measured when its replication status was read; null when there is no geo-redundant account or any one's last sync time is unknown
- `geo_failover_ready_accounts` — Number of geo-redundant storage accounts that Azure reports can fail over to the second region now
- `secondary_unavailable_accounts` — Number of geo-redundant storage accounts whose second region is reported unavailable
- `geo_failed_over_accounts` — Number of storage accounts that have failed over to their second region at least once

**Can deleted or changed data be recovered?**
- `blob_versioning_accounts` — Number of storage accounts with blob versioning on
- `container_soft_delete_accounts` — Number of storage accounts that keep deleted blob containers for a retention period (container soft delete)
- `share_soft_delete_accounts` — Number of storage accounts that keep deleted file shares for a retention period (share soft delete)
- `containers_with_immutability_policy` — Number of blob containers with a time-based retention (immutability) policy
- `containers_with_legal_hold` — Number of blob containers under a legal hold

**Which containers can be read anonymously?**
- `total_containers` — Number of blob containers across all storage accounts whose containers were listed
- `containers_with_public_access_level` — Number of blob containers set to the Blob or Container public access level
- `anonymously_accessible_containers` — Number of blob containers that can be read without signing in through the account's public endpoint: the container has a public access level, its account does not forbid public blob access (Azure allows it when the setting is on or was never set), and the account's network admits public clients. It doesn't when public network access is Disabled, or when the firewall's default action is Deny with no IP (IPv4 or IPv6) or virtual network rule; a Deny whose rule lists the API didn't return counts as admitting them. Not evaluated: which addresses or subnets a rule admits, a network security perimeter (SecuredByPerimeter counts as admitting), the trusted-services bypass and resource instance rules (which admit Azure services), and private endpoint connections (anonymous reads through one aren't counted)
- `accounts_with_containers_not_collected` — Number of storage accounts whose container list failed; their containers are missing from the counts

**Is each account owned and classified?**
- `accounts_with_owner_tag` — Number of storage accounts with an owner tag (the first configured owner tag key present, such as Owner)
- `accounts_with_classification_tag` — Number of storage accounts with a data classification tag (the first configured classification tag key present, such as DataClassification)


## Azure DevOps and code scanning

### azure_devops_audit_streams
Short Description: Shows whether an Azure DevOps organization records audit events and streams them to a destination that keeps them beyond Azure DevOps' 90 days.

Script: fetchers/azure/devops_audit_streams/fetcher.py

Access: A user with the View audit log permission, signed in with a personal access token that has Read Audit Log (vso.auditlog), or with Entra ID when no token is set. Only the Entra sign-in can read the Log Audit Events policy; with a token, auditing is judged from the audit log. Optional: Log Analytics Reader on a stream's workspace, for the ingestion check.

Commands Executed:
- `GET _apis/connectionData` — identifies the signed-in user (token or Entra ID)
- `GET _apis/OrganizationPolicy/Policies/Policy.LogAuditEvents` — whether auditing is on (best effort)
- `GET _apis/audit/streams` — every audit stream and its status
- `GET _apis/audit/auditlog` (last 90 days) — the newest audit events
- ARM `GET` on each Azure Monitor Logs stream's workspace — its workspace id
- KQL on `AzureDevOpsAuditing` (per workspace) — whether this organization's events arrived

Output: `azure_devops_audit_streams_<organization>.json` — whether auditing is on, each audit stream with its destination and status (and, for Azure Monitor Logs streams, whether events are arriving), and the newest audit log events.

Summary fields:

**Is auditing on?**
- `auditing_enabled` — True if auditing is on. Read from the Log Audit Events policy when the sign-in can (Entra ID); otherwise from the newest logged change to that policy; with no logged change, true if the audit log shows a recent event other than a read of the log itself; null if none of these shows it
- `newest_audit_event` — Time of the newest audit event, ignoring reads of the audit log

**Are audit events streamed somewhere that keeps them?**
- `streams` — Number of audit streams (null if the list couldn't be read)
- `streams_delivering` — Number of audit streams that are enabled or backfilling
- `streams_not_delivering` — List of audit streams (by name, or id) that are disabled, deleted or otherwise not delivering
- `streams_by_target` — Number of audit streams for each destination type (Azure Monitor Logs, Splunk, Azure Event Grid)

**Are the streamed events actually arriving?**
- `azure_monitor_streams_with_rows` — Number of Azure Monitor Logs streams whose workspace has received this organization's audit events in the window
- `azure_monitor_streams_missing_rows` — Number of delivering Azure Monitor Logs streams whose workspace has none of this organization's events, although an organization-level event newer than the stream and more than an hour old should have arrived


### azure_devops_identities
Short Description: Shows every Azure DevOps user's access level, groups and last access, and who holds privileged Azure DevOps groups, directly or through Entra groups.

Script: fetchers/azure/devops_identities/fetcher.py (uses the shared Azure DevOps client fetchers/azure/_shared/devops_rest.py)

Access: A personal access token for the organization with Graph and Member Entitlement Management (both Read), or an Entra identity that is a member of the organization.

Commands Executed:
- `GET _apis/connectionData` — identifies the signed-in user
- `GET _apis/graph/users` — people, and service identities such as the build service
- `GET _apis/graph/serviceprincipals` — service principals and managed identities added to the organization
- `GET _apis/graph/groups` — Azure DevOps and Entra groups in the organization
- `GET _apis/graph/Memberships/{group}` (per group) — each group's direct members
- `GET _apis/userentitlements` — each user's access level, status, date added and last access

Output: `azure_devops_identities_<organization>.json` — every user, service principal and service identity with its access level, last access and direct and inherited groups, every group with its direct members, and each privileged group's effective members with a path to each and whether it is held only through an Entra group.

Summary fields:

**Who is in the organization?**
- `users_total` — Number of people (Entra ID or Microsoft account users) in the organization; null if the users couldn't be read
- `guest_users` — Number of people who are guests in their Entra tenant; null if the users couldn't be read
- `users_by_access_level` — Number of people for each access level, such as Basic or Stakeholder, with unknown for a person who has no entitlement; null if the user entitlements couldn't be read
- `users_by_origin` — Number of people for each identity source; null if the users couldn't be read:
  - aad (Entra ID)
  - msa (Microsoft account)
  - unknown (no identity source recorded)
- `users_with_sign_in_disabled` — Number of people who can't sign in because their entitlement's status is disabled, pending disable or deleted; null if the user entitlements couldn't be read
- `users_deleted_in_origin` — List of people deleted in Entra ID or their Microsoft account who are still in the organization; null if the users couldn't be read
- `service_principals_total` — Number of service principals and managed identities added to the organization; null if they couldn't be read
- `service_identities_total` — Number of Azure DevOps service identities, such as the build service; null if the users couldn't be read
- `groups_total` — Number of groups, Azure DevOps and Entra; null if the groups couldn't be read
- `entra_groups_total` — Number of Entra groups added to the organization; null if the groups couldn't be read
- `groups_not_read` — List of groups whose members couldn't be read (the computed Project Collection Valid Users and Project Valid Users groups, and Azure DevOps enterprise-level groups, are never read and aren't listed); null if the groups couldn't be read

**Are unused accounts removed?**
- `inactivity_threshold_days` — Number of days without access after which a person counts as inactive (90 unless `inactive_days` sets it)
- `last_access_collected` — True if the user entitlements, which hold access levels and last access, were read; false if not
- `inactive_users` — List of inactive people: people who can still sign in but whose last access, or the day they were added if they never signed in, is older than `inactivity_threshold_days`; null if the user entitlements couldn't be read
- `users_never_accessed` — List of people who have never signed in to the organization (Azure DevOps records their last access as 0001-01-01); null if the user entitlements couldn't be read

**Who holds privileged access?**
- `privileged_groups` — Number of privileged groups found, meaning the Azure DevOps groups named Project Collection Administrators, Project Collection Service Accounts, Project Collection Build Administrators, and each project's Project Administrators, Build Administrators, Release Administrators and Endpoint Administrators; null if the groups couldn't be read
- `privileged_groups_not_fully_read` — List of privileged groups whose own members, or a nested group's members, couldn't be read, so the member list may be short; null if the groups couldn't be read
- `privileged_members_by_group` — Number of effective members for each privileged group, meaning the identities in it directly or through nested Azure DevOps or Entra groups; null if the groups couldn't be read
- `privileged_identities` — Number of distinct identities (people, service principals, service identities and Azure DevOps system identities) that are effective members of at least one privileged group; null if the groups couldn't be read
- `privileged_users` — List of people who are effective members of at least one privileged group; null if the groups couldn't be read
- `privileged_service_principals` — List of service principals and managed identities that are effective members of at least one privileged group; null if the groups couldn't be read
- `privileged_identities_only_through_entra_groups` — Number of identities that hold every privileged group they're in only through an Entra group, with no path through Azure DevOps groups alone; null if the groups couldn't be read
- `entra_groups_granting_privilege` — List of Entra groups on the way to a privileged group; Azure DevOps records only the members it has seen, so check these in Entra ID for full membership and PIM; null if the groups couldn't be read
- `inactive_privileged_users` — List of inactive people who are effective members of at least one privileged group; null if the groups or the user entitlements couldn't be read
- `guest_privileged_users` — List of guests who are effective members of at least one privileged group; null if the groups or the users couldn't be read

**What isn't collected?**
- `not_collected` — What the fetcher deliberately doesn't collect, with a note for each area:
  - time_bound_access (Azure DevOps memberships never expire; only a PIM-managed Entra group makes access time-bound)
  - entra_group_members (an Entra group's full membership; Azure DevOps records only the members it has seen)
  - permissions (what each group may do; see the permissions evidence)
  - service_principal_last_access (when a service principal or managed identity last used the organization)


### azure_devops_permissions
Short Description: Shows which identities and groups hold which Azure DevOps permissions at each scope, allowed or denied, and flags high-impact rights held outside the admin groups.

Script: fetchers/azure/devops_permissions/fetcher.py (uses the shared Azure DevOps client fetchers/azure/_shared/devops_rest.py)

Access: A personal access token for the organization with Security (Manage), Identity (Read), Code (Read) and Project and Team (Read), since Azure DevOps has no read-only scope for permissions and the fetcher only reads; or an Entra identity in the organization that can view permissions in each namespace and read every Git repository, since repositories it can't read aren't counted.

Commands Executed:
- `GET _apis/connectionData` — identifies the signed-in user
- `GET _apis/projects` — lists projects, to name them in each entry
- `GET _apis/securitynamespaces` — the security namespaces and the name of each permission bit
- `GET _apis/accesscontrollists/{namespace}` (per namespace) — every permission entry, with inherited and effective rights
- `GET _apis/git/repositories` — counts Git repositories, since branch policies exist only in Git
- `GET _apis/identities` (in batches) — the user, group or service account behind each entry

Output: `azure_devops_permissions_<organization>.json` — every explicit permission entry in the organization's delivery-related namespaces (organization, project, Git and TFVC, build, release, environments, service connections, library and audit streams), with who it applies to, the scope it applies at, and the actions it allows, denies and inherits, plus the high-impact rights held outside the admin groups.

Summary fields:

**What was read?**
- `namespaces_collected` — Number of security namespaces whose permission entries were read
- `namespaces_not_found` — List of expected namespaces missing from the organization's list of security namespaces; null if that list couldn't be read
- `namespaces_not_read` — List of namespaces whose permission entries couldn't be read; null if the list of security namespaces couldn't be read
- `acls_total` — Number of permission lists, one per secured object such as a project, repository, pipeline or service connection; null if a namespace couldn't be read
- `acls_with_inheritance_off` — Number of permission lists that don't inherit from their parent object; null if a namespace couldn't be read
- `entries_total` — Number of permission entries that allow or deny at least one action; null if a namespace couldn't be read
- `entries_by_scope` — Number of permission entries at each scope: organization, project, repository, branch (Git), path (TFVC), folder, pipeline (build), release_stage (classic release), environment, service_connection, variable_group, secure_file or library_item (any other library item); null if a namespace couldn't be read
- `entries_with_deny` — Number of permission entries that deny at least one action; null if a namespace couldn't be read
- `git_repositories` — Number of Git repositories in the projects collected (every project, or only the ones the `projects` setting names); 0 when the organization uses only TFVC; null if they couldn't be listed

**Who holds permissions?**
- `identities_with_explicit_entries` — Number of users, groups and service accounts named in at least one permission entry; null if a namespace couldn't be read
- `unresolved_identities` — Number of identities in permission entries that couldn't be looked up, so their name and type are unknown; null if a namespace couldn't be read
- `users_with_direct_entries` — List of people granted or denied permissions directly rather than through a group; null if a namespace couldn't be read

**Are high-impact rights limited to the admin groups?**
- `high_impact_grants` — Number of permission entries that allow, and don't also deny, a high-impact action, meaning managing permissions or enterprise policies, deleting a project or changing its visibility, editing or bypassing branch policies, deleting a repository or force-pushing, administering TFVC or checking in other users' changes, editing, deleting or administering build and release pipelines, overriding check-in validation, managing release approvers, administering service connections, environments or the library, and managing or deleting audit streams; null if a namespace couldn't be read
- `high_impact_grants_outside_admin_groups` — Number of permission entries that allow a high-impact action to anyone other than the admin groups, meaning the groups named Project Collection Administrators, Project Collection Service Accounts, Project Collection Build Administrators, and each project's Project Administrators, Build Administrators, Release Administrators and Endpoint Administrators; null if a namespace couldn't be read or an identity couldn't be looked up. Expect it above 0 even on an organization left at its defaults, since project Contributors may edit and delete build and release pipelines and manage release approvers, whoever creates a Git branch gets Force push and Manage permissions on it, and whoever creates an environment, service connection or variable group gets the Administrator role on it
- `identities_with_high_impact_rights_outside_admin_groups` — List of users, groups and service accounts outside the admin groups that hold a high-impact action; null if a namespace couldn't be read or an identity couldn't be looked up
- `high_impact_rights_outside_admin_groups_by_right` — Number of permission entries outside the admin groups for each high-impact action, as namespace: action; null if a namespace couldn't be read or an identity couldn't be looked up
- `branch_policy_bypass_holders` — List of identities allowed to bypass Git branch policies (exempt from policy enforcement, or bypass policies when completing a pull request); null if the organization has no Git repositories, as when it uses only TFVC, or if the Git permissions or repositories couldn't be read

**What isn't collected?**
- `not_collected` — What the fetcher deliberately doesn't collect, with a note for each area:
  - group_membership (who is in each group; see the identities evidence)
  - resource_names (repositories, pipelines, environments, service connections and library items appear by id)
  - other_namespaces (namespaces outside the delivery platform: work items, boards, wiki, dashboards, analytics, agent pools)
  - inherited_grants (a high-impact right only inherited from a parent object is flagged on that parent)


### azure_devops_pipelines
Short Description: Shows whether each Azure DevOps pipeline run that deployed was built from version control, passed its tests and scans, and was approved by someone other than its requester.

Script: fetchers/azure/devops_pipelines/fetcher.py (uses the shared Azure DevOps client fetchers/azure/_shared/devops_rest.py)

Access: A personal access token per organization (AZURE_DEVOPS_PAT) with Read on Build, Code, Test Management, Project and Team, and Release, plus Environment (Read & manage), since Azure DevOps has no read-only Environment scope. With no token set, it signs in with Entra ID instead: the identity must be a user in the organization with read access to each project (such as the project Readers group). Either way the fetcher only reads.

Commands Executed:
- `GET _apis/connectionData` — identifies the signed-in user (token or Entra ID)
- `GET _apis/projects` — lists projects
- `GET _apis/build/generalsettings` (per project) — pipeline security settings
- `GET _apis/build/definitions` (per project) — the pipelines
- `GET _apis/build/definitions/{id}` (per classic pipeline whose steps the list left out) — its steps and the service connections they use
- `GET _apis/build/builds` (per project) — completed runs in the lookback window
- `GET _apis/test/runs` (per project) — test results
- `GET _apis/git/repositories/{repo}/refs` (per default branch) — the head commit, so YAML is read at a fixed commit
- `POST _apis/pipelines/{id}/preview` (per YAML pipeline) — the final YAML with templates expanded; nothing is queued
- `GET _apis/git/repositories/{repo}/items` (when the preview is refused) — the raw YAML file
- `GET _apis/build/builds/{id}/timeline` (per run given detail) — the result of each stage, job and task
- `GET _apis/pipelines/approvals` (per run with an approval) — who approved, when, and their comment
- `GET _apis/pipelines/checks/runs/{id}` (per check suite in a run) — the result of each environment check
- `GET _apis/build/builds/{id}/artifacts` (per run given detail) — the artifacts it published; the SARIF artifact is downloaded as a zip
- `GET _apis/pipelines/{id}/runs/{id}` (per YAML run given detail) — the repositories and pipelines it consumed
- `GET _apis/build/builds/{id}/workitems` (per run given detail) — linked work items
- `POST _apis/git/repositories/{repo}/pullrequestquery` (per Git repository) — the pull requests merged as a run's commit
- `GET _apis/distributedtask/environments` (per project) — deployment environments
- `GET _apis/pipelines/checks/configurations` (per environment) — approvals and checks
- `GET _apis/distributedtask/environments/{id}/environmentdeploymentrecords` (per environment) — deployments in the lookback window
- `GET _apis/git/repositories` (per project) — repositories and default branches
- `GET _apis/policy/configurations` (per project) — branch policies
- `GET _apis/release/definitions` and `GET _apis/release/deployments` (per project) — classic release pipelines and their deployments in the lookback window
- `GET _apis/release/releases/{id}` (per release deployed in the window) — its approvals, the tasks it ran, the build it shipped and its service connections

Output: `azure_devops_pipelines_<organization>.json` — for each project: its pipelines with a record of every recent run and, for runs that deployed, their step results, approvals, artifacts and scan findings; its environments with their checks and deployments; its repositories' branch policies; and its classic release deployments.

Summary fields:

**What was collected?**
- `lookback_days` — Number of days back the fetcher looks for runs, test runs and deployments
- `projects_collected` — Number of projects read
- `pipelines_total` — Number of pipelines found
- `yaml_pipelines` — Number of pipelines defined in YAML
- `disabled_pipelines` — Number of pipelines that are disabled and can't be queued
- `yaml_pipelines_analyzed` — Number of YAML pipelines the fetcher analysed: it read the YAML (the final version with templates expanded, or else the raw file from Azure Repos), parsed it, and sorted each enabled step into tests, security scans, infrastructure validation, deploys, signing, signature checks and SBOMs by matching known task names and commands (for example, pytest, trivy, terraform plan, cosign sign)
- `yaml_pipelines_with_templates_expanded` — Number of analysed YAML pipelines read from the final YAML with templates expanded, rather than the raw file (which can't show steps inside templates)
- `yaml_pipelines_not_analyzed` — List of YAML pipelines (project/pipeline) whose YAML couldn't be read or parsed, so their steps weren't checked
- `runs_recorded` — Number of completed pipeline runs in the lookback period with a run record (commit or changeset, requester, times, result and test counts)
- `tfvc_runs` — Number of recorded runs that built a TFVC changeset or shelveset rather than a Git commit
- `runs_with_detail` — Number of runs given detail: the fetcher read their timeline, approvals, check results, artifacts, work items and scan findings. Runs that were deployed come first, newest first, then other runs of pipelines that deploy or use a service connection, then pull-request runs of pipelines that scan or validate infrastructure code, up to the run details limit per project (200 by default)
- `projects_with_run_details_truncated` — List of projects with more runs to detail than the limit, so their oldest candidate runs have a record but no detail

**Which security and quality steps do the pipelines run?**
- `pipelines_with_tests` — Number of analysed pipelines with at least one test step
- `pipelines_with_security_scan` — Number of analysed pipelines with a security-scan step
- `pipelines_with_iac_validation` — Number of analysed pipelines that validate infrastructure code before deploying it (plan, validate or what-if)
- `pipelines_deploying_infrastructure` — Number of analysed pipelines that deploy infrastructure
- `pipelines_signing_artifacts` — Number of analysed pipelines that sign what they build
- `pipelines_verifying_signatures` — Number of analysed pipelines that verify a signature
- `pipelines_generating_sbom` — Number of analysed pipelines that generate an SBOM (software bill of materials)

**Does a failing test stop a deployment?**
- `deploying_pipelines` — Number of analysed pipelines that deploy
- `deploying_pipelines_with_tests` — Number of deploying pipelines that also run tests
- `deploying_pipelines_with_tests_gating_deploys` — Number of deploying pipelines where a failing test stops every deploy
- `deploying_pipelines_without_tests` — List of deploying pipelines (project/pipeline) that run no tests
- `deploying_pipelines_with_ungated_deploys` — List of deploying pipelines (project/pipeline) with a deploy that still runs when a test fails

**Were tests actually run, and did they pass?**
- `pipeline_runs_in_window` — Number of completed pipeline runs in the lookback period
- `test_runs_in_window` — Number of test runs in the lookback period
- `tests_total` — Number of tests in test runs published by a pipeline run
- `tests_passed` — Number of passed tests in test runs published by a pipeline run
- `tests_not_passed` — Number of tests that didn't pass in test runs published by a pipeline run (tests marked not applicable aren't counted)
- `pipelines_with_test_runs_in_window` — Number of pipelines that published test results in the lookback period

**Did each deploying run pass its tests, and was it approved?**
- `deploying_runs` — Number of deploying runs: runs that an environment deployment job or a classic release deployment used, or whose timeline shows a deploy step that ran
- `deploying_runs_with_detail` — Number of deploying runs given detail
- `deploying_runs_with_tests_passed` — Number of deploying runs given detail whose tests passed: when the run deployed itself, at least one test step finished before its first deploy step started and every such test step succeeded; when a release deployed its build, every test step in the run succeeded
- `deploying_runs_without_passing_tests` — List of deploying runs given detail (project/pipeline#run) whose tests didn't pass, didn't finish before the deploy, or didn't run
- `deploying_runs_with_approval` — Number of deploying runs given detail with an environment approval that was approved

**What did security scans find on runs that deployed?**
- `runs_with_scan_results` — Number of runs given detail whose SARIF scan artifact was downloaded and read
- `scan_findings` — Number of unsuppressed, failing SARIF results across the runs read
- `scan_findings_critical` — Number of SARIF findings rated critical: a security-severity score of 9 or more
- `scan_findings_high` — Number of SARIF findings rated high: a security-severity score from 7 to below 9, or, with no score, a result at the error level
- `deploying_runs_with_critical_or_high_findings` — List of deploying runs (project/pipeline#run) whose scan results include a critical or high finding
- `runs_with_scan_steps_but_no_results` — List of runs given detail (project/pipeline#run) that ran a scan or infrastructure-validation step but published no SARIF artifact the fetcher could read

**Are deployment environments protected by checks?**
- `environments_total` — Number of deployment environments
- `environments_with_approval` — Number of environments that require an approval before a deployment
- `environments_with_branch_control` — Number of environments that only accept deployments from allowed branches
- `environments_with_required_template` — Number of environments that only accept pipelines built from a required template
- `environments_with_artifact_evaluation` — Number of environments that check a container image against a policy before deploying it (evaluate-artifact check)
- `environments_without_checks` — List of environments (project/environment) with no enabled check

**What was deployed, and from where?**
- `deployments_in_window` — Number of environment deployments in the lookback period
- `deployments_succeeded` — Number of environment deployments in the lookback period that succeeded
- `deployments_from_default_branch` — Number of environment deployments in the lookback period made from the repository's default branch
- `deployments_with_test_runs` — Number of environment deployments in the lookback period whose pipeline run published test results

**Do code changes need a review or a passing build before merging?**
- `repositories_total` — Number of enabled repositories
- `repositories_requiring_review` — Number of repositories whose default branch requires approval from at least one reviewer other than the author
- `repositories_where_self_approval_satisfies_review` — Number of repositories whose required review the author can approve themselves
- `repositories_requiring_build_validation` — Number of repositories whose default branch requires a successful build before merging
- `repositories_without_review_or_build_validation` — List of repositories (project/repository) whose default branch requires neither a review nor a successful build

**What do classic (non-YAML) pipelines do?**
- `classic_pipelines` — Number of pipelines built in the classic editor
- `projects_with_classic_pipeline_creation_disabled` — Number of projects that block creating new classic pipelines
- `classic_pipelines_analyzed` — Number of classic pipelines whose steps were read and sorted into tests, scans, infrastructure validation and deploys, by their inputs and by the task names their runs' timelines report
- `classic_pipelines_with_tests` — Number of analysed classic pipelines with at least one test step
- `classic_pipelines_deploying` — Number of analysed classic pipelines with a deploy step
- `classic_pipelines_using_service_connections` — Number of analysed classic pipelines with an enabled step that names a service connection
- `classic_release_definitions` — Number of classic release pipelines

**Who approved each classic release deployment, and what did it use?**
- `classic_release_deployments_in_window` — Number of classic release deployments started in the lookback period
- `release_deployments_recorded` — Number of classic release deployments in the lookback period with a deployment record (requester, approvals, tasks run, the build shipped and service connections)
- `release_deployments_succeeded` — Number of recorded classic release deployments that succeeded
- `release_deployments_with_independent_approval` — Number of recorded classic release deployments with an independent approval: a pre-deployment approval given by a person, not automatically, who isn't the one who requested the deployment
- `release_deployments_without_independent_approval` — List of recorded classic release deployments (project/release pipeline/stage#release) without an independent approval
- `release_deployments_using_service_connections` — Number of recorded classic release deployments whose enabled tasks name a service connection
- `projects_with_release_details_truncated` — List of projects with more releases in the lookback period than the run details limit, so their oldest releases weren't read

**What isn't collected?**
- `not_collected` — What the fetcher deliberately doesn't collect, by area:
  - projects the identity can't see;
  - detail for runs beyond the run details limit;
  - classic release gates and manual interventions;
  - whether a failing test stops a later deploy in a classic build;
  - service connections' service principals and execution history (collected by azure_devops_service_connections);
  - pull requests for TFVC runs (TFVC has none);
  - branch-policy bypass identities.


### azure_devops_service_connections
Short Description: Shows how each Azure DevOps service connection authenticates, which service principal it uses and which pipeline runs used it, and whether variable group secrets live in Key Vault.

Script: fetchers/azure/devops_service_connections/fetcher.py (uses the shared Azure DevOps client fetchers/azure/_shared/devops_rest.py)

Access: A personal access token per organization (AZURE_DEVOPS_PAT) with Service Connections, Variable Groups, Secure Files, Build, and Project and Team (all Read). With no token set, it signs in with Entra ID instead: the identity needs Reader on the service connections and on the Library.

Commands Executed:
- `GET _apis/connectionData` — identifies the signed-in user (token or Entra ID)
- `GET _apis/projects` — lists projects
- `GET _apis/serviceendpoint/endpoints` (per project) — service connections, failed ones included, with their sign-in scheme and service principal and tenant ids
- `GET _apis/pipelines/pipelinepermissions/endpoint/{id}` (per connection and project; preview API) — which YAML pipelines may use it
- `GET _apis/serviceendpoint/{id}/executionhistory` (per connection and project; preview API missing from Microsoft's REST reference) — the runs that used it, newest first
- `GET _apis/distributedtask/variablegroups` (per project) — variable groups, their secret counts and Key Vault links
- `GET _apis/distributedtask/securefiles` (per project; preview API) — secure files, by name

Output: `azure_devops_service_connections_<organization>.json` — each service connection with how it authenticates, its service principal, the pipelines allowed to use it and the runs that used it, plus each variable group's secrets and Key Vault link and each secure file.

Summary fields:

**What was collected?**
- `lookback_days` — Number of days back the fetcher looks for runs that used a service connection
- `projects_collected` — Number of projects read
- `service_connections_total` — Number of service connections, each counted once however many projects share it
- `service_connections_by_type` — Number of service connections of each type (for example azurerm for Azure Resource Manager, Generic, GitHub, kubernetes)
- `secure_files_total` — Number of secure files (certificates, keys and other files pipelines download)

**How do service connections authenticate?**
- `service_connections_by_auth_method` — Number of service connections using each sign-in method:
  - workload_identity_federation (a short-lived token, no stored secret)
  - managed_identity (the build agent's Azure identity, no stored secret)
  - github_app (a GitHub App installation, no stored secret)
  - service_principal_secret (a stored client secret)
  - service_principal_certificate (a stored certificate)
  - service_principal (a stored secret or certificate; Azure DevOps didn't say which)
  - username_password, token, personal_access_token, oauth, certificate, publish_profile, kubernetes (other stored credentials)
  - none (no sign-in scheme, though the connection can still keep a key such as a NuGet API key), or the raw scheme name for one the fetcher doesn't recognise
- `azure_service_connections` — Number of Azure Resource Manager (azurerm) service connections
- `azure_service_connections_using_workload_identity_federation` — Number of Azure Resource Manager service connections that use workload identity federation
- `azure_service_connections_with_stored_secret` — List of Azure Resource Manager service connections that hold a stored credential, meaning a secret, certificate, password, token, key, publish profile or kubeconfig kept in Azure DevOps
- `service_connections_with_stored_credential` — List of service connections of any type that hold a stored credential; a connection with no sign-in scheme counts when it keeps any parameter besides the service principal and tenant ids, and one with a scheme the fetcher doesn't recognise is left out
- `service_connections_not_ready` — List of service connections Azure DevOps reports as not ready (creation failed or incomplete)

**Who may use them, and were they used?**
- `service_connections_open_to_all_pipelines` — List of service connections that any YAML pipeline in at least one project may use without being authorised one by one (classic pipelines aren't limited by this); a connection whose pipeline permissions couldn't be read in some project, and that isn't open in another, is left out and the run reports the failure
- `service_principals` — Number of distinct service principals behind the service connections, told apart by tenant id and app id, both compared ignoring case and surrounding spaces
- `service_connections_used_in_window` — Number of service connections used by at least one pipeline run in the lookback period; a pipeline run is a build or a classic release, and the records a release logs for each of its stages count as one run
- `service_connections_unused_in_window` — List of service connections whose history was read in every project and shows no pipeline run in the lookback period
- `pipeline_runs_using_service_connections` — Number of pipeline runs in the lookback period that used at least one service connection, each run counted once however many connections or stages it used

**Are pipeline secrets kept in Key Vault?**
- `variable_groups_total` — Number of variable groups, each counted once however many projects share it
- `variable_groups_key_vault_linked` — Number of variable groups whose variables come from an Azure Key Vault
- `variable_groups_with_secrets_outside_key_vault` — List of variable groups holding secret variables stored in Azure DevOps itself rather than Key Vault
- `secret_variables_total` — Number of secret variables across all variable groups, Key Vault-linked secrets included
- `secret_variables_outside_key_vault` — Number of secret variables stored in Azure DevOps itself rather than Key Vault
- `key_vault_secrets_expired` — Number of Key Vault-linked secrets whose expiry date, as Azure DevOps last read it, has passed
- `key_vault_secrets_without_expiry` — Number of Key Vault-linked secrets with no expiry date set

**What isn't collected?**
- `not_collected` — What the fetcher deliberately doesn't collect, by area:
  - secret values (credentials, secret variables, secure file contents; of a connection's sign-in parameters only the service principal and tenant ids are kept, and its URL is cut to scheme and host);
  - when a service principal's secret or certificate expires (Azure DevOps doesn't expose it);
  - which classic pipelines may use a connection (pipeline permissions limit YAML pipelines only);
  - who holds the User, Creator and Administrator roles on each connection;
  - projects the identity can't see.


### checkov_bicep
Short Description: Shows which Checkov security checks pass and fail in a repository's Bicep and ARM templates, read from git or Azure DevOps TFVC at a recorded commit or changeset.

Script: fetchers/checkov/bicep/fetcher.sh (uses the shared helpers fetchers/checkov/_shared/clone.sh and fetchers/checkov/_shared/tfvc.sh; branch feat/checkov-bicep, not yet merged)

Access: Read access to the code. For Azure DevOps (Git or TFVC), a personal access token with Code (Read); for another git host, a read-only repository token. A public repository or project needs no token.

Commands Executed:
- `git clone --depth 1 --branch <branch>` (git source) — fetches the repository, falling back to its default branch
- `GET _apis/tfvc/changesets` or `GET _apis/tfvc/changesets/{id}` (TFVC source) — finds the project's newest changeset, or reads the one asked for
- `GET _apis/tfvc/items` with `Accept: application/zip` (TFVC source) — downloads the folder at that changeset as one zip
- `find` and `grep` over the files — counts the .bicep files and the ARM templates (JSON with a deploymentTemplate schema)
- `checkov --framework bicep,arm --output json` — runs the Bicep and ARM checks

Output: `checkov_bicep_<source>.json` — every passed, failed and skipped check with its file and resource, and where the code came from: the repository, branch and commit, or the TFVC folder and changeset.

Summary fields:

**What was scanned?**
- `resource_count` — Number of Bicep and ARM resources checkov evaluated; null when no Bicep or ARM files were found or the download, clone or scan failed
- `parsing_errors` — Number of Bicep or ARM files checkov could not parse, so did not scan; any above 0 fails the run (status partial); null when no Bicep or ARM files were found or the download, clone or scan failed
- `by_framework` — Number of passed, failed and skipped checks, parsing errors and resources for each framework that produced a report; empty when nothing was scanned:
  - arm (ARM template JSON files)
  - bicep (.bicep files)

**What did the checks find?**
- `passed_checks` — Number of checks that passed; null when no Bicep or ARM files were found or the download, clone or scan failed
- `failed_checks` — Number of checks that failed, not counting failures moved to skipped by a skip_resources pattern; null when no Bicep or ARM files were found or the download, clone or scan failed
- `skipped_checks` — Number of checks marked skipped, either by a suppression comment in the template or because their resource matched a skip_resources pattern. Checks turned off with skip_checks never run and are not counted (they are listed in the metadata); null when no Bicep or ARM files were found or the download, clone or scan failed
- `skipped_by_resource_filter` — Number of failed checks moved to skipped because their resource matched a skip_resources pattern; null when no Bicep or ARM files were found or the download, clone or scan failed
- `total_checks` — Number of checks evaluated, `passed_checks` + `failed_checks` + `skipped_checks`; 0 fails the run (status no_checks); null when no Bicep or ARM files were found or the download, clone or scan failed

**How many checks pass?**
- `aggregate_percentage` — Percentage of evaluated checks that passed = `passed_checks` / `total_checks` × 100 (to two decimal places); null when `total_checks` is 0 or nothing was scanned. Skipped checks count in the total but not as passing, so they lower it
