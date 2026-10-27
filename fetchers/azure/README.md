# Azure

Azure fetchers pull evidence from your Azure subscriptions, Microsoft Entra ID and
Azure DevOps with Microsoft's Python SDKs and REST APIs. All 77 fetchers are
read-only and sign in with azure-identity's `DefaultAzureCredential`, so no key file
or stored secret is required. Install the SDKs with `pip install -e '.[azure]'` (see
[Install](../../README.md#install)).

## Credential setup

Use a dedicated read-only identity for evidence collection. `DefaultAzureCredential`
tries a service principal, workload identity, managed identity and then a cached
`az login`, and uses the first that works. The full order and the variables the
runner lets through are in [`_categories/azure.yaml`](../_categories/azure.yaml).
When no service principal, workload or managed identity variable is set, 12 fetchers
try a cached `az login` first (the four `azure_sentinel_*`,
`azure_log_analytics_query_audit`, `azure_log_analytics_deletion_rights`,
`azure_log_storage_immutability`, `azure_app_service_backups`,
`azure_change_provenance`, `azure_residual_resources`,
`azure_entra_dormant_identities` and `azure_devops_audit_streams`), so on a VM using its managed identity, set
`AZURE_CLIENT_ID` for a user-assigned identity or don't leave an `az login` on the
runner.

### Option A: Managed or workload identity (recommended on Azure)

On Azure compute (VM, App Service, Container Apps) the managed identity is picked up
with nothing to configure. On AKS with workload identity, the pod's
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE` are passed
through. Neither path stores a secret.

### Option B: `az login` (workstation)

```bash
az login
az account show
```

The fetchers read the Azure CLI's cached token. Run the Entra fetchers as an
application instead (see [Microsoft Graph](#microsoft-graph)): under `az login`,
`azure_entra_authentication_policy` gets a 403 on the authentication methods policy
and security defaults, however privileged the user.

### Option C: Service principal

Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` together. They are
declared once for the whole category as the optional secrets `tenant_id`,
`client_id` and `client_secret`, so a manifest can map them with `set-secret`, or you
can export them in the runner's environment.

### Sovereign clouds

Set `AZURE_AUTHORITY_HOST` (for example `https://login.microsoftonline.us`). The ARM,
Microsoft Graph and Log Analytics endpoints are derived from it. Azure Government
uses the GCC High Graph host (`graph.microsoft.us`), so a DoD tenant is not
supported. Leave it unset for the public cloud.

## Required permissions

**Reader** on each subscription covers every subscription-scoped fetcher except the
additions below. Grant only the rows for the fetchers you run. A refused read is
recorded in `payload.metadata.api_failures` and fails the run, unless the row says
otherwise.

### Azure RBAC

| Access | Needed by | If it is missing |
|---|---|---|
| A custom role with `Microsoft.Web/sites/host/listkeys/action` and `Microsoft.Web/sites/config/list/action` | `azure_function_app_configuration` | Access keys and app settings read `not_authorized` per app; the run succeeds |
| `Microsoft.Web/sites/config/list/action` (optional) | `azure_app_service_backups` | The custom backup configuration reads `not_authorized`; the run succeeds |
| Key Vault Reader (RBAC vaults), or an access policy with key List and Get Rotation Policy (optional) | `azure_key_vault_key_rotation` | The vault reports `data_plane_status: inaccessible`; rotation policies still come from the management plane |
| Log Analytics Reader on the workspaces they query | `azure_log_analytics_query_audit`, `azure_sentinel_analytics_rules`, `azure_sentinel_data_sources`, `azure_sentinel_incidents`, `azure_devops_audit_streams` (Azure Monitor Logs streams) | The KQL query fails |
| Reader on other subscriptions (optional) | `azure_alert_rules` and `azure_activity_log_alerts` (action groups), `azure_app_gateway_waf` (WAF policies), `azure_vnet_egress_routing` (Virtual WAN hubs) | That reference reads unresolved; the run succeeds |
| Reader on the management group (optional) | `azure_policy_assignments` | Management-group custom definitions read `unavailable`; the run succeeds |

Reader also covers the Sentinel fetchers' ARM reads. Microsoft Sentinel Reader on the
workspace is the narrower alternative. The Defender fetchers accept Security Reader
instead of Reader.

### Microsoft Graph

Application permissions on the identity, with admin consent. The Entra fetchers are
tenant-scoped, except `azure_entra_dormant_identities`, which takes a subscription
and reads the tenant it belongs to.

| Permission | Needed by |
|---|---|
| `Application.Read.All` | `azure_entra_app_registrations`, `azure_entra_service_principals` |
| `Policy.Read.All` | `azure_entra_conditional_access_policies`, `azure_entra_authentication_policy` |
| `Directory.Read.All` | `azure_entra_authentication_policy` (group settings, subscribed SKUs), `azure_entra_mfa_status` (users, role members), `azure_entra_privileged_roles`, `azure_residual_resources` (principal lookup), `azure_entra_dormant_identities` (tenant check, users, role members, app registrations, principal lookup) |
| `AuditLog.Read.All` | `azure_entra_mfa_status` (sign-in activity and the registration report), `azure_entra_dormant_identities` (users' and service principals' sign-in activity) |
| `GroupMember.Read.All` | `azure_entra_groups` (groups, members and owners). `Directory.Read.All` covers it and the fetcher's optional permissions below, except `Member.Read.Hidden` |
| `Directory.Read.All` (optional) | `azure_log_analytics_deletion_rights`: principal names; without it the grants are listed by id |
| `Application.Read.All` (optional) | `azure_managed_identity_configuration`: each identity's Graph app permissions; without it `graph_access` reads `not_authorized` and the run succeeds. `azure_entra_groups`: the account state of owners that are apps or managed identities; without it `groups_with_only_disabled_owners` reads null when any owner is one |
| `User.Read.All` (optional) | `azure_entra_groups`: members' and owners' sign-in names, account state and guest status; without it users come back as an id only, so `member_details_readable` and `owner_details_readable` read false, the guest, disabled-user and disabled-owner figures read null, and the run succeeds |
| `Member.Read.Hidden` (optional) | `azure_entra_groups`: members of hidden-membership groups; without it they read unknown and are counted in `hidden_membership_groups_unread`. `Directory.Read.All` doesn't cover it |
| `Organization.Read.All` (optional) | Every `azure_entra_*` fetcher but `azure_entra_dormant_identities`: tenant name and domain; without it the tenant id comes from `AZURE_TENANT_ID`, and the run fails only if that is unset too |

For the Entra fetchers, narrower permissions can stand in for `Directory.Read.All`;
each call's Microsoft Graph reference page lists them.

### Azure DevOps

| PAT scope | Needed by |
|---|---|
| Build, Code, Test Management, Project and Team, Release (all Read), and Environment (Read & manage, as there is no read-only Environment scope) | `azure_devops_pipelines` |
| Read Audit Log (`vso.auditlog`), from a user with View audit log | `azure_devops_audit_streams` |

The PAT is optional. Without one, the fetchers sign in as the ambient Entra identity,
which must be added to the organization: project Reader for pipelines, View audit log
for audit streams. Only the Entra sign-in can read the Log Audit Events policy; with a
PAT, `azure_devops_audit_streams` judges auditing from the audit log instead.

## Wiring into a manifest

Azure fetchers declare no required secrets. Fan out with one target per subscription,
and label each with `environment`:

```bash
paramify manifest add azure_key_vault_configuration
paramify manifest add-target azure_key_vault_configuration subscription_id=<subscription id> environment=prod
paramify validate manifest.yaml
paramify run manifest.yaml
```

Without a target, a subscription fetcher collects from the first enabled subscription
the credential can see.

Other fetchers fan out differently:

```bash
# Entra: one target per tenant
paramify manifest add-target azure_entra_mfa_status tenant_id=<tenant id>

# Azure DevOps: one target per organization; drop --secret to sign in with Entra
paramify manifest add-target azure_devops_pipelines organization_url=https://dev.azure.com/<org> --secret pat=AZURE_DEVOPS_PAT

# Sentinel and Log Analytics: optionally limit to some workspaces
paramify manifest add-target azure_sentinel_incidents subscription_id=<subscription id> workspaces=<workspace name>
```

Multi-tenant Entra targets need a service principal or workload identity per tenant:
a managed identity or `az login` collects its own tenant whatever `tenant_id` says,
and still names the file after the target.

`workspaces` is accepted by the four `azure_sentinel_*` fetchers,
`azure_log_analytics_query_audit` and `azure_log_analytics_deletion_rights`, and
`projects` by `azure_devops_pipelines`. Fetchers with lookback windows or list limits
take `set-config` keys; `paramify describe <fetcher>` lists them with their defaults.

Ready-to-edit manifests:

- [`examples/azure_identity_and_access.yaml`](../../examples/azure_identity_and_access.yaml)
  — the Entra and RBAC fetchers.
- [`examples/azure_data_at_rest.yaml`](../../examples/azure_data_at_rest.yaml) —
  storage encryption, network security groups, Defender plans.
- [`examples/azure_database_posture.yaml`](../../examples/azure_database_posture.yaml)
  — SQL, PostgreSQL, MySQL and Cosmos DB.
- [`examples/azure_compute_posture.yaml`](../../examples/azure_compute_posture.yaml)
  — VMs, disks, AKS and container registries.
- [`examples/azure_appservice_posture.yaml`](../../examples/azure_appservice_posture.yaml)
  — web apps, function apps, App Service plans, Policy assignments, Databricks.
- [`examples/azure_keys_and_monitoring.yaml`](../../examples/azure_keys_and_monitoring.yaml)
  — Key Vault, Activity Log export and alerts, Recovery Services vaults.

## Smoke test

```bash
paramify doctor manifest.yaml --probe
```

`--probe` prints the principal the credential chain resolved to and the first enabled
subscription it can see. It does not check Graph or Azure DevOps access, and it always
calls the public cloud's endpoints.

## Fetchers

Each fetcher's `fetcher.yaml` lists the exact API calls it makes, under
`evidence_set.instructions`. The KSIs each one supports are in
[`docs/ksi_mapping.md`](../../docs/ksi_mapping.md).

Identity and access:

| Fetcher | Evidence |
|---|---|
| `azure_entra_app_registrations` | App registrations and each client secret and certificate with its expiry: expired, due within 30 days, or never expiring |
| `azure_entra_service_principals` | Service principals: type, enabled state, owning tenant, and every secret, certificate and federated credential they can present |
| `azure_entra_authentication_policy` | Allowed sign-in methods (weak and phishing-resistant flagged), registration campaign, security defaults, password protection and the Entra ID licence tier |
| `azure_entra_conditional_access_policies` | Conditional Access policies: state (on, report-only, off), included and excluded users, groups, roles and apps, conditions, grant and session controls |
| `azure_entra_mfa_status` | Each user's enabled state, last sign-in and MFA capability, with coverage for admins, members and guests |
| `azure_entra_privileged_roles` | Activated directory roles and their holders, with Global Administrators counted and tenant-wide admin roles flagged |
| `azure_entra_dormant_identities` | Users and service principals holding a directory role or an Azure role in the subscription, with their last sign-in: dormant, never-used, guest and deleted identities flagged |
| `azure_entra_groups` | Groups with their members and owners: kind, whether they can hold directory roles, and dynamic (paused flagged), assigned or synced membership, with groups that have no owner, only disabled owners, guests or disabled users flagged |
| `azure_rbac_role_assignments` | Role assignments at the subscription and above, and separately below it, with Owner, Contributor, User Access Administrator and RBAC Administrator flagged; whether each is permanent, time-bound or activated through PIM, PIM-eligible assignments, and the over-broad roles' PIM activation settings |
| `azure_rbac_custom_roles` | Custom role definitions with their full permission sets, flagged for wildcards and for permissions that allow privilege escalation |
| `azure_managed_identity_configuration` | Managed identities: attached resources, federated credentials, Azure roles judged by their permissions, and Microsoft Graph app permissions |

Network and edge:

| Fetcher | Evidence |
|---|---|
| `azure_network_security_groups` | NSG rules (whether admin ports such as 22 and 3389 are reachable from the internet) and each subnet's NSG association |
| `azure_vnet_egress_routing` | Where each subnet's internet-bound traffic goes: a firewall or appliance, a gateway, a NAT gateway, a black hole, or Azure's default outbound access |
| `azure_ddos_protection` | Whether every public IP is covered by DDoS Network or IP Protection, and every DDoS protection plan |
| `azure_dns_configuration` | Public zones with DNSSEC state and signing keys; private zones and their virtual network links |
| `azure_vpn_gateway_configuration` | VPN gateways (SKU, active-active, BGP, point-to-site) and each connection's IKE version and IPsec/IKE policy |
| `azure_virtual_wan_configuration` | Virtual WANs and hubs: VPN encryption, transit settings, secured hubs, and each hub VPN connection's IKE and IPsec settings |
| `azure_app_gateway_tls_listeners` | Application Gateway listeners: protocol, public or private frontend, HTTP-to-HTTPS redirects, and the TLS policy in effect |
| `azure_app_gateway_backend_tls` | Application Gateway backend settings: whether traffic to the backend is encrypted and its certificate validated |
| `azure_app_gateway_waf` | The WAF that applies to each Application Gateway listener, whether it is in Prevention mode, and every WAF policy's rules |
| `azure_front_door_tls` | Front Door routes that accept only HTTPS, and each custom domain's minimum TLS version and certificate |
| `azure_front_door_origins` | Front Door origin groups and origins: regions, active-active or failover, health probes, and how Front Door connects to them |
| `azure_front_door_waf_policies` | Front Door WAF policies: mode, managed rule sets, overrides, exclusions, custom rules, and whether each blocks |
| `azure_front_door_waf_coverage` | Each Front Door host resolved to the WAF policy that applies to it, with hosts lacking a blocking WAF flagged |
| `azure_api_management_configuration` | API Management services: network exposure, legacy TLS and ciphers, portal sign-up, how each API is protected, subscriptions, backends, audit logs |

Compute, containers and apps:

| Fetcher | Evidence |
|---|---|
| `azure_vm_hardening_status` | VMs and scale sets: Trusted Launch, encryption at host, managed disks, SSH-key-only Linux sign-in, source image |
| `azure_aks_cluster_configuration` | AKS control planes: private cluster or authorized IP ranges, Kubernetes RBAC and Entra integration, local accounts, workload identity, network policy |
| `azure_container_registry_configuration` | Container registries: admin account, anonymous pull, network access and private endpoints |
| `azure_container_workloads_configuration` | Container Apps environments, apps and jobs, and Container Instances: exposure, encryption between containers, identities, logging |
| `azure_app_service_configuration` | Web apps: HTTPS-only, minimum TLS, FTP state, client certificates, App Service Authentication, managed identity, network access |
| `azure_function_app_configuration` | Function apps: network exposure, transport settings, runtime, identity, and the names of access keys and app settings (never values) |
| `azure_app_service_plans` | App Service plans: SKU, instance count, zone redundancy, scaling, and the apps on each |
| `azure_ai_hub_configuration` | AI hubs, projects and Machine Learning workspaces: network exposure, managed network isolation, encryption, connections, endpoints and compute |
| `azure_ai_services_configuration` | AI services accounts (Foundry, OpenAI and others) and AI Search: network exposure, API keys or Entra only, encryption, audit logs, model deployments, content filters, agent connections |
| `azure_databricks_workspace_configuration` | Databricks workspaces: public access, secure cluster connectivity, VNet injection and customer-managed keys |

Data, storage and keys:

| Fetcher | Evidence |
|---|---|
| `azure_storage_encryption_status` | Storage accounts: customer- or platform-managed key, infrastructure encryption, HTTPS and TLS, public access, network rules, shared-key access, access-key age (never the keys), geo-replication health, each blob container's anonymous access and immutability, owner and classification tags |
| `azure_disk_encryption_status` | Managed disks: platform key, customer-managed key or double encryption, Azure Disk Encryption, export exposure |
| `azure_key_vault_configuration` | Key vaults: RBAC or access policies, soft delete and purge protection, network exposure, and whether audit events are exported |
| `azure_key_vault_key_rotation` | Every key's rotation policy and expiry, and every secret's expiry. No key material or secret value is read |
| `azure_sql_encryption_status` | Azure SQL TDE key source (customer- or service-managed), key auto-rotation, and per-database TDE state |
| `azure_sql_server_configuration` | Azure SQL servers: public access, minimum TLS, Entra admin and Entra-only auth, firewall rules (allow-all flagged), auditing, Defender alerts, vulnerability assessment |
| `azure_sql_managed_instance_configuration` | SQL Managed Instances: public data endpoint, connection type, minimum TLS, private endpoints, Entra admin and Entra-only auth |
| `azure_sql_managed_instance_encryption` | SQL Managed Instance TDE protector (service- or customer-managed key) and per-database TDE state |
| `azure_postgresql_configuration` | PostgreSQL flexible servers: secure transport, Entra auth and admins, logging parameters, firewall rules |
| `azure_mysql_configuration` | MySQL flexible servers: secure transport, every accepted TLS version, audit logging, network access |
| `azure_cosmosdb_configuration` | Cosmos DB accounts: customer-managed key, local auth disabled, firewall and network access, minimum TLS |
| `azure_redis_cache_configuration` | Azure Cache for Redis: minimum TLS, non-TLS port, access-key or Entra auth, network access and firewall rules |
| `azure_managed_redis_configuration` | Azure Managed Redis clusters and databases: minimum TLS, client protocol, access-key auth, network access, customer-managed keys |
| `azure_data_services_configuration` | DocumentDB (MongoDB vCore), Data Explorer and Event Hubs: network exposure, client authentication, admin assignments, logging |

Backup and recovery:

| Fetcher | Evidence |
|---|---|
| `azure_backup_recovery_status` | Recovery Services vaults: backup policies and retention, protected items and their last backup |
| `azure_app_service_backups` | Whether each web app is actually backed up: newest restore point, gaps, custom backup schedule and history |
| `azure_sql_managed_instance_backups` | SQL Managed Instance backup storage redundancy, zone redundancy, retention and failover groups |

Logging and monitoring:

| Fetcher | Evidence |
|---|---|
| `azure_diagnostic_settings` | Subscription diagnostic settings that export the Activity Log: categories and destinations |
| `azure_resource_diagnostic_settings` | Every resource's log categories and whether a diagnostic setting exports them, and where |
| `azure_log_analytics_workspaces` | Log Analytics workspaces: retention, daily cap, network access, access control mode |
| `azure_log_analytics_query_audit` | Whether each workspace audits queries, and who queried the logs in which weeks |
| `azure_log_analytics_deletion_rights` | Who can purge, delete or shorten the retention of each workspace's log data, active or PIM-eligible |
| `azure_log_storage_immutability` | Immutability policies, legal holds and soft delete on the blob containers Azure Monitor writes logs to |
| `azure_network_flow_logs` | Network Watchers and flow logs (target, state, storage, retention, Traffic Analytics), and which virtual networks and subnets an enabled flow log covers |
| `azure_alert_rules` | Metric, log search and smart detector alert rules, resolved to the receivers they notify and checked against suppression rules |
| `azure_activity_log_alerts` | Activity log alert rules and which security-relevant control-plane operations they cover |

Microsoft Sentinel:

| Fetcher | Evidence |
|---|---|
| `azure_sentinel_analytics_rules` | Analytics rules per workspace: kind, state, severity, MITRE tactics and techniques, a hash of each query (the text is opt-in), suppression, the tables each reads and whether they got data, which incident-creation rules are quiet (no alert from a product whose alerts are wired up), and whether Fusion is on |
| `azure_sentinel_automation_rules` | Automation rules per workspace: triggers, conditions, state and actions |
| `azure_sentinel_data_sources` | Data connectors per workspace, and which tables received data in the ingestion window |
| `azure_sentinel_incidents` | Incidents in the lookback plus every open one: severity, status, classification, owner and time to close |

Defender for Cloud and Azure Policy:

| Fetcher | Evidence |
|---|---|
| `azure_defender_plans` | Defender for Cloud plans: tier, sub-plan, enablement and coverage |
| `azure_defender_assessments` | Every Defender for Cloud assessment result per resource, with status and severity |
| `azure_defender_regulatory_compliance` | Regulatory compliance standards, their controls and assessments, with passed, failed and skipped counts |
| `azure_policy_assignments` | Policy assignments in effect, own and inherited: enforcement mode, scope, exclusions, and whether each actually enforces |
| `azure_policy_compliance` | Non-compliant resources and policies, evaluation details, and remediation tasks with their deployments |

Inventory and change:

| Fetcher | Evidence |
|---|---|
| `azure_resource_inventory` | Every resource from Resource Graph with type, location, tags and SKU, plus its Defender for Cloud coverage |
| `azure_residual_resources` | Leftovers: unattached disks, NICs and public IPs, unused NSGs, empty resource groups, stale slots, unused identities, assignments to deleted principals |
| `azure_change_provenance` | Every control-plane change in the last 14 days, attributed to a pipeline, a manual deployment or a direct edit |

Azure DevOps:

| Fetcher | Evidence |
|---|---|
| `azure_devops_pipelines` | Pipelines and what their YAML tests, scans and deploys, whether a failing test stops each deploy, runs, test results, environment checks and branch policies |
| `azure_devops_audit_streams` | Whether auditing is on, every audit stream and its status, and whether Azure Monitor Logs streams are receiving events |

## Notes

- One evidence file per target, written with sorted keys and a stable order, so a
  diff between runs shows real changes.
- Any failed API call is listed in `payload.metadata.api_failures`, sets
  `partial_failure: true` and exits non-zero. The failure reason and code follow the
  [fetcher contract](../../docs/fetcher_contract_guide.md).
- A resource provider that is not registered on the subscription is reported as
  `provider_registration_status: not_registered`, which means the service is not in
  use. It is not a failure.
- Most `*_percentage` summary fields are whole numbers rounded down, and 0 when there
  is nothing to count. Check the matching total before reading 0 as a finding.
- `paramify doctor` checks the installed Azure SDKs against the pins in
  `requirements.txt`. A wrong major version can return wrong or empty evidence rather
  than an error.
- The Azure DevOps fetchers accept Azure DevOps Services URLs
  (`https://dev.azure.com/<org>`, `https://<org>.visualstudio.com` or a bare
  organization name), not Azure DevOps Server.
- Rotating a service principal's secret means updating `AZURE_CLIENT_SECRET` in your
  secrets store. Managed and workload identities need nothing.
