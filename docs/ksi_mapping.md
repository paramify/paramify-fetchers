# Fetcher ↔ KSI mapping

**FedRAMP Consolidated Rules for 2026 — KSI release 2026.07.14.01**

Source of truth for the indicators: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json). Statements below are verbatim from it.

> [!IMPORTANT]
> These are **suggested / related** mappings. A `ksis` entry says *this evidence speaks to this indicator* — not that the fetcher alone satisfies it. Treat the mapping as the starting point for an assessor conversation, not a substitute for one. Where a claim would need a generous reading of the statement, the indicator is left uncovered on purpose: an honest gap is more useful than a mapping that has to be defended.

Generated — do not hand-edit. Change a fetcher's `ksis:` (or the reference) and regenerate:

```
python tools/gen_ksi_mapping.py
```

## Coverage

**35 of 36** config-evidenceable indicators covered — **97.2%**. Plus 10 organizational indicators (evidenced by HR, training or process, not cloud config), for 46 total.

| Family | | Covered | Gaps |
|---|---|---|---|
| `CNA` | Cloud Native Architecture | `██████████` 8/8 | — |
| `SVC` | Service Configuration | `██████████` 6/6 | — |
| `MLA` | Monitoring, Logging, and Auditing | `████████░░` 4/5 | `KSI-MLA-ALA` |
| `IAM` | Identity and Access Management | `██████████` 6/6 | — |
| `CMT` | Change Management | `██████████` 3/3 | — |
| `RPL` | Recovery Planning | `██████████` 2/2 | — |
| `PIY` | Policy and Inventory | `██████████` 1/1 | — |
| `SCR` | Supply Chain Risk | `██████████` 2/2 | — |
| `CED` | Cybersecurity Education | `██████████` 1/1 | — |
| `INR` | Incident Response | `██████████` 2/2 | — |

## Indicators, and what covers them

### CNA — Cloud Native Architecture  (8/8)

#### ✅ `KSI-CNA-DFP` — Defining Functionality and Privileges

> The functionality and privileges for infrastructure and services are strictly defined.

*Controls:* `cm-2`, `si-3`

*2 fetchers:* [`aws_organizations_scp`](../fetchers/aws/organizations_scp), [`k8s_kubectl_security`](../fetchers/k8s/kubectl_security)

#### ✅ `KSI-CNA-EIS` — Enforcing Intended State *(optional at Low)*

> Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.

*Controls:* `ca-2.1`, `ca-7.1`

*6 fetchers:* [`azure_defender_assessments`](../fetchers/azure/defender_assessments), [`azure_defender_plans`](../fetchers/azure/defender_plans), [`azure_policy_assignments`](../fetchers/azure/policy_assignments), [`crowdstrike_prevention_policies`](../fetchers/crowdstrike/prevention_policies), [`oci_cloud_guard_posture`](../fetchers/oci/cloud_guard_posture), [`sentinelone_agents`](../fetchers/sentinelone/agents)

#### ✅ `KSI-CNA-IBP` — Implementing Best Practices

> The use and configuration of third-party machine-based information resources is persistently compared against the original provider's best practices and guidance.

*Controls:* `ac-17.3`, `cm-2`, `pl-10`

*4 fetchers:* [`aws_config_conformance_packs`](../fetchers/aws/config_conformance_packs), [`aws_securityhub_status`](../fetchers/aws/securityhub_status), [`crowdstrike_zero_trust_assessment`](../fetchers/crowdstrike/zero_trust_assessment), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration)

#### ✅ `KSI-CNA-MAT` — Minimizing Attack Surface

> Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.

*Controls:* `ac-17.3`, `ac-18.1`, `ac-18.3`, `ac-20.1`, `ca-9`, `sc-7.3`, `sc-7.4`, `sc-7.5`, `sc-7.8`, `sc-8`, `sc-10`, `si-10`, `si-11`, `si-16`

*21 fetchers:* [`aws_ec2_public_exposure`](../fetchers/aws/ec2_public_exposure), [`aws_security_groups`](../fetchers/aws/security_groups), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_app_service_configuration`](../fetchers/azure/app_service_configuration), [`azure_container_registry_configuration`](../fetchers/azure/container_registry_configuration), [`azure_databricks_workspace_configuration`](../fetchers/azure/databricks_workspace_configuration), [`azure_function_app_configuration`](../fetchers/azure/function_app_configuration), [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration), [`azure_network_security_groups`](../fetchers/azure/network_security_groups), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`azure_vm_hardening_status`](../fetchers/azure/vm_hardening_status), [`crowdstrike_firewall_policies`](../fetchers/crowdstrike/firewall_policies), [`gcp_cloud_sql_network_configuration`](../fetchers/gcp/cloud_sql_network_configuration), [`gcp_compute_instance_configuration`](../fetchers/gcp/compute_instance_configuration), [`gcp_firewall_rules`](../fetchers/gcp/firewall_rules), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`k8s_eks_microservice_segmentation`](../fetchers/k8s/eks_microservice_segmentation), [`k8s_kubectl_security`](../fetchers/k8s/kubectl_security), [`oci_compute_instances`](../fetchers/oci/compute_instances), [`oci_data_service_exposure`](../fetchers/oci/data_service_exposure), [`oci_network_exposure`](../fetchers/oci/network_exposure)

#### ✅ `KSI-CNA-OFA` — Optimizing for Availability

> Machine-based information resources are persistently reviewed to ensure they are appropriately optimized for high availability and rapid recovery.

*13 fetchers:* [`aws_auto_scaling_high_availability`](../fetchers/aws/auto_scaling_high_availability), [`aws_backup_recovery_high_availability`](../fetchers/aws/backup_recovery_high_availability), [`aws_cloudwatch_high_availability`](../fetchers/aws/cloudwatch_high_availability), [`aws_database_high_availability`](../fetchers/aws/database_high_availability), [`aws_efs_high_availability`](../fetchers/aws/efs_high_availability), [`aws_eks_high_availability`](../fetchers/aws/eks_high_availability), [`aws_global_accelerator_ha`](../fetchers/aws/global_accelerator_ha), [`aws_load_balancer_high_availability`](../fetchers/aws/load_balancer_high_availability), [`aws_network_resilience_high_availability`](../fetchers/aws/network_resilience_high_availability), [`aws_route53_high_availability`](../fetchers/aws/route53_high_availability), [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration), [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration)

#### ✅ `KSI-CNA-RNT` — Restricting Network Traffic

> Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.

*Controls:* `ac-17.3`, `ca-9`, `cm-7.1`, `sc-7.5`, `si-8`

*15 fetchers:* [`aws_network_acls`](../fetchers/aws/network_acls), [`aws_network_firewall_rules`](../fetchers/aws/network_firewall_rules), [`aws_security_groups`](../fetchers/aws/security_groups), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration), [`azure_network_security_groups`](../fetchers/azure/network_security_groups), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`azure_storage_encryption_status`](../fetchers/azure/storage_encryption_status), [`crowdstrike_firewall_policies`](../fetchers/crowdstrike/firewall_policies), [`gcp_cloud_sql_network_configuration`](../fetchers/gcp/cloud_sql_network_configuration), [`gcp_firewall_rules`](../fetchers/gcp/firewall_rules), [`oci_data_service_exposure`](../fetchers/oci/data_service_exposure), [`oci_network_exposure`](../fetchers/oci/network_exposure), [`oci_zpr_policies`](../fetchers/oci/zpr_policies)

#### ✅ `KSI-CNA-RVP` — Reviewing Protections

> The effectiveness of protection against denial of service attacks and other unwanted activity for machine-based information resources is persistently reviewed.

*Controls:* `sc-5`, `si-8`, `si-8.2`

*4 fetchers:* [`aws_cloudfront_distribution_security`](../fetchers/aws/cloudfront_distribution_security), [`aws_shield_dos_protection`](../fetchers/aws/shield_dos_protection), [`aws_waf_all_rules`](../fetchers/aws/waf_all_rules), [`aws_waf_dos_rules`](../fetchers/aws/waf_dos_rules)

#### ✅ `KSI-CNA-ULN` — Using Logical Networking

> Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.

*Controls:* `ac-12`, `ac-17.3`, `ca-9`, `sc-4`, `sc-7`, `sc-7.7`, `sc-8`, `sc-10`

*10 fetchers:* [`aws_network_acls`](../fetchers/aws/network_acls), [`aws_network_firewall_rules`](../fetchers/aws/network_firewall_rules), [`aws_vpc_network_segmentation`](../fetchers/aws/vpc_network_segmentation), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_databricks_workspace_configuration`](../fetchers/azure/databricks_workspace_configuration), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`gcp_vpc_network_configuration`](../fetchers/gcp/vpc_network_configuration), [`k8s_eks_microservice_segmentation`](../fetchers/k8s/eks_microservice_segmentation), [`k8s_kubectl_security`](../fetchers/k8s/kubectl_security), [`oci_zpr_policies`](../fetchers/oci/zpr_policies)

### SVC — Service Configuration  (6/6)

#### ✅ `KSI-SVC-ACM` — Automating Configuration Management

> The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.

*Controls:* `ac-2.4`, `cm-2`, `cm-2.2`, `cm-2.3`, `cm-6`, `cm-7.1`, `pl-9`, `pl-10`, `sa-5`, `si-5`, `sr-10`

*3 fetchers:* [`aws_cloudformation_drift`](../fetchers/aws/cloudformation_drift), [`aws_config_monitoring`](../fetchers/aws/config_monitoring), [`azure_policy_assignments`](../fetchers/azure/policy_assignments)

#### ✅ `KSI-SVC-ASM` — Automating Secret Management

> Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

*Controls:* `ac-17.2`, `ia-5.2`, `ia-5.6`, `sc-12`, `sc-17`

*12 fetchers:* [`aws_acm_certificate_status`](../fetchers/aws/acm_certificate_status), [`aws_kms_key_rotation`](../fetchers/aws/kms_key_rotation), [`aws_secrets_manager_rotation`](../fetchers/aws/secrets_manager_rotation), [`azure_databricks_workspace_configuration`](../fetchers/azure/databricks_workspace_configuration), [`azure_entra_app_registrations`](../fetchers/azure/entra_app_registrations), [`azure_key_vault_key_rotation`](../fetchers/azure/key_vault_key_rotation), [`azure_storage_encryption_status`](../fetchers/azure/storage_encryption_status), [`gcp_api_keys_inventory`](../fetchers/gcp/api_keys_inventory), [`gcp_iam_service_accounts`](../fetchers/gcp/iam_service_accounts), [`gcp_kms_key_configuration`](../fetchers/gcp/kms_key_configuration), [`gcp_secret_manager_configuration`](../fetchers/gcp/secret_manager_configuration), [`oci_vault_keys`](../fetchers/oci/vault_keys)

#### ✅ `KSI-SVC-EIS` — Evaluating and Improving Security

> Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.

*Controls:* `cm-7.1`, `cm-12.1`, `ma-2`, `pl-8`, `sc-7`, `sc-39`, `si-2.2`, `si-4`, `sr-10`

*13 fetchers:* [`aws_guard_duty_findings`](../fetchers/aws/guard_duty_findings), [`aws_inspector_vulnerability_scanning`](../fetchers/aws/inspector_vulnerability_scanning), [`aws_ssm_patch_compliance`](../fetchers/aws/ssm_patch_compliance), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_app_service_configuration`](../fetchers/azure/app_service_configuration), [`azure_defender_assessments`](../fetchers/azure/defender_assessments), [`azure_defender_plans`](../fetchers/azure/defender_plans), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`crowdstrike_spotlight_vulnerabilities`](../fetchers/crowdstrike/spotlight_vulnerabilities), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`paramify_accepted_vulnerabilities`](../fetchers/paramify/accepted_vulnerabilities), [`paramify_historical_ver_activity`](../fetchers/paramify/historical_ver_activity), [`paramify_vulnerability_detail_report`](../fetchers/paramify/vulnerability_detail_report)

#### ⬜ `KSI-SVC-PRR` — Preventing Residual Risk *(optional at Low)*

> Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

*Controls:* `sc-4`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ⬜ `KSI-SVC-RUD` — Removing Unwanted Data *(optional at Low)*

> Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

*Controls:* `si-12.3`, `si-18.4`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ✅ `KSI-SVC-SIN` — Securing Information

> Information is encrypted or otherwise secured from unwanted access or modification.

*Controls:* `ac-1`, `ac-17.2`, `cp-9.8`, `sc-8`, `sc-8.1`, `sc-13`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-28`, `sc-28.1`

*56 fetchers:* [`aws_apigateway_tls_enforcement`](../fetchers/aws/apigateway_tls_enforcement), [`aws_athena_encryption_status`](../fetchers/aws/athena_encryption_status), [`aws_block_storage_encryption_status`](../fetchers/aws/block_storage_encryption_status), [`aws_cloudfront_distribution_security`](../fetchers/aws/cloudfront_distribution_security), [`aws_codeartifact_encryption_status`](../fetchers/aws/codeartifact_encryption_status), [`aws_component_ssl_enforcement_status`](../fetchers/aws/component_ssl_enforcement_status), [`aws_dms_encryption_status`](../fetchers/aws/dms_encryption_status), [`aws_documentdb_encryption_status`](../fetchers/aws/documentdb_encryption_status), [`aws_dynamodb_encryption_status`](../fetchers/aws/dynamodb_encryption_status), [`aws_ebs_snapshot_status`](../fetchers/aws/ebs_snapshot_status), [`aws_efs_encryption_status`](../fetchers/aws/efs_encryption_status), [`aws_elasticache_encryption_status`](../fetchers/aws/elasticache_encryption_status), [`aws_emr_encryption_status`](../fetchers/aws/emr_encryption_status), [`aws_firehose_encryption_status`](../fetchers/aws/firehose_encryption_status), [`aws_fsx_encryption_status`](../fetchers/aws/fsx_encryption_status), [`aws_glacier_encryption_status`](../fetchers/aws/glacier_encryption_status), [`aws_glue_encryption_status`](../fetchers/aws/glue_encryption_status), [`aws_kafka_encryption_status`](../fetchers/aws/kafka_encryption_status), [`aws_kinesis_encryption_status`](../fetchers/aws/kinesis_encryption_status), [`aws_load_balancer_encryption_status`](../fetchers/aws/load_balancer_encryption_status), [`aws_macie_data_discovery`](../fetchers/aws/macie_data_discovery), [`aws_memorydb_encryption_status`](../fetchers/aws/memorydb_encryption_status), [`aws_neptune_encryption_status`](../fetchers/aws/neptune_encryption_status), [`aws_opensearch_encryption_status`](../fetchers/aws/opensearch_encryption_status), [`aws_rds_encryption_status`](../fetchers/aws/rds_encryption_status), [`aws_rds_tls_configuration`](../fetchers/aws/rds_tls_configuration), [`aws_redshift_encryption_status`](../fetchers/aws/redshift_encryption_status), [`aws_s3_encryption_status`](../fetchers/aws/s3_encryption_status), [`aws_sagemaker_encryption_status`](../fetchers/aws/sagemaker_encryption_status), [`aws_sns_encryption_status`](../fetchers/aws/sns_encryption_status), [`aws_sqs_encryption_status`](../fetchers/aws/sqs_encryption_status), [`aws_transfer_tls_enforcement`](../fetchers/aws/transfer_tls_enforcement), [`azure_app_service_configuration`](../fetchers/azure/app_service_configuration), [`azure_container_registry_configuration`](../fetchers/azure/container_registry_configuration), [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration), [`azure_databricks_workspace_configuration`](../fetchers/azure/databricks_workspace_configuration), [`azure_disk_encryption_status`](../fetchers/azure/disk_encryption_status), [`azure_function_app_configuration`](../fetchers/azure/function_app_configuration), [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration), [`azure_sql_encryption_status`](../fetchers/azure/sql_encryption_status), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`azure_storage_encryption_status`](../fetchers/azure/storage_encryption_status), [`azure_vm_hardening_status`](../fetchers/azure/vm_hardening_status), [`gcp_bigquery_dataset_configuration`](../fetchers/gcp/bigquery_dataset_configuration), [`gcp_cloud_sql_encryption_status`](../fetchers/gcp/cloud_sql_encryption_status), [`gcp_cloud_storage_encryption_status`](../fetchers/gcp/cloud_storage_encryption_status), [`gcp_dns_configuration`](../fetchers/gcp/dns_configuration), [`gcp_load_balancer_tls_configuration`](../fetchers/gcp/load_balancer_tls_configuration), [`gcp_persistent_disk_encryption_status`](../fetchers/gcp/persistent_disk_encryption_status), [`oci_block_volume_encryption`](../fetchers/oci/block_volume_encryption), [`oci_certificates`](../fetchers/oci/certificates), [`oci_compute_instances`](../fetchers/oci/compute_instances), [`oci_data_service_exposure`](../fetchers/oci/data_service_exposure), [`oci_object_storage_buckets`](../fetchers/oci/object_storage_buckets), [`oci_vault_keys`](../fetchers/oci/vault_keys)

#### ✅ `KSI-SVC-VCM` — Validating Communications *(optional at Low)*

> The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

*Controls:* `sc-23`, `si-7.1`

*1 fetcher:* [`oci_certificates`](../fetchers/oci/certificates)

#### ✅ `KSI-SVC-VRI` — Validating Resource Integrity

> Use cryptographic methods to validate the integrity of machine-based information resources.

*Controls:* `cm-2.2`, `cm-8.3`, `sc-13`, `sc-23`, `si-7`, `si-7.1`, `sr-10`

*5 fetchers:* [`azure_container_registry_configuration`](../fetchers/azure/container_registry_configuration), [`azure_vm_hardening_status`](../fetchers/azure/vm_hardening_status), [`gcp_compute_instance_configuration`](../fetchers/gcp/compute_instance_configuration), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`oci_compute_instances`](../fetchers/oci/compute_instances)

### MLA — Monitoring, Logging, and Auditing  (4/5)

#### ❌ `KSI-MLA-ALA` — Authorizing Log Access *(optional at Low)*

> A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.

*Controls:* `si-11`

*No fetcher covers this yet — a capability gap, not a mapping gap.*

#### ✅ `KSI-MLA-EVC` — Evaluating Configurations

> The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

*Controls:* `ca-7`, `cm-2`, `cm-6`, `si-7.7`

*7 fetchers:* [`aws_cloudformation_drift`](../fetchers/aws/cloudformation_drift), [`aws_config_conformance_packs`](../fetchers/aws/config_conformance_packs), [`aws_config_monitoring`](../fetchers/aws/config_monitoring), [`checkov_kubernetes`](../fetchers/checkov/kubernetes), [`checkov_terraform`](../fetchers/checkov/terraform), [`datadog_infra_agent_checks`](../fetchers/datadog/infra_agent_checks), [`oci_cloud_guard_posture`](../fetchers/oci/cloud_guard_posture)

#### ✅ `KSI-MLA-LET` — Logging Event Types

> A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

*Controls:* `ac-2.4`, `ac-6.9`, `ac-17.1`, `ac-20.1`, `au-2`, `au-7.1`, `au-12`, `si-4.4`, `si-4.5`, `si-7.7`

*10 fetchers:* [`aws_vpc_flow_logs`](../fetchers/aws/vpc_flow_logs), [`azure_diagnostic_settings`](../fetchers/azure/diagnostic_settings), [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`datadog_log_indexes`](../fetchers/datadog/log_indexes), [`datadog_log_pipelines`](../fetchers/datadog/log_pipelines), [`oci_audit_logging_events`](../fetchers/oci/audit_logging_events), [`oci_network_exposure`](../fetchers/oci/network_exposure), [`oci_object_storage_buckets`](../fetchers/oci/object_storage_buckets)

#### ✅ `KSI-MLA-OSM` — Operating SIEM Capability

> A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.

*Controls:* `ac-17.1`, `ac-20.1`, `au-2`, `au-3`, `au-3.1`, `au-4`, `au-5`, `au-6.1`, `au-6.3`, `au-7`, `au-7.1`, `au-8`, `au-9`, `au-11`, `ir-4.1`, `si-4.2`, `si-4.4`, `si-7.7`

*7 fetchers:* [`aws_cloudtrail_configuration`](../fetchers/aws/cloudtrail_configuration), [`aws_securityhub_status`](../fetchers/aws/securityhub_status), [`datadog_log_archives`](../fetchers/datadog/log_archives), [`datadog_siem_configuration`](../fetchers/datadog/siem_configuration), [`datadog_siem_detection_rules`](../fetchers/datadog/siem_detection_rules), [`gcp_cloud_logging_configuration`](../fetchers/gcp/cloud_logging_configuration), [`oci_audit_logging_events`](../fetchers/oci/audit_logging_events)

#### ✅ `KSI-MLA-RVL` — Reviewing Logs

> Logs are persistently reviewed and audited.

*Controls:* `ac-2.4`, `ac-6.9`, `au-2`, `au-6`, `au-6.1`, `si-4`, `si-4.4`

*10 fetchers:* [`aws_cloudwatch_high_availability`](../fetchers/aws/cloudwatch_high_availability), [`aws_guard_duty`](../fetchers/aws/guard_duty), [`aws_guard_duty_findings`](../fetchers/aws/guard_duty_findings), [`azure_activity_log_alerts`](../fetchers/azure/activity_log_alerts), [`crowdstrike_detections`](../fetchers/crowdstrike/detections), [`datadog_monitors_list`](../fetchers/datadog/monitors_list), [`datadog_siem_detection_rules`](../fetchers/datadog/siem_detection_rules), [`datadog_siem_signals`](../fetchers/datadog/siem_signals), [`sentinelone_activities`](../fetchers/sentinelone/activities), [`sentinelone_cloud_detection_rules`](../fetchers/sentinelone/cloud_detection_rules)

### IAM — Identity and Access Management  (6/6)

#### ✅ `KSI-IAM-AAM` — Automating Account Management

> The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.

*Controls:* `ac-2.2`, `ac-2.3`, `ac-2.13`, `ac-6.7`, `ia-4.4`, `ia-12`, `ia-12.2`, `ia-12.3`, `ia-12.5`

*4 fetchers:* [`aws_iam_identity_center`](../fetchers/aws/iam_identity_center), [`okta_automated_account_management`](../fetchers/okta/automated_account_management), [`rippling_all_employees`](../fetchers/rippling/all_employees), [`rippling_current_employees`](../fetchers/rippling/current_employees)

#### ✅ `KSI-IAM-APM` — Adopting Passwordless Methods

> Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.

*Controls:* `ac-3`, `ia-5.1`, `ia-5.2`, `ia-5.6`, `ia-6`, `ac-2`, `ia-2`, `ia-2.1`, `ia-2.2`, `ia-2.8`, `ia-5`, `ia-8`, `sc-23`

*14 fetchers:* [`aws_iam_mfa_status`](../fetchers/aws/iam_mfa_status), [`aws_iam_password_policy`](../fetchers/aws/iam_password_policy), [`aws_iam_users_groups`](../fetchers/aws/iam_users_groups), [`azure_entra_mfa_status`](../fetchers/azure/entra_mfa_status), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration), [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration), [`azure_vm_hardening_status`](../fetchers/azure/vm_hardening_status), [`gcp_compute_instance_configuration`](../fetchers/gcp/compute_instance_configuration), [`oci_iam_password_policy`](../fetchers/oci/iam_password_policy), [`oci_iam_users_credentials`](../fetchers/oci/iam_users_credentials), [`okta_authenticators`](../fetchers/okta/authenticators), [`okta_passwordless_authentication`](../fetchers/okta/passwordless_authentication), [`okta_phishing_resistant_mfa`](../fetchers/okta/phishing_resistant_mfa), [`sentinelone_user_config`](../fetchers/sentinelone/user_config)

#### ✅ `KSI-IAM-ELP` — Ensuring Least Privilege

> Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.

*Controls:* `ac-2.5`, `ac-2.6`, `ac-3`, `ac-4`, `ac-6`, `ac-12`, `ac-14`, `ac-17`, `ac-17.1`, `ac-17.2`, `ac-17.3`, `ac-20`, `ac-20.1`, `cm-2.7`, `cm-9`, `ia-2`, `ia-3`, `ia-4`, `ia-4.4`, `ia-5.2`, `ia-5.6`, `ia-11`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `sc-4`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-39`, `si-3`

*24 fetchers:* [`aws_access_analyzer_findings`](../fetchers/aws/access_analyzer_findings), [`aws_iam_policies`](../fetchers/aws/iam_policies), [`aws_iam_roles`](../fetchers/aws/iam_roles), [`aws_iam_users_groups`](../fetchers/aws/iam_users_groups), [`aws_organizations_scp`](../fetchers/aws/organizations_scp), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_container_registry_configuration`](../fetchers/azure/container_registry_configuration), [`azure_entra_conditional_access_policies`](../fetchers/azure/entra_conditional_access_policies), [`azure_entra_privileged_roles`](../fetchers/azure/entra_privileged_roles), [`azure_key_vault_configuration`](../fetchers/azure/key_vault_configuration), [`azure_rbac_custom_roles`](../fetchers/azure/rbac_custom_roles), [`azure_rbac_role_assignments`](../fetchers/azure/rbac_role_assignments), [`gcp_api_keys_inventory`](../fetchers/gcp/api_keys_inventory), [`gcp_bigquery_dataset_configuration`](../fetchers/gcp/bigquery_dataset_configuration), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`gcp_iam_custom_roles`](../fetchers/gcp/iam_custom_roles), [`gcp_iam_policy_bindings`](../fetchers/gcp/iam_policy_bindings), [`gcp_iam_service_accounts`](../fetchers/gcp/iam_service_accounts), [`oci_bastion_sessions`](../fetchers/oci/bastion_sessions), [`oci_iam_policies`](../fetchers/oci/iam_policies), [`oci_iam_users_credentials`](../fetchers/oci/iam_users_credentials), [`oci_object_storage_buckets`](../fetchers/oci/object_storage_buckets), [`okta_least_privilege`](../fetchers/okta/least_privilege), [`sentinelone_user_config`](../fetchers/sentinelone/user_config)

#### ✅ `KSI-IAM-JIT` — Authorizing Just-in-Time

> A least-privileged, role and attribute-based, and just-in-time security authorization model is used and persistently reviewed for all user and non-user accounts and services.

*Controls:* `ac-2`, `ac-2.1`, `ac-2.2`, `ac-2.3`, `ac-2.4`, `ac-2.6`, `ac-3`, `ac-4`, `ac-5`, `ac-6`, `ac-6.1`, `ac-6.2`, `ac-6.5`, `ac-6.7`, `ac-6.9`, `ac-6.10`, `ac-7`, `ac-20.1`, `ac-17`, `au-9.4`, `cm-5`, `cm-7`, `cm-7.2`, `cm-7.5`, `cm-9`, `ia-4`, `ia-4.4`, `ia-7`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `ps-9`, `ra-5.5`, `sc-2`, `sc-23`, `sc-39`

*5 fetchers:* [`aws_iam_identity_center`](../fetchers/aws/iam_identity_center), [`azure_entra_conditional_access_policies`](../fetchers/azure/entra_conditional_access_policies), [`oci_bastion_sessions`](../fetchers/oci/bastion_sessions), [`oci_operator_access_control`](../fetchers/oci/operator_access_control), [`okta_just_in_time_authorization`](../fetchers/okta/just_in_time_authorization)

#### ✅ `KSI-IAM-SNU` — Securing Non-User Authentication

> Appropriately secure authentication methods are used and persistently reviewed for non-user accounts and services.

*Controls:* `ac-2`, `ac-2.2`, `ac-4`, `ac-6.5`, `ia-3`, `ia-5.2`, `ra-5.5`

*12 fetchers:* [`aws_eks_least_privilege`](../fetchers/aws/eks_least_privilege), [`aws_iam_roles`](../fetchers/aws/iam_roles), [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration), [`azure_app_service_configuration`](../fetchers/azure/app_service_configuration), [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration), [`azure_entra_app_registrations`](../fetchers/azure/entra_app_registrations), [`gcp_api_keys_inventory`](../fetchers/gcp/api_keys_inventory), [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration), [`gcp_iam_service_accounts`](../fetchers/gcp/iam_service_accounts), [`oci_iam_policies`](../fetchers/oci/iam_policies), [`oci_iam_users_credentials`](../fetchers/oci/iam_users_credentials), [`okta_non_user_accounts_authentication`](../fetchers/okta/non_user_accounts_authentication)

#### ✅ `KSI-IAM-SUS` — Responding to Suspicious Activity

> Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.

*Controls:* `ac-2`, `ac-2.1`, `ac-2.3`, `ac-2.13`, `ac-7`, `ps-4`, `ps-8`

*2 fetchers:* [`azure_entra_conditional_access_policies`](../fetchers/azure/entra_conditional_access_policies), [`okta_suspicious_activity_management`](../fetchers/okta/suspicious_activity_management)

### CMT — Change Management  (3/3)

#### ✅ `KSI-CMT-LMC` — Logging Changes

> Modifications to the cloud service offering are logged and monitored.

*Controls:* `au-2`, `cm-3`, `cm-3.2`, `cm-4.2`, `cm-6`, `cm-8.3`, `ma-2`

*9 fetchers:* [`aws_cloudtrail_configuration`](../fetchers/aws/cloudtrail_configuration), [`aws_config_monitoring`](../fetchers/aws/config_monitoring), [`aws_detect_new_aws_resource`](../fetchers/aws/detect_new_aws_resource), [`azure_activity_log_alerts`](../fetchers/azure/activity_log_alerts), [`azure_diagnostic_settings`](../fetchers/azure/diagnostic_settings), [`crowdstrike_filevantage`](../fetchers/crowdstrike/filevantage), [`gcp_cloud_logging_configuration`](../fetchers/gcp/cloud_logging_configuration), [`gitlab_merge_request_summary`](../fetchers/gitlab/merge_request_summary), [`gitlab_significant_change_notifications`](../fetchers/gitlab/significant_change_notifications)

#### ✅ `KSI-CMT-RMV` — Redeploying vs Modifying

> Changes to machine-based information resources are executed through the redeployment of version controlled resources rather than direct modification wherever reasonable.

*Controls:* `cm-2`, `cm-3`, `cm-5`, `cm-6`, `cm-7`, `cm-8.1`, `si-3`

*3 fetchers:* [`aws_cloudformation_drift`](../fetchers/aws/cloudformation_drift), [`aws_codepipeline_config`](../fetchers/aws/codepipeline_config), [`gitlab_ci_cd_pipeline_config`](../fetchers/gitlab/ci_cd_pipeline_config)

#### ⬜ `KSI-CMT-RVP` — Reviewing Change Procedures

> The effectiveness of documented change management procedures is persistently reviewed.

*Controls:* `cm-3`, `cm-3.2`, `cm-3.4`, `cm-5`, `cm-7.1`, `cm-9`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ✅ `KSI-CMT-VTD` — Validating Throughout Deployment

> Persistent testing and validation of changes throughout deployment is automated.

*Controls:* `cm-3`, `cm-3.2`, `cm-4.2`, `si-2`

*3 fetchers:* [`aws_codebuild_pipeline_config`](../fetchers/aws/codebuild_pipeline_config), [`aws_codepipeline_config`](../fetchers/aws/codepipeline_config), [`gitlab_ci_cd_pipeline_config`](../fetchers/gitlab/ci_cd_pipeline_config)

### RPL — Recovery Planning  (2/2)

#### ✅ `KSI-RPL-ABO` — Aligning Backups with Objectives

> The alignment of machine-based information resource backups with defined recovery objectives is persistently reviewed.

*Controls:* `cm-2.3`, `cp-6`, `cp-9`, `cp-10`, `cp-10.2`, `si-12`

*13 fetchers:* [`aws_backup_recovery_high_availability`](../fetchers/aws/backup_recovery_high_availability), [`aws_backup_validation`](../fetchers/aws/backup_validation), [`aws_dlm_lifecycle_policies`](../fetchers/aws/dlm_lifecycle_policies), [`aws_dynamodb_pitr_status`](../fetchers/aws/dynamodb_pitr_status), [`aws_ebs_snapshot_status`](../fetchers/aws/ebs_snapshot_status), [`azure_backup_recovery_status`](../fetchers/azure/backup_recovery_status), [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration), [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration), [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration), [`gcp_cloud_sql_backup_configuration`](../fetchers/gcp/cloud_sql_backup_configuration), [`gcp_cloud_sql_encryption_status`](../fetchers/gcp/cloud_sql_encryption_status), [`gcp_cloud_storage_encryption_status`](../fetchers/gcp/cloud_storage_encryption_status), [`oci_dr_plan_executions`](../fetchers/oci/dr_plan_executions)

#### ⬜ `KSI-RPL-ARP` — Aligning Recovery Plan

> The alignment of recovery plans with defined recovery objectives is persistently reviewed.

*Controls:* `cp-2`, `cp-2.1`, `cp-2.3`, `cp-4.1`, `cp-6`, `cp-6.1`, `cp-6.3`, `cp-7`, `cp-7.1`, `cp-7.2`, `cp-7.3`, `cp-8`, `cp-8.1`, `cp-8.2`, `cp-10`, `cp-10.2`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ⬜ `KSI-RPL-RRO` — Reviewing Recovery Objectives

> The desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) are defined and persistently reviewed for alignment with the provider's business needs and capabilities.

*Controls:* `cp-2.3`, `cp-10`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ✅ `KSI-RPL-TRC` — Testing Recovery Capabilities

> The capability to recover from incidents and contingencies aligned with defined recovery objectives is persistently tested.

*Controls:* `cp-2.1`, `cp-2.3`, `cp-4`, `cp-4.1`, `cp-6`, `cp-6.1`, `cp-9.1`, `cp-10`, `ir-3`, `ir-3.2`

*1 fetcher:* [`oci_dr_plan_executions`](../fetchers/oci/dr_plan_executions)

### PIY — Policy and Inventory  (1/1)

#### ✅ `KSI-PIY-GIV` — Generating Inventories

> Authoritative sources are used to automatically generate real-time inventories of all information resources when needed.

*Controls:* `cm-2.2`, `cm-7.5`, `cm-8`, `cm-8.1`, `cm-12`, `cm-12.1`, `cp-2.8`

*11 fetchers:* [`aws_detect_new_aws_resource`](../fetchers/aws/detect_new_aws_resource), [`aws_resource_inventory`](../fetchers/aws/resource_inventory), [`crowdstrike_hosts`](../fetchers/crowdstrike/hosts), [`datadog_agent_hosts`](../fetchers/datadog/agent_hosts), [`datadog_apm_services`](../fetchers/datadog/apm_services), [`datadog_containers`](../fetchers/datadog/containers), [`gitlab_project_summary`](../fetchers/gitlab/project_summary), [`k8s_eks_pod_inventory`](../fetchers/k8s/eks_pod_inventory), [`rippling_devices`](../fetchers/rippling/devices), [`sentinelone_agents`](../fetchers/sentinelone/agents), [`sentinelone_xdr_assets`](../fetchers/sentinelone/xdr_assets)

#### ⬜ `KSI-PIY-RES` — Reviewing Executive Support

> Executive support for achieving the provider's security goals is persistently reviewed and demonstrated.

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ⬜ `KSI-PIY-RIS` — Reviewing Investments in Security

> The effectiveness of the provider's investments in achieving security goals is persistently reviewed.

*Controls:* `ac-5`, `ca-2`, `cp-2.1`, `cp-4.1`, `ir-3.2`, `pm-3`, `sa-2`, `sa-3`, `sr-2.1`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ⬜ `KSI-PIY-RSD` — Reviewing Security in the SDLC

> The effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles is persistently reviewed.

*Controls:* `ac-5`, `au-3.3`, `cm-3.4`, `pl-8`, `pm-7`, `sa-3`, `sa-8`, `sc-4`, `sc-18`, `si-10`, `si-11`, `si-16`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ⬜ `KSI-PIY-RVD` — Reviewing Vulnerability Disclosures

> The effectiveness of the provider's vulnerability disclosure program is persistently reviewed.

*Controls:* `ra-5.11`

*Organizational — evidenced by HR, training or process, not cloud config.*

### SCR — Supply Chain Risk  (2/2)

#### ✅ `KSI-SCR-MIT` — Mitigating Supply Chain Risk

> Persistently identify, review, and mitigate potential supply chain risks.

*Controls:* `ac-20`, `ra-3.1`, `sa-9`, `sa-10`, `sa-11`, `sa-15.3`, `sa-22`, `si-7.1`, `sr-5`, `sr-6`, `ca-7.4`, `sc-18`

*2 fetchers:* [`oci_dependency_vulnerabilities`](../fetchers/oci/dependency_vulnerabilities), [`oci_operator_access_control`](../fetchers/oci/operator_access_control)

#### ✅ `KSI-SCR-MON` — Monitoring Supply Chain Risk

> Third party software information resources are automatically monitored for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.

*Controls:* `ac-20`, `ca-3`, `ir-6.3`, `ps-7`, `ra-5`, `sa-9`, `si-5`, `sr-5`, `sr-6`, `sr-8`

*3 fetchers:* [`aws_ecr_image_scanning`](../fetchers/aws/ecr_image_scanning), [`aws_inspector_vulnerability_scanning`](../fetchers/aws/inspector_vulnerability_scanning), [`oci_dependency_vulnerabilities`](../fetchers/oci/dependency_vulnerabilities)

### CED — Cybersecurity Education  (1/1)

#### ✅ `KSI-CED-RAT` — Reviewing All Training

> The effectiveness of relevant cybersecurity education and training is persistently reviewed, including at least general training for all employees, role-specific training for employees in high risk roles, training for development and engineering staff on secure software delivery, and training for staff involved with incident response or disaster recovery.

*Controls:* `cp-3`, `ir-2`, `ps-6`, `at-2`, `at-2.2`, `at-2.3`, `at-3.5`, `at-4`, `ir-2.3`, `at-3`, `sr-11.1`

*4 fetchers:* [`knowbe4_developer_specific_training`](../fetchers/knowbe4/developer_specific_training), [`knowbe4_high_risk_training`](../fetchers/knowbe4/high_risk_training), [`knowbe4_module_based_summary`](../fetchers/knowbe4/module_based_summary), [`knowbe4_security_awareness_training`](../fetchers/knowbe4/security_awareness_training)

### INR — Incident Response  (2/2)

#### ✅ `KSI-INR-AAR` — Generating After Action Reports

> Incident after action reports are generated and lessons learned are persistently incorporated.

*Controls:* `ir-3`, `ir-4`, `ir-4.1`, `ir-8`

*1 fetcher:* [`datadog_incident_timelines`](../fetchers/datadog/incident_timelines)

#### ⬜ `KSI-INR-RIR` — Reviewing Incident Response Procedures

> The effectiveness of documented incident response procedures is persistently reviewed.

*Controls:* `ir-4`, `ir-4.1`, `ir-6`, `ir-6.1`, `ir-6.3`, `ir-7`, `ir-7.1`, `ir-8`, `ir-8.1`, `si-4.5`

*Organizational — evidenced by HR, training or process, not cloud config.*

#### ✅ `KSI-INR-RPI` — Reviewing Past Incidents

> Past incidents are persistently reviewed for patterns or vulnerabilities that were not previously apparent or identified.

*Controls:* `ir-3`, `ir-4`, `ir-4.1`, `ir-5`, `ir-8`

*1 fetcher:* [`datadog_incidents_list`](../fetchers/datadog/incidents_list)

## Open gaps

1 config-evidenceable indicator that nothing covers. Each is a **fetcher backlog item** — the evidence does not exist yet, rather than existing and being unmapped.

| Indicator | | What would be needed |
|---|---|---|
| `KSI-MLA-ALA` | Authorizing Log Access | A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity. |

## By fetcher

196 of 199 fetchers carry a mapping.

### aws  (80)

| Fetcher | Indicators |
|---|---|
| [`aws_access_analyzer_findings`](../fetchers/aws/access_analyzer_findings) | `KSI-IAM-ELP` |
| [`aws_acm_certificate_status`](../fetchers/aws/acm_certificate_status) | `KSI-SVC-ASM` |
| [`aws_apigateway_tls_enforcement`](../fetchers/aws/apigateway_tls_enforcement) | `KSI-SVC-SIN` |
| [`aws_athena_encryption_status`](../fetchers/aws/athena_encryption_status) | `KSI-SVC-SIN` |
| [`aws_auto_scaling_high_availability`](../fetchers/aws/auto_scaling_high_availability) | `KSI-CNA-OFA` |
| [`aws_backup_recovery_high_availability`](../fetchers/aws/backup_recovery_high_availability) | `KSI-CNA-OFA`, `KSI-RPL-ABO` |
| [`aws_backup_validation`](../fetchers/aws/backup_validation) | `KSI-RPL-ABO` |
| [`aws_block_storage_encryption_status`](../fetchers/aws/block_storage_encryption_status) | `KSI-SVC-SIN` |
| [`aws_cloudformation_drift`](../fetchers/aws/cloudformation_drift) | `KSI-CMT-RMV`, `KSI-MLA-EVC`, `KSI-SVC-ACM` |
| [`aws_cloudfront_distribution_security`](../fetchers/aws/cloudfront_distribution_security) | `KSI-CNA-RVP`, `KSI-SVC-SIN` |
| [`aws_cloudtrail_configuration`](../fetchers/aws/cloudtrail_configuration) | `KSI-CMT-LMC`, `KSI-MLA-OSM` |
| [`aws_cloudwatch_high_availability`](../fetchers/aws/cloudwatch_high_availability) | `KSI-CNA-OFA`, `KSI-MLA-RVL` |
| [`aws_codeartifact_encryption_status`](../fetchers/aws/codeartifact_encryption_status) | `KSI-SVC-SIN` |
| [`aws_codebuild_pipeline_config`](../fetchers/aws/codebuild_pipeline_config) | `KSI-CMT-VTD` |
| [`aws_codepipeline_config`](../fetchers/aws/codepipeline_config) | `KSI-CMT-RMV`, `KSI-CMT-VTD` |
| [`aws_component_ssl_enforcement_status`](../fetchers/aws/component_ssl_enforcement_status) | `KSI-SVC-SIN` |
| [`aws_config_conformance_packs`](../fetchers/aws/config_conformance_packs) | `KSI-CNA-IBP`, `KSI-MLA-EVC` |
| [`aws_config_monitoring`](../fetchers/aws/config_monitoring) | `KSI-CMT-LMC`, `KSI-MLA-EVC`, `KSI-SVC-ACM` |
| [`aws_database_high_availability`](../fetchers/aws/database_high_availability) | `KSI-CNA-OFA` |
| [`aws_detect_new_aws_resource`](../fetchers/aws/detect_new_aws_resource) | `KSI-CMT-LMC`, `KSI-PIY-GIV` |
| [`aws_dlm_lifecycle_policies`](../fetchers/aws/dlm_lifecycle_policies) | `KSI-RPL-ABO` |
| [`aws_dms_encryption_status`](../fetchers/aws/dms_encryption_status) | `KSI-SVC-SIN` |
| [`aws_documentdb_encryption_status`](../fetchers/aws/documentdb_encryption_status) | `KSI-SVC-SIN` |
| [`aws_dynamodb_encryption_status`](../fetchers/aws/dynamodb_encryption_status) | `KSI-SVC-SIN` |
| [`aws_dynamodb_pitr_status`](../fetchers/aws/dynamodb_pitr_status) | `KSI-RPL-ABO` |
| [`aws_ebs_snapshot_status`](../fetchers/aws/ebs_snapshot_status) | `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`aws_ec2_public_exposure`](../fetchers/aws/ec2_public_exposure) | `KSI-CNA-MAT` |
| [`aws_ecr_image_scanning`](../fetchers/aws/ecr_image_scanning) | `KSI-SCR-MON` |
| [`aws_efs_encryption_status`](../fetchers/aws/efs_encryption_status) | `KSI-SVC-SIN` |
| [`aws_efs_high_availability`](../fetchers/aws/efs_high_availability) | `KSI-CNA-OFA` |
| [`aws_eks_high_availability`](../fetchers/aws/eks_high_availability) | `KSI-CNA-OFA` |
| [`aws_eks_least_privilege`](../fetchers/aws/eks_least_privilege) | `KSI-IAM-SNU` |
| [`aws_elasticache_encryption_status`](../fetchers/aws/elasticache_encryption_status) | `KSI-SVC-SIN` |
| [`aws_emr_encryption_status`](../fetchers/aws/emr_encryption_status) | `KSI-SVC-SIN` |
| [`aws_firehose_encryption_status`](../fetchers/aws/firehose_encryption_status) | `KSI-SVC-SIN` |
| [`aws_fsx_encryption_status`](../fetchers/aws/fsx_encryption_status) | `KSI-SVC-SIN` |
| [`aws_glacier_encryption_status`](../fetchers/aws/glacier_encryption_status) | `KSI-SVC-SIN` |
| [`aws_global_accelerator_ha`](../fetchers/aws/global_accelerator_ha) | `KSI-CNA-OFA` |
| [`aws_glue_encryption_status`](../fetchers/aws/glue_encryption_status) | `KSI-SVC-SIN` |
| [`aws_guard_duty`](../fetchers/aws/guard_duty) | `KSI-MLA-RVL` |
| [`aws_guard_duty_findings`](../fetchers/aws/guard_duty_findings) | `KSI-MLA-RVL`, `KSI-SVC-EIS` |
| [`aws_iam_identity_center`](../fetchers/aws/iam_identity_center) | `KSI-IAM-AAM`, `KSI-IAM-JIT` |
| [`aws_iam_mfa_status`](../fetchers/aws/iam_mfa_status) | `KSI-IAM-APM` |
| [`aws_iam_password_policy`](../fetchers/aws/iam_password_policy) | `KSI-IAM-APM` |
| [`aws_iam_policies`](../fetchers/aws/iam_policies) | `KSI-IAM-ELP` |
| [`aws_iam_roles`](../fetchers/aws/iam_roles) | `KSI-IAM-ELP`, `KSI-IAM-SNU` |
| [`aws_iam_users_groups`](../fetchers/aws/iam_users_groups) | `KSI-IAM-APM`, `KSI-IAM-ELP` |
| [`aws_inspector_vulnerability_scanning`](../fetchers/aws/inspector_vulnerability_scanning) | `KSI-SCR-MON`, `KSI-SVC-EIS` |
| [`aws_kafka_encryption_status`](../fetchers/aws/kafka_encryption_status) | `KSI-SVC-SIN` |
| [`aws_kinesis_encryption_status`](../fetchers/aws/kinesis_encryption_status) | `KSI-SVC-SIN` |
| [`aws_kms_key_rotation`](../fetchers/aws/kms_key_rotation) | `KSI-SVC-ASM` |
| [`aws_load_balancer_encryption_status`](../fetchers/aws/load_balancer_encryption_status) | `KSI-SVC-SIN` |
| [`aws_load_balancer_high_availability`](../fetchers/aws/load_balancer_high_availability) | `KSI-CNA-OFA` |
| [`aws_macie_data_discovery`](../fetchers/aws/macie_data_discovery) | `KSI-SVC-SIN` |
| [`aws_memorydb_encryption_status`](../fetchers/aws/memorydb_encryption_status) | `KSI-SVC-SIN` |
| [`aws_neptune_encryption_status`](../fetchers/aws/neptune_encryption_status) | `KSI-SVC-SIN` |
| [`aws_network_acls`](../fetchers/aws/network_acls) | `KSI-CNA-RNT`, `KSI-CNA-ULN` |
| [`aws_network_firewall_rules`](../fetchers/aws/network_firewall_rules) | `KSI-CNA-RNT`, `KSI-CNA-ULN` |
| [`aws_network_resilience_high_availability`](../fetchers/aws/network_resilience_high_availability) | `KSI-CNA-OFA` |
| [`aws_opensearch_encryption_status`](../fetchers/aws/opensearch_encryption_status) | `KSI-SVC-SIN` |
| [`aws_organizations_scp`](../fetchers/aws/organizations_scp) | `KSI-CNA-DFP`, `KSI-IAM-ELP` |
| [`aws_rds_encryption_status`](../fetchers/aws/rds_encryption_status) | `KSI-SVC-SIN` |
| [`aws_rds_tls_configuration`](../fetchers/aws/rds_tls_configuration) | `KSI-SVC-SIN` |
| [`aws_redshift_encryption_status`](../fetchers/aws/redshift_encryption_status) | `KSI-SVC-SIN` |
| [`aws_resource_inventory`](../fetchers/aws/resource_inventory) | `KSI-PIY-GIV` |
| [`aws_route53_high_availability`](../fetchers/aws/route53_high_availability) | `KSI-CNA-OFA` |
| [`aws_s3_encryption_status`](../fetchers/aws/s3_encryption_status) | `KSI-SVC-SIN` |
| [`aws_sagemaker_encryption_status`](../fetchers/aws/sagemaker_encryption_status) | `KSI-SVC-SIN` |
| [`aws_secrets_manager_rotation`](../fetchers/aws/secrets_manager_rotation) | `KSI-SVC-ASM` |
| [`aws_security_groups`](../fetchers/aws/security_groups) | `KSI-CNA-MAT`, `KSI-CNA-RNT` |
| [`aws_securityhub_status`](../fetchers/aws/securityhub_status) | `KSI-CNA-IBP`, `KSI-MLA-OSM` |
| [`aws_shield_dos_protection`](../fetchers/aws/shield_dos_protection) | `KSI-CNA-RVP` |
| [`aws_sns_encryption_status`](../fetchers/aws/sns_encryption_status) | `KSI-SVC-SIN` |
| [`aws_sqs_encryption_status`](../fetchers/aws/sqs_encryption_status) | `KSI-SVC-SIN` |
| [`aws_ssm_patch_compliance`](../fetchers/aws/ssm_patch_compliance) | `KSI-SVC-EIS` |
| [`aws_transfer_tls_enforcement`](../fetchers/aws/transfer_tls_enforcement) | `KSI-SVC-SIN` |
| [`aws_vpc_flow_logs`](../fetchers/aws/vpc_flow_logs) | `KSI-MLA-LET` |
| [`aws_vpc_network_segmentation`](../fetchers/aws/vpc_network_segmentation) | `KSI-CNA-ULN` |
| [`aws_waf_all_rules`](../fetchers/aws/waf_all_rules) | `KSI-CNA-RVP` |
| [`aws_waf_dos_rules`](../fetchers/aws/waf_dos_rules) | `KSI-CNA-RVP` |

### azure  (28)

| Fetcher | Indicators |
|---|---|
| [`azure_activity_log_alerts`](../fetchers/azure/activity_log_alerts) | `KSI-CMT-LMC`, `KSI-MLA-RVL` |
| [`azure_aks_cluster_configuration`](../fetchers/azure/aks_cluster_configuration) | `KSI-CNA-MAT`, `KSI-CNA-RNT`, `KSI-CNA-ULN`, `KSI-IAM-ELP`, `KSI-IAM-SNU`, `KSI-SVC-EIS` |
| [`azure_app_service_configuration`](../fetchers/azure/app_service_configuration) | `KSI-CNA-MAT`, `KSI-IAM-SNU`, `KSI-SVC-EIS`, `KSI-SVC-SIN` |
| [`azure_backup_recovery_status`](../fetchers/azure/backup_recovery_status) | `KSI-RPL-ABO` |
| [`azure_container_registry_configuration`](../fetchers/azure/container_registry_configuration) | `KSI-CNA-MAT`, `KSI-IAM-ELP`, `KSI-SVC-SIN`, `KSI-SVC-VRI` |
| [`azure_cosmosdb_configuration`](../fetchers/azure/cosmosdb_configuration) | `KSI-CNA-OFA`, `KSI-CNA-RNT`, `KSI-IAM-SNU`, `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`azure_databricks_workspace_configuration`](../fetchers/azure/databricks_workspace_configuration) | `KSI-CNA-MAT`, `KSI-CNA-ULN`, `KSI-SVC-ASM`, `KSI-SVC-SIN` |
| [`azure_defender_assessments`](../fetchers/azure/defender_assessments) | `KSI-CNA-EIS`, `KSI-SVC-EIS` |
| [`azure_defender_plans`](../fetchers/azure/defender_plans) | `KSI-CNA-EIS`, `KSI-SVC-EIS` |
| [`azure_diagnostic_settings`](../fetchers/azure/diagnostic_settings) | `KSI-CMT-LMC`, `KSI-MLA-LET` |
| [`azure_disk_encryption_status`](../fetchers/azure/disk_encryption_status) | `KSI-SVC-SIN` |
| [`azure_entra_app_registrations`](../fetchers/azure/entra_app_registrations) | `KSI-IAM-SNU`, `KSI-SVC-ASM` |
| [`azure_entra_conditional_access_policies`](../fetchers/azure/entra_conditional_access_policies) | `KSI-IAM-ELP`, `KSI-IAM-JIT`, `KSI-IAM-SUS` |
| [`azure_entra_mfa_status`](../fetchers/azure/entra_mfa_status) | `KSI-IAM-APM` |
| [`azure_entra_privileged_roles`](../fetchers/azure/entra_privileged_roles) | `KSI-IAM-ELP` |
| [`azure_function_app_configuration`](../fetchers/azure/function_app_configuration) | `KSI-CNA-MAT`, `KSI-SVC-SIN` |
| [`azure_key_vault_configuration`](../fetchers/azure/key_vault_configuration) | `KSI-IAM-ELP` |
| [`azure_key_vault_key_rotation`](../fetchers/azure/key_vault_key_rotation) | `KSI-SVC-ASM` |
| [`azure_mysql_configuration`](../fetchers/azure/mysql_configuration) | `KSI-CNA-MAT`, `KSI-CNA-OFA`, `KSI-MLA-LET`, `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`azure_network_security_groups`](../fetchers/azure/network_security_groups) | `KSI-CNA-MAT`, `KSI-CNA-RNT` |
| [`azure_policy_assignments`](../fetchers/azure/policy_assignments) | `KSI-CNA-EIS`, `KSI-SVC-ACM` |
| [`azure_postgresql_configuration`](../fetchers/azure/postgresql_configuration) | `KSI-CNA-OFA`, `KSI-CNA-RNT`, `KSI-IAM-APM`, `KSI-MLA-LET`, `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`azure_rbac_custom_roles`](../fetchers/azure/rbac_custom_roles) | `KSI-IAM-ELP` |
| [`azure_rbac_role_assignments`](../fetchers/azure/rbac_role_assignments) | `KSI-IAM-ELP` |
| [`azure_sql_encryption_status`](../fetchers/azure/sql_encryption_status) | `KSI-SVC-SIN` |
| [`azure_sql_server_configuration`](../fetchers/azure/sql_server_configuration) | `KSI-CNA-MAT`, `KSI-CNA-RNT`, `KSI-IAM-APM`, `KSI-MLA-LET`, `KSI-SVC-EIS`, `KSI-SVC-SIN` |
| [`azure_storage_encryption_status`](../fetchers/azure/storage_encryption_status) | `KSI-CNA-RNT`, `KSI-SVC-ASM`, `KSI-SVC-SIN` |
| [`azure_vm_hardening_status`](../fetchers/azure/vm_hardening_status) | `KSI-CNA-MAT`, `KSI-IAM-APM`, `KSI-SVC-SIN`, `KSI-SVC-VRI` |

### checkov  (2)

| Fetcher | Indicators |
|---|---|
| [`checkov_kubernetes`](../fetchers/checkov/kubernetes) | `KSI-MLA-EVC` |
| [`checkov_terraform`](../fetchers/checkov/terraform) | `KSI-MLA-EVC` |

### crowdstrike  (7)

| Fetcher | Indicators |
|---|---|
| [`crowdstrike_detections`](../fetchers/crowdstrike/detections) | `KSI-MLA-RVL` |
| [`crowdstrike_filevantage`](../fetchers/crowdstrike/filevantage) | `KSI-CMT-LMC` |
| [`crowdstrike_firewall_policies`](../fetchers/crowdstrike/firewall_policies) | `KSI-CNA-MAT`, `KSI-CNA-RNT` |
| [`crowdstrike_hosts`](../fetchers/crowdstrike/hosts) | `KSI-PIY-GIV` |
| [`crowdstrike_prevention_policies`](../fetchers/crowdstrike/prevention_policies) | `KSI-CNA-EIS` |
| [`crowdstrike_spotlight_vulnerabilities`](../fetchers/crowdstrike/spotlight_vulnerabilities) | `KSI-SVC-EIS` |
| [`crowdstrike_zero_trust_assessment`](../fetchers/crowdstrike/zero_trust_assessment) | `KSI-CNA-IBP` |

### datadog  (13)

| Fetcher | Indicators |
|---|---|
| [`datadog_agent_hosts`](../fetchers/datadog/agent_hosts) | `KSI-PIY-GIV` |
| [`datadog_apm_services`](../fetchers/datadog/apm_services) | `KSI-PIY-GIV` |
| [`datadog_containers`](../fetchers/datadog/containers) | `KSI-PIY-GIV` |
| [`datadog_incident_timelines`](../fetchers/datadog/incident_timelines) | `KSI-INR-AAR` |
| [`datadog_incidents_list`](../fetchers/datadog/incidents_list) | `KSI-INR-RPI` |
| [`datadog_infra_agent_checks`](../fetchers/datadog/infra_agent_checks) | `KSI-MLA-EVC` |
| [`datadog_log_archives`](../fetchers/datadog/log_archives) | `KSI-MLA-OSM` |
| [`datadog_log_indexes`](../fetchers/datadog/log_indexes) | `KSI-MLA-LET` |
| [`datadog_log_pipelines`](../fetchers/datadog/log_pipelines) | `KSI-MLA-LET` |
| [`datadog_monitors_list`](../fetchers/datadog/monitors_list) | `KSI-MLA-RVL` |
| [`datadog_siem_configuration`](../fetchers/datadog/siem_configuration) | `KSI-MLA-OSM` |
| [`datadog_siem_detection_rules`](../fetchers/datadog/siem_detection_rules) | `KSI-MLA-OSM`, `KSI-MLA-RVL` |
| [`datadog_siem_signals`](../fetchers/datadog/siem_signals) | `KSI-MLA-RVL` |

### gcp  (19)

| Fetcher | Indicators |
|---|---|
| [`gcp_api_keys_inventory`](../fetchers/gcp/api_keys_inventory) | `KSI-IAM-ELP`, `KSI-IAM-SNU`, `KSI-SVC-ASM` |
| [`gcp_bigquery_dataset_configuration`](../fetchers/gcp/bigquery_dataset_configuration) | `KSI-IAM-ELP`, `KSI-SVC-SIN` |
| [`gcp_cloud_logging_configuration`](../fetchers/gcp/cloud_logging_configuration) | `KSI-CMT-LMC`, `KSI-MLA-OSM` |
| [`gcp_cloud_sql_backup_configuration`](../fetchers/gcp/cloud_sql_backup_configuration) | `KSI-RPL-ABO` |
| [`gcp_cloud_sql_encryption_status`](../fetchers/gcp/cloud_sql_encryption_status) | `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`gcp_cloud_sql_network_configuration`](../fetchers/gcp/cloud_sql_network_configuration) | `KSI-CNA-MAT`, `KSI-CNA-RNT` |
| [`gcp_cloud_storage_encryption_status`](../fetchers/gcp/cloud_storage_encryption_status) | `KSI-RPL-ABO`, `KSI-SVC-SIN` |
| [`gcp_compute_instance_configuration`](../fetchers/gcp/compute_instance_configuration) | `KSI-CNA-MAT`, `KSI-IAM-APM`, `KSI-SVC-VRI` |
| [`gcp_dns_configuration`](../fetchers/gcp/dns_configuration) | `KSI-SVC-SIN` |
| [`gcp_firewall_rules`](../fetchers/gcp/firewall_rules) | `KSI-CNA-MAT`, `KSI-CNA-RNT` |
| [`gcp_gke_cluster_configuration`](../fetchers/gcp/gke_cluster_configuration) | `KSI-CNA-IBP`, `KSI-CNA-MAT`, `KSI-CNA-ULN`, `KSI-IAM-ELP`, `KSI-IAM-SNU`, `KSI-SVC-EIS`, `KSI-SVC-VRI` |
| [`gcp_iam_custom_roles`](../fetchers/gcp/iam_custom_roles) | `KSI-IAM-ELP` |
| [`gcp_iam_policy_bindings`](../fetchers/gcp/iam_policy_bindings) | `KSI-IAM-ELP` |
| [`gcp_iam_service_accounts`](../fetchers/gcp/iam_service_accounts) | `KSI-IAM-ELP`, `KSI-IAM-SNU`, `KSI-SVC-ASM` |
| [`gcp_kms_key_configuration`](../fetchers/gcp/kms_key_configuration) | `KSI-SVC-ASM` |
| [`gcp_load_balancer_tls_configuration`](../fetchers/gcp/load_balancer_tls_configuration) | `KSI-SVC-SIN` |
| [`gcp_persistent_disk_encryption_status`](../fetchers/gcp/persistent_disk_encryption_status) | `KSI-SVC-SIN` |
| [`gcp_secret_manager_configuration`](../fetchers/gcp/secret_manager_configuration) | `KSI-SVC-ASM` |
| [`gcp_vpc_network_configuration`](../fetchers/gcp/vpc_network_configuration) | `KSI-CNA-ULN` |

### gitlab  (4)

| Fetcher | Indicators |
|---|---|
| [`gitlab_ci_cd_pipeline_config`](../fetchers/gitlab/ci_cd_pipeline_config) | `KSI-CMT-RMV`, `KSI-CMT-VTD` |
| [`gitlab_merge_request_summary`](../fetchers/gitlab/merge_request_summary) | `KSI-CMT-LMC` |
| [`gitlab_project_summary`](../fetchers/gitlab/project_summary) | `KSI-PIY-GIV` |
| [`gitlab_significant_change_notifications`](../fetchers/gitlab/significant_change_notifications) | `KSI-CMT-LMC` |

### k8s  (3)

| Fetcher | Indicators |
|---|---|
| [`k8s_eks_microservice_segmentation`](../fetchers/k8s/eks_microservice_segmentation) | `KSI-CNA-MAT`, `KSI-CNA-ULN` |
| [`k8s_eks_pod_inventory`](../fetchers/k8s/eks_pod_inventory) | `KSI-PIY-GIV` |
| [`k8s_kubectl_security`](../fetchers/k8s/kubectl_security) | `KSI-CNA-DFP`, `KSI-CNA-MAT`, `KSI-CNA-ULN` |

### knowbe4  (4)

| Fetcher | Indicators |
|---|---|
| [`knowbe4_developer_specific_training`](../fetchers/knowbe4/developer_specific_training) | `KSI-CED-RAT` |
| [`knowbe4_high_risk_training`](../fetchers/knowbe4/high_risk_training) | `KSI-CED-RAT` |
| [`knowbe4_module_based_summary`](../fetchers/knowbe4/module_based_summary) | `KSI-CED-RAT` |
| [`knowbe4_security_awareness_training`](../fetchers/knowbe4/security_awareness_training) | `KSI-CED-RAT` |

### oci  (17)

| Fetcher | Indicators |
|---|---|
| [`oci_audit_logging_events`](../fetchers/oci/audit_logging_events) | `KSI-MLA-LET`, `KSI-MLA-OSM` |
| [`oci_bastion_sessions`](../fetchers/oci/bastion_sessions) | `KSI-IAM-ELP`, `KSI-IAM-JIT` |
| [`oci_block_volume_encryption`](../fetchers/oci/block_volume_encryption) | `KSI-SVC-SIN` |
| [`oci_certificates`](../fetchers/oci/certificates) | `KSI-SVC-SIN`, `KSI-SVC-VCM` |
| [`oci_cloud_guard_posture`](../fetchers/oci/cloud_guard_posture) | `KSI-CNA-EIS`, `KSI-MLA-EVC` |
| [`oci_compute_instances`](../fetchers/oci/compute_instances) | `KSI-CNA-MAT`, `KSI-SVC-SIN`, `KSI-SVC-VRI` |
| [`oci_data_service_exposure`](../fetchers/oci/data_service_exposure) | `KSI-CNA-MAT`, `KSI-CNA-RNT`, `KSI-SVC-SIN` |
| [`oci_dependency_vulnerabilities`](../fetchers/oci/dependency_vulnerabilities) | `KSI-SCR-MIT`, `KSI-SCR-MON` |
| [`oci_dr_plan_executions`](../fetchers/oci/dr_plan_executions) | `KSI-RPL-ABO`, `KSI-RPL-TRC` |
| [`oci_iam_password_policy`](../fetchers/oci/iam_password_policy) | `KSI-IAM-APM` |
| [`oci_iam_policies`](../fetchers/oci/iam_policies) | `KSI-IAM-ELP`, `KSI-IAM-SNU` |
| [`oci_iam_users_credentials`](../fetchers/oci/iam_users_credentials) | `KSI-IAM-APM`, `KSI-IAM-ELP`, `KSI-IAM-SNU` |
| [`oci_network_exposure`](../fetchers/oci/network_exposure) | `KSI-CNA-MAT`, `KSI-CNA-RNT`, `KSI-MLA-LET` |
| [`oci_object_storage_buckets`](../fetchers/oci/object_storage_buckets) | `KSI-IAM-ELP`, `KSI-MLA-LET`, `KSI-SVC-SIN` |
| [`oci_operator_access_control`](../fetchers/oci/operator_access_control) | `KSI-IAM-JIT`, `KSI-SCR-MIT` |
| [`oci_vault_keys`](../fetchers/oci/vault_keys) | `KSI-SVC-ASM`, `KSI-SVC-SIN` |
| [`oci_zpr_policies`](../fetchers/oci/zpr_policies) | `KSI-CNA-RNT`, `KSI-CNA-ULN` |

### okta  (8)

| Fetcher | Indicators |
|---|---|
| [`okta_authenticators`](../fetchers/okta/authenticators) | `KSI-IAM-APM` |
| [`okta_automated_account_management`](../fetchers/okta/automated_account_management) | `KSI-IAM-AAM` |
| [`okta_just_in_time_authorization`](../fetchers/okta/just_in_time_authorization) | `KSI-IAM-JIT` |
| [`okta_least_privilege`](../fetchers/okta/least_privilege) | `KSI-IAM-ELP` |
| [`okta_non_user_accounts_authentication`](../fetchers/okta/non_user_accounts_authentication) | `KSI-IAM-SNU` |
| [`okta_passwordless_authentication`](../fetchers/okta/passwordless_authentication) | `KSI-IAM-APM` |
| [`okta_phishing_resistant_mfa`](../fetchers/okta/phishing_resistant_mfa) | `KSI-IAM-APM` |
| [`okta_suspicious_activity_management`](../fetchers/okta/suspicious_activity_management) | `KSI-IAM-SUS` |

### paramify  (3)

| Fetcher | Indicators |
|---|---|
| [`paramify_accepted_vulnerabilities`](../fetchers/paramify/accepted_vulnerabilities) | `KSI-SVC-EIS` |
| [`paramify_historical_ver_activity`](../fetchers/paramify/historical_ver_activity) | `KSI-SVC-EIS` |
| [`paramify_vulnerability_detail_report`](../fetchers/paramify/vulnerability_detail_report) | `KSI-SVC-EIS` |

### rippling  (3)

| Fetcher | Indicators |
|---|---|
| [`rippling_all_employees`](../fetchers/rippling/all_employees) | `KSI-IAM-AAM` |
| [`rippling_current_employees`](../fetchers/rippling/current_employees) | `KSI-IAM-AAM` |
| [`rippling_devices`](../fetchers/rippling/devices) | `KSI-PIY-GIV` |

### sentinelone  (5)

| Fetcher | Indicators |
|---|---|
| [`sentinelone_activities`](../fetchers/sentinelone/activities) | `KSI-MLA-RVL` |
| [`sentinelone_agents`](../fetchers/sentinelone/agents) | `KSI-CNA-EIS`, `KSI-PIY-GIV` |
| [`sentinelone_cloud_detection_rules`](../fetchers/sentinelone/cloud_detection_rules) | `KSI-MLA-RVL` |
| [`sentinelone_user_config`](../fetchers/sentinelone/user_config) | `KSI-IAM-APM`, `KSI-IAM-ELP` |
| [`sentinelone_xdr_assets`](../fetchers/sentinelone/xdr_assets) | `KSI-PIY-GIV` |

### Unmapped

[`demo_hello`](../fetchers/demo/hello), [`servicenow_cases`](../fetchers/servicenow/cases), [`servicenow_changes`](../fetchers/servicenow/changes) — deliberately carry no mapping.
