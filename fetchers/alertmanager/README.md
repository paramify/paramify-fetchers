# Alertmanager fetchers

Read-only evidence from Prometheus Alertmanager's v2 API and metrics endpoint. Every call is a GET: the fetchers never
create, change or expire silences or alerts, and receiver settings, which hold webhook URLs and API keys, are never
copied.

## Setup

1. Find a network path to Alertmanager, such as `http://alertmanager-operated.monitoring:9093` inside the cluster or
   an ingress in front of it. Point at one Alertmanager, or one member of an HA cluster: members share alerts and
   silences, but each counts its own notifications.
2. Set `ALERTMANAGER_BASE_URL`, including any path prefix it is served under (`--web.route-prefix`).
3. Alertmanager has no authentication of its own. Set the optional `ALERTMANAGER_TOKEN` secret only when a proxy in
   front of it requires a bearer token.
4. Optional: start Alertmanager with `--enable-feature=receiver-name-in-metrics` so notification counts are reported per
   receiver rather than per integration type. With this feature, Alertmanager resets the counts on every configuration
   reload, so they cover the time since the last reload, not since the process started.
5. Make sure `/metrics` reaches Alertmanager, not only `/api/`. A proxy that answers `/metrics` with its own page gives a
   failed read, and the run exits 1.

| Fetcher | Evidence set | Shows |
| --- | --- | --- |
| `alert_delivery` | `EVD-ALERTMANAGER-ALERT-DELIVERY` | Routing and receivers, what is firing or suppressed, silences, and notifications started and failed |

The counts show notifications that Alertmanager started to send, and notifications that failed after all their
retries. They do not show that an integration's API accepted a notification, or that a person received it. Both need
their own evidence.
