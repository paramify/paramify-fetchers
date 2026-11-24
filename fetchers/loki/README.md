# Loki fetchers

Read-only evidence from Grafana Loki's HTTP query API. Every call is a GET under `/loki/api/v1`, and log lines are
never copied into the evidence: only counts, timestamps and stream counts.

## Setup

1. Find a network path to Loki's query API: the gateway or query frontend, such as
   `http://loki-gateway.logging.svc.cluster.local`, or an ingress in front of it. Running the fetcher inside the
   cluster is the simplest.
2. Set `LOKI_BASE_URL`. If Loki runs multi-tenant (`auth_enabled: true`), set `LOKI_TENANT_ID`; it is sent as the
   `X-Scope-OrgID` header. Loki has no authentication of its own, so set the optional `LOKI_TOKEN` secret only when a
   proxy in front of it requires a bearer token.
3. List the sources Loki should be receiving in `LOKI_EXPECTED_SOURCES`, as `name={stream selector}` entries
   separated by semicolons. Use the labels your log shipper sets; check them in Grafana Explore or with
   `GET /loki/api/v1/labels` first. For example:

   ```
   kubernetes_pods={namespace=~".+", container!=""}; falco={namespace="falco"}; keycloak={app="keycloak"}
   ```

   A selector can be followed by line filters (`|=`, `!=`, `|~`, `!~`) to pick out one kind of line, such as a
   heartbeat. No other pipeline stage is allowed.
4. Set `LOKI_MAX_AGE_MINUTES`, the oldest the newest line of a source may be. It has no default: until it is set,
   staleness is not judged and its validator fails.
5. For a source whose silence is normal, such as an alerting tool that logs only when something happens, add a
   heartbeat source that must keep arriving and pair them in `LOKI_QUIET_SOURCES`:

   ```
   LOKI_EXPECTED_SOURCES=...; falco={namespace="falco"}; falco_heartbeat={namespace="falco"} |= "<a line Falco writes on a schedule>"
   LOKI_QUIET_SOURCES=falco:falco_heartbeat
   ```

   A quiet source is judged by its heartbeat. One without a heartbeat leaves the overall verdict unknown, since its
   silence can't be told apart from a broken collection path.

Optional: `LOKI_WINDOW_MINUTES` (default 60) for the line and stream counts, and `LOKI_SEARCH_HOURS` (default 24) for
how far back to look for each source's newest line.

| Fetcher | Evidence set | Shows |
| --- | --- | --- |
| `log_ingestion` | `EVD-LOKI-LOG-INGESTION` | Whether each expected log source is arriving, how many streams carry it, and how recently its newest line arrived |

A source arriving in Loki shows it is collected and stored, not that anyone reviews it or alerts on it.
