# flexible_server_backups fixtures

Response bodies of `GET flexibleServers/{server}/backups`, copied from Microsoft's published examples in
[Azure/azure-rest-api-specs](https://github.com/Azure/azure-rest-api-specs):

- `postgresql-backups-2024-08-01.json`: `Microsoft.DBforPostgreSQL/PostgreSql/stable/2024-08-01/examples/BackupListByServer.json`
  (one automatic and one on-demand backup).
- `mysql-backups-2023-12-30.json`: `Microsoft.DBforMySQL/FlexibleServers/stable/2023-12-30/examples/BackupsListByServer.json`
  (automatic backups only).
- `mysql-backups-live-2024-12-30.json`: a live, read-only `GET flexibleServers/{server}/backups` response from Azure
  Government (api-version 2024-12-30), seven automatic backups. The subscription, resource group, server name and
  backup id are replaced with placeholders; names, times and labels are as returned. Live names use hyphens
  (`daily-<time>-<id>`), unlike the published examples (`daily_...`), and there is no `provisioningState`.
- `mysql-backup-on-demand-2023-12-30.json`: the response body of
  `Microsoft.DBforMySQL/FlexibleServers/stable/2023-12-30/examples/BackupPut.json` (one on-demand backup).

They hold no tenant data. The published MySQL on-demand example labels its backup `FULL` / `Automatic`, the same as a
scheduled backup; only its name, `customer_<time>_<id>_<user name>`, sets it apart (automatic backups are named
`daily_...`). The fetcher therefore counts a MySQL backup whose name starts with `customer_` or `customer-` as manual, whatever
its labels; the live response's hyphenated names are why both separators are accepted. A live response should still confirm this.
