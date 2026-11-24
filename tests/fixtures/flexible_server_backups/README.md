# flexible_server_backups fixtures

Response bodies of `GET flexibleServers/{server}/backups`, copied from Microsoft's published examples in
[Azure/azure-rest-api-specs](https://github.com/Azure/azure-rest-api-specs):

- `postgresql-backups-2024-08-01.json`: `Microsoft.DBforPostgreSQL/PostgreSql/stable/2024-08-01/examples/BackupListByServer.json`
  (one automatic and one on-demand backup).
- `mysql-backups-2023-12-30.json`: `Microsoft.DBforMySQL/FlexibleServers/stable/2023-12-30/examples/BackupsListByServer.json`
  (automatic backups only).
- `mysql-backups-hyphenated-2024-12-30.json`: a hand-written list in the shape the 2024-12-30 api-version returns,
  seven automatic backups. Its names use hyphens (`daily-<time>-<id>`), unlike the published examples
  (`daily_...`), and it has no `provisioningState`. Every value is a placeholder.
- `mysql-backup-on-demand-2023-12-30.json`: the response body of
  `Microsoft.DBforMySQL/FlexibleServers/stable/2023-12-30/examples/BackupPut.json` (one on-demand backup).

They hold no tenant data. The published MySQL on-demand example labels its backup `FULL` / `Automatic`, the same as a
scheduled backup; only its name, `customer_<time>_<id>_<user name>`, sets it apart (automatic backups are named
`daily_...`). The fetcher therefore counts a MySQL backup whose name starts with `customer_` or `customer-` as manual, whatever
its labels; the hyphenated names returned by the 2024-12-30 api-version are why both separators are accepted.
