# flexible_server_backups fixtures

Response bodies of `GET flexibleServers/{server}/backups`, copied from Microsoft's published examples in
[Azure/azure-rest-api-specs](https://github.com/Azure/azure-rest-api-specs):

- `postgresql-backups-2024-08-01.json`: `Microsoft.DBforPostgreSQL/PostgreSql/stable/2024-08-01/examples/BackupListByServer.json`
  (one automatic and one on-demand backup).
- `mysql-backups-2023-12-30.json`: `Microsoft.DBforMySQL/FlexibleServers/stable/2023-12-30/examples/BackupsListByServer.json`
  (automatic backups only).

They hold no tenant data. The MySQL list has no on-demand backup, and the published MySQL on-demand example reports
`source: Automatic`, so how a real MySQL on-demand backup is labelled is still to be confirmed against a live response.
