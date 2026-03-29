# TaskHound Starter Queries

Pre-built Cypher queries for exploring TaskHound's OpenGraph data in BloodHound CE.

## Import

**Drag and drop** `starter_queries.json` into the BloodHound CE Cypher tab, or:

1. Open BloodHound CE
2. Navigate to **Explore > Cypher**
3. Click **Saved Queries > Import**
4. Select `starter_queries.json`

All queries appear under the **TaskHound** category.

## Included queries

| Query | What it shows |
|---|---|
| All Scheduled Tasks | Every ingested task node |
| All Windows Services | Every ingested service node |
| Tasks with Stored Credentials (Full Path) | Computer -> Task -> User for stored-cred tasks |
| Services with Stored Credentials (Full Path) | Computer -> Service -> User |
| TIER-0 Scheduled Tasks | Tasks running as Domain Admin / Enterprise Admin |
| TIER-0 Windows Services | Services running as Tier-0 principals |
| Tasks with Decrypted Passwords | Tasks where DPAPI extraction succeeded |
| Services with Extracted Credentials | Services where LSA extraction succeeded |
| gMSA Services | Services using Group Managed Service Accounts |
| Tasks Running as Domain Admins | Full path: Computer -> Task -> User -> Domain Admins |
| Services Running as Domain Admins | Full path: Computer -> Service -> User -> Domain Admins |
| Hosts with Most Privileged Tasks and Services | Ranked list of high-value hosts |
| Stale Credential Tasks | Tasks with password freshness warnings |
| Shortest Path: Task Account to Domain Admins | BloodHound pathfinding from task accounts |
| Shortest Path: Service Account to Domain Admins | BloodHound pathfinding from service accounts |

## Notes

- OpenGraph nodes are **not** supported in BloodHound's Search or Pathfinding tabs.
  Use the **Cypher tab** exclusively.
- Queries use `LIMIT 1000` by default. Adjust as needed for large environments.
- The `TaskHound` kind is shared by both ScheduledTask and WindowsService nodes,
  useful for cross-type queries.
