# Test Data Directory

This directory is for **YOUR** BloodHound data exports for testing purposes.

## Required Files

To run live integration tests, you need to provide your own BloodHound exports:

- `legacy_bh_data.json` - BloodHound Legacy format data (from your test environment)
- `bhce_bh_data.json` - BloodHound Community Edition format data (from your test environment)

## How to Generate Test Data

### BloodHound Community Edition (BHCE)

Export high-value users from your test environment:

```cypher
MATCH (n)
WHERE coalesce(n.system_tags, "") CONTAINS "admin_tier_0"
   OR n.highvalue = true
MATCH p = (n)-[:MemberOf*1..]->(g:Group)
RETURN p;
```

Save the results to `bhce_bh_data.json`

### Legacy BloodHound

Export high-value users from your test environment:

```cypher
MATCH (u:User {highvalue:true})
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, properties(u) as all_props, collect(g.name) as groups, collect(g.objectid) as group_sids
RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
ORDER BY SamAccountName
```

Save the results to `legacy_bh_data.json`

## Important Notes

⚠️ **These files contain data from YOUR test environment**

- **DO NOT** commit these files to git (they are gitignored)
- **DO NOT** use production data
- **DO NOT** share these files publicly
- Files should contain data from your LAB/TEST environment only

## File Structure

```
tests/test_data/
├── README.md (this file)
├── legacy_bh_data.json (YOU must create this)
└── bhce_bh_data.json (YOU must create this)
```

## Configuration

Update `tests/live_test_config.json` to reference these files:

```json
{
  "bloodhound_data_files": {
    "legacy": "test_data/legacy_bh_data.json",
    "bhce": "test_data/bhce_bh_data.json"
  }
}
```

## See Also

- Main README for BloodHound export queries
- `tests/live_test_config.json.example` for full configuration
- `LIVE_TESTING.md` for live testing guide
