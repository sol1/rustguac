# Reports

The reports page provides usage analytics and session history for your rustguac deployment. It is available to users with the **poweruser** role or higher.

## Summary cards

The top of the reports page shows four summary metrics:

- **Total Sessions** -- lifetime count of all sessions (within the retention window)
- **Total Hours** -- cumulative session duration in hours
- **Unique Users** -- number of distinct users who have created sessions
- **Active Now** -- sessions currently in progress

## Session history

A searchable, sortable table of all past and current sessions. Each row includes the user who created the session, the address book entry and folder (if applicable), session type (SSH, RDP, VNC, Web), hostname, start time, duration, status, and a link to the recording if one exists.

The table supports:

- **Text filter** -- type in the filter box to narrow results across all visible columns
- **Column sorting** -- click any column header to sort ascending/descending
- **Pagination** -- navigate through results 100 at a time

### CSV export

Click the **Export CSV** button next to the filter input to download the full session history as a CSV file. The export respects the same filters available via the API (user, entry, type, date range) and returns all matching rows (up to 100,000).

The CSV columns are: Session ID, Type, Hostname, Username, User, Entry, Folder, Started, Ended, Duration (secs), Status, Recording.

## Leaderboards

Two side-by-side panels at the bottom of the page:

- **Top Connections** -- most frequently used connections, ranked by session count, with total hours
- **Top Users** -- most active users, ranked by session count, with total hours and last session time

## Access control

All report endpoints require the **poweruser** role (level 3) or higher. Users with the **operator** or **viewer** role will receive a 403 Forbidden response.

## Session history retention

Session history is retained for a configurable number of days. Old entries are automatically cleaned up once per hour. Configure this in your `config.toml`:

```toml
session_history_retention_days = 90   # default: 90, set to 0 to keep forever
```

## API endpoints

All endpoints require authentication (API key, user token, or OIDC session cookie) with poweruser+ role.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/reports/summary` | Summary statistics (total sessions, hours, unique users, active now) |
| `GET` | `/api/reports/sessions` | Paginated session history with filters |
| `GET` | `/api/reports/sessions/csv` | Export session history as CSV download |
| `GET` | `/api/reports/top-connections` | Most-used connections leaderboard |
| `GET` | `/api/reports/top-users` | Most active users leaderboard |

### Query parameters for session endpoints

| Parameter | Description |
|-----------|-------------|
| `user` | Filter by username (partial match) |
| `entry` | Filter by address book entry name (partial match) |
| `type` | Filter by session type: `ssh`, `rdp`, `vnc`, `web` |
| `from` | Start date filter (ISO 8601, e.g. `2025-01-01T00:00:00Z`) |
| `to` | End date filter (ISO 8601) |
| `limit` | Page size (default 100, max 1000; ignored for CSV export) |
| `offset` | Page offset (default 0; ignored for CSV export) |

### Example: export last month's SSH sessions

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "https://console.example.com/api/reports/sessions/csv?type=ssh&from=2025-02-01T00:00:00Z&to=2025-03-01T00:00:00Z" \
  -o ssh-sessions.csv
```
