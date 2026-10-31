# HACKII PANEL — Render Web Service

## Deploy
1. Push this project folder to GitHub.
2. In Render choose **New + → Blueprint** and select the repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add only one secret environment variable: `ADMIN_SECRET` (minimum 16 characters; keep it private).
6. Attach a persistent disk mounted at `/var/data`. The included `render.yaml` defines a 1 GB disk. Keys and online-time data are stored in `/var/data/hackii-data.json`.

Render provides `PORT` automatically. `NODE_ENV=production` is set in the Blueprint. No other environment variables are required.

## Admin
On the member login screen, tap the **ADMIN PANEL** shield button (also available in the top bar after login) and enter `ADMIN_SECRET`. Create login keys for 1–365 days, revoke keys, and view total/active keys, online members, login count, last activity, cumulative online time and the member with the highest recorded online time. A new key is displayed once; copy it before closing the panel.

## Notes
- Render provides HTTPS. Never share `ADMIN_SECRET`.
- Without the persistent disk, data may be lost on restart/redeploy.
- The existing WinGo history API and client-side ChaCha20 selection are retained. Random number selection does not guarantee the real game's outcome.
- Existing demo history rows and hard-coded performance labels remain from the source HTML; they are display samples, not verified live performance.


## Shared device state and member online time
- A single server-side round record is saved for each API issue. The first authenticated device to submit a ChaCha20 candidate establishes that issue's shared prediction; all other devices receive the same prediction and two candidate numbers from the server.
- Multiple devices can stay logged in with the same member key at the same time.
- Admin member cards show cumulative online time and the current online session duration. Heartbeats run every 30 seconds; online status expires after 90 seconds without a heartbeat.
- Keep the Render persistent disk mounted at `/var/data` so shared rounds, member sessions, and online-time totals survive restarts.
