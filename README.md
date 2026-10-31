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


## Shared ChaCha20 upcoming signal
- The Node server fetches the official WinGo 1-minute history API.
- For each newly observed official issue, the server generates exactly one ChaCha20 pick for the next issue and saves it to the persistent data file.
- Every logged-in member reads that same saved signal from `/api/signal`; browser refreshes do not generate a new pick.
- When the API publishes that upcoming issue's result, the server matches the saved prediction against the actual API number, records WIN/LOSS and exact-number JACKPOT, then creates the next period's shared signal.
- If the official API is unavailable, the app reports a sync error and does not invent a local result.

## Member activity details
The Admin member list shows live/offline state, session start, current session duration, cumulative online time, last activity, login count, and a browser/device description. The Device ID is a random app-generated identifier stored by the browser; it is not an IMEI, serial number, or hardware identifier. Browser/platform details are supplied by the member's device.
