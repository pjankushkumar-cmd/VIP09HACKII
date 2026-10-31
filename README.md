# HACKII PANEL — restored original dashboard + shared ChaCha20

## Deploy to Render
- Build: `npm install`
- Start: `npm start`
- Set `ADMIN_SECRET` (minimum 16 characters; retain your existing value if already set).
- Attach a persistent disk at `/var/data` (the Blueprint specifies 1 GB).
- Node 20+ is required. Render provides `PORT`.

## Preserved UI
The public dashboard is restored from the original `NO_LOGIN_CHACHA20_UPDATED.html` source: original period card, countdown, prediction display, result popup, Latest Signals and History layout, themes, tabs, and original visual styling. Branding is HACKII PANEL. Telegram points to the supplied channel.

## Shared prediction
The browser no longer generates an independent prediction. The server fetches the official WinGo 1-minute history endpoint and generates one ChaCha20 prediction per newly observed API issue. It stores the pick and upcoming issue on the persistent disk. All authenticated members receive the same signal from `/api/signal`. When the API reports that upcoming issue, the server matches the saved BIG/SMALL side and the two selected numbers, then records WIN/LOSS/JACKPOT. API failures do not trigger simulated results.

## Admin
Open `/admin` or tap the shield on the login screen. Admin can create keys (1–365 days), disable/enable keys, delete keys, see online/offline/disabled counts, per-member activity time, current session duration, first/last seen, device ID and browser/platform details, and disable/enable an individual member device session. Device ID is an app-generated browser identifier, not IMEI or a hardware serial number.

## Notes
Historical demo WIN/LOSS rows have been removed so the restored History is populated from server-verified rounds after this deployment. Earlier API results cannot be assigned old predictions retrospectively. The server requires a working official API to create the shared upcoming signal.
