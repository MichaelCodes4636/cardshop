# CardVault
Made by Michael Joo, 2026.

## Run on your computer
1. Install Node.js 18+ (nodejs.org).
2. In this folder: `npm install`, then copy `.env.example` to `.env` and fill it in.
3. `npm start`, then open http://localhost:3000

## Put it online with Render
1. Create a free GitHub repository, then upload everything in this folder
   (NOT `node_modules`, `.env` or `data`; `.gitignore` already skips them).
2. In Google Cloud (APIs & Services > Credentials) add your Render address,
   `https://YOUR-APP.onrender.com`, to Authorized JavaScript origins of your Web application client.
3. On render.com: New + > Web Service > connect the repository.
   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
4. Environment variables (same names as `.env.example`):
   `BASE_URL` = your https Render address, `JWT_SECRET` = a new long random string,
   `GOOGLE_CLIENT_ID`, `ADMIN_EMAIL`, and the `SMTP_*` values.
5. To keep users, cards and photos between deploys, use a FREE database: create a project at neon.tech,
   copy its connection string, and add it in Render as `DATABASE_URL`. (Alternative: a paid Render Disk
   mounted at `/var/data` with `DATA_DIR=/var/data`.)
6. Deploy, open your address, and sign in with Google as the admin.

Notes: Render's free plan sleeps after inactivity (the first visit is slow) and blocks standard
SMTP ports, so use port 2525 with Brevo/Mailgun/SendGrid, or a paid plan, for verification emails.
