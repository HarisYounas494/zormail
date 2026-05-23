# ZorMail Render Edition

This version is rebuilt for Render. It does **not** run SMTP/port 25. Render runs the web app, and incoming emails must be delivered to `/webhook/receive` by an inbound email provider or Cloudflare Email Routing Worker.

## Deploy on Render

1. Upload this folder to GitHub.
2. On Render, create a **Blueprint** from `render.yaml`, or create a Web Service manually.
3. Add environment variables:
   - `ADMIN_PASSWORD` = your strong admin password
   - `ADMIN_PATH` = a secret path like `admin-x9k2-private`
   - `WEBHOOK_SECRET` = a long random secret
4. Add a Render persistent disk mounted at `/var/data` if you create it manually.
5. Open `https://your-app.onrender.com/<ADMIN_PATH>`.

## User flow

- Admin adds allowed domains.
- Users go to `/signup` and create mailboxes under those domains.
- Users sign in at `/signin`.
- Admin can view users, disable accounts, and send test mail.

## Webhook format

POST to:

```text
https://your-app.onrender.com/webhook/receive
```

Headers:

```text
Content-Type: application/json
X-ZorMail-Secret: YOUR_WEBHOOK_SECRET
```

JSON body:

```json
{
  "to": "user@yourdomain.com",
  "from": "sender@example.com",
  "subject": "Hello",
  "text": "Plain text body",
  "html": "<p>HTML body</p>",
  "date": "Sun, 24 May 2026 12:00:00 +0000"
}
```

## Cloudflare Email Worker example

```js
export default {
  async email(message, env, ctx) {
    const raw = await new Response(message.raw).text();

    await fetch(env.ZORMAIL_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZorMail-Secret": env.ZORMAIL_SECRET
      },
      body: JSON.stringify({
        to: message.to,
        from: message.from,
        subject: message.headers.get("subject") || "(No Subject)",
        text: raw
      })
    });
  }
}
```

Set Worker environment variables:
- `ZORMAIL_WEBHOOK_URL`
- `ZORMAIL_SECRET`

## Security added

- Passwords are stored with Werkzeug password hashing, not SHA-256.
- Secret admin URL; `/admin` and `/admin-panel` do not expose login unless authenticated.
- Admin login locks an IP after 3 wrong passwords.
- User login has rate limits and lockout.
- Webhook requires a shared secret.
- HTML emails are sanitized with Bleach before display.
- Secure session cookie settings and basic security headers.
- Render persistent disk path support through `DATA_DIR=/var/data`.

## Important

Free Render services can sleep. For email receiving, sleeping can delay webhook delivery or make providers retry. A paid always-on instance is better for real mail.
