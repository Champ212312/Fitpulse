# FitPulse 2.0 implementation notes

## Security and architecture delivered

- Added an Express API with server-side role checks (`member`, `staff`, `admin`).
- Added SQLite persistence with foreign keys, indexes, WAL mode, attendance, members, sessions and audit events.
- Passwords are hashed with bcrypt (cost 12); there are no default credentials in source code.
- Authentication uses signed, HttpOnly, SameSite=Strict cookies and revocable server-side sessions.
- Login is rate limited; request bodies are size-limited; Helmet security headers and a restrictive Content Security Policy are enabled.
- Registration creates a 30-day membership in `pending` payment state. Only an administrator can mark it paid; expired/unpaid accounts cannot log in or check in.
- Attendance capacity, duplicate active check-in and checkout rules are enforced server-side.
- Attendance rows use stable member IDs where available; member history is scoped to the authenticated member.
- Administrative changes are written to an audit log.
- Added automated validation tests and Node syntax checks.

## Important integration boundary

The original `index.html` and `app.js` are preserved as the legacy browser-only demonstration UI. They still use localStorage for the existing demo workflow and are **not yet wired to the new API**. Do not enter real member information into the legacy UI. The secure API is available at `/api`; connecting the existing UI to these endpoints is a separate frontend migration step. This is stated explicitly rather than claiming that the browser-only UI is secured by the backend existing alongside it.

## Production deployment checklist

1. Use Node.js 20 or later and run `npm ci`.
2. Copy `.env.example` to `.env`; generate a unique random `JWT_SECRET` of at least 32 characters and set strong unique admin/staff passwords (at least 12 characters).
3. Set `NODE_ENV=production`, configure HTTPS at the reverse proxy, and use a persistent encrypted volume for the SQLite database. For multi-instance production deployments, migrate the DB layer to PostgreSQL.
4. Back up `data/fitpulse.sqlite` regularly and test restore procedures.
5. Configure a payment provider and only mark memberships paid after verified payment webhooks; the included admin payment-status endpoint is a manual operational control, not payment processing.
6. Configure log retention, monitoring, backups, and privacy/retention policies appropriate to local law.
7. Replace external CDN assets with pinned/self-hosted assets and review the CSP before deployment.
8. Run `npm test` and `npm run check` before release.

## API overview

- `POST /api/auth/register` — member registration (pending payment)
- `POST /api/auth/login` — login; accepts `{email,password,role?}`
- `POST /api/auth/logout` — revoke current session
- `GET /api/auth/me` — current account
- `GET /api/members` — staff/admin member list
- `PATCH /api/members/:id/payment` — admin changes payment state
- `GET /api/attendance` — member's own history or staff/admin history
- `POST /api/attendance/check-in` — member self check-in or staff/admin check-in `{memberId}` / `{name}`
- `POST /api/attendance/:id/check-out` — staff/admin checkout
- `DELETE /api/attendance/:id` — admin deletion
- `GET /api/reports/summary` — staff/admin summary
- `GET /api/audit` — admin audit events
- `GET /api/health` — health check

All authenticated routes use the HttpOnly session cookie. For production, enforce HTTPS and add CSRF protection if cross-site request patterns or cookie settings change.
