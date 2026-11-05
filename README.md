# FitPulse 2.0

Gym attendance and membership management project with the original front-end demonstration and a new secure API foundation.

## Requirements
- Node.js 20+
- npm

## Setup
```bash
npm install
cp .env.example .env
```
Edit `.env` before starting. Set `JWT_SECRET` to a unique random value of at least 32 characters. Set unique admin and staff passwords of at least 12 characters. The server creates the configured bootstrap accounts on first startup only; there are no hardcoded credentials.

```bash
npm start
```
Open `http://localhost:3000`.

## Important: demo UI vs secure API
The original browser UI is preserved. Its legacy attendance and registration flows still use `localStorage` and are **not yet connected to the secure API**. Do not use that legacy UI for real member data. The new backend API under `/api` implements password hashing, server-side authorization, persistent records, attendance capacity checks, membership payment/expiry gates, sessions and audit logging. See [implementation notes](docs/IMPLEMENTATION-NOTES.md) for API routes and deployment requirements.

## Tests
```bash
npm test
npm run check
```

## Capacity
Default maximum occupancy is 50; configure `MAX_CAPACITY` in `.env`.
