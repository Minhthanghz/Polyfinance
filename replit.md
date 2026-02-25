# PolyFinance

## Overview

PolyFinance is a cryptocurrency finance platform (mobile-first web app) built in Vietnamese. It provides features like user wallets, USDT deposits/withdrawals, token swapping (PFT token), crypto mining packages, staking with APR, P2P trading, KYC verification, affiliate/referral systems, and an admin panel. The app has a dark purple/neon cyberpunk theme and targets mobile users.

The project uses a Node.js/Express backend with PostgreSQL for data storage, serving static HTML files as the frontend. Authentication is handled via JWT tokens with bcrypt password hashing.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
- **Static HTML pages** — Each feature has its own standalone HTML file (no SPA framework). Pages include: `index.html` (home/dashboard), `login-register.html`, `profile.html` (wallet), `deposit.html`, `withdraw.html`, `transfer.html`, `swap.html`, `mining.html`, `staking.html`, `market.html`, `p2p.html`, `affiliate.html`, `history.html`, `kyc.html`, `security.html`, `support.html`, `admin.html`.
- **Styling**: Inline `<style>` blocks in each HTML file using CSS custom properties. The design system uses a consistent dark theme with purple neon accents (Orbitron font for headings, Inter for body text).
- **Client-side auth guard**: Pages use a loading overlay (`#auth-guard`) that checks for a valid JWT token in localStorage before showing content. Unauthenticated users are redirected to `login-register.html`.
- **No frontend build step** — plain HTML/CSS/JS served as static files.
- **CDN dependencies**: Google Fonts (Orbitron, Inter) and Font Awesome 6.4.0 icons.

### Backend
- **Express.js** (v5) server in `index.js` serving both the API and static files.
- **API pattern**: REST endpoints under `/api/` prefix (e.g., `/api/auth/register`, `/api/auth/login`).
- **Authentication**: JWT tokens via `jwt-simple` library with a hardcoded secret key. Middleware function `authUser` extracts and validates tokens from the `Authorization` header.
- **Password hashing**: `bcryptjs` with salt rounds of 10.
- **User identification**: Each user gets a 6-digit UID and a referral code formatted as `PFT{UID}`.
- **Static file serving**: `express.static` serves from the project root directory.

### Database
- **PostgreSQL** via the `pg` library, connecting through `DATABASE_URL` environment variable with SSL enabled.
- **Key tables** (inferred from code):
  - `users` — columns include: `id`, `uid` (6-digit number), `email`, `password_hash`, `fullname`, `referral_code`, `referred_by`
  - Additional tables likely needed for: transactions/history, deposits, withdrawals, mining packages, staking records, KYC submissions, wallet addresses, P2P orders
- **Note**: The full database schema is not present in the codebase — tables need to be created. The SQL schema should be set up to support all the features visible in the HTML pages.

### Key Features Requiring Backend Support
1. **Auth** — Register (with referral code), Login, JWT token generation
2. **Wallet** — Balance tracking for USDT and PFT tokens
3. **Deposit** — Wallet address assignment, QR code generation for USDT TRC-20
4. **Withdraw** — Withdrawal requests with fee calculation
5. **Transfer** — Internal transfers between users (by UID)
6. **Swap** — PFT ↔ USDT conversion
7. **Mining** — Package purchases, daily mining rewards, claim system
8. **Staking** — Lock PFT for fixed periods with APR rewards
9. **P2P Trading** — Buy/sell with merchant system
10. **KYC** — Identity verification with document upload
11. **Affiliate** — Referral tracking, team stats, commission calculation
12. **Admin Panel** — User management, transaction approval, system controls (password-protected)
13. **Security** — Password change, 2FA options
14. **Transaction History** — Filterable log of all user activities

## External Dependencies

### NPM Packages
- `express` (v5.2.1) — Web server framework
- `pg` (v8.18.0) — PostgreSQL client
- `bcryptjs` (v3.0.3) — Password hashing
- `jwt-simple` (v0.5.6) — JWT token encoding/decoding
- `cors` (v2.8.6) — Cross-origin resource sharing
- `express-session` (v1.19.0) — Session management (listed in dependencies but usage not visible in current code)

### External Services
- **PostgreSQL database** — Connected via `DATABASE_URL` environment variable
- **Google Fonts CDN** — Orbitron and Inter typefaces
- **Font Awesome CDN** — Icon library (v6.4.0)

### Environment Variables Required
- `DATABASE_URL` — PostgreSQL connection string