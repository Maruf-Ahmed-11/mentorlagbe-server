# MentorLagbe — Backend API Server

Express.js + MongoDB REST API powering **MentorLagbe (Smart Tuition & Mentorship Platform)** with BetterAuth JWKS/JWT verification, role-based middlewares, and Stripe payment verification.

- **Live Server URL:** https://mentorlagbe-server-indol.vercel.app/
- **Live Client URL:** https://mentorlagbe-seven.vercel.app/

## Tech Stack & NPM Packages

- `express` (`^5.3.0`) — HTTP server and REST API routing
- `mongodb` (`^7.9.1`) — Native MongoDB Atlas driver
- `jose` (`^6.2.18`) — Remote JWKS & JWT token verification
- `stripe` (`^23.2.0`) — Stripe Checkout session verification
- `cors` (`^2.8.6`) — Cross-Origin Resource Sharing for Vercel & client origin
- `dotenv` (`^18.0.10`) — Environment variable configuration

## Role-Based Middlewares

- `verifyToken` — Validates Bearer JWT via BetterAuth Remote JWKS (`/api/auth/jwks`)
- `verifyStudent` — Restricts routes to `student` accounts
- `verifyTutor` — Restricts routes to `tutor` (or `admin`) accounts
- `verifyAdmin` — Restricts routes to `admin` accounts

## Environment Variables (`.env`)

```env
CLIENT_URL=https://mentorlagbe-seven.vercel.app
MONGODB_URI=your_mongodb_connection_string
STRIPE_SECRET_KEY=your_stripe_secret_key
JWT_SECRET=your_jwt_secret
```
