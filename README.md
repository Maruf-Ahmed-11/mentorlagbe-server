# MentorLagbe — Backend API Server

## Purpose

The **MentorLagbe Backend API** is an Express.js and MongoDB service that powers secure data operations, JWT/JWKS authentication verification, role-based access control, tuition search and filtering, student reviews, and Stripe payment verification for the MentorLagbe platform.

---

## Live URLs

- **Live Server API:** https://mentorlagbe-server-indol.vercel.app/
- **Live Web Application:** https://mentorlagbe-seven.vercel.app/
- **Server Repository:** https://github.com/Maruf-Ahmed-11/mentorlagbe-server
- **Client Repository:** https://github.com/Maruf-Ahmed-11/mentorlagbe-client

---

## Key Features

- **JWT & JWKS Verification:** Validates client Bearer tokens against BetterAuth Remote JWKS with HS256 secret fallback.
- **Role-Based Middlewares:** Dedicated `verifyToken`, `verifyStudent`, `verifyTutor`, and `verifyAdmin` middlewares protecting sensitive endpoints.
- **Server-Side Search & Filtering:** MongoDB query filtering for tuitions by keyword (`q`), subject, class level, mode, active state, sorting, and pagination.
- **Subscription Limits & Stripe Verification:** Enforces Free vs. Pro tier limits, verifies Stripe Checkout sessions against replay/spoofing, records transactions, and activates Pro plans.
- **Applications, Reviews & Moderation:** Manages student applications, pending cancellations, accepted-student reviews, and admin user/tuition moderation.

---

## NPM Packages Used

| Package | Description |
| :--- | :--- |
| `express` | Fast, minimalist Node.js web framework for REST APIs |
| `mongodb` | Official MongoDB driver for database queries and aggregations |
| `jose` | Standards-compliant JWT and Remote JWKS verification |
| `stripe` | Stripe SDK for server-side Checkout session retrieval and verification |
| `cors` | Cross-Origin Resource Sharing middleware for frontend integration |
| `dotenv` | Environment variable loader for configuration management |
