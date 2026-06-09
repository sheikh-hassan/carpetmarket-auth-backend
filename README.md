# CarpetMarket — Authentication & RBAC Backend

Production authentication system for **CarpetMarket**, a multi-vendor eCommerce 
platform. Built with Django REST Framework, this module handles the full identity 
and access management layer for a platform with five distinct user roles.

## What This Does

This is the `accounts` app from the CarpetMarket backend — responsible for:

- **Multi-role JWT authentication** — custom token claims per role (customer, vendor, cleaner, admin, superadmin)
- **Role-Based Access Control (RBAC)** — dynamic permission classes with granular codename-level enforcement
- **Google OAuth 2.0** — full authorization code flow with CSRF state validation and UTM parameter tracking
- **Secure password reset** — Redis-cached single-active-token policy with 15-minute TTL; no email enumeration
- **Email verification** — token-based onboarding flow for vendors and cleaners before account activation
- **Admin approval workflow** — two-stage activation (email verify → admin approve) with email notifications

## Key Design Decisions

**Single-token password reset via Redis**  
Instead of allowing unlimited reset tokens, each user gets one active token stored 
in Redis with a 15-minute TTL. Re-requesting within the window re-sends the same 
token rather than generating a new one — preventing token spam and simplifying 
invalidation on use.

**Dynamic permission classes**  
Rather than hardcoding permissions per view, `HasGroupedPermission.with_codename()` 
generates permission classes at declaration time. This keeps viewsets clean and 
makes permission requirements explicit and readable at a glance.

**No email enumeration**  
Password reset always returns the same response regardless of whether the email 
exists in the database — a standard security practice to prevent user enumeration 
attacks.

**Role-aware login responses**  
The login endpoint returns role-specific data: admin users receive their grouped 
permissions alongside the token, enabling the frontend to render the correct 
dashboard without an extra round-trip.

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Django 4.2 + Django REST Framework |
| Auth | JWT (simplejwt) + Google OAuth 2.0 |
| Caching | Redis (django-redis) |
| Database | PostgreSQL |
| Email | Django EmailMultiAlternatives (HTML + plaintext) |
| Deployment | Docker + AWS EC2 |

## Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login/` | JWT login with role checks |
| POST | `/api/auth/register/` | Customer registration |
| POST | `/api/auth/vendor/signup/` | Vendor registration + email verification |
| POST | `/api/auth/cleaner/signup/` | Cleaner registration + email verification |
| GET | `/api/auth/verify-email/` | Email token verification |
| POST | `/api/auth/password-reset/` | Request password reset (Redis-cached) |
| POST | `/api/auth/password-reset/confirm/` | Confirm and apply new password |
| GET | `/api/auth/login/google/` | Initiate Google OAuth flow |
| GET | `/api/auth/google/callback/` | Google OAuth callback handler |
| GET | `/api/auth/me/` | Authenticated user profile |
| PATCH | `/api/auth/profile/update/` | Update display name |
| POST | `/api/auth/change-password/` | Change password (authenticated) |

## User Roles
superadmin  — full platform access, bypasses all permission checks
admin       — granular codename-based permissions assigned per deployment
vendor      — must pass email verification + admin approval before login
cleaner     — must pass email verification + admin approval before login
customer    — self-registers, immediately active

## Running Locally

```bash
# Clone and install
git clone https://github.com/YOUR_USERNAME/carpetmarket-auth-backend
cd carpetmarket-auth-backend
pip install -r requirements.txt

# Environment variables required
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
GOOGLE_OAUTH_REDIRECT_URI=...
FRONTEND_BASE_URL=http://localhost:3000

# Redis must be running
redis-server

# Run
python manage.py migrate
python manage.py runserver
```

## Notes

This is the authentication module extracted from a private client project. 
The full platform includes a product catalog, order management, payment 
integration (Stripe), and an admin dashboard — built with Next.js on the frontend 
and deployed on AWS EC2 + RDS.
