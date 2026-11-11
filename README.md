# min-security

[![CI](https://github.com/lcmuniz/min-security/actions/workflows/ci.yml/badge.svg)](https://github.com/lcmuniz/min-security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small, readable reference for **stateless JWT authentication with Spring Security** — no database,
no OAuth server, just the pieces you need to understand how access and refresh tokens fit together.

**Stack:** Java 25 · Spring Boot 4.1 · Spring Security 7 · JJWT 0.13 · JUnit 5 / MockMvc

## What it shows

- Login with username/password (bcrypt, `DaoAuthenticationProvider`) returning an **access + refresh token pair**
- A `OncePerRequestFilter` that authenticates `Authorization: Bearer <token>` requests
- **Short-lived access tokens** (15 min) and **single-use refresh tokens** (rotation, 1 day)
- **Logout** that revokes the refresh token
- Token **type**, **issuer**, signature and expiry checked on every request — a refresh token can't be used as an access token
- Role-based authorization (`/api/admin` requires `ADMIN`)
- Clean errors: `401` for bad credentials or tokens, `400` for invalid bodies, as RFC 9457 problem details
- 25 tests covering the happy path and token misuse (expired, forged, wrong type, reused, someone else's)

## Run it

```bash
export JWT_SECRET=$(openssl rand -base64 32)   # optional; a random key is used if unset
./mvnw spring-boot:run
```

Demo users: `admin` / `admin` (roles ADMIN, USER) and `user` / `user` (role USER).
These defaults are for local use only — override them with `DEMO_ADMIN_PASSWORD` and `DEMO_USER_PASSWORD`.

## Try it

```bash
# log in
curl -s localhost:8080/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
# -> {"accessToken":"…","refreshToken":"…","tokenType":"Bearer"}

# call a protected endpoint
curl -s localhost:8080/api/private -H "Authorization: Bearer $ACCESS"

# get a new pair (the old refresh token stops working)
curl -s localhost:8080/api/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"

# log out (revokes the refresh token)
curl -s -X POST localhost:8080/api/logout -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"
```

| Method | Path           | Auth          | Description                          |
|--------|----------------|---------------|--------------------------------------|
| GET    | `/api/public`  | none          | Public endpoint                      |
| POST   | `/api/login`   | none          | Exchange credentials for tokens      |
| POST   | `/api/refresh` | none          | Exchange a refresh token for a new pair |
| GET    | `/api/private` | access token  | Returns the current user and roles   |
| GET    | `/api/admin`   | ADMIN role    | Admin-only endpoint                  |
| POST   | `/api/logout`  | access token  | Revokes the given refresh token      |

## Configuration

| Property               | Env var               | Default        |
|------------------------|-----------------------|----------------|
| `app.jwt.secret`       | `JWT_SECRET`          | random per run |
| `app.jwt.access-ttl`   |                       | `15m`          |
| `app.jwt.refresh-ttl`  |                       | `1d`           |
| `app.demo.admin-password` | `DEMO_ADMIN_PASSWORD` | `admin`     |
| `app.demo.user-password`  | `DEMO_USER_PASSWORD`  | `user`      |

## Design notes and limits

This is a teaching project, so some choices are deliberately simple:

- **Users and refresh tokens live in memory.** A real service would load users from a database and keep
  refresh-token state in Redis or a table so it survives restarts and works across instances.
- **Access tokens are not revoked on logout**; they simply expire (15 min). Keep the TTL short or add a deny-list if you need instant revocation.
- **HS256 with a shared secret** is fine for a single service. When other services must verify tokens, prefer an asymmetric key (RS256/EdDSA) or an OAuth2 authorization server with `spring-boot-starter-oauth2-resource-server`.
- No rate limiting on `/api/login`; put one in front of it in production.

## Tests

```bash
./mvnw verify
```

## License

[MIT](LICENSE)
