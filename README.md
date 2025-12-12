# Authentication System Documentation

## Overview

This document describes the authentication and authorization system implemented in the Security application. The system uses JWT (JSON Web Tokens) with HttpOnly cookies for a secure BFF (Backend For Frontend) architecture, complemented by Basic Authentication for the initial login.

## Architecture

### Authentication Flow

```
1. User Registration
   POST /api/v1/auth/register
   └─> Register new user

2. User Login (Basic Authentication)
   POST /api/v1/auth/authenticate (with Authorization: Basic header)
   └─> Sets HttpOnly cookies: access_token (15 min) and refresh_token (7 days)

3. Subsequent Requests
   Any protected endpoint
   └─> JwtAuthenticationFilter reads token from cookie or Bearer header
   └─> Validates token and authorizes the request

4. Token Refresh
   POST /api/v1/auth/refresh-token
   └─> Reads refresh_token from cookie
   └─> Generates new access_token
   └─> Sets updated cookies

5. Logout
   POST /api/v1/auth/logout
   └─> Clears all authentication cookies
```

## Components

### 1. AuthenticationService
**Location:** `com.panda.security.auth.AuthenticationService`

Handles all authentication logic:

- **`register(RegisterRequest)`**: Creates a new user with encoded password and returns JWT tokens
- **`authenticate(Authentication)`**: Validates user credentials and returns tokens (used internally)
- **`authenticateAndSetCookies(Authentication, HttpServletResponse)`**: Authenticates user and sets HttpOnly cookies
- **`refreshToken(HttpServletRequest, HttpServletResponse)`**: Validates refresh token and issues new access token
- **`cleanCookies(HttpServletResponse)`**: Clears authentication cookies on logout

#### Cookie Configuration
- **access_token**: 15 minutes duration, HttpOnly, Secure, SameSite=Strict
- **refresh_token**: 7 days duration, HttpOnly, Secure, SameSite=Strict

### 2. JwtAuthenticationFilter
**Location:** `com.panda.security.config.JwtAuthenticationFilter`

Spring Security filter that validates JWT tokens on each request:

- Reads token from either:
  1. `Authorization: Bearer <token>` header (backward compatibility)
  2. `access_token` cookie (primary method for BFF)
- Validates token signature and expiration
- Checks token revocation status in database
- Sets SecurityContext if token is valid

### 3. BasicAuthFilter
**Location:** `com.panda.security.config.BasicAuthFilter`

Custom filter that handles Basic Authentication for the `/api/v1/auth/authenticate` endpoint:

- Decodes Base64-encoded credentials from `Authorization: Basic` header
- Loads user details from database
- Validates password using BCrypt encoder
- Sets SecurityContext for authenticated user
- Only active on `/api/v1/auth/authenticate` endpoint

### 4. SecurityConfiguration
**Location:** `com.panda.security.config.SecurityConfiguration`

Configures Spring Security with:

- **CSRF disabled**: Not needed for stateless JWT-based authentication
- **Session management**: Stateless (no server-side sessions)
- **Authorization rules**:
  - White-listed endpoints (register, refresh-token, Swagger UI) are public
  - `/api/v1/auth/authenticate` requires Basic Authentication
  - `/api/v1/management/**` requires specific roles and permissions (ADMIN/MANAGER)
  - All other endpoints require valid JWT token
- **CORS configuration**: Allows credentials (cookies) from frontend origin (localhost:5173)
- **Filter chain**: BasicAuthFilter → JwtAuthenticationFilter

## API Endpoints

### Public Endpoints

#### POST `/api/v1/auth/register`
Register a new user.

**Request (JSON):**
```json
{
  "firstname": "John",
  "lastname": "Doe",
  "email": "john@example.com",
  "password": "SecurePassword123",
  "role": "USER"
}
```

**Response: empty**



### Protected Endpoints (Require Authentication)

#### POST `/api/v1/auth/authenticate`
Login with Basic Authentication.

**Request:**
```
Authorization: Basic base64(username:password)
```

**Response:**
Sets two HttpOnly cookies:
- `access_token`: JWT token (15 minutes)
- `refresh_token`: Refresh token (7 days)

#### POST `/api/v1/auth/refresh-token`
Refresh the access token using the refresh token.

**Request:**
Browser automatically sends `refresh_token` cookie.

**Response:**
Sets updated cookies with new `access_token`.

#### POST `/api/v1/auth/logout`
Logout and clear all authentication cookies.

**Request:**
```
Authorization: Bearer <access_token>
```

**Response:**
Clears both `access_token` and `refresh_token` cookies.

## Security Features

### 1. Password Security
- Passwords are encoded using **BCrypt** (PasswordEncoder bean)
- Never stored or transmitted in plain text
- Validated during login using BCrypt's `matches()` method

### 2. Token Security
- JWT tokens signed with HMAC-SHA256 (HS256 algorithm)
- Tokens include:
  - User email
  - Expiration time
  - Custom claims (roles, permissions)
- Token signature cannot be forged without the secret key

### 3. Cookie Security
- **HttpOnly**: Cannot be accessed by JavaScript (prevents XSS attacks)
- **Secure**: Only transmitted over HTTPS (in production)
- **SameSite=Strict**: Prevents CSRF attacks
- Cookies are automatically sent by browser in same-origin requests

### 4. Token Revocation
- All issued tokens are stored in database
- Tokens marked as `expired` or `revoked` are invalidated
- On user login, all previous tokens are revoked
- On logout, tokens can be explicitly revoked

### 5. Role-Based Access Control (RBAC)
- Users have roles: USER, ADMIN, MANAGER
- Each role has specific permissions
- Protected endpoints check both role and permission

## Token Lifecycle

### Access Token
- **Duration**: 15 minutes
- **Usage**: Authenticate requests to protected endpoints
- **Storage**: HttpOnly cookie (primary) or Bearer header (fallback)

### Refresh Token
- **Duration**: 7 days
- **Usage**: Obtain new access token without re-authenticating
- **Storage**: HttpOnly cookie with restricted path
- **Validation**: Verified against database before issuing new access token

## Development vs Production

### Current Configuration (Development)
- `Secure` flag set to `false` (allows HTTP)
- Suitable for local development

### For Production
Update `setAuthenticationCookies()` in `AuthenticationService`:
```java
accessCookie.setSecure(true);  // Enforce HTTPS
refreshCookie.setSecure(true); // Enforce HTTPS
```

Also update CORS configuration to accept your production domain:
```java
configuration.addAllowedOrigin("https://yourdomain.com");
```

## Error Handling

- **Missing credentials**: Returns 401 Unauthorized with WWW-Authenticate header
- **Invalid credentials**: Returns 401 Unauthorized
- **Invalid token**: Returns 401 Unauthorized
- **Expired token**: Returns 401 Unauthorized
- **Insufficient permissions**: Returns 403 Forbidden

## Database Schema

### Users Table
- `id`: User ID
- `firstname`: User's first name
- `lastname`: User's last name
- `email`: User's email (unique)
- `password`: BCrypt-encoded password
- `role`: User's role (USER, ADMIN, MANAGER)

### Tokens Table
- `id`: Token ID
- `user_id`: Foreign key to Users
- `token`: JWT token value
- `token_type`: BEARER
- `expired`: Boolean flag
- `revoked`: Boolean flag

## Dependencies

- **Spring Security 6.x**: Authentication and authorization
- **JWT (jjwt)**: JSON Web Token implementation
- **BCrypt**: Password encoding
- **Lombok**: Reduce boilerplate code
- **Jakarta Servlet**: Servlet API for cookies and requests

## Future Enhancements

- [ ] Add Two-Factor Authentication (2FA)
- [ ] Implement OAuth2 provider
- [ ] Add social login (Google, GitHub)
- [ ] Implement token blacklist for immediate revocation
- [ ] Add audit logging for security events
- [ ] Implement rate limiting on authentication endpoints

