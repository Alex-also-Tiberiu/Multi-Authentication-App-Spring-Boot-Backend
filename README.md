# Authentication System Documentation

## Overview

This document describes the authentication and authorization system implemented in the Security application. The system uses JWT (JSON Web Tokens) with HttpOnly cookies for a secure BFF (Backend For Frontend) architecture, complemented by Basic Authentication for the initial login, and CSRF protection with database-backed tokens.

## Architecture

### Authentication Flow

```
1. User Registration
   POST /api/v1/auth/register
   └─> Register new user (no CSRF required)

2. User Login (Basic Authentication)
   POST /api/v1/auth/authenticate (with Authorization: Basic header)
   └─> Validates credentials
   └─> Sets HttpOnly cookies:
       - access_token (JWT, 15 min)
       - refresh_token (JWT, 7 days)
       - XSRF-TOKEN (CSRF token, 15 min, readable by JS)
   └─> Saves tokens in database:
       - TokenType.BEARER (access token)
       - TokenType.REFRESH (refresh token)
       - TokenType.CSRF (CSRF token)

3. Subsequent Requests (POST/PUT/DELETE/PATCH)
   Any protected endpoint
   └─> Browser sends cookies: access_token, XSRF-TOKEN
   └─> Frontend reads XSRF-TOKEN cookie and sends in X-XSRF-TOKEN header
   └─> JwtAuthenticationFilter validates JWT
   └─> CsrfCookieFilter validates CSRF token against database
   └─> Authorizes the request if both valid

4. Token Refresh
   POST /api/v1/auth/refresh-token
   └─> Reads refresh_token from cookie
   └─> Validates refresh token from database
   └─> Generates NEW access_token and NEW refresh_token
   └─> Generates NEW CSRF token
   └─> Revokes all old tokens (rotation)
   └─> Sets updated cookies

5. Logout
   POST /api/v1/auth/logout
   └─> Revokes all tokens in database (BEARER, REFRESH, CSRF)
   └─> Clears all authentication cookies
```

## Components

### 1. AuthenticationService
**Location:** `com.panda.security.auth.AuthenticationService`

Handles all authentication logic:

- **`register(RegisterRequest)`**: Creates a new user with encoded password and returns JWT tokens
- **`authenticate(Authentication)`**: Validates user credentials and returns tokens (used internally)
- **`authenticateAndSetCookies(Authentication, HttpServletResponse)`**: 
  - Authenticates user and sets HttpOnly cookies
  - Generates and saves CSRF token in database
  - Saves access token (BEARER) and refresh token (REFRESH) in database
- **`refreshToken(HttpServletRequest, HttpServletResponse)`**: 
  - Validates refresh token from database
  - Issues new access token, refresh token, and CSRF token
  - Implements refresh token rotation (old tokens revoked)
- **`cleanCookies(HttpServletResponse)`**: Clears authentication cookies on logout

#### Cookie Configuration
- **access_token**: 15 minutes, HttpOnly, Secure (prod), SameSite=Strict, Path=/
- **refresh_token**: 7 days, HttpOnly, Secure (prod), SameSite=Strict, Path=/api/v1/auth/refresh-token
- **XSRF-TOKEN**: 15 minutes, HttpOnly=false (readable by JS), Secure (prod), SameSite=Strict, Path=/

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

### 4. CsrfCookieFilter
**Location:** `com.panda.security.csrf.CsrfCookieFilter`

Custom filter that validates CSRF tokens for state-changing requests:

- Validates CSRF token for POST, PUT, DELETE, PATCH requests
- Skips validation for exempt endpoints (register, refresh-token, csrf/token)
- Retrieves authenticated user from SecurityContext
- Compares X-XSRF-TOKEN header with token stored in database (TokenType.CSRF)
- Returns 403 Forbidden if token is invalid or missing

### 5. CsrfTokenService
**Location:** `com.panda.security.csrf.CsrfTokenService`

Service for managing CSRF tokens:

- **`generateAndSaveCsrfToken(User, HttpServletResponse)`**: 
  - Generates cryptographically secure random token
  - Revokes old CSRF tokens for the user
  - Saves new token in database with TokenType.CSRF
  - Sets XSRF-TOKEN cookie (HttpOnly=false)
- **`validateCsrfToken(HttpServletRequest, User)`**: 
  - Validates X-XSRF-TOKEN header against database
  - Returns true if token matches and is not revoked/expired
- **`clearCsrfCookie(HttpServletResponse)`**: Removes XSRF-TOKEN cookie

### 6. SecurityConfiguration
**Location:** `com.panda.security.config.SecurityConfiguration`

Configures Spring Security with:

- **CSRF**: Built-in CSRF disabled (using custom implementation with database-backed tokens)
- **Session management**: Stateless (no server-side sessions)
- **Authorization rules**:
  - White-listed endpoints (register, refresh-token, csrf/token, Swagger UI) are public
  - `/api/v1/auth/authenticate` requires Basic Authentication
  - `/api/v1/management/**` requires specific roles and permissions (ADMIN/MANAGER)
  - All other endpoints require valid JWT token
- **CORS configuration**: Allows credentials (cookies) from frontend origin (localhost:5173)
- **Filter chain**: BasicAuthFilter → JwtAuthenticationFilter → CsrfCookieFilter

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

#### GET `/api/v1/csrf/token`
Get the current CSRF token for the authenticated user.

**Request:**
Requires authentication (sends `access_token` cookie automatically).

**Response (JSON):**
```json
{
  "token": "k3j2h4k3j2h4k3j2h4k3j2h4...",
  "headerName": "X-XSRF-TOKEN",
  "parameterName": "_csrf"
}
```

**Note:** The CSRF token is also available in the `XSRF-TOKEN` cookie.

### Protected Endpoints (Require Authentication)

#### POST `/api/v1/auth/authenticate`
Login with Basic Authentication.

**Request:**
```
Authorization: Basic base64(username:password)
```

**Response:**
Sets three cookies:
- `access_token`: JWT token (15 minutes, HttpOnly)
- `refresh_token`: Refresh token (7 days, HttpOnly)
- `XSRF-TOKEN`: CSRF token (15 minutes, readable by JavaScript)

#### POST `/api/v1/auth/refresh-token`
Refresh the access token using the refresh token.

**Request:**
Browser automatically sends `refresh_token` cookie.

**Response:**
Sets updated cookies with new tokens:
- `access_token`: New JWT token (15 minutes)
- `refresh_token`: New refresh token (7 days) - Token Rotation
- `XSRF-TOKEN`: New CSRF token (15 minutes)

**Note:** Old tokens are automatically revoked in the database.

#### POST `/api/v1/auth/logout`
Logout and clear all authentication cookies.

**Request:**
```
Cookie: access_token=...
X-XSRF-TOKEN: <csrf-token>
```

**Response:**
Clears all cookies (`access_token`, `refresh_token`, `XSRF-TOKEN`) and revokes all tokens in database.

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
- **HttpOnly cookies** (`access_token`, `refresh_token`): Cannot be accessed by JavaScript (prevents XSS attacks)
- **Non-HttpOnly cookie** (`XSRF-TOKEN`): Must be readable by JavaScript to send in request headers
- **Secure**: Only transmitted over HTTPS (in production)
- **SameSite=Strict**: Prevents CSRF attacks by not sending cookies on cross-site requests
- **Path restrictions**: 
  - `access_token`: Available for entire site (/)
  - `refresh_token`: Only for /api/v1/auth/refresh-token
  - `XSRF-TOKEN`: Available for entire site (/)
- Cookies are automatically sent by browser in same-origin requests

### 4. CSRF Protection
- **Database-backed tokens**: CSRF tokens stored in database with TokenType.CSRF
- **Double Submit Cookie pattern**: Token sent both as cookie and in X-XSRF-TOKEN header
- **Validation**: Backend compares header value with database value
- **Token rotation**: New CSRF token generated on login and refresh
- **Automatic revocation**: CSRF tokens revoked on logout
- **Exempt endpoints**: Register, refresh-token, CSRF endpoint, GET requests

#### Frontend Usage
```javascript
// Read CSRF token from cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('XSRF-TOKEN='))
  ?.split('=')[1];

// Include in POST/PUT/DELETE/PATCH requests
fetch('/api/v1/books', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-XSRF-TOKEN': csrfToken  // Required!
  },
  credentials: 'include',
  body: JSON.stringify({ title: 'Book', author: 'Author' })
});
```

### 5. Token Revocation
- All issued tokens are stored in database with specific types:
  - **TokenType.BEARER**: Access tokens (JWT)
  - **TokenType.REFRESH**: Refresh tokens (JWT)
  - **TokenType.CSRF**: CSRF protection tokens
- Tokens marked as `expired` or `revoked` are invalidated
- On user login from new device, all previous tokens are revoked
- On refresh token use, old refresh token is revoked (rotation)
- On logout, all tokens (BEARER, REFRESH, CSRF) are explicitly revoked

### 6. Role-Based Access Control (RBAC)
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
- **Storage**: HttpOnly cookie with restricted path (/api/v1/auth/refresh-token)
- **Validation**: Verified against database (TokenType.REFRESH) before issuing new tokens
- **Rotation**: Each refresh generates a NEW refresh token and revokes the old one
- **Security**: Prevents replay attacks and token theft

### CSRF Token
- **Duration**: 15 minutes (same as access token)
- **Usage**: Protect against Cross-Site Request Forgery attacks
- **Storage**: Non-HttpOnly cookie (XSRF-TOKEN) + database (TokenType.CSRF)
- **Validation**: X-XSRF-TOKEN header must match database value
- **Required for**: POST, PUT, DELETE, PATCH requests to protected endpoints
- **Exempt**: GET requests, register, refresh-token, csrf/token endpoint

## Development vs Production

### Current Configuration (Development)
- `Secure` flag set to `false` (allows HTTP)
- Suitable for local development

### For Production
Update cookie settings in `AuthenticationService` and `CsrfTokenService`:
```java
// In AuthenticationService.setAuthenticationCookies()
accessCookie.setSecure(true);   // Enforce HTTPS
refreshCookie.setSecure(true);  // Enforce HTTPS

// In CsrfTokenService.setCsrfCookie()
csrfCookie.setSecure(true);     // Enforce HTTPS
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
- **Missing CSRF token**: Returns 403 Forbidden with JSON error message
- **Invalid CSRF token**: Returns 403 Forbidden with `{ "error": "Invalid CSRF token" }`

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
- `token`: Token value (JWT for BEARER/REFRESH, random for CSRF)
- `token_type`: BEARER, REFRESH, or CSRF
- `expired`: Boolean flag
- `revoked`: Boolean flag

**Example Data:**
```sql
SELECT id, LEFT(token, 20) as token_preview, token_type, expired, revoked
FROM token WHERE user_id = 42;

| id | token_preview        | token_type | expired | revoked |
|----|----------------------|------------|---------|---------|
| 1  | eyJhbGciOiJIUzI1... | BEARER     | false   | false   |
| 2  | k3j2h4k3j2h4k3j2... | CSRF       | false   | false   |
| 3  | eyJhbGciOiJIUzI1... | REFRESH    | false   | false   |
```

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
- [ ] Add audit logging for security events
- [ ] Implement rate limiting on authentication endpoints
- [ ] Add password reset functionality
- [ ] Implement email verification
