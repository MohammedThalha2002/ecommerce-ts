# Authentication API Documentation

## Overview

This authentication system implements a secure JWT-based authentication with the following features:

- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (30 days) with automatic rotation
- Secure httpOnly cookies for refresh tokens
- Device/session management
- Argon2id password hashing
- Role-based access control

## Authentication Flow

### 1. Registration/Login

```
POST /api/auth/register
POST /api/auth/login
```

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "name": "John Doe" // Optional for registration
}
```

**Response:**

```json
{
  "message": "Login successful",
  "user": {
    "id": "clxxx123",
    "email": "user@example.com",
    "name": "John Doe",
    "role": 0,
    "emailVerifiedAt": null,
    "createdAt": "2025-01-01T00:00:00.000Z",
    "updatedAt": "2025-01-01T00:00:00.000Z"
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

**Headers Set:**

- `Set-Cookie: refreshToken=<secure-token>; HttpOnly; Secure; SameSite=strict; Path=/api/auth/refresh`

### 2. Token Refresh

```
POST /api/auth/refresh
```

**Requirements:**

- Refresh token must be sent as httpOnly cookie
- Old refresh token is automatically revoked (token rotation)

**Response:**

```json
{
  "message": "Token refreshed successfully",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

### 3. Using Access Tokens

Include in request headers:

```
Authorization: Bearer <access-token>
```

## API Endpoints

### Public Endpoints

#### Register User

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "name": "John Doe"
}
```

#### Login User

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Refresh Access Token

```http
POST /api/auth/refresh
Cookie: refreshToken=<refresh-token>
```

### Protected Endpoints

#### Get User Profile

```http
GET /api/auth/profile
Authorization: Bearer <access-token>
```

#### Logout (Single Device)

```http
POST /api/auth/logout
Cookie: refreshToken=<refresh-token>
```

#### Logout All Devices

```http
POST /api/auth/logout-all
Authorization: Bearer <access-token>
```

#### Get Active Sessions

```http
GET /api/auth/sessions
Authorization: Bearer <access-token>
```

**Response:**

```json
{
  "message": "Sessions retrieved successfully",
  "sessions": [
    {
      "id": "clxxx456",
      "createdByIp": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "deviceId": "device-123",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "expiresAt": "2025-01-31T00:00:00.000Z"
    }
  ]
}
```

#### Revoke Specific Session

```http
DELETE /api/auth/sessions/:sessionId
Authorization: Bearer <access-token>
```

## Token Structure

### Access Token (JWT)

```json
{
  "sub": "clxxx123", // User ID
  "role": 0, // User role (0=customer, 1=admin)
  "iat": 1712345678, // Issued at
  "exp": 1712346578, // Expires at
  "jti": "unique-id" // JWT ID
}
```

### Refresh Token

- 256-bit random token (base64url encoded)
- Stored as SHA-256 hash in database
- Tied to specific device/session

## Security Features

### Password Security

- Argon2id hashing with:
  - Memory cost: 64MB
  - Time cost: 3 iterations
  - Parallelism: 4 threads

### Token Security

- Access tokens: 15-minute lifetime
- Refresh tokens: 30-day lifetime with rotation
- Secure, HttpOnly, SameSite=strict cookies
- Device tracking and session management

### Headers

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (production only)

## Role-Based Access Control

### User Roles

- `0` - Customer (default)
- `1` - Admin

### Middleware Usage

```typescript
import { authMiddleware, requireAdmin } from "./middlewares/auth.middleware.js";

// Require any authenticated user
router.get("/protected", authMiddleware, controller);

// Require admin role
router.get("/admin-only", authMiddleware, requireAdmin, controller);

// Optional authentication
router.get("/public", optionalAuthMiddleware, controller);
```

## Error Responses

### Authentication Errors

```json
{
  "message": "Access token expired",
  "code": "TOKEN_EXPIRED"
}
```

```json
{
  "message": "Invalid access token",
  "code": "INVALID_TOKEN"
}
```

### Authorization Errors

```json
{
  "message": "Insufficient permissions",
  "required": 1,
  "current": 0
}
```

### Validation Errors

```json
{
  "message": "Validation failed",
  "errors": {
    "email": "Please provide a valid email address",
    "password": "Password must be at least 6 characters long"
  }
}
```

## Client Implementation Example

### JavaScript/TypeScript Client

```typescript
class AuthClient {
  private accessToken: string | null = null;

  async login(email: string, password: string) {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
      credentials: "include", // Important for cookies
    });

    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.accessToken;
      return data;
    }
    throw new Error("Login failed");
  }

  async apiCall(url: string, options: RequestInit = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${this.accessToken}`,
      },
      credentials: "include",
    });

    if (response.status === 401) {
      // Try to refresh token
      await this.refreshToken();
      // Retry original request
      return this.apiCall(url, options);
    }

    return response;
  }

  async refreshToken() {
    const response = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
    });

    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.accessToken;
      return data;
    }

    // Refresh failed, redirect to login
    this.logout();
    throw new Error("Session expired");
  }

  async logout() {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    this.accessToken = null;
  }
}
```

## Environment Variables

```env
# Required
DATABASE_URL="mysql://username:password@localhost:3306/ecommerce"
JWT_SECRET="your-super-secret-jwt-key-here"

# Optional
JWT_REFRESH_SECRET="separate-refresh-token-secret" # Falls back to JWT_SECRET
NODE_ENV="development" # or "production"
```

## Database Schema

The authentication system uses the following database tables:

### Users Table

- `id` - Primary key (CUID)
- `email` - Unique email address
- `passwordHash` - Argon2id hash (nullable for OAuth users)
- `role` - Integer role (0=customer, 1=admin)
- `emailVerifiedAt` - Email verification timestamp
- `createdAt` / `updatedAt` - Timestamps

### Refresh Tokens Table

- `id` - Primary key (CUID)
- `userId` - Foreign key to users
- `tokenHash` - SHA-256 hash of refresh token
- `expiresAt` - Expiration timestamp
- `createdByIp` - IP address of device
- `userAgent` - Browser/device user agent
- `deviceId` - Optional device identifier
- `revokedAt` - Revocation timestamp
- `createdAt` - Creation timestamp

### OAuth Accounts Table (for future OAuth integration)

- `provider` - OAuth provider (google, apple, etc.)
- `providerId` - Provider's user ID
- `userId` - Foreign key to users
