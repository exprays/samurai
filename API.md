# Samurai MCP Super Server - API Documentation

## Base URL
```
http://localhost:8080/api/v1
```

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

## Response Format

All API responses follow a consistent JSON format:

### Success Response
```json
{
  "status": "success",
  "data": {
    // Response data
  },
  "message": "Operation completed successfully"
}
```

### Error Response
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {}
  }
}
```

## Health Endpoints

### Health Check
Check if the service is running.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "ok",
  "service": "mcp-super-server",
  "version": "0.1.0"
}
```

### Readiness Check
Check if the service is ready to accept requests (database connectivity).

**Endpoint:** `GET /health/ready`

**Response:**
```json
{
  "status": "ready",
  "database": "connected"
}
```

**Error Response:**
```json
{
  "status": "error",
  "error": "database connection failed"
}
```

## Authentication Endpoints

### User Registration
Register a new user account.

**Endpoint:** `POST /api/v1/auth/register`

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "full_name": "string"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "full_name": "string",
      "role": "user",
      "created_at": "2024-01-01T00:00:00Z"
    },
    "token": "jwt_token_string"
  },
  "message": "User registered successfully"
}
```

**Validation Rules:**
- `username`: Required, 3-50 characters, alphanumeric + underscore
- `email`: Required, valid email format
- `password`: Required, minimum 8 characters
- `full_name`: Required, 2-100 characters

### User Login
Authenticate and receive JWT token.

**Endpoint:** `POST /api/v1/auth/login`

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "full_name": "string",
      "role": "user"
    },
    "token": "jwt_token_string",
    "expires_at": "2024-01-02T00:00:00Z"
  },
  "message": "Login successful"
}
```

## Protected Endpoints

These endpoints require authentication via JWT token.

### Get User Profile
Get current user's profile information.

**Endpoint:** `GET /api/v1/profile`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "full_name": "string",
      "role": "user",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  }
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Access denied |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `DATABASE_ERROR` | 500 | Database operation failed |

## Rate Limiting

API requests are rate limited per user:
- **Authenticated users**: 1000 requests per hour
- **Unauthenticated users**: 100 requests per hour

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Database Models

### User Model
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "password_hash": "string",
  "full_name": "string",
  "role": "enum(admin,user)",
  "is_active": "boolean",
  "email_verified": "boolean",
  "last_login": "timestamp",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

### Plugin Model (Future)
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "version": "string",
  "author": "string",
  "config_schema": "json",
  "is_active": "boolean",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

### Audit Log Model
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "action": "string",
  "resource": "string",
  "resource_id": "string",
  "metadata": "json",
  "ip_address": "string",
  "user_agent": "string",
  "created_at": "timestamp"
}
```

## Request/Response Examples

### cURL Examples

**Register User:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "securepassword123",
    "full_name": "John Doe"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Get Profile:**
```bash
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer <jwt_token>"
```

## Upcoming API Endpoints

The following endpoints are planned for future releases:

### Plugin Management
- `GET /api/v1/plugins` - List all plugins
- `POST /api/v1/plugins` - Create/install plugin
- `GET /api/v1/plugins/{id}` - Get plugin details
- `PUT /api/v1/plugins/{id}` - Update plugin
- `DELETE /api/v1/plugins/{id}` - Remove plugin
- `POST /api/v1/plugins/{id}/activate` - Activate plugin
- `POST /api/v1/plugins/{id}/deactivate` - Deactivate plugin

### LLM Provider Management
- `GET /api/v1/providers` - List LLM providers
- `POST /api/v1/providers` - Add LLM provider
- `PUT /api/v1/providers/{id}` - Update provider
- `DELETE /api/v1/providers/{id}` - Remove provider

### Configuration Management
- `GET /api/v1/config` - Get configuration
- `PUT /api/v1/config` - Update configuration
- `POST /api/v1/config/validate` - Validate configuration

### Analytics & Monitoring
- `GET /api/v1/analytics/usage` - Usage statistics
- `GET /api/v1/analytics/costs` - Cost tracking
- `GET /api/v1/monitoring/health` - System health
- `GET /api/v1/monitoring/metrics` - Performance metrics

## WebSocket API (Future)

Real-time features will be available through WebSocket connections:

**Endpoint:** `ws://localhost:8080/ws`

**Events:**
- `plugin.status.changed` - Plugin status updates
- `provider.status.changed` - LLM provider status updates
- `system.health.changed` - System health updates
- `analytics.update` - Real-time analytics updates