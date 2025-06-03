# Development Guide

## Development Setup

### Prerequisites
Ensure you have the required tools installed:
- Go 1.21+
- Docker Desktop
- Git

### Initial Setup
1. Clone the repository
2. Run setup command:
   ```bash
   go run samurai.go setup
   ```

### Environment Configuration
Create `.env` file from template:
```bash
cp .env.example .env
```

Edit `.env` with your local settings:
```env
# Development settings
SERVER_ENVIRONMENT=development
LOG_LEVEL=debug

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=samurai
DATABASE_PASSWORD=samurai_password
DATABASE_NAME=samurai_db

# JWT Secret (generate a secure secret for production)
JWT_SECRET=your-development-jwt-secret
```

## Code Organization

### Backend Structure
```
backend/
├── cmd/server/          # Application entry point
├── internal/
│   ├── api/
│   │   ├── handlers/    # HTTP request handlers
│   │   ├── middleware/  # HTTP middleware
│   │   └── routes/      # Route definitions
│   ├── config/          # Configuration management
│   ├── database/        # Database layer
│   │   ├── models/      # Database models
│   │   └── connection.go
│   └── utils/           # Shared utilities
```

### Key Components

#### Configuration Management ([`backend/internal/config/config.go`](backend/internal/config/config.go))
- Uses Viper for configuration management
- Supports environment variables and JSON files
- Hierarchical configuration loading

#### Database Layer ([`backend/internal/database/`](backend/internal/database/))
- GORM for ORM functionality
- PostgreSQL driver
- Auto-migration support
- Structured logging for database operations

#### API Layer ([`backend/internal/api/`](backend/internal/api/))
- Gin framework for HTTP handling
- Middleware for authentication, CORS, logging
- Structured error handling

## Development Workflow

### Starting Development Environment
```bash
go run samurai.go dev
```

This starts:
- PostgreSQL database (Docker)
- Backend server with hot-reload
- Logs monitoring

### Running Tests
```bash
# All tests
go run samurai.go test

# Specific package
cd backend && go test ./internal/api/handlers/...

# With coverage
cd backend && go test -cover ./...
```

### Building
```bash
# Development build
go run samurai.go build

# Production build
cd backend && go build -o ../bin/server ./cmd/server
```

## Database Management

### Models
Database models are defined in [`backend/internal/database/models/`](backend/internal/database/models/):

- [`user.go`](backend/internal/database/models/user.go) - User authentication and profiles
- [`plugin.go`](backend/internal/database/models/plugin.go) - Plugin definitions
- [`config.go`](backend/internal/database/models/config.go) - System configuration
- [`audit.go`](backend/internal/database/models/audit.go) - Audit logging

### Migrations
Auto-migration runs on server startup. For manual migration:
```go
db.AutoMigrate(&models.User{}, &models.Plugin{}, ...)
```

### Database Access
```bash
# Connect to development database
docker exec -it postgres psql -U samurai -d samurai_db
```

## Logging

### Log Levels
- `debug`: Detailed debug information
- `info`: General information (default)
- `warn`: Warning messages
- `error`: Error messages

### Log Files
- `logs/app.log` - Application logs
- `logs/access.log` - HTTP access logs
- `logs/database.log` - Database operation logs

### Logging in Code
```go
// Get logger from context or inject
logger.Info("Operation completed", "user_id", userID)
logger.Error("Operation failed", "error", err)
logger.Debugw("Debug info", "data", complexData)
```

## Adding New Features

### Adding API Endpoints

1. **Create Handler** ([`backend/internal/api/handlers/`](backend/internal/api/handlers/)):
```go
func (h *Handler) NewEndpoint(c *gin.Context) {
    // Implementation
    c.JSON(http.StatusOK, gin.H{"status": "success"})
}
```

2. **Add Route** ([`backend/internal/api/routes/router.go`](backend/internal/api/routes/router.go)):
```go
v1.GET("/new-endpoint", handler.NewEndpoint)
```

3. **Add Tests**:
```go
func TestNewEndpoint(t *testing.T) {
    // Test implementation
}
```

### Adding Database Models

1. **Create Model** ([`backend/internal/database/models/`](backend/internal/database/models/)):
```go
type NewModel struct {
    ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    Name      string    `gorm:"not null"`
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

2. **Add to Migration**:
```go
db.AutoMigrate(&models.NewModel{})
```

### Adding Middleware

1. **Create Middleware** ([`backend/internal/api/middleware/`](backend/internal/api/middleware/)):
```go
func NewMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Middleware logic
        c.Next()
    }
}
```

2. **Register Middleware**:
```go
router.Use(middleware.NewMiddleware())
```

## Testing Guidelines

### Unit Tests
- Test individual functions and methods
- Mock external dependencies
- Use table-driven tests for multiple scenarios

### Integration Tests
- Test API endpoints end-to-end
- Use test database
- Test authentication flows

### Test Structure
```go
func TestFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    interface{}
        expected interface{}
        wantErr  bool
    }{
        // Test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Performance Considerations

### Database
- Use database indexes appropriately
- Implement query optimization
- Use connection pooling
- Monitor slow queries

### API
- Implement request rate limiting
- Use response caching where appropriate
- Optimize JSON serialization
- Monitor response times

### Logging
- Use structured logging
- Implement log rotation
- Avoid excessive debug logging in production

## Security Best Practices

### Authentication
- Use JWT tokens with appropriate expiration
- Implement secure password hashing
- Validate input data
- Use HTTPS in production

### Database
- Use prepared statements (GORM handles this)
- Implement proper access controls
- Regular security updates
- Backup strategies

### API
- Input validation
- Output sanitization
- CORS configuration
- Rate limiting

## Debugging

### Local Debugging
1. Set breakpoints in your IDE
2. Run with debug configuration
3. Use logging for runtime debugging

### Production Debugging
1. Check application logs: `logs/app.log`
2. Monitor health endpoints
3. Use metrics and monitoring tools

### Common Issues
- Database connection: Check PostgreSQL service
- Port conflicts: Ensure ports 8080, 5432 are available
- Permission issues: Check file/directory permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow code style guidelines
4. Add tests for new features
5. Update documentation
6. Submit pull request

### Code Style
- Follow Go conventions
- Use `gofmt` for formatting
- Add comments for public functions
- Use meaningful variable names
- Keep functions focused and small

## For more information and feature plans which we have ahead please reach out to me on @suryakantsubudhi on Instagram.