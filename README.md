# Samurai MCP Super Server

A comprehensive Model Context Protocol (MCP) super server with plugin architecture, secure vault integration, and real-time web dashboard.

## 🚀 Features

### Core Features
- **Plugin-Based Architecture**: Modular MCP instances for different services (SMS via Twilio, etc.)
- **LLM Provider Management**: Support for multiple LLM providers with API key management
- **Secure Vault Integration**: Industry-standard API key storage and encryption
- **Real-time Web Dashboard**: Live monitoring and management interface
- **Rate Limiting & Throttling**: Per-provider and per-plugin request control
- **Comprehensive Logging**: Request/response analytics with queryable history

### Advanced Features
- **Plugin Marketplace**: Community-contributed plugins
- **A/B Testing Framework**: Different LLM configuration testing
- **Cost Tracking**: Budgeting per user/organization
- **Response Caching**: API cost reduction through intelligent caching
- **Plugin Sandboxing**: Security isolation for plugins
- **Metrics & Observability**: Prometheus/Grafana integration

### Developer Experience
- **Plugin SDK/CLI**: Easy plugin development tools
- **Hot-reloading**: Development-time plugin reloading
- **OpenAPI Documentation**: Auto-generated API docs
- **Testing Framework**: Mock services for plugin testing

## 📁 Project Structure

```
├── README.md
├── go.mod
├── go.sum
├── samurai.go                 # Development CLI tool
├── docker-compose.yml         # Database services
├── .env.example              # Environment template
├── backend/
│   ├── cmd/
│   │   └── server/
│   │       └── main.go       # Application entry point
│   └── internal/
│       ├── api/
│       │   ├── handlers/     # HTTP request handlers
│       │   ├── middleware/   # HTTP middleware
│       │   └── routes/       # Route definitions
│       ├── config/           # Configuration management
│       ├── database/         # Database connection & models
│       └── utils/            # Utilities (logging, etc.)
├── config/
│   └── development.json      # Development configuration
├── logs/                     # Application logs
├── bin/                      # Compiled binaries
└── data/                     # Database data
```

## 🛠️ Prerequisites

- **Go 1.21+**: [Download Go](https://golang.org/dl/)
- **Docker Desktop**: [Download Docker](https://www.docker.com/products/docker-desktop)
- **Git**: [Download Git](https://git-scm.com/downloads)

## ⚡ Quick Start

### 1. Clone Repository
```bash
git clone <repository-url>
cd exprays-samurai
```

### 2. Setup Development Environment
```bash
go run samurai.go setup
```
This will:
- Create necessary directories
- Copy `.env.example` to `.env`
- Download Go dependencies
- Pull required Docker images

### 3. Start Development Environment
```bash
go run samurai.go dev
```
This will:
- Start PostgreSQL database
- Start the backend server
- Display service URLs and status

### 4. Verify Installation
```bash
go run samurai.go status
```

## 🔧 Development Commands

| Command | Description |
|---------|-------------|
| `go run samurai.go dev` | Start full development environment |
| `go run samurai.go setup` | Setup development environment |
| `go run samurai.go build` | Build the application |
| `go run samurai.go test` | Run all tests |
| `go run samurai.go status` | Show service status |
| `go run samurai.go logs` | Show service logs |
| `go run samurai.go stop` | Stop all services |
| `go run samurai.go clean` | Clean build artifacts |

## 🌐 Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Health Check | http://localhost:8080/health | Service health status |
| Ready Check | http://localhost:8080/health/ready | Database readiness |
| API Base | http://localhost:8080/api/v1 | REST API endpoints |
| Database | localhost:5432 | PostgreSQL database |

## 📊 Logging

The application uses structured logging with separate log files:

- **Application Logs**: `logs/app.log` - Main application events
- **Access Logs**: `logs/access.log` - HTTP request/response logs
- **Database Logs**: `logs/database.log` - Database queries and operations

### Log Configuration
Logs are configured via environment variables:
- `LOG_LEVEL`: debug, info, warn, error (default: info)
- `LOG_FORMAT`: json, console (default: json)

## 🔒 Environment Configuration

Copy `.env.example` to `.env` and configure:

```env
# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost
SERVER_ENVIRONMENT=development

# Database Configuration
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=samurai
DATABASE_PASSWORD=samurai_password
DATABASE_NAME=samurai_db
DATABASE_SSL_MODE=disable

# Authentication
JWT_SECRET=your-jwt-secret-here
JWT_EXPIRY=24h

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

## 🏗️ Architecture

### Current Implementation (Phase 1)
- ✅ Go project structure with module management
- ✅ HTTP server with Gin framework
- ✅ Configuration management system
- ✅ PostgreSQL database with GORM
- ✅ Structured logging infrastructure
- ✅ JWT-based authentication
- ✅ User registration and login APIs
- ✅ Role-based access control (RBAC)
- ✅ API middleware (auth, CORS, logging, recovery)

### Upcoming Features (Phase 2+)
- 🔄 MCP Protocol Implementation
- 🔄 LLM Provider Integration
- 🔄 Plugin System Architecture
- 🔄 Vault Integration
- 🔄 Frontend Dashboard
- 🔄 Monitoring & Observability

## 🧪 Testing

```bash
# Run all tests
go run samurai.go test

# Run specific package tests
cd backend && go test ./internal/...

# Run tests with coverage
cd backend && go test -cover ./...
```

## 📦 Building

```bash
# Build for current platform
go run samurai.go build

# Build for specific platform
cd backend && GOOS=linux GOARCH=amd64 go build -o ../bin/mcp-server-linux ./cmd/server
```

## 🔍 Monitoring

### Health Checks
- `GET /health` - Basic service health
- `GET /health/ready` - Database connectivity check

### Logs
View real-time logs:
```bash
# Application logs
tail -f logs/app.log

# Access logs
tail -f logs/access.log

# Database logs
tail -f logs/database.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests and ensure they pass
6. Submit a pull request

## 📋 Development Phases

### Phase 1: Foundation (Completed)
- [x] Project setup & basic backend
- [x] Authentication & security foundation
- [x] Database models and connections
- [x] Logging infrastructure
- [x] Basic API documentation

### Phase 2: Core MCP Integration (In Progress)
- [ ] MCP protocol implementation
- [ ] LLM provider integration
- [ ] Plugin-MCP bridge
- [ ] API key management

### Phase 3+: Advanced Features
- [ ] Vault integration
- [ ] Frontend dashboard
- [ ] Monitoring & observability
- [ ] Plugin marketplace
- [ ] Enterprise features

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the [API Documentation](docs/API.md)
- Review the [Development Guide](docs/DEVELOPMENT.md)

## 📄 License

[License information to be added]