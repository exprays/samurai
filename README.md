# Samurai MSS

A comprehensive MCP (Model Context Protocol) super server with plugin system, LLM integration, and web dashboard.

## Quick Start

### Prerequisites
- Go 1.21 or later
- Docker Desktop
- Git

### One-Command Setup and Start

```bash
# Setup and start everything
go run main.go dev
```

That's it! This single command will:
1. ✅ Check all prerequisites
2. 🔧 Setup the development environment
3. 🐘 Start PostgreSQL database
4. 🚀 Start the backend server
5. 📊 Show you all the important URLs

## Available Commands

```bash
# Development
go run main.go dev          # Start full development environment
go run main.go setup        # Setup development environment only

# Building & Testing
go run main.go build        # Build the application
go run main.go test         # Run all tests
go run main.go clean        # Clean build artifacts

# Monitoring & Control
go run main.go status       # Check status of all services
go run main.go stop         # Stop all running services
go run main.go logs         # Show logs (add service name for specific logs)
go run main.go help         # Show help

# Examples
go run main.go logs postgres    # Show PostgreSQL logs only
go run main.go status          # Check what's running
```

## Windows Users

For easier access, you can use the provided batch file:

```cmd
# Copy mcp.bat to your PATH or use directly
mcp.bat dev
mcp.bat build
mcp.bat test
```

Or PowerShell:
```powershell
.\mcp.ps1 dev
.\mcp.ps1 build
```

## What Happens When You Run `go run main.go dev`

1. **Prerequisites Check**: Verifies Go, Docker, and Docker Compose are installed
2. **Environment Setup**: Creates necessary directories and configuration files
3. **Database Startup**: Starts PostgreSQL in Docker container
4. **Health Check**: Waits for database to be ready
5. **Server Startup**: Starts the Go backend server
6. **Ready to Use**: Shows you all the endpoints and URLs

## Service URLs

When running in development mode:
- 🏥 **Health Check**: http://localhost:8080/health
- 📚 **API Base**: http://localhost:8080/api/v1
- 🐘 **PostgreSQL**: localhost:5432 (mcpuser/mcppassword/mcpserver)

## Project Structure

```
Samurai/
├── main.go                 # 🎯 Main entrypoint (THIS IS WHAT YOU RUN)
├── backend/                # Go backend code
├── config/                 # Configuration files
├── bin/                    # Built executables (created automatically)
├── logs/                   # Log files (created automatically)
└── scripts/                # Legacy scripts (not needed anymore)
```

## Development Workflow

```bash
# First time setup
git clone <repository>
cd mcp-super-server
go run main.go dev

# Daily development
go run main.go dev          # Start everything
# ... do your development work ...
# Ctrl+C to stop everything

# Running tests
go run main.go test

# Building for production
go run main.go build        # Creates bin/mcp-server(.exe)
```

## Troubleshooting

### "Command not found" errors
- Make sure Go is installed: `go version`
- Make sure Docker is running: `docker version`

### Database connection issues
- Check if PostgreSQL is running: `go run main.go status`
- View database logs: `go run main.go logs postgres`

### Port already in use
- Stop all services: `go run main.go stop`
- Check what's using port 8080: `netstat -ano | findstr :8080` (Windows)

### Clean start
```bash
go run main.go stop
go run main.go clean
go run main.go dev
```

## Features

- 🔌 Plugin-based architecture for MCP servers
- 🤖 Multi-LLM provider support (OpenAI, Anthropic, Google, Azure)
- 🔐 Secure API key storage with Vault integration
- 🌐 Web dashboard with real-time features
- 📊 Request/response logging and analytics
- 🚦 Rate limiting and throttling
- 🔄 Auto-retry mechanisms
- 🏥 Health monitoring
- 👥 Multi-tenancy support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `go run main.go test`
5. Submit a pull request