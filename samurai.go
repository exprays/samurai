package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type MCPSuperServer struct {
	workingDir string
}

func main() {
	mcp := &MCPSuperServer{
		workingDir: getCurrentDir(),
	}

	if len(os.Args) < 2 {
		mcp.showHelp()
		return
	}

	command := os.Args[1]
	switch command {
	case "dev":
		mcp.startDevelopment()
	case "build":
		mcp.build()
	case "test":
		mcp.test()
	case "clean":
		mcp.clean()
	case "setup":
		mcp.setup()
	case "status":
		mcp.status()
	case "stop":
		mcp.stop()
	case "help", "--help", "-h":
		mcp.showHelp()
	default:
		mcp.printError(fmt.Sprintf("Unknown command: %s", command))
		mcp.showHelp()
	}
}

func (mcp *MCPSuperServer) startDevelopment() {
	mcp.printHeader("Starting MCP Super Server Development Environment")

	// Check prerequisites
	if !mcp.checkPrerequisites() {
		return
	}

	// Setup if needed
	if !mcp.isSetup() {
		mcp.printInfo("Development environment not setup. Running setup...")
		if !mcp.setup() {
			return
		}
	}

	// Start services
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the backend server
	mcp.printStep("Starting backend server with SQLite database...")
	go mcp.startBackendServer(ctx)

	// Give server time to start
	time.Sleep(2 * time.Second)

	// Check if server started successfully
	if mcp.isServerRunning() {
		mcp.printSuccess("✅ Development environment is running!")
		mcp.printInfo("📊 Server: http://localhost:8080")
		mcp.printInfo("🏥 Health: http://localhost:8080/health")
		mcp.printInfo("📚 API: http://localhost:8080/api/v1")
		mcp.printInfo("💾 Database: SQLite (data/mcp.db)")
		mcp.printInfo("")
		mcp.printInfo("Press Ctrl+C to stop the server")
	} else {
		mcp.printError("❌ Failed to start backend server")
		return
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	mcp.printInfo("\n🛑 Shutting down server...")
	cancel()
	time.Sleep(1 * time.Second)
	mcp.printSuccess("✅ Server stopped")
}

func (mcp *MCPSuperServer) setup() bool {
	mcp.printHeader("Setting Up MCP Super Server Development Environment")

	// Check prerequisites
	if !mcp.checkPrerequisites() {
		return false
	}

	// Create necessary directories
	mcp.printStep("Creating necessary directories...")
	dirs := []string{"bin", "logs", "data"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			mcp.printError(fmt.Sprintf("Failed to create directory %s: %v", dir, err))
			return false
		}
	}

	// Copy environment file
	mcp.printStep("Setting up environment configuration...")
	if !fileExists(".env") {
		if fileExists(".env.example") {
			if err := copyFile(".env.example", ".env"); err != nil {
				mcp.printError(fmt.Sprintf("Failed to copy .env.example to .env: %v", err))
				return false
			}
			mcp.printInfo("✅ Created .env file from template")
		} else {
			// Create a basic .env file
			basicEnv := `# MCP Super Server Environment Configuration
SERVER_HOST=localhost
SERVER_PORT=8080
SERVER_ENVIRONMENT=development

# SQLite Database Configuration
DATABASE_TYPE=sqlite
DATABASE_PATH=./data/mcp.db

# Logger Configuration
LOGGER_LEVEL=debug
LOGGER_FORMAT=console

# Auth Configuration
AUTH_JWT_SECRET=your-secret-key-change-in-production
AUTH_TOKEN_DURATION=24
`
			if err := os.WriteFile(".env", []byte(basicEnv), 0644); err != nil {
				mcp.printError(fmt.Sprintf("Failed to create .env file: %v", err))
				return false
			}
			mcp.printInfo("✅ Created basic .env file")
		}
	} else {
		mcp.printInfo("📝 .env file already exists")
	}

	// Initialize Go module if needed
	if !fileExists("go.mod") {
		mcp.printStep("Initializing Go module...")
		if !mcp.runCommand("go", []string{"mod", "init", "mcp-super-server"}, ".") {
			return false
		}
	}

	// Download Go dependencies
	mcp.printStep("Downloading Go dependencies...")
	if !mcp.runCommand("go", []string{"mod", "tidy"}, ".") {
		// Continue even if this fails, we'll handle it in the backend
		mcp.printWarning("⚠️ Could not download dependencies, will try during server start")
	}

	mcp.printSuccess("✅ Development environment setup completed!")
	mcp.printInfo("You can now run: go run samurai.go dev")
	return true
}

func (mcp *MCPSuperServer) build() bool {
	mcp.printHeader("Building MCP Super Server")

	// Create bin directory
	if err := os.MkdirAll("bin", 0755); err != nil {
		mcp.printError(fmt.Sprintf("Failed to create bin directory: %v", err))
		return false
	}

	// Build for current platform
	mcp.printStep("Building backend server...")

	var outputName string
	if runtime.GOOS == "windows" {
		outputName = "../bin/mcp-server.exe"
	} else {
		outputName = "../bin/mcp-server"
	}

	args := []string{"build", "-o", outputName, "./cmd/server"}
	if !mcp.runCommand("go", args, "backend") {
		return false
	}

	mcp.printSuccess(fmt.Sprintf("✅ Build completed! Executable: %s", outputName))
	return true
}

func (mcp *MCPSuperServer) test() bool {
	mcp.printHeader("Running Tests")

	mcp.printStep("Running unit tests...")
	if !mcp.runCommand("go", []string{"test", "./..."}, "backend") {
		mcp.printError("❌ Tests failed!")
		return false
	}

	mcp.printSuccess("✅ All tests passed!")
	return true
}

func (mcp *MCPSuperServer) clean() bool {
	mcp.printHeader("Cleaning Build Artifacts")

	// Remove bin directory
	if dirExists("bin") {
		if err := os.RemoveAll("bin"); err != nil {
			mcp.printError(fmt.Sprintf("Failed to remove bin directory: %v", err))
			return false
		}
		mcp.printInfo("🗑️  Removed bin directory")
	}

	// Remove logs directory
	if dirExists("logs") {
		if err := os.RemoveAll("logs"); err != nil {
			mcp.printError(fmt.Sprintf("Failed to remove logs directory: %v", err))
			return false
		}
		mcp.printInfo("🗑️  Removed logs directory")
	}

	// Clean Go build cache
	mcp.printStep("Cleaning Go build cache...")
	mcp.runCommand("go", []string{"clean", "-cache"}, "backend")

	mcp.printSuccess("✅ Clean completed!")
	return true
}

func (mcp *MCPSuperServer) status() {
	mcp.printHeader("Service Status")

	// Check if server is running
	mcp.printStep("Checking backend server...")
	if mcp.isServerRunning() {
		mcp.printSuccess("✅ Backend server is running on http://localhost:8080")
	} else {
		mcp.printWarning("⚠️  Backend server is not running")
	}

	// Check database file
	if fileExists("data/mcp.db") {
		mcp.printSuccess("✅ SQLite database exists at data/mcp.db")
	} else {
		mcp.printInfo("📝 SQLite database will be created on first run")
	}
}

func (mcp *MCPSuperServer) stop() {
	mcp.printHeader("Stopping All Services")
	mcp.printInfo("Use Ctrl+C to stop the running server")
	mcp.printSuccess("✅ No background services to stop")
}

func (mcp *MCPSuperServer) checkPrerequisites() bool {
	mcp.printStep("Checking prerequisites...")

	// Check Go
	if !mcp.commandExists("go") {
		mcp.printError("❌ Go is not installed. Please install Go 1.21 or later")
		return false
	}
	mcp.printInfo("✅ Go is installed")

	return true
}

func (mcp *MCPSuperServer) isSetup() bool {
	return fileExists(".env")
}

func (mcp *MCPSuperServer) startBackendServer(ctx context.Context) {
	// First ensure backend directory exists
	if !dirExists("backend") {
		mcp.printError("❌ Backend directory not found. Please ensure you're in the correct directory.")
		return
	}

	// Download dependencies first
	mcp.printStep("Ensuring Go dependencies are downloaded...")
	depsCmd := exec.Command("go", "mod", "tidy")
	depsCmd.Dir = "backend"
	depsCmd.Run() // Don't fail if this doesn't work

	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/server")
	cmd.Dir = "backend"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		mcp.printError(fmt.Sprintf("Backend server failed: %v", err))
	}
}

func (mcp *MCPSuperServer) isServerRunning() bool {
	// Try to connect to the health endpoint
	if mcp.commandExists("curl") {
		cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8080/health")
		output, err := cmd.Output()
		if err == nil && string(output) == "200" {
			return true
		}
	}

	// Alternative check using Go's net package would be better, but this is simpler for now
	return false
}

func (mcp *MCPSuperServer) runCommand(name string, args []string, dir string) bool {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		mcp.printError(fmt.Sprintf("Command failed: %s %v", name, args))
		return false
	}
	return true
}

func (mcp *MCPSuperServer) commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (mcp *MCPSuperServer) showHelp() {
	fmt.Printf(`
%sMCP Super Server - Development Tool%s

%sUSAGE:%s
    go run samurai.go <command> [arguments]

%sCOMMANDS:%s
    %sdev%s      Start development environment (SQLite + server)
    %ssetup%s    Setup development environment
    %sbuild%s    Build the application
    %stest%s     Run all tests
    %sclean%s    Clean build artifacts
    %sstatus%s   Show status of all services
    %sstop%s     Stop all running services
    %shelp%s     Show this help message

%sEXAMPLES:%s
    go run samurai.go dev       # Start full development environment
    go run samurai.go setup     # Setup development environment
    go run samurai.go build     # Build the application
    go run samurai.go test      # Run tests
    go run samurai.go status    # Check service status

%sSERVICES:%s
    - Backend API Server (port 8080)
    - SQLite Database (data/mcp.db)

%sENDPOINTS:%s
    - Health Check: http://localhost:8080/health
    - API Base: http://localhost:8080/api/v1

%sPREREQUISITES:%s
    - Go 1.21 or later

%sNOTE:%s
    This version uses SQLite database instead of PostgreSQL for easier setup.
    No Docker required!

`,
		ColorCyan, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorGreen, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorBlue, ColorReset,
		ColorBlue, ColorReset,
	)
}

// Helper functions
func (mcp *MCPSuperServer) printHeader(message string) {
	fmt.Printf("\n%s=== %s ===%s\n", ColorCyan, message, ColorReset)
}

func (mcp *MCPSuperServer) printStep(message string) {
	fmt.Printf("%s🔄 %s%s\n", ColorBlue, message, ColorReset)
}

func (mcp *MCPSuperServer) printSuccess(message string) {
	fmt.Printf("%s%s%s\n", ColorGreen, message, ColorReset)
}

func (mcp *MCPSuperServer) printInfo(message string) {
	fmt.Printf("%s%s%s\n", ColorWhite, message, ColorReset)
}

func (mcp *MCPSuperServer) printWarning(message string) {
	fmt.Printf("%s%s%s\n", ColorYellow, message, ColorReset)
}

func (mcp *MCPSuperServer) printError(message string) {
	fmt.Printf("%s%s%s\n", ColorRed, message, ColorReset)
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	return dir
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func dirExists(dirname string) bool {
	info, err := os.Stat(dirname)
	return !os.IsNotExist(err) && info.IsDir()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
