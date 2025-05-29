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
	case "logs":
		mcp.logs()
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

	// Start PostgreSQL
	mcp.printStep("Starting PostgreSQL database...")
	if !mcp.startPostgreSQL(ctx) {
		return
	}

	// Wait for database to be ready
	mcp.printStep("Waiting for database to be ready...")
	if !mcp.waitForDatabase() {
		return
	}

	// Start the backend server
	mcp.printStep("Starting backend server...")
	go mcp.startBackendServer(ctx)

	// Handle graceful shutdown
	mcp.printSuccess("✅ Development environment is running!")
	mcp.printInfo("📊 Server: http://localhost:8080")
	mcp.printInfo("🏥 Health: http://localhost:8080/health")
	mcp.printInfo("📚 API: http://localhost:8080/api/v1")
	mcp.printInfo("")
	mcp.printInfo("Press Ctrl+C to stop all services")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	mcp.printInfo("\n🛑 Shutting down services...")
	cancel()
	mcp.stopAllServices()
	mcp.printSuccess("✅ All services stopped")
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
		if err := copyFile(".env.example", ".env"); err != nil {
			mcp.printError(fmt.Sprintf("Failed to copy .env.example to .env: %v", err))
			return false
		}
		mcp.printInfo("✅ Created .env file from template")
	} else {
		mcp.printInfo("📝 .env file already exists")
	}

	// Download Go dependencies
	mcp.printStep("Downloading Go dependencies...")
	if !mcp.runCommand("go", []string{"mod", "download"}, "backend") {
		return false
	}

	// Pull Docker images
	mcp.printStep("Pulling required Docker images...")
	if !mcp.runCommand("docker", []string{"compose", "pull"}, ".") {
		return false
	}

	mcp.printSuccess("✅ Development environment setup completed!")
	mcp.printInfo("You can now run: go run main.go dev")
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

	// Check Docker services
	mcp.printStep("Checking Docker services...")
	cmd := exec.Command("docker", "compose", "ps")
	output, err := cmd.Output()
	if err != nil {
		mcp.printError("Failed to check Docker services")
	} else {
		fmt.Print(string(output))
	}

	// Check if server is running
	mcp.printStep("Checking backend server...")
	if mcp.isServerRunning() {
		mcp.printSuccess("✅ Backend server is running on http://localhost:8080")
	} else {
		mcp.printWarning("⚠️  Backend server is not running")
	}
}

func (mcp *MCPSuperServer) stop() {
	mcp.printHeader("Stopping All Services")
	mcp.stopAllServices()
	mcp.printSuccess("✅ All services stopped")
}

func (mcp *MCPSuperServer) logs() {
	mcp.printHeader("Service Logs")

	if len(os.Args) > 2 {
		service := os.Args[2]
		mcp.runCommand("docker", []string{"compose", "logs", "-f", service}, ".")
	} else {
		mcp.runCommand("docker", []string{"compose", "logs", "-f"}, ".")
	}
}

func (mcp *MCPSuperServer) checkPrerequisites() bool {
	mcp.printStep("Checking prerequisites...")

	// Check Go
	if !mcp.commandExists("go") {
		mcp.printError("❌ Go is not installed. Please install Go 1.21 or later")
		return false
	}
	mcp.printInfo("✅ Go is installed")

	// Check Docker
	if !mcp.commandExists("docker") {
		mcp.printError("❌ Docker is not installed. Please install Docker Desktop")
		return false
	}
	mcp.printInfo("✅ Docker is installed")

	// Check Docker Compose
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err != nil {
		mcp.printError("❌ Docker Compose is not available")
		return false
	}
	mcp.printInfo("✅ Docker Compose is available")

	return true
}

func (mcp *MCPSuperServer) isSetup() bool {
	return fileExists(".env") && dirExists("backend/vendor") || mcp.commandExists("go")
}

func (mcp *MCPSuperServer) startPostgreSQL(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "compose", "up", "-d", "postgres")
	if err := cmd.Run(); err != nil {
		mcp.printError(fmt.Sprintf("Failed to start PostgreSQL: %v", err))
		return false
	}
	return true
}

func (mcp *MCPSuperServer) waitForDatabase() bool {
	mcp.printInfo("Waiting for PostgreSQL to be ready...")

	for i := 0; i < 30; i++ { // Wait up to 30 seconds
		cmd := exec.Command("docker", "compose", "exec", "-T", "postgres",
			"pg_isready", "-U", "mcpuser", "-d", "mcpserver")
		if err := cmd.Run(); err == nil {
			mcp.printSuccess("✅ PostgreSQL is ready")
			return true
		}
		time.Sleep(1 * time.Second)
		fmt.Print(".")
	}

	mcp.printError("❌ PostgreSQL failed to start within 30 seconds")
	return false
}

func (mcp *MCPSuperServer) startBackendServer(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/server")
	cmd.Dir = "backend"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		mcp.printError(fmt.Sprintf("Backend server failed: %v", err))
	}
}

func (mcp *MCPSuperServer) stopAllServices() {
	// Stop Docker services
	cmd := exec.Command("docker", "compose", "down")
	cmd.Run()
}

func (mcp *MCPSuperServer) isServerRunning() bool {
	cmd := exec.Command("curl", "-s", "http://localhost:8080/health")
	return cmd.Run() == nil
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
%sSamurai MSS - Development Tool%s

%sUSAGE:%s
	go run samurai.go <command> [arguments]

%sCOMMANDS:%s
	%sdev%s      Start development environment (database + server)
	%ssetup%s    Setup development environment
	%sbuild%s    Build the application
	%stest%s     Run all tests
	%sclean%s    Clean build artifacts
	%sstatus%s   Show status of all services
	%sstop%s     Stop all running services
	%slogs%s     Show logs from services (optional: specify service name)
	%shelp%s     Show this help message

%sEXAMPLES:%s
	go run main.go dev          # Start full development environment
	go run main.go setup        # Setup development environment
	go run main.go build        # Build the application
	go run main.go test         # Run tests
	go run main.go logs postgres # Show PostgreSQL logs
	go run main.go status       # Check service status

%sSERVICES:%s
	- PostgreSQL Database (port 5432)
	- Backend API Server (port 8080)

%sENDPOINTS:%s
	- Health Check: http://localhost:8080/health
	- API Base: http://localhost:8080/api/v1

%sPREREQUISITES:%s
	- Go 1.21 or later
	- Docker Desktop
	- Git

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
		ColorGreen, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
		ColorYellow, ColorReset,
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
