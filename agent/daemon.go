package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// DefaultLogDir is the default directory for log files
const DefaultLogDir = "/var/log/kerneleye"

// DefaultLogFile is the default log file path
const DefaultLogFile = "/var/log/kerneleye/agent.log"

// Daemonize forks the process into the background and exits the parent.
// If logFile is provided, stdout/stderr will be redirected there; otherwise /dev/null.
// Returns true in the child process, false in the parent.
func Daemonize(logFile string) (bool, error) {
	// First fork
	dpid, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return false, fmt.Errorf("fork failed: %v", errno)
	}

	if dpid > 0 {
		// Parent process: exit cleanly
		os.Exit(0)
	}

	// Child process: create new session
	_, err := syscall.Setsid()
	if err != nil {
		return false, fmt.Errorf("setsid failed: %v", err)
	}

	// Second fork to prevent reacquiring terminal
	dpid2, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return false, fmt.Errorf("second fork failed: %v", errno)
	}

	if dpid2 > 0 {
		// First child exits
		os.Exit(0)
	}

	// Grandchild continues as daemon
	// Setup log file or /dev/null for stdout/stderr
	var output *os.File
	if logFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(logFile)
		if logDir != "" && logDir != "." {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				// Fall back to /dev/null if we can't create the directory
				logFile = ""
			}
		}
		
		if logFile != "" {
			f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				// Fall back to /dev/null if we can't open the log file
				output = nil
			} else {
				output = f
			}
		}
	}
	
	// If no log file, use /dev/null
	if output == nil {
		f, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err != nil {
			return false, fmt.Errorf("failed to open /dev/null: %v", err)
		}
		output = f
	}
	defer output.Close()

	syscall.Dup2(int(output.Fd()), int(os.Stdin.Fd()))
	syscall.Dup2(int(output.Fd()), int(os.Stdout.Fd()))
	syscall.Dup2(int(output.Fd()), int(os.Stderr.Fd()))

	// Change working directory to root
	os.Chdir("/")

	return true, nil
}

// IsRunningAsDaemon checks if the current process appears to be a daemon
func IsRunningAsDaemon() bool {
	// Check if parent is init (PID 1) or systemd
	ppid := os.Getppid()
	return ppid == 1
}

// WritePIDFile writes the current process ID to a file
func WritePIDFile(pidFile string) error {
	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	return err
}

// RemovePIDFile removes the PID file
func RemovePIDFile(pidFile string) {
	os.Remove(pidFile)
}

// CheckAndStopDaemon checks if a daemon is running and stops it
func CheckAndStopDaemon(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No PID file, no daemon running
		}
		return err
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return fmt.Errorf("invalid PID file: %v", err)
	}

	// Check if process exists
	proc, err := os.FindProcess(pid)
	if err != nil {
		// Process not found, remove stale PID file
		RemovePIDFile(pidFile)
		return nil
	}

	// Try to signal the process (0 signal checks if it exists)
	err = proc.Signal(syscall.Signal(0))
	if err != nil {
		// Process not running, remove stale PID file
		RemovePIDFile(pidFile)
		return nil
	}

	// Process is running, stop it
	log.Printf("Stopping existing daemon (PID %d)...", pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop daemon: %v", err)
	}

	RemovePIDFile(pidFile)
	return nil
}
