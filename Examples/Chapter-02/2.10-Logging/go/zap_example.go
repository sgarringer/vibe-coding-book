// Structured Security Logging — Go with Uber Zap
// Chapter 2.10.3
//
// Demonstrates:
// - Structured JSON output
// - Security event logging for all five critical event types (Section 2.10.1)
// - Safe logging patterns (Section 2.10.2)

package main

import (
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ─── Logger Setup ─────────────────────────────────────────────────────────────

func newLogger() *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	// ISO 8601 timestamps (Section 2.10.3)
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Encoding:         "json", // Always structured JSON (Section 2.10.3)
		EncoderConfig:    encoderCfg,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := config.Build(
		// Add service context to every log entry
		zap.Fields(
			zap.String("service", getEnv("SERVICE_NAME", "my-app")),
			zap.String("environment", getEnv("APP_ENV", "development")),
		),
	)
	if err != nil {
		panic(err)
	}
	return logger
}

// ─── Security Event Helpers ───────────────────────────────────────────────────

type SecurityLogger struct {
	log *zap.Logger
}

func NewSecurityLogger(log *zap.Logger) *SecurityLogger {
	return &SecurityLogger{log: log}
}

// Event Type 1: Authentication
func (s *SecurityLogger) LoginSuccess(userID, ip, userAgent string) {
	s.log.Info("auth.login.success",
		zap.String("event", "auth.login.success"),
		zap.String("userId", userID),
		zap.String("ip", ip),
		zap.String("userAgent", userAgent),
	)
}

func (s *SecurityLogger) LoginFailure(username, ip, userAgent, reason string) {
	s.log.Warn("auth.login.failure",
		zap.String("event", "auth.login.failure"),
		zap.String("username", username), // Log username, NOT password
		zap.String("ip", ip),
		zap.String("userAgent", userAgent),
		zap.String("reason", reason),
	)
}

// Event Type 2: Authorization failure
func (s *SecurityLogger) AuthorizationFailure(userID, resource, action, ip string) {
	s.log.Warn("authz.failure",
		zap.String("event", "authz.failure"),
		zap.String("userId", userID),
		zap.String("resource", resource),
		zap.String("action", action),
		zap.String("ip", ip),
	)
}

// Event Type 3: Privilege change
func (s *SecurityLogger) PrivilegeChange(actorID, targetUserID, oldRole, newRole, ip string) {
	s.log.Info("authz.privilege.change",
		zap.String("event", "authz.privilege.change"),
		zap.String("actorId", actorID),
		zap.String("targetUserId", targetUserID),
		zap.String("oldRole", oldRole),
		zap.String("newRole", newRole),
		zap.String("ip", ip),
	)
}

// Event Type 4: Password reset
func (s *SecurityLogger) PasswordResetInitiated(userID, ip string) {
	s.log.Info("auth.password_reset.initiated",
		zap.String("event", "auth.password_reset.initiated"),
		zap.String("userId", userID),
		zap.String("ip", ip),
		// NOT logged: reset token
	)
}

func (s *SecurityLogger) PasswordResetCompleted(userID, ip string) {
	s.log.Info("auth.password_reset.completed",
		zap.String("event", "auth.password_reset.completed"),
		zap.String("userId", userID),
		zap.String("ip", ip),
	)
}

// Event Type 5: API key lifecycle
func (s *SecurityLogger) APIKeyCreated(userID, keyID, ip string) {
	s.log.Info("apikey.created",
		zap.String("event", "apikey.created"),
		zap.String("userId", userID),
		zap.String("keyId", keyID), // Log the ID, never the key value
		zap.String("ip", ip),
	)
}

func (s *SecurityLogger) APIKeyRevoked(userID, keyID, ip string) {
	s.log.Info("apikey.revoked",
		zap.String("event", "apikey.revoked"),
		zap.String("userId", userID),
		zap.String("keyId", keyID),
		zap.String("ip", ip),
	)
}

// Generic security event (triggers Alert 3, Section 2.10.6)
func (s *SecurityLogger) SecurityEvent(eventType, details, ip string) {
	s.log.Warn("security.event",
		zap.String("event", "security.event"),
		zap.String("type", eventType),
		zap.String("details", details),
		zap.String("ip", ip),
	)
}

// ─── Request Logging Middleware ───────────────────────────────────────────────

func requestLogger(log *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		log.Info("http.request",
			zap.String("event", "http.request"),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("statusCode", wrapped.statusCode),
			zap.Int64("durationMs", time.Since(start).Milliseconds()),
			zap.String("ip", r.RemoteAddr),
			// NOT logged: request body, Authorization header, cookies
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	log := newLogger()
	defer log.Sync()

	security := NewSecurityLogger(log)

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// In a real app, parse the body and authenticate.
		// Log the username, never the password.
		security.LoginSuccess("usr_abc123", r.RemoteAddr, r.UserAgent())
		w.WriteHeader(http.StatusOK)
	})

	port := getEnv("PORT", "8080")
	log.Info("server.start", zap.String("event", "server.start"), zap.String("port", port))

	if err := http.ListenAndServe(":"+port, requestLogger(log, mux)); err != nil {
		log.Fatal("server.error", zap.Error(err))
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
