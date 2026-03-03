// Structured Security Logging — Go with zerolog
// Chapter 2.10.3
//
// zerolog is the fastest Go JSON logger.
// Use it for high-throughput services.

package main

import (
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func initZerolog() zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339

	return zerolog.New(os.Stdout).
		With().
		Timestamp().
		Str("service", getEnvZ("SERVICE_NAME", "my-app")).
		Str("environment", getEnvZ("APP_ENV", "development")).
		Logger().
		Level(zerolog.InfoLevel)
}

type ZeroSecurityLogger struct {
	log zerolog.Logger
}

func NewZeroSecurityLogger(l zerolog.Logger) *ZeroSecurityLogger {
	return &ZeroSecurityLogger{log: l}
}

// Event Type 1: Authentication
func (s *ZeroSecurityLogger) LoginSuccess(userID, ip, userAgent string) {
	s.log.Info().
		Str("event", "auth.login.success").
		Str("userId", userID).
		Str("ip", ip).
		Str("userAgent", userAgent).
		Send()
}

func (s *ZeroSecurityLogger) LoginFailure(username, ip, userAgent, reason string) {
	s.log.Warn().
		Str("event", "auth.login.failure").
		Str("username", username).
		Str("ip", ip).
		Str("userAgent", userAgent).
		Str("reason", reason).
		Send()
}

// Event Type 2: Authorization failure
func (s *ZeroSecurityLogger) AuthorizationFailure(userID, resource, action, ip string) {
	s.log.Warn().
		Str("event", "authz.failure").
		Str("userId", userID).
		Str("resource", resource).
		Str("action", action).
		Str("ip", ip).
		Send()
}

// Event Type 3: Privilege change
func (s *ZeroSecurityLogger) PrivilegeChange(actorID, targetUserID, oldRole, newRole, ip string) {
	s.log.Info().
		Str("event", "authz.privilege.change").
		Str("actorId", actorID).
		Str("targetUserId", targetUserID).
		Str("oldRole", oldRole).
		Str("newRole", newRole).
		Str("ip", ip).
		Send()
}

// Event Type 4: Password reset
func (s *ZeroSecurityLogger) PasswordResetInitiated(userID, ip string) {
	s.log.Info().
		Str("event", "auth.password_reset.initiated").
		Str("userId", userID).
		Str("ip", ip).
		Send()
}

func (s *ZeroSecurityLogger) PasswordResetCompleted(userID, ip string) {
	s.log.Info().
		Str("event", "auth.password_reset.completed").
		Str("userId", userID).
		Str("ip", ip).
		Send()
}

// Event Type 5: API key lifecycle
func (s *ZeroSecurityLogger) APIKeyCreated(userID, keyID, ip string) {
	s.log.Info().
		Str("event", "apikey.created").
		Str("userId", userID).
		Str("keyId", keyID).
		Str("ip", ip).
		Send()
}

func (s *ZeroSecurityLogger) APIKeyRevoked(userID, keyID, ip string) {
	s.log.Info().
		Str("event", "apikey.revoked").
		Str("userId", userID).
		Str("keyId", keyID).
		Str("ip", ip).
		Send()
}

func (s *ZeroSecurityLogger) SecurityEvent(eventType, details, ip string) {
	s.log.Warn().
		Str("event", "security.event").
		Str("type", eventType).
		Str("details", details).
		Str("ip", ip).
		Send()
}

func zeroRequestLogger(l zerolog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &zeroResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		l.Info().
			Str("event", "http.request").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("statusCode", wrapped.statusCode).
			Int64("durationMs", time.Since(start).Milliseconds()).
			Str("ip", r.RemoteAddr).
			Send()
	})
}

type zeroResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *zeroResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func mainZero() {
	logger := initZerolog()
	_ = log.Logger // suppress unused import
	security := NewZeroSecurityLogger(logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		security.LoginSuccess("usr_abc123", r.RemoteAddr, r.UserAgent())
		w.WriteHeader(http.StatusOK)
	})

	port := getEnvZ("PORT", "8081")
	logger.Info().Str("event", "server.start").Str("port", port).Send()

	if err := http.ListenAndServe(":"+port, zeroRequestLogger(logger, mux)); err != nil {
		logger.Fatal().Err(err).Msg("server.error")
	}
}

func getEnvZ(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
