package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"knative.dev/pkg/signals"

	"github.com/pkking/gitee-tekton-interceptor/pkg/interceptors/gitee"
)

const (
	// Port is the port that the port that interceptor service listens on
	Port         = 8080
	readTimeout  = 5 * time.Second
	writeTimeout = 20 * time.Second
	idleTimeout  = 60 * time.Second

	giteeTokenHeader     = "X-Gitee-Token"
	giteeEventHeader     = "X-Gitee-Event"
	giteeTimestampHeader = "X-Gitee-Timestamp"
)

type handler struct {
	Logger *zap.SugaredLogger
}

func main() {
	// set up signals so we handle the first shutdown signal gracefully

	zap, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %s", err)
	}
	logger := zap.Sugar()

	defer func() {
		if err := logger.Sync(); err != nil {
			log.Fatalf("failed to sync the logger: %s", err)
		}
	}()

	ctx := signals.NewContext()

	h := &handler{
		Logger: logger,
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	mux.HandleFunc("/ready", readinessHandler)

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", Port),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		Handler:      mux,
	}

	logger.Infof("Listen and serve on port %d", Port)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("failed to start interceptors service: %v", err)
	}
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (gi *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headers := r.Header
	var eventGUID string
	if eventGUID = headers.Get(giteeTimestampHeader); eventGUID == "" {
		gi.Logger.Error("missing X-Gitee-Timestamp header")
		http.Error(w, "missing X-Gitee-Timestamp header", http.StatusBadRequest)
		return
	}

	if err := gitee.ValidateWebhook(&headers, []byte("tokton_webhook_secret"), eventGUID); err != nil {
		gi.Logger.Errorf("failed to validate webhook: %s", err)
		http.Error(w, fmt.Sprintf("failed to validate webhook: %s", err), http.StatusBadRequest)
		return
	}

	gi.Logger.Infof("Webhook validated successfully for event: %s", eventGUID)
	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write([]byte("ok")); err != nil {
		gi.Logger.Errorf("failed to write response: %s", err)
	}
}

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")
