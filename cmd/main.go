package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	"github.com/tektoncd/triggers/pkg/interceptors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	secretInformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/signals"

	"slices"

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

func main() {
	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.NewContext()

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to build config: %v", err)
	}

	ctx, startInformer := injection.EnableInjectionOrDie(ctx, clusterConfig)

	zap, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %s", err)
	}
	logger := zap.Sugar()
	ctx = logging.WithLogger(ctx, logger)
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Fatalf("failed to sync the logger: %s", err)
		}
	}()

	secretLister := secretInformer.Get(ctx).Lister()
	service := NewGiteeInterceptor(secretLister, logger)
	startInformer()

	mux := http.NewServeMux()
	mux.Handle("/", service)
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

func (gi *GiteeInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := gi.executeInterceptor(r)
	if err != nil {
		switch e := err.(type) {
		case Error:
			gi.Logger.Infof("HTTP %d - %s", e.Status(), e)
			http.Error(w, e.Error(), e.Status())
		default:
			gi.Logger.Errorf("Non Status Error: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		gi.Logger.Errorf("failed to write response: %s", err)
	}
}

// Error represents a handler error. It provides methods for a HTTP status
// code and embeds the built-in error interface.
type Error interface {
	error
	Status() int
}

// HTTPError represents an error with an associated HTTP status code.
type HTTPError struct {
	Code int
	Err  error
}

// Allows HTTPError to satisfy the error interface.
func (se HTTPError) Error() string {
	return se.Err.Error()
}

// Returns our HTTP status code.
func (se HTTPError) Status() int {
	return se.Code
}

func badRequest(err error) HTTPError {
	return HTTPError{Code: http.StatusBadRequest, Err: err}
}

func internal(err error) HTTPError {
	return HTTPError{Code: http.StatusInternalServerError, Err: err}
}

func (gi *GiteeInterceptor) executeInterceptor(r *http.Request) ([]byte, error) {
	// Create a context
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var body bytes.Buffer
	defer r.Body.Close()
	if _, err := io.Copy(&body, r.Body); err != nil {
		return nil, internal(fmt.Errorf("failed to read body: %w", err))
	}
	var ireq triggersv1.InterceptorRequest
	if err := json.Unmarshal(body.Bytes(), &ireq); err != nil {
		return nil, badRequest(fmt.Errorf("failed to parse body as InterceptorRequest: %w", err))
	}
	gi.Logger.Debugf("Interceptor Request is: %+v", ireq)
	iresp := gi.Process(ctx, &ireq)
	gi.Logger.Infof("Interceptor response is: %+v", iresp)
	respBytes, err := json.Marshal(iresp)
	if err != nil {
		return nil, internal(err)
	}
	return respBytes, nil
}

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")

type GiteeInterceptor struct {
	SecretLister corev1lister.SecretLister
	Logger       *zap.SugaredLogger
}

// GiteeInterceptorParams 定义了我们期望从 CRD 的 params 字段中获取的参数结构
type GiteeInterceptorParams struct {
	SecretRef  *triggersv1.SecretRef `json:"secretRef,omitempty"`
	EventTypes []string              `json:"eventTypes,omitempty"`
}

func NewGiteeInterceptor(s corev1lister.SecretLister, l *zap.SugaredLogger) *GiteeInterceptor {
	return &GiteeInterceptor{
		SecretLister: s,
		Logger:       l,
	}
}

func (w *GiteeInterceptor) Process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
	headers := interceptors.Canonical(r.Header)
	if v := headers.Get("Content-Type"); v == "application/x-www-form-urlencoded" {
		return interceptors.Fail(codes.InvalidArgument, ErrInvalidContentType.Error())
	}

	p := GiteeInterceptorParams{}
	if err := interceptors.UnmarshalParams(r.InterceptorParams, &p); err != nil {
		return interceptors.Failf(codes.InvalidArgument, "failed to parse interceptor params: %v", err)
	}

	// Check if the event type is in the allow-list
	if p.EventTypes != nil {
		actualEvent := headers.Get(giteeEventHeader)
		isAllowed := slices.Contains(p.EventTypes, actualEvent)
		if !isAllowed {
			return interceptors.Failf(codes.FailedPrecondition, "event type %s is not allowed", actualEvent)
		}
	}

	// Next validate secrets
	if p.SecretRef != nil {
		// Check the secret to see if it is empty
		if p.SecretRef.SecretKey == "" {
			return interceptors.Fail(codes.FailedPrecondition, "Gitee interceptor secretRef.secretKey is empty")
		}
		header := headers.Get(giteeTokenHeader)
		if header == "" {
			return interceptors.Failf(codes.FailedPrecondition, "no %s set", giteeEventHeader)
		}

		ns, _ := triggersv1.ParseTriggerID(r.Context.TriggerID)
		secret, err := w.SecretLister.Secrets(ns).Get(p.SecretRef.SecretName)
		if err != nil {
			return interceptors.Failf(codes.FailedPrecondition, "error getting secret: %v", err)
		}
		secretToken := secret.Data[p.SecretRef.SecretKey]
		w.Logger.Infof("Using secret %s/%s.%s for validation value: %s", ns, p.SecretRef.SecretName, p.SecretRef.SecretKey, string(secretToken))

		var eventGUID string
		if eventGUID = headers.Get(giteeTimestampHeader); eventGUID == "" {
			return interceptors.Failf(codes.InvalidArgument, "missing X-Gitee-Timestamp header")
		}

		if err := gitee.ValidateWebhook(&headers, secretToken, eventGUID); err != nil {
			return interceptors.Fail(codes.FailedPrecondition, err.Error())
		}
	}

	return &triggersv1.InterceptorResponse{
		Continue: true,
	}
}
