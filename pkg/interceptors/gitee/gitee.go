// pkg/interceptors/gitee/gitee.go

package gitee

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/tektoncd/triggers/pkg/interceptors"
	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1alpha1"
	"google.golang.org/grpc/codes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	giteeTokenHeader = "X-Gitee-Token"
	giteeEventHeader = "X-Gitee-Event"
)

// 预定义错误，这是 Go 的最佳实践
var (
	ErrMissingGiteeToken   = errors.New("missing X-Gitee-Token header")
	ErrInvalidSignature    = errors.New("webhook signature validation failed")
	ErrSecretRefRequired   = errors.New("secretRef parameter is required for validation")
	ErrNsMissingFromCtx    = errors.New("event listener namespace is missing from context")
	ErrEventTypeNotAllowed = errors.New("event type is not allowed")
)

// Interceptor 包含与 K8s API Server 通信所需的客户端
type Interceptor struct {
	KubeClientSet kubernetes.Interface
}

// GiteeInterceptorParams 定义了我们期望从 CRD 的 params 字段中获取的参数结构
type GiteeInterceptorParams struct {
	SecretRef  *corev1.SecretKeySelector `json:"secretRef,omitempty"`
	EventTypes []string                  `json:"eventTypes,omitempty"`
}

// New 是 Interceptor 的构造函数
func New(k kubernetes.Interface) *Interceptor {
	return &Interceptor{KubeClientSet: k}
}

// Process 是处理拦截器请求的核心方法
func (i *Interceptor) Process(r *http.Request) *triggersv1.InterceptorResponse {
	// 1. 解析 Body
	var req triggersv1.InterceptorRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return interceptors.Fail(codes.InvalidArgument, "failed to read request body: %v", err)
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return interceptors.Fail(codes.InvalidArgument, "failed to parse request body: %v", err)
	}

	// 2. 解析 Params
	var params GiteeInterceptorParams
	if err := interceptors.UnmarshalParams(req.InterceptorParams, &params); err != nil {
		return interceptors.Fail(codes.InvalidArgument, "failed to unmarshal interceptor params: %v", err)
	}

	// 3. 以官方推荐方式获取标准化的 Headers
	headers := interceptors.Canonical(req.Header)
	giteeEvent := headers.Get(giteeEventHeader)
	giteeSignature := headers.Get(giteeTokenHeader)

	if giteeSignature == "" {
		return interceptors.Fail(codes.InvalidArgument, ErrMissingGiteeToken.Error())
	}

	// 4. 事件过滤
	if len(params.EventTypes) > 0 {
		isAllowed := false
		for _, eventType := range params.EventTypes {
			if giteeEvent == eventType {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return interceptors.Fail(codes.PermissionDenied, "%s: %s", ErrEventTypeNotAllowed.Error(), giteeEvent)
		}
	}

	// 5. 签名验证
	if params.SecretRef != nil {
		if req.Context == nil || req.Context.EventListenerNamespace == "" {
			return interceptors.Fail(codes.FailedPrecondition, ErrNsMissingFromCtx.Error())
		}
		secret, err := i.KubeClientSet.CoreV1().Secrets(req.Context.EventListenerNamespace).Get(context.Background(), params.SecretRef.Name, metav1.GetOptions{})
		if err != nil {
			return interceptors.Fail(codes.Internal, "failed to get secret %s: %v", params.SecretRef.Name, err)
		}
		secretBytes, ok := secret.Data[params.SecretRef.Key]
		if !ok {
			return interceptors.Fail(codes.InvalidArgument, "key %s not found in secret %s", params.SecretRef.Key, params.SecretRef.Name)
		}

		mac := hmac.New(sha256.New, secretBytes)
		mac.Write([]byte(req.Body))
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(giteeSignature), []byte(expectedSignature)) {
			return interceptors.Fail(codes.Unauthenticated, ErrInvalidSignature.Error())
		}
	} else {
		return interceptors.Fail(codes.InvalidArgument, ErrSecretRefRequired.Error())
	}

	// 6. 成功
	return &triggersv1.InterceptorResponse{
		Continue:          true,
		InterceptorParams: req.InterceptorParams,
		Extensions:        req.Extensions,
	}
}
