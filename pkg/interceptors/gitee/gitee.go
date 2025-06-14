// pkg/interceptors/gitee/gitee.go

package gitee

import (
	"errors"
)

const (
	giteeTokenHeader     = "X-Gitee-Token"
	giteeEventHeader     = "X-Gitee-Event"
	giteeTimestampHeader = "X-Gitee-Timestamp"
)

// 预定义错误，这是 Go 的最佳实践
var (
	ErrSecretRefRequired   = errors.New("secretRef parameter is required for validation")
	ErrNsMissingFromCtx    = errors.New("event listener namespace is missing from context")
	ErrEventTypeNotAllowed = errors.New("event type is not allowed")
	// ErrInvalidContentType is returned when the content-type is not a JSON body.
	ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")
)
