package gitee

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// ValidateWebhook ensures that the provided request conforms to the
// format of a Gitee webhook and the payload can be validated with
// the provided hmac secret. It returns the event type, the event guid,
// whether the webhook is valid or not
func ValidateWebhook(
	h *http.Header,
	secret []byte,
	eventGUID string,
) error {
	if v := h.Get("content-type"); v != "application/json" {
		return ErrInvalidContentType
	}

	sig := h.Get(giteeTokenHeader)
	if sig == "" {
		return errors.New("missing X-Gitee-Token header")

	}

	// Validate the payload with our HMAC secret.
	if sig != payloadSignature(eventGUID, secret) {
		return errors.New("webhook signature validation failed")
	}

	return nil
}

func payloadSignature(timestamp string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)

	c := fmt.Sprintf("%s\n%s", timestamp, string(secret))
	mac.Write([]byte(c))

	h := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(h)
}
