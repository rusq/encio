package encio

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var ErrEmptyID = errors.New("empty id")

func idOverrideFn(id string) func(string) (string, error) {
	return func(appID string) (string, error) {
		if id == "" {
			return "", ErrEmptyID
		}
		mac := hmac.New(sha256.New, []byte(id))
		mac.Write([]byte(appID))
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
}
