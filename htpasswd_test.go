package main

import (
	"bytes"
	"testing"
)

func TestHtpasswd(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:{SHA}PaVBVZkYqAjCQCu6UBL2xgsnZhw=\n"))
	h, err := NewHtpasswd(file)

	if err != nil {
		t.Errorf("unexpected error %+v", err)
	}

	if ok := h.Validate("testuser", "asdf"); !ok {
		t.Error("expected credentials to be valid")
	}
}
