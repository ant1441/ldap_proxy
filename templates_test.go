package main

import (
	"testing"
)

func TestTemplatesCompile(t *testing.T) {
	if tmpl := getTemplates(); tmpl == nil {
		t.Error("expected templates")
	}
}
