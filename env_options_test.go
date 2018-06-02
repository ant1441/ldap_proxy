package main

import (
	"os"
	"testing"
)

type envTest struct {
	testField string `cfg:"target_field" env:"TEST_ENV_FIELD"`
}

func TestLoadEnvForStruct(t *testing.T) {

	cfg := make(EnvOptions)
	cfg.LoadEnvForStruct(&envTest{})

	if _, ok := cfg["target_field"]; ok {
		t.Errorf("target_field shouldn't be present: %v", ok)
	}

	os.Setenv("TEST_ENV_FIELD", "1234abcd")
	cfg.LoadEnvForStruct(&envTest{})
	v, ok := cfg["target_field"]

	if !ok || v != "1234abcd" {
		t.Errorf("unexpected target_field value: %v", v)
	}
}
