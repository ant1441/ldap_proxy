package main

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testOptions() *Options {
	o := NewOptions()
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8080/")
	o.CookieSecret = "foobar"
	o.EmailDomains = []string{"*"}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := NewOptions()
	o.EmailDomains = []string{"*"}
	err := o.Validate()

	if err == nil {
		t.Error("expected error")
	}

	expected := errorMsg([]string{
		"missing setting: upstream",
		"missing setting: cookie-secret"})

	if expected != err.Error() {
		t.Errorf("unexpected error: %+v", err)
	}
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()

	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}
}

func TestProxyURLs(t *testing.T) {
	o := testOptions()

	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8081")
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	expected := []*url.URL{
		{Scheme: "http", Host: "127.0.0.1:8080", Path: "/"},
		// note the '/' was added
		{Scheme: "http", Host: "127.0.0.1:8081", Path: "/"},
	}

	if !reflect.DeepEqual(expected, o.proxyURLs) {
		t.Errorf("unexpected value: %+v, expected %+v", expected, o.proxyURLs)
	}
}

func TestCompiledRegex(t *testing.T) {
	o := testOptions()

	regexps := []string{"/foo/.*", "/ba[rz]/quux"}
	o.SkipAuthRegex = regexps
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	actual := make([]string, 0)
	for _, regex := range o.CompiledPathRegex {
		actual = append(actual, regex.String())
	}

	if !reflect.DeepEqual(regexps, actual) {
		t.Errorf("unexpected value: %+v, expected %+v", actual, regexps)
	}
}

func TestCompiledRegexError(t *testing.T) {
	o := testOptions()
	o.SkipAuthRegex = []string{"(foobaz", "barquux)"}

	err := o.Validate()

	if err == nil {
		t.Error("expected error")
		return
	}

	expected := errorMsg([]string{
		"error compiling regex=\"(foobaz\" error parsing regexp: " +
			"missing closing ): `(foobaz`",
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})

	if expected != err.Error() {
		t.Errorf("unexpected error message: %+v, expected %+v", expected, err)
	}
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	o.CookieSecret = "0123456789abcdefabcd"
	o.CookieRefresh = o.CookieExpire
	if err := o.Validate(); err == nil {
		t.Errorf("expected error, got %+v", err)
	}

	o.CookieRefresh -= time.Duration(1)
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	// 24 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	// 16 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA=="
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA"
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}
}

func TestValidateSignatureKey(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "sha1:secret"
	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	if o.signatureData.hash != crypto.SHA1 {
		t.Errorf("expected %+v to be equal to %+v", o.signatureData.hash, crypto.SHA1)
	}

	if o.signatureData.key != "secret" {
		t.Errorf("expected %+v to be equal to %+v", o.signatureData.key, "secret")
	}
}

func TestValidateSignatureKeyInvalidSpec(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "invalid spec"
	err := o.Validate()

	if err.Error() != "Invalid configuration:\n  invalid signature hash:key spec: "+o.SignatureKey {
		t.Error("unexpected error", err)
	}
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := o.Validate()

	if err.Error() != "Invalid configuration:\n  unsupported signature hash algorithm: "+o.SignatureKey {
		t.Error("unexpected error", err)
	}
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.CookieName = "_valid_cookie_name"

	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions()
	o.CookieName = "_bad_cookie_name{}"
	err := o.Validate()

	if err.Error() != fmt.Sprintf("Invalid configuration:\n  invalid cookie name: %q", o.CookieName) {
		t.Error("unexpected error", err)
	}
}

func TestValidateCiphersBadName(t *testing.T) {
	o := testOptions()
	o.CiphersSuites = "bad_cipher"
	err := o.Validate()

	if err.Error() != fmt.Sprintf("Invalid configuration:\n  unsupported cipher %q", o.CiphersSuites) {
		t.Error("unexpected error", err)
	}
}

func TestValidateCipher(t *testing.T) {
	o := testOptions()
	o.CiphersSuites = "TLS_RSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"

	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	if err := o.Validate(); err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	if tls.TLS_RSA_WITH_RC4_128_SHA != o.ciphersSuites[0] {
		t.Errorf("unexpected cipher: %+v", o.ciphersSuites[0])
	}

	if tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 != o.ciphersSuites[1] {
		t.Errorf("unexpected cipher: %+v", o.ciphersSuites[1])
	}
}
