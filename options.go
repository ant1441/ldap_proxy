package main

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/18F/hmacauth"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyPrefix  string `flag:"proxy-prefix" cfg:"proxy-prefix"`
	HttpAddress  string `flag:"http-address" cfg:"http_address"`
	HttpsAddress string `flag:"https-address" cfg:"https_address"`

	TLSCertFile   string `flag:"tls-cert" cfg:"tls_cert_file"`
	TLSKeyFile    string `flag:"tls-key" cfg:"tls_key_file"`
	CiphersSuites string `flag:"cipher-suites" cfg:"cipher_suites"`

	EmailDomains            []string `flag:"email-domain" cfg:"email_domains"`
	AuthenticatedEmailsFile string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	HtpasswdFile            string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	CustomTemplatesDir      string   `flag:"custom-templates-dir" cfg:"custom_templates_dir"`
	Footer                  string   `flag:"footer" cfg:"footer"`

	CookieName     string        `flag:"cookie-name" cfg:"cookie_name" env:"LDAP_PROXY_COOKIE_NAME"`
	CookieSecret   string        `flag:"cookie-secret" cfg:"cookie_secret" env:"LDAP_PROXY_COOKIE_SECRET"`
	CookieDomain   string        `flag:"cookie-domain" cfg:"cookie_domain" env:"LDAP_PROXY_COOKIE_DOMAIN"`
	CookieExpire   time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"LDAP_PROXY_COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"LDAP_PROXY_COOKIE_REFRESH"`
	CookieSecure   bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	CookieHttpOnly bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`

	Upstreams             []string `flag:"upstream" cfg:"upstreams"`
	SkipAuthRegex         []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthIPs           []string `flag:"skip-auth-ips" cfg:"skip_auth_ips"`
	PassBasicAuth         bool     `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	BasicAuthPassword     string   `flag:"basic-auth-password" cfg:"basic_auth_password"`
	PassHostHeader        bool     `flag:"pass-host-header" cfg:"pass_host_header"`
	PassUserHeaders       bool     `flag:"pass-user-headers" cfg:"pass_user_headers"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SetXAuthRequest       bool     `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SkipAuthPreflight     bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	RealIPHeader          string   `flag:"real-ip-header" cfg:"real_ip_header"`
	ProxyIPHeader         string   `flag:"proxy-ip-header" cfg:"proxy_ip_header"`

	RequestLogging bool `flag:"request-logging" cfg:"request_logging"`

	SignatureKey string `flag:"signature-key" cfg:"signature_key" env:"LDAP_PROXY_SIGNATURE_KEY"`

	LdapServerHost     string   `flag:"ldap-server-host" cfg:"ldap_server_host"`
	LdapServerPort     int      `flag:"ldap-server-port" cfg:"ldap_server_port"`
	LdapTLS            bool     `flag:"ldap-tls" cfg:"ldap_tls"`
	LdapScopeName      string   `flag:"ldap-scope-name" cfg:"ldap_scope_name"`
	LdapBaseDn         string   `flag:"ldap-base-dn" cfg:"ldap_base_dn"`
	LdapBindDn         string   `flag:"ldap-bind-dn" cfg:"ldap_bind_dn"`
	LdapBindDnPassword string   `flag:"ldap-bind-dn-password" cfg:"ldap_bind_dn_password"`
	LdapGroups         []string `flag:"ldap-groups" cfg:"ldap_groups"`

	// internal values that are set after config validation
	proxyURLs         []*url.URL
	CompiledPathRegex []*regexp.Regexp
	skipIPs           []*net.IPNet
	signatureData     *SignatureData
	ciphersSuites     []uint16
}

type SignatureData struct {
	hash crypto.Hash
	key  string
}

func NewOptions() *Options {
	return &Options{
		ProxyPrefix:       "/ldap",
		HttpAddress:       "127.0.0.1:4180",
		HttpsAddress:      ":443",
		CookieName:        "_ldap_proxy",
		CookieSecure:      true,
		CookieHttpOnly:    true,
		CookieExpire:      time.Duration(168) * time.Hour,
		CookieRefresh:     time.Duration(0),
		SetXAuthRequest:   false,
		SkipAuthPreflight: false,
		PassBasicAuth:     true,
		PassUserHeaders:   true,
		PassHostHeader:    true,
		RequestLogging:    true,
	}
}

func parseURL(to_parse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(to_parse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, to_parse, err))
	}
	return parsed, msgs
}

func (o *Options) Validate() error {
	// TODO Validate Ldap

	msgs := make([]string, 0)
	if len(o.Upstreams) < 1 {
		msgs = append(msgs, "missing setting: upstream")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}

	for _, u := range o.Upstreams {
		upstreamURL, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing upstream=%q %s",
				upstreamURL, err))
		}
		if upstreamURL.Path == "" {
			upstreamURL.Path = "/"
		}
		o.proxyURLs = append(o.proxyURLs, upstreamURL)
	}

	for _, u := range o.SkipAuthRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledPathRegex = append(o.CompiledPathRegex, CompiledRegex)
	}
	for _, u := range o.SkipAuthIPs {
		if !strings.ContainsAny(u, "/") {
			// This is a raw IP not a range, lets make it one
			if strings.ContainsAny(u, ":") {
				// IPv6
				u = u + "/128"
			} else {
				// IPv4
				u = u + "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing cidr %q: %v", u, err))
		}
		o.skipIPs = append(o.skipIPs, cidr)
	}

	if o.CookieRefresh != time.Duration(0) {
		valid_cookie_secret_size := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				valid_cookie_secret_size = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if valid_cookie_secret_size == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			msgs = append(msgs, fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		}
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)

	if o.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	msgs = parseCipherSuites(o, msgs)

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseSignatureKey(o *Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	if hash, err := hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	} else {
		o.signatureData = &SignatureData{hash, secretKey}
	}
	return msgs
}

func parseCipherSuites(o *Options, msgs []string) []string {
	if o.CiphersSuites == "" {
		return msgs
	}

	if ciphers, err := cipherSuites(o.CiphersSuites); err != nil {
		return append(msgs, err.Error())
	} else {
		o.ciphersSuites = ciphers
	}
	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}

// parse user supplied cipher list
func cipherSuites(cipherStr string) ([]uint16, error) {
	// https://golang.org/src/crypto/tls/cipher_suites.go

	cipherMap := map[string]uint16{
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}

	userCiphers := strings.Split(cipherStr, ",")
	suites := []uint16{}

	for _, cipher := range userCiphers {
		if v, ok := cipherMap[cipher]; ok {
			suites = append(suites, v)
		} else {
			return suites, fmt.Errorf("unsupported cipher %q", cipher)
		}
	}

	return suites, nil
}
