package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	flagSet := flag.NewFlagSet("ldap_proxy", flag.ExitOnError)

	emailDomains := StringArray{}
	upstreams := StringArray{}
	skipAuthRegex := StringArray{}
	skipAuthIPs := StringArray{}

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")
	flagSet.String("cipher-suites", "", "cipher suites (comma separated)")

	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Var(&skipAuthRegex, "skip-auth-regex", "bypass authentication for requests paths that match (may be given multiple times)")
	flagSet.Var(&skipAuthIPs, "skip-auth-ips", "bypass authentication for request hosts that match (may be given multiple times)")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS")
	flagSet.String("real-ip-header", "X-Real-IP", "The header which specifies the real IP of the request. Caution: This header may allow a malicious actor to spoof an internal IP, bypassing whitelists. Set to the empty string to ignore")
	flagSet.String("proxy-ip-header", "X-Forwarded-For", "The header which specifies the real IP of the proxied request. Caution: This header may allow a malicious actor to spoof an internal IP, bypassing whitelists. Set to the empty string to ignore")

	flagSet.Var(&emailDomains, "email-domain", "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.String("proxy-prefix", "/ldap_auth", "the url root path that this proxy should be nested under (e.g. /<ldap_auth>/sign_in)")

	flagSet.String("cookie-name", "_ldap_proxy", "the name of the cookie that the ldap_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")

	flagSet.Bool("request-logging", true, "Log requests to stdout")

	flagSet.String("login-url", "", "Authentication endpoint")

	flagSet.String("signature-key", "", "LAP-Signature request signature key (algorithm:secretkey)")

	// TODO I don't know how LDAP works
	flagSet.String("ldap-server-host", "localhost", "Hostname of LDAP server")
	flagSet.Int("ldap-server-port", 389, "Port of LDAP server")
	flagSet.Bool("ldap-tls", true, "Use TLS when communicating with the LDAP server")
	flagSet.String("ldap-scope-name", "LDAP", "Name of LDAP scope")
	flagSet.String("ldap-base-dn", "", "Base DN for LDAP bind")
	flagSet.String("ldap-bind-dn", "", "Bind DN for LDAP bind")
	flagSet.String("ldap-bind-dn-password", "", "Bind DN password for LDAP bind")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("ldap_proxy v%s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := NewOptions()

	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	err := opts.Validate()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	ldapproxy := NewLdapProxy(opts, validator)

	if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			ldapproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			ldapproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		log.Printf("using htpasswd file %s", opts.HtpasswdFile)
		ldapproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}

	s := &Server{
		Handler: LoggingHandler(os.Stdout, ldapproxy, opts.RequestLogging),
		Opts:    opts,
	}
	s.ListenAndServe()
}
