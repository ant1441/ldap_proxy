package main

import (
	b64 "encoding/base64"

	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/18F/hmacauth"

	"github.com/ant1441/ldap_proxy/cookie"
)

const SignatureHeader = "LAP-Signature"

var SignatureHeaders []string = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Lap-Auth",
}

type LdapProxy struct {
	CookieSeed     string
	CookieName     string
	CSRFCookieName string
	CookieDomain   string
	CookieSecure   bool
	CookieHttpOnly bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	Validator      func(string) bool

	RobotsPath   string
	PingPath     string
	SignInPath   string
	SignOutPath  string
	AuthOnlyPath string

	ProxyPrefix         string
	SignInMessage       string
	HtpasswdFile        *HtpasswdFile
	DisplayHtpasswdForm bool
	serveMux            http.Handler
	SetXAuthRequest     bool
	PassBasicAuth       bool

	PassUserHeaders   bool
	BasicAuthPassword string

	RealIPHeader  string
	ProxyIPHeader string

	LdapConnection *LdapConnection

	CookieCipher      *cookie.Cipher
	skipAuthRegex     []string
	skipAuthIPs       []*net.IPNet
	skipAuthPreflight bool
	compiledPathRegex []*regexp.Regexp
	templates         *template.Template
	Footer            string
}

func NewLdapProxy(opts *Options, validator func(string) bool) *LdapProxy {
	serveMux := http.NewServeMux()
	var auth hmacauth.HmacAuth
	if sigData := opts.signatureData; sigData != nil {
		auth = hmacauth.NewHmacAuth(sigData.hash, []byte(sigData.key),
			SignatureHeader, SignatureHeaders)
	}
	for _, u := range opts.proxyURLs {
		path := u.Path
		switch u.Scheme {
		case "http", "https":
			u.Path = ""
			log.Printf("mapping path %q => upstream %q", path, u)
			proxy := NewReverseProxy(u)
			if !opts.PassHostHeader {
				setProxyUpstreamHostHeader(proxy, u)
			} else {
				setProxyDirector(proxy)
			}
			serveMux.Handle(path,
				&UpstreamProxy{u.Host, proxy, auth})
		case "file":
			if u.Fragment != "" {
				path = u.Fragment
			}
			log.Printf("mapping path %q => file system %q", path, u.Path)
			proxy := NewFileServer(path, u.Path)
			serveMux.Handle(path, &UpstreamProxy{path, proxy, nil})
		default:
			panic(fmt.Sprintf("unknown upstream protocol %s", u.Scheme))
		}
	}
	for _, u := range opts.CompiledPathRegex {
		log.Printf("compiled skip-auth-regex => %q", u)
	}

	domain := opts.CookieDomain
	if domain == "" {
		domain = "<default>"
	}
	refresh := "disabled"
	if opts.CookieRefresh != time.Duration(0) {
		refresh = fmt.Sprintf("after %s", opts.CookieRefresh)
	}

	log.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domain:%s refresh:%s", opts.CookieName, opts.CookieSecure, opts.CookieHttpOnly, opts.CookieExpire, domain, refresh)

	var cipher *cookie.Cipher
	if opts.CookieRefresh != time.Duration(0) {
		var err error
		cipher, err = cookie.NewCipher(secretBytes(opts.CookieSecret))
		if err != nil {
			log.Fatal("cookie-secret error: ", err)
		}
	}

	ldapConnection := NewLdapConnection(
		opts.LdapServerHost,
		opts.LdapServerPort,
		opts.LdapTLS,
		opts.LdapBaseDn,
		opts.LdapBindDn,
		opts.LdapBindDnPassword,
		opts.LdapScopeName,
	)

	return &LdapProxy{
		CookieName:     opts.CookieName,
		CSRFCookieName: fmt.Sprintf("%v_%v", opts.CookieName, "csrf"),
		CookieSeed:     opts.CookieSecret,
		CookieDomain:   opts.CookieDomain,
		CookieSecure:   opts.CookieSecure,
		CookieHttpOnly: opts.CookieHttpOnly,
		CookieExpire:   opts.CookieExpire,
		CookieRefresh:  opts.CookieRefresh,
		Validator:      validator,

		RobotsPath:   "/robots.txt",
		PingPath:     "/ping",
		SignInPath:   fmt.Sprintf("%s/sign_in", opts.ProxyPrefix),
		SignOutPath:  fmt.Sprintf("%s/sign_out", opts.ProxyPrefix),
		AuthOnlyPath: fmt.Sprintf("%s/auth", opts.ProxyPrefix),

		ProxyPrefix:     opts.ProxyPrefix,
		serveMux:        serveMux,
		SetXAuthRequest: opts.SetXAuthRequest,
		PassBasicAuth:   opts.PassBasicAuth,

		PassUserHeaders:   opts.PassUserHeaders,
		BasicAuthPassword: opts.BasicAuthPassword,

		RealIPHeader:  opts.RealIPHeader,
		ProxyIPHeader: opts.ProxyIPHeader,

		LdapConnection: ldapConnection,

		skipAuthRegex:     opts.SkipAuthRegex,
		skipAuthIPs:       opts.skipIPs,
		skipAuthPreflight: opts.SkipAuthPreflight,
		compiledPathRegex: opts.CompiledPathRegex,
		CookieCipher:      cipher,
		templates:         loadTemplates(opts.CustomTemplatesDir),
		Footer:            opts.Footer,
	}
}

func (p *LdapProxy) MakeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	if value != "" {
		value = cookie.SignedValue(p.CookieSeed, p.CookieName, value, now)
		if len(value) > 4096 {
			// Cookies cannot be larger than 4kb
			log.Printf("WARNING - Cookie Size: %d bytes", len(value))
		}
	}
	return p.makeCookie(req, p.CookieName, value, expiration, now)
}

func (p *LdapProxy) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if p.CookieDomain != "" {
		if !strings.HasSuffix(domain, p.CookieDomain) {
			log.Printf("Warning: request host is %q but using configured cookie domain of %q", domain, p.CookieDomain)
		}
		domain = p.CookieDomain
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: p.CookieHttpOnly,
		Secure:   p.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

func (p *LdapProxy) RobotsTxt(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

func (p *LdapProxy) PingPage(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
}

func (p *LdapProxy) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	log.Printf("ErrorPage %d %s %s", code, title, message)
	rw.WriteHeader(code)
	t := struct {
		Title       string
		Message     string
		ProxyPrefix string
	}{
		Title:       fmt.Sprintf("%d %s", code, title),
		Message:     message,
		ProxyPrefix: p.ProxyPrefix,
	}
	p.templates.ExecuteTemplate(rw, "error.html", t)
}

func (p *LdapProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int, failed bool) {
	// TODO Basic Auth?
	p.ClearSessionCookie(rw, req)
	rw.WriteHeader(code)

	redirect_url := req.URL.RequestURI()
	if req.Header.Get("X-Auth-Request-Redirect") != "" {
		redirect_url = req.Header.Get("X-Auth-Request-Redirect")
	}
	if redirect_url == p.SignInPath {
		redirect_url = "/"
	}

	t := struct {
		LdapScopeName string
		SignInMessage string
		Failed        bool
		Redirect      string
		Version       string
		ProxyPrefix   string
		Footer        template.HTML
	}{
		LdapScopeName: p.LdapConnection.LdapScopeName,
		SignInMessage: p.SignInMessage,
		Failed:        failed,
		Redirect:      redirect_url,
		Version:       VERSION,
		ProxyPrefix:   p.ProxyPrefix,
		Footer:        template.HTML(p.Footer),
	}
	p.templates.ExecuteTemplate(rw, "sign_in.html", t)
}
func (p *LdapProxy) ManualSignIn(rw http.ResponseWriter, req *http.Request) (string, bool) {
	if req.Method != "POST" || p.HtpasswdFile == nil {
		return "", false
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.HtpasswdFile.Validate(user, passwd) {
		log.Printf("authenticated %q via HtpasswdFile", user)
		return user, true
	}
	return "", false
}

func (p *LdapProxy) LdapSignIn(rw http.ResponseWriter, req *http.Request) (string, bool) {
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.LdapConnection.VerifyUserPass(user, passwd) {
		log.Printf("authenticated %q via LDAP", user)
		return user, true
	}
	return "", false
}

func (p *LdapProxy) GetRedirect(req *http.Request) (redirect string, err error) {
	err = req.ParseForm()
	if err != nil {
		return
	}

	redirect = req.Form.Get("rd")
	if redirect == "" || !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/"
	}

	return
}

func (p *LdapProxy) IsWhitelistedRequest(req *http.Request) (ok bool) {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed || p.IsWhitelistedPath(req.URL.Path) || p.IsWhitelistedIP(p.getRemoteAddr(req))
}

func (p *LdapProxy) IsWhitelistedIP(remoteAddr net.IP) (ok bool) {
	if remoteAddr == nil {
		return false
	}
	for _, c := range p.skipAuthIPs {
		if c.Contains(remoteAddr) {
			return true
		}
	}
	return false
}

func (p *LdapProxy) IsWhitelistedPath(path string) (ok bool) {
	for _, u := range p.compiledPathRegex {
		ok = u.MatchString(path)
		if ok {
			return
		}
	}
	return
}

// TODO: Should we trust X-Real-IP and X-Forwarded-For
func (p *LdapProxy) getRemoteAddr(req *http.Request) (ip net.IP) {
	remoteAddrstr := strings.SplitN(req.RemoteAddr, ":", 2)[0]
	ip = net.ParseIP(remoteAddrstr)
	if req.Header.Get(p.RealIPHeader) != "" {
		ip = net.ParseIP(req.Header.Get(p.RealIPHeader))
	}
	if req.Header.Get(p.ProxyIPHeader) != "" {
		ip = net.ParseIP(req.Header.Get(p.ProxyIPHeader))
	}
	return
}

func (p *LdapProxy) getRemoteAddrStr(req *http.Request) (s string) {
	s = req.RemoteAddr
	if req.Header.Get(p.RealIPHeader) != "" {
		s += fmt.Sprintf(" (%q)", req.Header.Get(p.RealIPHeader))
	}
	if req.Header.Get(p.ProxyIPHeader) != "" {
		s += fmt.Sprintf(" (%q)", req.Header.Get(p.ProxyIPHeader))
	}
	return
}

func (p *LdapProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch path := req.URL.Path; {
	case path == p.RobotsPath:
		p.RobotsTxt(rw)
	case path == p.PingPath:
		p.PingPage(rw)
	case p.IsWhitelistedRequest(req):
		p.serveMux.ServeHTTP(rw, req)
	case path == p.SignInPath:
		p.SignIn(rw, req)
	case path == p.SignOutPath:
		p.SignOut(rw, req)
	case path == p.AuthOnlyPath:
		p.AuthenticateOnly(rw, req)
	default:
		p.Proxy(rw, req)
	}
}

func NewReverseProxy(target *url.URL) (proxy *httputil.ReverseProxy) {
	return httputil.NewSingleHostReverseProxy(target)
}
func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.Host = target.Host
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}
func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}
func NewFileServer(path string, filesystemPath string) (proxy http.Handler) {
	return http.StripPrefix(path, http.FileServer(http.Dir(filesystemPath)))
}

func (p *LdapProxy) SignIn(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.GetRedirect(req)
	if err != nil {
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}

	user, ok := p.ManualSignIn(rw, req)
	if ok {
		session := &SessionState{User: user}
		p.SaveSession(rw, req, session)
		http.Redirect(rw, req, redirect, 302)
	} else {
		user, ok := p.LdapSignIn(rw, req)
		if ok {
			session := &SessionState{User: user}
			p.SaveSession(rw, req, session)
			http.Redirect(rw, req, redirect, 302)
		} else {
			p.SignInPage(rw, req, 200, true)
		}
	}
}

func (p *LdapProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	// TODO not working?
	p.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, "/", 302)
}

func (p *LdapProxy) AuthenticateOnly(rw http.ResponseWriter, req *http.Request) {
	status := p.Authenticate(rw, req)
	if status == http.StatusAccepted {
		rw.WriteHeader(http.StatusAccepted)
	} else {
		http.Error(rw, "unauthorized request", http.StatusUnauthorized)
	}
}

func (p *LdapProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	status := p.Authenticate(rw, req)
	if status == http.StatusInternalServerError {
		p.ErrorPage(rw, http.StatusInternalServerError,
			"Internal Error", "Internal Error")
	} else if status == http.StatusForbidden {
		p.SignInPage(rw, req, http.StatusForbidden, false)
	} else {
		p.serveMux.ServeHTTP(rw, req)
	}
}

func (p *LdapProxy) Authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool
	remoteAddr := p.getRemoteAddrStr(req)

	session, sessionAge, err := p.LoadCookiedSession(req)
	if err != nil {
		log.Printf("%s %s", remoteAddr, err)
	}
	if session != nil && sessionAge > p.CookieRefresh && p.CookieRefresh != time.Duration(0) {
		log.Printf("%s refreshing %s old session cookie for %s (refresh after %s)", remoteAddr, sessionAge, session, p.CookieRefresh)
		saveSession = true
	}

	if ok, err := p.RefreshSessionIfNeeded(session); err != nil {
		log.Printf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
		clearSession = true
		session = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if session != nil && session.IsExpired() {
		log.Printf("%s removing session. token expired %s", remoteAddr, session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && session != nil {
		if !p.ValidateSessionState(session) {
			log.Printf("%s removing session. error validating %s", remoteAddr, session)
			saveSession = false
			session = nil
			clearSession = true
		}
	}

	if session != nil && session.Email != "" && !p.Validator(session.Email) {
		log.Printf("%s Permission Denied: removing session %s", remoteAddr, session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && session != nil {
		err := p.SaveSession(rw, req, session)
		if err != nil {
			log.Printf("%s %s", remoteAddr, err)
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		p.ClearSessionCookie(rw, req)
	}

	if session == nil {
		session, err = p.CheckBasicAuth(req)
		if err != nil {
			log.Printf("%s %s", remoteAddr, err)
		}
	}

	if session == nil {
		return http.StatusForbidden
	}

	// At this point, the user is authenticated. proxy normally
	if p.PassBasicAuth {
		req.SetBasicAuth(session.User, p.BasicAuthPassword)
		req.Header["X-Forwarded-User"] = []string{session.User}
		if session.Email != "" {
			req.Header["X-Forwarded-Email"] = []string{session.Email}
		}
	}
	if p.PassUserHeaders {
		req.Header["X-Forwarded-User"] = []string{session.User}
		if session.Email != "" {
			req.Header["X-Forwarded-Email"] = []string{session.Email}
		}
	}
	if p.SetXAuthRequest {
		rw.Header().Set("X-Auth-Request-User", session.User)
		if session.Email != "" {
			rw.Header().Set("X-Auth-Request-Email", session.Email)
		}
	}
	if session.Email == "" {
		rw.Header().Set("LAP-Auth", session.User)
	} else {
		rw.Header().Set("LAP-Auth", session.Email)
	}
	return http.StatusAccepted
}

func (p *LdapProxy) CheckBasicAuth(req *http.Request) (*SessionState, error) {
	if p.HtpasswdFile == nil {
		return nil, nil
	}
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}
	s := strings.SplitN(auth, " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, fmt.Errorf("invalid Authorization header %s", req.Header.Get("Authorization"))
	}
	b, err := b64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, fmt.Errorf("invalid format %s", b)
	}
	if p.HtpasswdFile.Validate(pair[0], pair[1]) {
		log.Printf("authenticated %q via basic auth", pair[0])
		return &SessionState{User: pair[0]}, nil
	}
	return nil, fmt.Errorf("%s not in HtpasswdFile", pair[0])
}
