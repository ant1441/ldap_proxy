package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/skybet/ldap_proxy/cookie"
)

func (p *LdapProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, p.MakeSessionCookie(req, "", time.Hour*-1, time.Now()))
}

func (p *LdapProxy) SetSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, p.MakeSessionCookie(req, val, p.CookieExpire, time.Now()))
}

func (p *LdapProxy) LoadCookiedSession(req *http.Request) (*SessionState, time.Duration, error) {
	var age time.Duration
	c, err := req.Cookie(p.CookieName)
	if err != nil {
		// always http.ErrNoCookie
		return nil, age, fmt.Errorf("Cookie %q not present", p.CookieName)
	}
	val, timestamp, ok := cookie.Validate(c, p.CookieSeed, p.CookieExpire)
	if !ok {
		return nil, age, errors.New("Cookie Signature not valid")
	}

	session, err := SessionFromCookie(val, p.CookieCipher)
	if err != nil {
		return nil, age, err
	}

	age = time.Now().Truncate(time.Second).Sub(timestamp)
	return session, age, nil
}

func (p *LdapProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *SessionState) error {
	value, err := CookieForSession(s, p.CookieCipher)
	if err != nil {
		return err
	}

	p.SetSessionCookie(rw, req, value)
	return nil
}

func (p *LdapProxy) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	// TODO: RefreshSessionIfNeeded
	return false, nil
}

func (p *LdapProxy) ValidateSessionState(s *SessionState) bool {
	// TODO: ValidateSessionState
	return true
}
