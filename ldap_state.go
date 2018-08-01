package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/skybet/ldap_proxy/cookie"
)

type SessionState struct {
	ExpiresOn time.Time
	Email     string
	User      string
}

const COOKIE_CHUNK_COUNT = 2

// CookieForSession serializes a session state for storage in a cookie
func CookieForSession(s *SessionState, c *cookie.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func SessionFromCookie(v string, c *cookie.Cipher) (s *SessionState, err error) {
	return DecodeSessionState(v, c)
}

func (s *SessionState) EncodeSessionState(c *cookie.Cipher) (string, error) {
	if c == nil {
		return s.userOrEmail(), nil
	}
	return s.EncryptedString(c)
}

func (s *SessionState) userOrEmail() string {
	u := s.User
	if s.Email != "" {
		u = s.Email
	}
	return u
}

func (s *SessionState) EncryptedString(c *cookie.Cipher) (string, error) {
	if c == nil {
		panic("error. missing cipher")
	}
	return fmt.Sprintf("%s|%d", s.userOrEmail(), s.ExpiresOn.Unix()), nil
}

func DecodeSessionState(v string, c *cookie.Cipher) (s *SessionState, err error) {
	chunks := strings.Split(v, "|")
	if len(chunks) == 1 {
		if strings.Contains(chunks[0], "@") {
			u := strings.Split(v, "@")[0]
			return &SessionState{Email: v, User: u}, nil
		}
		return &SessionState{User: v}, nil
	}

	if len(chunks) != COOKIE_CHUNK_COUNT {
		err = fmt.Errorf("invalid number of fields (got %d expected %d)", len(chunks), COOKIE_CHUNK_COUNT)
		return
	}

	s = &SessionState{}
	if u := chunks[0]; strings.Contains(u, "@") {
		s.Email = u
		s.User = strings.Split(u, "@")[0]
	} else {
		s.User = u
	}
	ts, _ := strconv.Atoi(chunks[1])
	s.ExpiresOn = time.Unix(int64(ts), 0)
	return
}

func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}
