package main

import (
	"net/http"

	"github.com/18F/hmacauth"
)

type UpstreamProxy struct {
	upstream string
	handler  http.Handler
	auth     hmacauth.HmacAuth
}

func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("LAP-Upstream-Address", u.upstream)
	if u.auth != nil {
		r.Header.Set("LAP-Auth", w.Header().Get("LAP-Auth"))
		u.auth.SignRequest(r)
	}
	u.handler.ServeHTTP(w, r)
}
