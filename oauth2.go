// Copyright 2014 GoIncremental Limited. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oauth2 contains Negroni middleware to provide
// user login via an OAuth 2.0 backend.

package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/codegangsta/negroni"
	sessions "github.com/goincremental/negroni-sessions"
	"github.com/golang/oauth2"
)

const (
	codeRedirect = 302
	keyToken     = "oauth2_token"
	keyNextPage  = "next"
)

var (
	// Path to handle OAuth 2.0 logins.
	PathLogin = "/login"
	// Path to handle OAuth 2.0 logouts.
	PathLogout = "/logout"
	// Path to handle callback from OAuth 2.0 backend
	// to exchange credentials.
	PathCallback = "/oauth2callback"
	// Path to handle error cases.
	PathError = "/oauth2error"
)

type Options struct {
	// ClientID is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	ClientID string `json:"client_id"`

	// ClientSecret is the OAuth client secret used when communicating with
	// the configured OAuth provider.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to which the user will be returned after
	// granting (or denying) access.
	RedirectURL string `json:"redirect_url"`

	// Optional, identifies the level of access being requested.
	Scopes []string `json:"scopes"`

	// Optional, "online" (default) or "offline", no refresh token if "online"
	AccessType string `json:"omit"`

	// ApprovalPrompt indicates whether the user should be
	// re-prompted for consent. If set to "auto" (default) the
	// user will be prompted only if they haven't previously
	// granted consent and the code can only be exchanged for an
	// access token.
	// If set to "force" the user will always be prompted, and the
	// code can be exchanged for a refresh token.
	ApprovalPrompt string `json:"omit"`
}

// Represents a container that contains
// user's OAuth 2.0 access and refresh tokens.
type Tokens interface {
	Access() string
	Refresh() string
	Expired() bool
	ExpiryTime() time.Time
	ExtraData(string) string
}

type token struct {
	oauth2.Token
}

func (t *token) ExtraData(key string) string {
	return t.Extra(key)
}

// Returns the access token.
func (t *token) Access() string {
	return t.AccessToken
}

// Returns the refresh token.
func (t *token) Refresh() string {
	return t.RefreshToken
}

// Returns whether the access token is
// expired or not.
func (t *token) Expired() bool {
	if t == nil {
		return true
	}
	return t.Token.Expired()
}

// Returns the expiry time of the user's
// access token.
func (t *token) ExpiryTime() time.Time {
	return t.Expiry
}

// String returns the string representation of the token.
func (t *token) String() string {
	return fmt.Sprintf("tokens: %v", t)
}

// Google returns a new Google OAuth 2.0 backend endpoint.
func Google(opt ...oauth2.Option) negroni.Handler {
	return NewOAuth2Provider(append(opt, oauth2.Endpoint(
		"https://accounts.google.com/o/oauth2/auth",
		"https://accounts.google.com/o/oauth2/token"),
	))
}

// Github returns a new Github OAuth 2.0 backend endpoint.
func Github(opt ...oauth2.Option) negroni.Handler {
	return NewOAuth2Provider(append(opt, oauth2.Endpoint(
		"https://github.com/login/oauth/authorize",
		"https://github.com/login/oauth/access_token"),
	))
}

func Facebook(opt ...oauth2.Option) negroni.Handler {
	return NewOAuth2Provider(append(opt, oauth2.Endpoint(
		"https://www.facebook.com/dialog/oauth",
		"https://graph.facebook.com/oauth/access_token"),
	))
}

func LinkedIn(opt ...oauth2.Option) negroni.Handler {
	return NewOAuth2Provider(append(opt, oauth2.Endpoint(
		"https://www.linkedin.com/uas/oauth2/authorization",
		"https://www.linkedin.com/uas/oauth2/accessToken"),
	))
}

// Returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(opts []oauth2.Option) negroni.HandlerFunc {

	options, err := oauth2.New(opts...)

	if err != nil {
		panic(fmt.Sprintf("oauth2: %s", err))
	}

	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		s := sessions.GetSession(r)

		if r.Method == "GET" {
			switch r.URL.Path {
			case PathLogin:
				login(opts, options, s, rw, r)
			case PathLogout:
				logout(s, rw, r)
			case PathCallback:
				handleOAuth2Callback(options, s, rw, r)
			default:
				next(rw, r)
			}
		} else {
			next(rw, r)
		}

	}
}

func GetToken(r *http.Request) Tokens {
	s := sessions.GetSession(r)
	t := unmarshallToken(s)

	//not doing this doesn't pass through the
	//nil return, causing a test to fail - not sure why??
	if t == nil {
		return nil
	} else {
		return t
	}
}

func SetToken(r *http.Request, t interface{}) {
	s := sessions.GetSession(r)
	val, _ := json.Marshal(t)
	s.Set(keyToken, val)
	//Check immediately to see if the token is expired
	tk := unmarshallToken(s)
	if tk != nil {
		// check if the access token is expired
		if tk.Expired() && tk.Refresh() == "" {
			s.Delete(keyToken)
			tk = nil
		}
	}
}

// Handler that redirects user to the login page
// if user is not logged in.
func LoginRequired() negroni.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		s := sessions.GetSession(r)
		token := unmarshallToken(s)
		if token == nil || token.Expired() {
			// Set token to null to avoid redirection loop
			SetToken(r, nil)
			next := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(rw, r, PathLogin+"?next="+next, http.StatusFound)
		} else {
			next(rw, r)
		}
	}
}

func login(opts []oauth2.Option, options *oauth2.Options, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))
	if s.Get(keyToken) == nil {
		// User is not logged in.
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, options.AuthCodeURL(next, "", ""), http.StatusFound)
		return
	}
	// No need to login, redirect to the next page.
	http.Redirect(w, r, next, http.StatusFound)
}

func logout(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))
	s.Delete(keyToken)
	http.Redirect(w, r, next, http.StatusFound)
}

func handleOAuth2Callback(options *oauth2.Options, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get("state"))
	code := r.URL.Query().Get("code")
	t, err := options.NewTransportFromCode(code)

	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		http.Redirect(w, r, PathError, http.StatusFound)
		return
	}
	// Store the credentials in the session.
	val, _ := json.Marshal(t.Token())
	s.Set(keyToken, val)
	http.Redirect(w, r, next, http.StatusFound)
}

func unmarshallToken(s sessions.Session) *token {

	if s.Get(keyToken) == nil {
		return nil
	}

	data := s.Get(keyToken).([]byte)
	var tk oauth2.Token
	json.Unmarshal(data, &tk)
	return &token{tk}

}

func extractPath(next string) string {
	n, err := url.Parse(next)
	if err != nil {
		return "/"
	}
	return n.Path
}
