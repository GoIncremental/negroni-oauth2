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
	"github.com/goincremental/negroni-sessions"
	"github.com/golang/oauth2"
)

const (
	keyToken    = "oauth2_token"
	keyNextPage = "next"
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
	IsExpired() bool
	ExpiryTime() time.Time
	ExtraData() map[string]string
}

type token struct {
	oauth2.Token
}

func (t *token) ExtraData() map[string]string {
	return t.Extra
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
func (t *token) IsExpired() bool {
	if t == nil {
		return true
	}
	return t.Expired()
}

// Returns the expiry time of the user's
// access token.
func (t *token) ExpiryTime() time.Time {
	return t.Expiry
}

// // Formats tokens into string.
// func (t *token) String() string {
// 	return fmt.Sprintf("tokens: %v", t)
// }

// Returns a new Google OAuth 2.0 backend endpoint.
func Google(opts *Options) negroni.Handler {
	authUrl := "https://accounts.google.com/o/oauth2/auth"
	tokenUrl := "https://accounts.google.com/o/oauth2/token"
	return NewOAuth2Provider(opts, authUrl, tokenUrl)
}

// Returns a new Github OAuth 2.0 backend endpoint.
func Github(opts *Options) negroni.Handler {
	authUrl := "https://github.com/login/oauth/authorize"
	tokenUrl := "https://github.com/login/oauth/access_token"
	return NewOAuth2Provider(opts, authUrl, tokenUrl)
}

func Facebook(opts *Options) negroni.Handler {
	authUrl := "https://www.facebook.com/dialog/oauth"
	tokenUrl := "https://graph.facebook.com/oauth/access_token"
	return NewOAuth2Provider(opts, authUrl, tokenUrl)
}

func LinkedIn(opts *Options) negroni.Handler {
	authUrl := "https://www.linkedin.com/uas/oauth2/authorization"
	tokenUrl := "https://www.linkedin.com/uas/oauth2/accessToken"
	return NewOAuth2Provider(opts, authUrl, tokenUrl)
}

// Returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(opts *Options, authUrl, tokenUrl string) negroni.HandlerFunc {

	options := &oauth2.Options{
		ClientID:       opts.ClientID,
		ClientSecret:   opts.ClientSecret,
		RedirectURL:    opts.RedirectURL,
		Scopes:         opts.Scopes,
		AccessType:     opts.AccessType,
		ApprovalPrompt: opts.ApprovalPrompt,
	}

	config, err := oauth2.NewConfig(options, authUrl, tokenUrl)
	if err != nil {
		panic(fmt.Sprintf("oauth2: %s", err))
	}

	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		s := sessions.GetSession(r)

		if r.Method == "GET" {
			switch r.URL.Path {
			case PathLogin:
				login(config, s, rw, r)
			case PathLogout:
				logout(s, rw, r)
			case PathCallback:
				handleOAuth2Callback(config, s, rw, r)
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
		if tk.IsExpired() && tk.Refresh() == "" {
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
		if token == nil || token.IsExpired() {
			next := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(rw, r, PathLogin+"?next="+next, http.StatusFound)
		} else {
			next(rw, r)
		}
	}
}

func login(c *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))
	if s.Get(keyToken) == nil {
		// User is not logged in.
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, c.AuthCodeURL(next), http.StatusFound)
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

func handleOAuth2Callback(c *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get("state"))
	code := r.URL.Query().Get("code")
	t, err := c.NewTransportWithCode(code)
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
