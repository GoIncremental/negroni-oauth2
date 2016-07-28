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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	sessions "github.com/goincremental/negroni-sessions"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
)

const (
	codeRedirect = 302
	keyToken     = "oauth2_token"
	keyNextPage  = "next"
	keyState     = "state"
)

var (
	// PathLogin sets the path to handle OAuth 2.0 logins.
	PathLogin = "/login"
	// PathLogout sets to handle OAuth 2.0 logouts.
	PathLogout = "/logout"
	// PathCallback sets the path to handle callback from OAuth 2.0 backend
	// to exchange credentials.
	PathCallback = "/oauth2callback"
	// PathError sets the path to handle error cases.
	PathError = "/oauth2error"
)

type Config oauth2.Config

// Tokens Represents a container that contains
// user's OAuth 2.0 access and refresh tokens.
type Tokens interface {
	Access() string
	Refresh() string
	Valid() bool
	ExpiryTime() time.Time
	ExtraData(string) interface{}
	Get() Token
}

type Token oauth2.Token

type token struct {
	oauth2.Token
}

func (t *token) ExtraData(key string) interface{} {
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
func (t *token) Valid() bool {
	if t == nil {
		return true
	}
	return t.Token.Valid()
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

// Returns oauth2.Token.
func (t *token) Get() Token {
	return (Token)(t.Token)
}

// Returns a new Google OAuth 2.0 backend endpoint.
func Google(config *Config) negroni.Handler {
	authUrl := "https://accounts.google.com/o/oauth2/auth"
	tokenUrl := "https://accounts.google.com/o/oauth2/token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

// Returns a new Github OAuth 2.0 backend endpoint.
func Github(config *Config) negroni.Handler {
	authUrl := "https://github.com/login/oauth/authorize"
	tokenUrl := "https://github.com/login/oauth/access_token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

func Facebook(config *Config) negroni.Handler {
	authUrl := "https://www.facebook.com/dialog/oauth"
	tokenUrl := "https://graph.facebook.com/oauth/access_token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

func LinkedIn(config *Config) negroni.Handler {
	authUrl := "https://www.linkedin.com/uas/oauth2/authorization"
	tokenUrl := "https://www.linkedin.com/uas/oauth2/accessToken"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

// Returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(config *Config, authUrl, tokenUrl string) negroni.HandlerFunc {
	c := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       config.Scopes,
		RedirectURL:  config.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authUrl,
			TokenURL: tokenUrl,
		},
	}

	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		s := sessions.GetSession(r)

		if r.Method == "GET" {
			switch r.URL.Path {
			case PathLogin:
				login(c, s, w, r)
			case PathLogout:
				logout(s, w, r)
			case PathCallback:
				handleOAuth2Callback(c, s, w, r)
			default:
				next(w, r)
			}
		} else {
			next(w, r)
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
		if !tk.Valid() && tk.Refresh() == "" {
			s.Delete(keyToken)
			tk = nil
		}
	}
}

// Handler that redirects user to the login page
// if user is not logged in.
func LoginRequired() negroni.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		token := GetToken(r)
		if token == nil || !token.Valid() {
			// Set token to null to avoid redirection loop
			SetToken(r, nil)
			next := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(rw, r, PathLogin+"?"+keyNextPage+"="+next, http.StatusFound)
		} else {
			next(rw, r)
		}
	}
}

func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}

func login(config *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := extractPath(r.URL.Query().Get(keyNextPage))

	if s.Get(keyToken) == nil {
		// User is not logged in.
		if next == "" {
			next = "/"
		}

		state := newState()
		// store the next url and state token in the session
		s.Set(keyState, state)
		s.Set(keyNextPage, next)
		http.Redirect(w, r, config.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
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

func handleOAuth2Callback(config *oauth2.Config, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	providedState := extractPath(r.URL.Query().Get("state"))

	//verify that the provided state is the state we generated
	//if it is not, then redirect to the error page
	originalState := s.Get(keyState)
	if providedState != originalState {
		http.Redirect(w, r, PathError, http.StatusFound)
		return
	}

	next := s.Get(keyNextPage).(string)
	code := r.URL.Query().Get("code")
	t, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		http.Redirect(w, r, PathError, http.StatusFound)
		return
	}
	// Store the credentials in the session.
	val, _ := json.Marshal(t)
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
