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

// Package oauth2_test contains tests for the oauth2 package
// user login via an OAuth 2.0 backend.

package oauth2_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codegangsta/negroni"
	"github.com/goincremental/negroni-oauth"
	"github.com/goincremental/negroni-sessions"
)

func Test_LoginRedirect(t *testing.T) {
	recorder := httptest.NewRecorder()
	n := negroni.New()
	n.Use(sessions.Sessions("my_session", sessions.NewCookieStore([]byte("secret123"))))
	n.Use(oauth2.Google(&oauth2.Options{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "refresh_url",
		Scopes:       []string{"x", "y"},
	}))

	r, _ := http.NewRequest("GET", "/login", nil)
	n.ServeHTTP(recorder, r)

	location := recorder.HeaderMap["Location"][0]
	if recorder.Code != 302 {
		t.Errorf("Not being redirected to the auth page.")
	}
	if location != "https://accounts.google.com/o/oauth2/auth?access_type=&approval_prompt=&client_id=client_id&redirect_uri=refresh_url&response_type=code&scope=x+y&state=%2F" {
		t.Errorf("Not being redirected to the right page, %v found", location)
	}
}

func Test_LoginRedirectAfterLoginRequired(t *testing.T) {
	recorder := httptest.NewRecorder()
	n := negroni.New()
	n.Use(sessions.Sessions("my_session", sessions.NewCookieStore([]byte("secret123"))))
	n.Use(oauth2.Google(&oauth2.Options{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "refresh_url",
		Scopes:       []string{"x", "y"},
	}))

	n.Use(oauth2.LoginRequired())

	mux := http.NewServeMux()

	mux.HandleFunc("/login-required", func(w http.ResponseWriter, req *http.Request) {
		t.Log("hi there")
		fmt.Fprintf(w, "OK")
	})

	n.UseHandler(mux)

	r, _ := http.NewRequest("GET", "/login-required?key=value", nil)
	n.ServeHTTP(recorder, r)

	location := recorder.HeaderMap["Location"][0]
	if recorder.Code != 302 {
		t.Errorf("Not being redirected to the auth page.")
	}
	if location != "/login?next=%2Flogin-required%3Fkey%3Dvalue" {
		t.Errorf("Not being redirected to the right page, %v found", location)
	}
}

func Test_Logout(t *testing.T) {
	recorder := httptest.NewRecorder()
	s := sessions.NewCookieStore([]byte("secret123"))

	n := negroni.Classic()
	n.Use(sessions.Sessions("my_session", s))
	n.Use(oauth2.Google(&oauth2.Options{
		ClientID:     "foo",
		ClientSecret: "foo",
		RedirectURL:  "foo",
	}))

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		oauth2.SetToken(req, "dummy token")
		fmt.Fprintf(w, "OK")
	})

	mux.HandleFunc("/get", func(w http.ResponseWriter, req *http.Request) {
		tok := oauth2.GetToken(req)
		if tok != nil {
			t.Errorf("User credentials are still kept in the session.")
		}
		fmt.Fprintf(w, "OK")
	})

	n.UseHandler(mux)
	logout, _ := http.NewRequest("GET", "/logout", nil)
	index, _ := http.NewRequest("GET", "/", nil)

	n.ServeHTTP(httptest.NewRecorder(), index)
	n.ServeHTTP(recorder, logout)

	if recorder.Code != 302 {
		t.Errorf("Not being redirected to the next page.")
	}
}

func Test_LogoutOnAccessTokenExpiration(t *testing.T) {
	recorder := httptest.NewRecorder()
	s := sessions.NewCookieStore([]byte("secret123"))

	n := negroni.Classic()
	n.Use(sessions.Sessions("my_session", s))
	n.Use(oauth2.Google(&oauth2.Options{
		ClientID:     "foo",
		ClientSecret: "foo",
		RedirectURL:  "foo",
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("/addtoken", func(w http.ResponseWriter, req *http.Request) {
		oauth2.SetToken(req, "dummy token")
		fmt.Fprintf(w, "OK")
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		tok := oauth2.GetToken(req)
		if tok != nil {
			t.Errorf("User not logged out although access token is expired. %v\n", tok)
		}
	})
	n.UseHandler(mux)
	addtoken, _ := http.NewRequest("GET", "/addtoken", nil)
	index, _ := http.NewRequest("GET", "/", nil)
	n.ServeHTTP(recorder, addtoken)
	n.ServeHTTP(recorder, index)
}

func Test_LoginRequired(t *testing.T) {
	recorder := httptest.NewRecorder()
	n := negroni.Classic()
	n.Use(sessions.Sessions("my_session", sessions.NewCookieStore([]byte("secret123"))))
	n.Use(oauth2.Google(&oauth2.Options{
		ClientID:     "foo",
		ClientSecret: "foo",
		RedirectURL:  "foo",
	}))

	n.Use(oauth2.LoginRequired())

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	n.UseHandler(mux)
	r, _ := http.NewRequest("GET", "/", nil)
	n.ServeHTTP(recorder, r)
	if recorder.Code != 302 {
		t.Errorf("Not being redirected to the auth page although user is not logged in. %d\n", recorder.Code)
	}
}
