// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
)

type formStateKeyType struct{}

var formStateKey formStateKeyType

type formState struct {
	once sync.Once
	err  error
}

// WithFormState adds the slot ParseForm records its result in.
func WithFormState(c context.Context) context.Context {
	return context.WithValue(c, formStateKey, &formState{})
}

// ParseForm parses the request's form (urlencoded or multipart) once and returns the same error to every caller, so
// no reader acts on a form Go read in part (malformed, too large, or over its field limit). Only a handler that reads
// the form calls it: a raw body is untouched.
func ParseForm(req *http.Request) error {
	parse := func() error {
		if err := req.ParseForm(); err != nil && strings.Contains(req.Header.Get("Content-Type"), "form-urlencoded") {
			return err
		}
		if err := req.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			return err
		}
		return nil
	}
	s, _ := req.Context().Value(formStateKey).(*formState)
	if s == nil {
		return parse()
	}
	s.once.Do(func() { s.err = parse() })
	return s.err
}

// FormRefused is what RefuseForm panics with; the request recovery ends the request, the 400 is already written.
type FormRefused struct{}

// FormErrorStatus is 413 for a body over a limit a route set (http.MaxBytesReader), else 400.
func FormErrorStatus(err error) int {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// RefuseForm answers for the form error err and stops the handler.
func RefuseForm(resp http.ResponseWriter, err error) {
	http.Error(resp, "The request could not be parsed.", FormErrorStatus(err))
	panic(FormRefused{})
}
