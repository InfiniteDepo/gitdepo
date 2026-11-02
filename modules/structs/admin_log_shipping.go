// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// LogShippingHeader is a custom header of a log destination; the value is never returned
type LogShippingHeader struct {
	Name     string `json:"name"`
	HasValue bool   `json:"has_value"`
}

// LogShippingStatus is what this instance sent to a log destination since it started
type LogShippingStatus struct {
	Sent        uint64     `json:"sent"`
	Dropped     uint64     `json:"dropped"`
	Errors      uint64     `json:"errors"`
	LastSuccess *time.Time `json:"last_success"`
	// the class of the last failure ("status 5xx", "connection failed", "timeout")
	LastError string `json:"last_error"`
}

// LogShippingDestination is a place the logs are shipped to
type LogShippingDestination struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	// whether a key is stored; the key is never returned
	HasKey     bool                 `json:"has_key"`
	Headers    []*LogShippingHeader `json:"headers"`
	NDJSON     bool                 `json:"ndjson"`
	Enabled    bool                 `json:"enabled"`
	LogTypes   []string             `json:"log_types"`
	Level      string               `json:"level"`
	Expression string               `json:"expression"`
	Exclusion  string               `json:"exclusion"`
	Status     LogShippingStatus    `json:"status"`
}

// LogShippingHeaderOption is a custom header to send; an empty value keeps the stored value of the header
type LogShippingHeaderOption struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CreateLogShippingDestinationOption creates a log destination
type CreateLogShippingDestinationOption struct {
	// lower-case letters, digits and dashes, unique
	// required: true
	Name string `json:"name" binding:"Required"`
	// newrelic, http or loki
	// required: true
	Type string `json:"type" binding:"Required"`
	// an https:// URL without credentials or query
	// required: true
	Endpoint string `json:"endpoint" binding:"Required"`
	// the ingest key (newrelic)
	Key string `json:"key"`
	// custom headers (http); the values are stored encrypted
	Headers []*LogShippingHeaderOption `json:"headers"`
	// one event per line instead of a JSON array (http)
	NDJSON  bool  `json:"ndjson"`
	Enabled *bool `json:"enabled"`
	// all (not audit), application, access, router, git, audit
	// required: true
	LogTypes []string `json:"log_types" binding:"Required"`
	// trace, debug, info, warn or error; info if empty
	Level      string `json:"level"`
	Expression string `json:"expression"`
	Exclusion  string `json:"exclusion"`
}

// EditLogShippingDestinationOption changes a log destination; fields left out stay as they are.
// A new endpoint needs the key and every header value again.
type EditLogShippingDestinationOption struct {
	Name     *string `json:"name"`
	Endpoint *string `json:"endpoint"`
	Key      *string `json:"key"`
	// the complete list of headers: one left out is removed, one without a value keeps its stored value
	Headers    *[]*LogShippingHeaderOption `json:"headers"`
	NDJSON     *bool                       `json:"ndjson"`
	Enabled    *bool                       `json:"enabled"`
	LogTypes   *[]string                   `json:"log_types"`
	Level      *string                     `json:"level"`
	Expression *string                     `json:"expression"`
	Exclusion  *string                     `json:"exclusion"`
}

// LogShippingTestResult is the outcome of a test event
type LogShippingTestResult struct {
	// the HTTP status of the destination, 0 if it wasn't reached
	Status int `json:"status"`
	// "status 4xx", "status 5xx", "connection failed" or "timeout"; empty on success
	Error string `json:"error"`
}
