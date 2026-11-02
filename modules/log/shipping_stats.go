// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"sort"
	"sync"
	"time"
)

// ShippingStat counts the events a shipping writer sent, dropped and failed to send for one logger.
type ShippingStat struct {
	Writer, Logger        string
	Sent, Dropped, Errors uint64
}

var (
	shippingMu    sync.Mutex
	shippingStats = map[[2]string]*ShippingStat{}
)

func addShipping(writer, logger string, sent, dropped, errs uint64) {
	shippingMu.Lock()
	defer shippingMu.Unlock()
	st := shippingStats[[2]string{writer, logger}]
	if st == nil {
		st = &ShippingStat{Writer: writer, Logger: logger}
		shippingStats[[2]string{writer, logger}] = st
	}
	st.Sent += sent
	st.Dropped += dropped
	st.Errors += errs
}

// ShippingStatsSnapshot returns a sorted copy of the counters, for the metrics collector.
func ShippingStatsSnapshot() []ShippingStat {
	shippingMu.Lock()
	defer shippingMu.Unlock()
	out := make([]ShippingStat, 0, len(shippingStats))
	for _, st := range shippingStats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Writer != out[j].Writer {
			return out[i].Writer < out[j].Writer
		}
		return out[i].Logger < out[j].Logger
	})
	return out
}

type shippingStatus struct {
	lastSuccess time.Time
	lastError   string
}

var shippingStatuses = map[string]*shippingStatus{}

// setShippingStatus records the outcome of a send: success stamps the time, a failure keeps only its class
// ("status 5xx", "connection failed", "timeout").
func setShippingStatus(writer string, ok bool, errClass string) {
	shippingMu.Lock()
	defer shippingMu.Unlock()
	st := shippingStatuses[writer]
	if st == nil {
		st = &shippingStatus{}
		shippingStatuses[writer] = st
	}
	if ok {
		st.lastSuccess = time.Now()
	} else {
		st.lastError = errClass
	}
}

// ShippingStatus returns when the writer last sent a batch and the class of its last failure.
func ShippingStatus(writer string) (lastSuccess time.Time, lastError string) {
	shippingMu.Lock()
	defer shippingMu.Unlock()
	if st := shippingStatuses[writer]; st != nil {
		return st.lastSuccess, st.lastError
	}
	return time.Time{}, ""
}

// ForgetShipping drops the counters and the status of a writer that was removed.
func ForgetShipping(writer string) {
	shippingMu.Lock()
	defer shippingMu.Unlock()
	delete(shippingStatuses, writer)
	for k := range shippingStats {
		if k[0] == writer {
			delete(shippingStats, k)
		}
	}
}
