// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"maps"
	"strconv"
	"sync"
	"time"

	"forgejo.org/modules/timeutil"
)

// AggregateCap and AggregateOverflowCap bound the pending aggregates per pod. When the first is full a new key goes
// to the overflow bucket of its action and subject; when that is full too, to the one bucket of its action.
// AggregateFirstWrites bounds the first events written at once per window and pod; past it, a new key only counts
// into an overflow bucket.
var (
	AggregateCap         = 10_000
	AggregateOverflowCap = 1_000
	AggregateFirstWrites = 1_000
)

const aggregateWindow = 60 // seconds

type aggBucket struct {
	ev          Event
	actor       Actor
	overflow    bool
	start       timeutil.TimeStamp
	count       int64 // events after the first, which was written at once
	first, last timeutil.TimeStamp
}

var agg struct {
	sync.Mutex
	buckets, overflow map[string]*aggBucket
	windowStart       timeutil.TimeStamp // of the first-writes count
	firstWrites       int
}

// RecordAggregated writes the first event of (action, key) in a window of one minute at once, and counts the rest
// into one "<action>.aggregated" entry {count, first, last} written when the window ends.
func RecordAggregated(ctx context.Context, ev Event, key string) {
	now := timeutil.TimeStampNow()
	k := ev.Action + "|" + key
	agg.Lock()
	if now >= agg.windowStart+aggregateWindow {
		agg.windowStart, agg.firstWrites = now, 0
	}
	b, m, overflow := agg.buckets[k], agg.buckets, false
	if b == nil && (len(agg.buckets) >= AggregateCap || agg.firstWrites >= AggregateFirstWrites) {
		m, overflow = agg.overflow, true
		if k = ev.Action + "|subject:" + strconv.FormatInt(ev.SubjectUserID, 10); m[k] == nil && len(m) >= AggregateOverflowCap {
			k = ev.Action + "|"
		}
		b = m[k]
	}
	if b != nil {
		b.count++
		if b.first == 0 {
			b.first = now
		}
		b.last = now
		agg.Unlock()
		return
	}
	b = &aggBucket{ev: ev, overflow: overflow, start: now}
	if a := ActorFromContext(ctx); a != nil {
		b.actor = *a
		b.actor.RequestID = ""
	} else {
		b.actor = Actor{Type: ActorUnknown}
	}
	m[k] = b
	write := agg.firstWrites < AggregateFirstWrites
	if write {
		agg.firstWrites++
	} else {
		b.count, b.first, b.last = 1, now, now // only counted: too many first events in this window
	}
	agg.Unlock()
	if write {
		RecordActivity(ctx, ev)
	}
}

// FlushAggregated writes the aggregates whose window has ended, or every pending one when all is set (shutdown).
func FlushAggregated(ctx context.Context, all bool) {
	deadline := timeutil.TimeStampNow() - aggregateWindow
	var done []*aggBucket
	agg.Lock()
	for _, m := range []map[string]*aggBucket{agg.buckets, agg.overflow} {
		for k, b := range m {
			if all || b.start <= deadline {
				done = append(done, b)
				delete(m, k)
			}
		}
	}
	agg.Unlock()
	for _, b := range done {
		if b.count == 0 {
			continue
		}
		ev := b.ev
		ev.Action += ".aggregated"
		ev.Data = maps.Clone(ev.Data)
		if ev.Data == nil {
			ev.Data = map[string]any{}
		}
		ev.Data["count"], ev.Data["first"], ev.Data["last"] = b.count, int64(b.first), int64(b.last)
		if b.overflow {
			ev.Data["overflow"] = true
		}
		actor := b.actor
		RecordActivity(WithActor(ctx, &actor), ev)
	}
}

// RunAggregator flushes ended windows every 10 seconds until ctx is done, then flushes everything.
func RunAggregator(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			FlushAggregated(context.WithoutCancel(ctx), true)
			return
		case <-t.C:
			FlushAggregated(ctx, false)
		}
	}
}
