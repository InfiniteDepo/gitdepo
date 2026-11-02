// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"context"
	"errors"
	"sync"

	"forgejo.org/modules/setting"

	"golang.org/x/sync/semaphore"
)

// ErrServerBusy is returned by AcquireOperation when no slot became free within setting.Git.OperationQueueTimeout.
var ErrServerBusy = errors.New("too many git operations are running")

// OperationRetryAfter is the Retry-After value, in seconds, sent with a refusal because of ErrServerBusy.
const OperationRetryAfter = 10

var (
	operationMu   sync.Mutex
	operationSem  *semaphore.Weighted
	operationSize int
)

func operationSemaphore(n int) *semaphore.Weighted {
	operationMu.Lock()
	defer operationMu.Unlock()
	if operationSem == nil || operationSize != n {
		operationSem, operationSize = semaphore.NewWeighted(int64(n)), n
	}
	return operationSem
}

// AcquireOperation takes one of the setting.Git.MaxConcurrentOperations slots for a clone, fetch or push,
// waiting at most setting.Git.OperationQueueTimeout. The caller must call release when the operation ends.
// It returns ErrServerBusy when no slot became free in time, and the context's error when ctx ended first.
func AcquireOperation(ctx context.Context) (release func(), err error) {
	n := setting.Git.MaxConcurrentOperations
	if n <= 0 {
		return func() {}, nil
	}
	sem := operationSemaphore(n)
	waitCtx, cancel := context.WithTimeout(ctx, setting.Git.OperationQueueTimeout)
	defer cancel()
	if err := sem.Acquire(waitCtx, 1); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrServerBusy
	}
	return func() { sem.Release(1) }, nil
}
