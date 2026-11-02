// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretScanningSettings(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, loadSecretScanningFrom(mustProvider(t, ""))) })
	require.NoError(t, loadSecretScanningFrom(mustProvider(t, "")))
	assert.False(t, SecretScanning.Enabled)
	assert.False(t, SecretScanning.GenericRules)
	assert.EqualValues(t, 1, SecretScanning.MaxConcurrentScans)
	assert.Equal(t, 5*time.Minute, SecretScanning.ScanTimeout)
	assert.EqualValues(t, 1<<20, SecretScanning.MaxBlobSize)
	assert.EqualValues(t, 2<<30, SecretScanning.MaxScanBytes)
	assert.EqualValues(t, 2_000_000, SecretScanning.MaxScanBlobs)
	assert.EqualValues(t, 10_000, SecretScanning.MaxAlertsPerRepo)
	assert.EqualValues(t, 100, SecretScanning.MaxLocationsPerAlert)

	require.NoError(t, loadSecretScanningFrom(mustProvider(t, "[secret_scanning]\nENABLED = true\nGENERIC_RULES = true\nMAX_CONCURRENT_SCANS = 99\nSCAN_TIMEOUT = 5m\nMAX_ALERTS_PER_REPO = 5\nMAX_BLOB_SIZE = 1\n")))
	assert.True(t, SecretScanning.Enabled)
	assert.True(t, SecretScanning.GenericRules)
	assert.EqualValues(t, 16, SecretScanning.MaxConcurrentScans, "lowered to the maximum")
	assert.Equal(t, 5*time.Minute, SecretScanning.ScanTimeout)
	assert.EqualValues(t, 100, SecretScanning.MaxAlertsPerRepo, "raised to the minimum")
	assert.EqualValues(t, 64<<10, SecretScanning.MaxBlobSize, "raised to the minimum")
	require.NoError(t, loadSecretScanningFrom(mustProvider(t, "[secret_scanning]\nSCAN_TIMEOUT = 2s\n")))
	assert.Equal(t, 30*time.Second, SecretScanning.ScanTimeout, "raised to the minimum")
}

func TestSecretScanningParsing(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, loadSecretScanningFrom(mustProvider(t, ""))) })
	load := func(ini string) {
		t.Helper()
		require.NoError(t, loadSecretScanningFrom(mustProvider(t, "[secret_scanning]\n"+ini)), "a bad value never stops the server")
	}
	load("SCAN_TIMEOUT = 90\n")
	assert.Equal(t, 90*time.Second, SecretScanning.ScanTimeout, "bare seconds")
	load("SCAN_TIMEOUT = 2h\n")
	assert.Equal(t, 2*time.Hour, SecretScanning.ScanTimeout, "duration")
	load("SCAN_TIMEOUT = 48h\n")
	assert.Equal(t, 24*time.Hour, SecretScanning.ScanTimeout, "clamped to the maximum")
	load("SCAN_TIMEOUT = soon\n")
	assert.Equal(t, 5*time.Minute, SecretScanning.ScanTimeout, "malformed: the default")
	load("SCAN_TIMEOUT = -5m\n")
	assert.Equal(t, 5*time.Minute, SecretScanning.ScanTimeout, "negative duration: the default")

	for _, bad := range []string{"0x10000", "1_000", "1e5", "+5000", "-5000", "5000.5", "many"} {
		load("MAX_ALERTS_PER_REPO = " + bad + "\n")
		assert.EqualValues(t, 10_000, SecretScanning.MaxAlertsPerRepo, bad)
	}
	load("MAX_ALERTS_PER_REPO = 99999999999999999999999\n")
	assert.EqualValues(t, 1_000_000, SecretScanning.MaxAlertsPerRepo, "too long for 64 bits: the maximum, not the default")
	load("SCAN_TIMEOUT = 99999999999999999999999\n")
	assert.Equal(t, 24*time.Hour, SecretScanning.ScanTimeout, "the same for seconds")
	load("ENABLED = true\nGENERIC_RULES = yes\n")
	assert.True(t, SecretScanning.Enabled)
	assert.True(t, SecretScanning.GenericRules)
	load("ENABLED = maybe\nGENERIC_RULES = 2\n")
	assert.False(t, SecretScanning.Enabled, "not a boolean: the default")
	assert.False(t, SecretScanning.GenericRules)
	load("MAX_ALERTS_PER_REPO = 7\n")
	assert.EqualValues(t, 100, SecretScanning.MaxAlertsPerRepo, "raised to the minimum")
	load("MAX_ALERTS_PER_REPO = 250\n")
	assert.EqualValues(t, 250, SecretScanning.MaxAlertsPerRepo)
	load("MAX_SCAN_BYTES = 5\nMAX_SCAN_BLOBS = 5\nMAX_LOCATIONS_PER_ALERT = 0\n")
	assert.EqualValues(t, 1<<20, SecretScanning.MaxScanBytes)
	assert.EqualValues(t, 1000, SecretScanning.MaxScanBlobs)
	assert.EqualValues(t, 1, SecretScanning.MaxLocationsPerAlert)
}

func TestSecretScanningMerge(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, loadSecretScanningFrom(mustProvider(t, ""))) })
	require.NoError(t, loadSecretScanningFrom(mustProvider(t, "")))
	generic := true
	cfg := SecretScanningConfig{GenericRules: &generic, Limits: map[string]int64{"max_alerts_per_repo": 500, "scan_timeout": 90, "max_blob_size": 0, "nope": 1}}
	o := cfg.Merge()
	assert.True(t, o.GenericRules)
	assert.EqualValues(t, 500, o.MaxAlertsPerRepo)
	assert.Equal(t, 90*time.Second, o.ScanTimeout)
	assert.EqualValues(t, 1<<20, o.MaxBlobSize, "out of bounds: the app.ini value")
	assert.Equal(t, SecretScanning.MaxScanBytes, o.MaxScanBytes)
	assert.Equal(t, SecretScanning.MaxScanBytes, SecretScanningConfig{Invalid: true}.Merge().MaxScanBytes)
}

func mustProvider(t *testing.T, ini string) ConfigProvider {
	t.Helper()
	cfg, err := NewConfigProviderFromData(ini)
	require.NoError(t, err)
	return cfg
}
