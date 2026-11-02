// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"context"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hostileSize = 20 << 20 // the default MAX_MANIFEST_SIZE

// allocated returns the bytes allocated while f ran.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A hostile lockfile must not cost much more memory than its size: only the keys we read are kept.
func TestHostileLockfilesBoundMemory(t *testing.T) {
	const limit = 6 * hostileSize
	cases := map[string]string{
		// the values under the dependency maps are never used
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"x":[` + strings.Repeat("0,", hostileSize/2) + `0]}}}}`,
		// many lines just below the line limit, each a flow sequence a YAML library would build nodes for
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n" + strings.Repeat("other: ["+strings.Repeat("0,", 30000)+"0]\n", hostileSize/60000),
		"yarn.lock":      "x@^1:\n  version \"1.0.0\"\n" + strings.Repeat("#"+strings.Repeat("a", 60)+"\n", hostileSize/62),
		"composer.lock":  `{"packages":[{"name":"a/b","version":"1","extra":[` + strings.Repeat("0,", hostileSize/2) + `0]}]}`,
		"packages.lock.json": `{"version":1,"dependencies":{"net8.0":{"A":{"type":"Direct","resolved":"1.0.0","extra":[` +
			strings.Repeat("0,", hostileSize/2) + `0]}}}}`,
		"poetry.lock": "[[package]]\nname = \"a\"\nversion = \"1\"\n" + strings.Repeat("# "+strings.Repeat("a", 60)+"\n", hostileSize/62),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			require.GreaterOrEqual(t, len(content), hostileSize-(256<<10))
			data := []byte(content)
			content = ""
			var err error
			n := allocated(func() { _, err = FormatFor(name).Parse(t.Context(), data, nil) })
			t.Logf("%s: %d MiB allocated for %d MiB", name, n>>20, len(data)>>20)
			assert.LessOrEqual(t, n, uint64(limit), "allocations of a %d MiB file", len(data)>>20)
			_ = err // a file that isn't valid may be refused; the cost is what is measured
		})
	}
}

// A lockfile of a real size still gives all its packages.
func TestLargeLockfilesStillParse(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      pkg0:\n        specifier: ^1.0.0\n        version: 1.0.0\n\npackages:\n\n")
	for i := range 20000 {
		b.WriteString("  'pkg" + itoa(i) + "@1.0.0':\n    resolution: {integrity: sha512-abc}\n    engines: {node: '>=12'}\n\n")
	}
	deps, err := FormatFor("pnpm-lock.yaml").Parse(t.Context(), []byte(b.String()), nil)
	require.NoError(t, err)
	assert.Len(t, deps, 20000)
	assert.True(t, deps[0].Direct || deps[len(deps)-1].Direct)
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var s []byte
	for ; i > 0; i /= 10 {
		s = append([]byte{digits[i%10]}, s...)
	}
	return string(s)
}

// fill repeats gen(i) until the result is at least size bytes.
func fill(prefix, suffix string, size int, gen func(b []byte, i int) []byte) []byte {
	b := make([]byte, 0, size+1024)
	b = append(b, prefix...)
	for i := 0; len(b) < size; i++ {
		b = gen(b, i)
	}
	return append(b, suffix...)
}

func hexID(b []byte, i int) []byte {
	b = append(b, "p"...)
	return strconv.AppendInt(b, int64(i), 16)
}

// peakHeap runs f and returns the highest HeapInuse seen above the heap before it, sampled every 2 ms.
func peakHeap(f func()) (peak uint64, elapsed time.Duration) {
	old := debug.SetGCPercent(20)
	defer debug.SetGCPercent(old)
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	base := m.HeapInuse
	var top atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var s runtime.MemStats
		for {
			runtime.ReadMemStats(&s)
			if s.HeapInuse > top.Load() {
				top.Store(s.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	start := time.Now()
	f()
	elapsed = time.Since(start)
	close(stop)
	<-done
	if top.Load() < base {
		return 0, elapsed
	}
	return top.Load() - base, elapsed
}

// For every parser, a file of the maximum size made of tiny entries must stop at the cap with a bounded heap and in
// a few seconds: the work of a parse is O(the limits), not O(the shape of the input).
func TestHostileTinyEntriesPeakHeap(t *testing.T) {
	const big, small = 20 << 20, 1 << 20
	const yarnV1Head = "# yarn lockfile v1\n\n"
	// the work is linear in the file (the frameworks case is ~6M JSON tokens, ~0.3 s), so the bound only catches a
	// superlinear parse; the race detector makes the same work 10-20 times slower
	timeBound := 5 * time.Second
	if raceEnabled {
		timeBound = 60 * time.Second
	}
	line := func(format string) func([]byte, int) []byte {
		return func(b []byte, i int) []byte {
			before, after, _ := strings.Cut(format, "%")
			b = append(b, before...)
			b = hexID(b, i)
			return append(b, after...)
		}
	}
	cases := []struct {
		name, file string
		data       func() []byte
	}{
		{"npm v3 packages", "package-lock.json", func() []byte {
			return fill(`{"packages":{`, `"z":{}}}`, big, line(`"node_modules/%":{"version":"1"},`))
		}},
		{"npm v3 root dependency names", "package-lock.json", func() []byte { return fill(`{"packages":{"":{"dependencies":{`, `"z":"1"}}}}`, big, line(`"%":"1",`)) }},
		{"npm v1 tree", "package-lock.json", func() []byte { return fill(`{"dependencies":{`, `"z":{}}}`, big, line(`"%":{"version":"1"},`)) }},
		{"npm v1 nested", "package-lock.json", func() []byte {
			return fill(`{"dependencies":{"a":{"dependencies":{`, `"z":{}}}}}`, big, line(`"%":{"version":"1"},`))
		}},
		{"composer packages", "composer.lock", func() []byte { return fill(`{"packages":[`, `{}]}`, big, line(`{"name":"%"},`)) }},
		{"composer license list", "composer.lock", func() []byte { return fill(`{"packages":[{"name":"a","license":[`, `"x"]}]}`, big, line(`"%",`)) }},
		{"nuget lock", "packages.lock.json", func() []byte { return fill(`{"dependencies":{"f":{`, `"z":{}}}}`, big, line(`"%":{},`)) }},
		{"nuget lock frameworks", "packages.lock.json", func() []byte { return fill(`{"dependencies":{`, `"z":{}}}`, big, line(`"%":{"a":{}},`)) }},
		// the shapes are ones the readers accept (yamlgrammar.go), so the parse runs to the cap, not to a refusal
		{"yarn", "yarn.lock", func() []byte { return fill(yarnV1Head, "", big, line("%@1:\n  version \"1\"\n")) }},
		{"yarn descriptors", "yarn.lock", func() []byte {
			return fill(yarnV1Head, "", big, func(b []byte, i int) []byte {
				for j := range 50 {
					if j > 0 {
						b = append(b, ", "...)
					}
					b = hexID(append(b, "a@"...), i*50+j)
				}
				return append(b, ":\n  version \"1\"\n"...)
			})
		}},
		{"yarn berry", "yarn.lock", func() []byte {
			return fill("__metadata:\n  version: 8\n\n", "", big, line("\"%@npm:1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n"))
		}},
		{"pnpm packages", "pnpm-lock.yaml", func() []byte {
			return fill("lockfileVersion: '9.0'\npackages:\n", "", big, line("  %@1.0.0:\n    resolution: {integrity: x}\n"))
		}},
		{"pnpm v5 dependencies", "pnpm-lock.yaml", func() []byte { return fill("lockfileVersion: 5.4\ndependencies:\n", "", big, line("  %: 1.0.0\n")) }},
		{"pnpm importer dependencies", "pnpm-lock.yaml", func() []byte {
			return fill("lockfileVersion: 5.4\nimporters:\n  .:\n    dependencies:\n", "", big, line("      %: 1.0.0\n"))
		}},
		{"poetry", "poetry.lock", func() []byte { return fill("", "", big, line("[[package]]\nname = \"%\"\n")) }},
		{"cargo", "Cargo.lock", func() []byte { return fill("", "", big, line("[[package]]\nname = \"%\"\nsource = \"s\"\n")) }},
		{"cargo dependency lines", "Cargo.lock", func() []byte {
			return fill("[[package]]\nname = \"a\"\ndependencies = [\n", "]\n", big, line(" \"% 1\",\n"))
		}},
		{"requirements", "requirements.txt", func() []byte { return fill("", "", small, line("%\n")) }},
		{"gemfile", "Gemfile.lock", func() []byte { return fill("GEM\n  specs:\n", "", small, line("    % (1)\n")) }},
		{"go.mod", "go.mod", func() []byte { return fill("module m\n", "", small, line("require example.com/% v1.0.0\n")) }},
		// the manifests read without a lock file are small formats too
		{"package.json", "package.json", func() []byte { return fill(`{"dependencies":{`, `"z":"1"}}`, small, line(`"%":"^1",`)) }},
		{"composer.json", "composer.json", func() []byte { return fill(`{"require":{`, `"a/z":"1"}}`, small, line(`"a/%":"^1",`)) }},
		{"Cargo.toml", "Cargo.toml", func() []byte { return fill("[dependencies]\n", "", small, line("% = { version = \"1\" }\n")) }},
		{"Cargo.toml fields", "Cargo.toml", func() []byte { return fill("[dependencies.a]\n", "", small, line("% = 1\n")) }},
		{"pyproject.toml", "pyproject.toml", func() []byte { return fill("[project]\ndependencies = [\n", "]\n", small, line("\"%>=1\",\n")) }},
		{"pyproject.toml nested", "pyproject.toml", func() []byte { return fill("[tool.x]\nk = [", "0]\n", small, line("[[[%]]],")) }},
		{"Gemfile", "Gemfile", func() []byte { return fill("", "", small, line("gem \"%\", \"~> 1\", \">= 1.0\"\n")) }},
		{"pom", "pom.xml", func() []byte {
			return fill("<project><dependencies>", "</dependencies></project>", small, line("<dependency><groupId>g</groupId><artifactId>%</artifactId></dependency>"))
		}},
		{"csproj", "a.csproj", func() []byte {
			return fill("<Project><ItemGroup>", "</ItemGroup></Project>", small, line(`<PackageReference Include="%" Version="1"/>`))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			var rows int
			data := c.data()
			peak, elapsed := peakHeap(func() {
				var deps []Dependency
				deps, err = FormatFor(c.file).ParseLimited(t.Context(), data, nil, 50000)
				rows = len(deps)
			})
			t.Logf("%s: %d MiB file, peak %d MiB, %v, %d rows, %v", c.name, len(data)>>20, peak>>20, elapsed.Round(time.Millisecond), rows, err)
			assert.Less(t, peak, uint64(64<<20), "peak heap above the baseline")
			assert.Less(t, elapsed, timeBound)
			// a file this size is refused at the cap, or (a shape that keeps few rows) read in full
			if err != nil {
				assert.True(t, isLimit(err), "%v", err)
			}
		})
	}
}

// The limit applies to the rows of the whole scan: the parser is told how many are left.
func TestParseLimited(t *testing.T) {
	f := FormatFor("go.mod")
	data := []byte("module m\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\texample.com/c v1.0.0\n)\n")
	_, err := f.ParseLimited(t.Context(), data, nil, 2)
	require.ErrorIs(t, err, ErrTooManyDependencies)
	deps, err := f.ParseLimited(t.Context(), data, nil, 3)
	require.NoError(t, err)
	assert.Len(t, deps, 3)
	// a package listed twice is one row
	deps, err = FormatFor("packages.lock.json").ParseLimited(t.Context(), []byte(`{"dependencies":{"net6":{"A":{"type":"Direct","resolved":"1"}},"net8":{"A":{"type":"Transitive","resolved":"1"}}}}`), nil, 1)
	require.NoError(t, err)
	assert.Len(t, deps, 1)
	assert.True(t, deps[0].Direct)
}

// A parse stops when its context ends, JSON included.
func TestParseStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, data := range map[string][]byte{
		"package-lock.json":  fill(`{"x":[`, `0]}`, 4<<20, func(b []byte, i int) []byte { return append(b, "0,"...) }),
		"composer.lock":      fill(`{"x":[`, `0]}`, 4<<20, func(b []byte, i int) []byte { return append(b, "0,"...) }),
		"packages.lock.json": fill(`{"x":[`, `0]}`, 4<<20, func(b []byte, i int) []byte { return append(b, "0,"...) }),
		"go.mod":             fill("module m\n", "", 1<<20, func(b []byte, i int) []byte { return append(b, "// x\n"...) }),
	} {
		start := time.Now()
		_, err := FormatFor(name).Parse(ctx, data, nil)
		require.ErrorIs(t, err, context.Canceled, name)
		assert.Less(t, time.Since(start), time.Second, name)
	}
}
