// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	vulnerability_service "forgejo.org/services/vulnerability"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyGraphSettingsAdmin(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		enableDependencyGraph(t)
		const token = "settings-token-0123456789"
		page := "/admin/config/dependency-graph"
		admin := loginUser(t, "user1")
		var hits, authorized atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			authorized.Add(1)
			http.NotFound(w, r)
		}))
		defer srv.Close()
		// a loopback mirror can only come from app.ini (the page refuses it), with app.ini's host list and token; the
		// webhook list stays at its default (external)
		t.Cleanup(test.MockVariableValue(&setting.Webhook.AllowedHostList, ""))
		t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.OSVMirrorURL, srv.URL))
		t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.OSVMirrorHosts, "loopback"))
		t.Cleanup(test.MockVariableValue(&setting.DependencyGraph.OSVMirrorToken, token))
		t.Cleanup(test.MockVariableValue(&setting.AppDataPath, t.TempDir()))
		t.Cleanup(test.MockVariableValue(&vulnerability_service.TestConnectionInterval, 0))
		t.Cleanup(func() {
			require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraphConfig.DynKey(): ""}))
			bumpSettingsRevision(t)
		})
		key := setting.Config().DependencyGraphConfig.DynKey()
		stored := func() string {
			v, _, err := system_model.GetSettingForUpdate(db.DefaultContext, key)
			require.NoError(t, err)
			return v
		}
		post := func(s *TestSession, path string, values map[string]string, status int) *httptest.ResponseRecorder {
			t.Helper()
			resp := s.MakeRequest(t, NewRequestWithValues(t, "POST", path, values), status)
			bumpSettingsRevision(t)
			return resp
		}
		// a mirror the tests never contact: a token is entered on the page only over https
		form := map[string]string{
			"source": "mirror", "mirror_url": "https://art.example/osv", "sign_in": "token", "token": token, "allowed_hosts": "art.example",
			"update_interval": "12", "max_concurrent_scans": "2",
		}
		// the app.ini mirror, as the page shows it
		appForm := map[string]string{"source": "mirror", "mirror_url": srv.URL, "sign_in": "token"}

		t.Run("save", func(t *testing.T) {
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.Contains(t, doc.Find("#advisory-mirror-table").Text(), "Not updated yet", "nothing downloaded yet")
			assert.NotContains(t, doc.Find("#advisory-mirror-table").Text(), "Up to date")

			since := auditMaxID(t)
			post(admin, page+"/settings", form, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "The dependency graph settings were saved.")
			assert.NotContains(t, stored(), token, "stored encrypted")
			assert.Contains(t, stored(), "token_enc")
			e := auditOne(t, since, "admin.dependency_graph.settings_changed")
			assert.Equal(t, "admin", e.Category)
			assert.NotContains(t, e.Data, token)
			data := auditData(t, e)
			assert.Equal(t, true, data["token_changed"])
			assert.EqualValues(t, 12*3600, data["after"].(map[string]any)["update_interval"])
			assert.Equal(t, "art.example", data["after"].(map[string]any)["allowed_hosts"])

			cfg := setting.DependencyGraphSettings(t.Context())
			assert.Equal(t, 12*time.Hour, cfg.UpdateInterval)
			assert.Equal(t, 2, cfg.MaxConcurrentScans)
			assert.Equal(t, token, cfg.OSVMirrorToken)
			body := admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String()
			assert.NotContains(t, body, token, "the page never holds the token")
		})

		t.Run("an unchanged save writes nothing", func(t *testing.T) {
			since, before := auditMaxID(t), stored()
			unchanged := maps.Clone(form)
			unchanged["token"] = ""
			post(admin, page+"/settings", unchanged, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "Nothing changed.")
			assert.Equal(t, before, stored())
			var n int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Where("id > ? AND action = ?", since, "admin.dependency_graph.settings_changed").Select("COUNT(*)").Get(&n)
			require.NoError(t, err)
			assert.Zero(t, n)
		})

		t.Run("refusals", func(t *testing.T) {
			before := stored()
			for name, c := range map[string]struct {
				change  map[string]string
				field   string // the id of the refused input
				message string
			}{
				"host change without a token": {map[string]string{"mirror_url": "https://other.example/osv", "token": ""}, "dg-token", "scheme, host or port changed"},
				"own host":                    {map[string]string{"mirror_url": setting.AppURL + "osv"}, "dg-mirror_url", "points to this instance"},
				"loopback":                    {map[string]string{"mirror_url": "https://127.0.0.1:8443/osv"}, "dg-mirror_url", "points to this instance or to localhost"},
				"token over http":             {map[string]string{"mirror_url": "http://art.example/osv"}, "dg-mirror_url", "sent only over https"},
				"out of range":                {map[string]string{"update_interval": "721"}, "dg-update_interval", "Update every must be 1 to 720 hours."},
				"scans at once":               {map[string]string{"max_concurrent_scans": "17"}, "dg-max_concurrent_scans", "Scans at once must be 1 to 16"},
				"largest lock file":           {map[string]string{"max_manifest_size": "100.5"}, "dg-max_manifest_size", "Largest lock file must be more than 0 and at most 100 MiB."},
				"a count with decimals":       {map[string]string{"max_manifests": "1.5"}, "dg-max_manifests", "Lock files per repository: the value can"},
				"page host list too wide":     {map[string]string{"allowed_hosts": "*"}, "dg-allowed_hosts", "Hosts the mirror may be on: only exact host names"},
				"cloud metadata host":         {map[string]string{"allowed_hosts": "fd00:ec2::254"}, "dg-allowed_hosts", "never internal or cloud metadata addresses"},
				"IPv4-mapped network":         {map[string]string{"allowed_hosts": "::ffff:0:0/96"}, "dg-allowed_hosts", "Hosts the mirror may be on: only exact host names"},
				"numeric loopback":            {map[string]string{"mirror_url": "https://127.1:8443/osv"}, "dg-mirror_url", "points to this instance or to localhost"},
				"basic without a user":        {map[string]string{"sign_in": "basic"}, "dg-user", "Basic sign-in needs a username"},
			} {
				t.Run(name, func(t *testing.T) {
					values := maps.Clone(form)
					maps.Copy(values, c.change)
					resp := post(admin, page+"/settings", values, http.StatusUnprocessableEntity)
					assert.Equal(t, before, stored())
					body := resp.Body.String()
					assert.NotContains(t, body, token, "the token is never sent back")
					doc := NewHTMLParser(t, bytes.NewBufferString(body))
					assert.Contains(t, doc.Find("#dg-form-error[role=alert][tabindex='-1']").Text(), c.message, "at the top of the form")
					doc.AssertElement(t, "#dg-form-error[autofocus]", false) // the field gets the focus
					assert.Contains(t, doc.Find("#dg-save-error").Text(), c.message, "and next to Save")
					input := doc.Find("#" + c.field)
					assert.Equal(t, "true", input.AttrOr("aria-invalid", ""))
					assert.Contains(t, input.AttrOr("aria-describedby", ""), c.field+"-error")
					assert.Contains(t, doc.Find("#"+c.field+"-error").Text(), c.message)
					_, autofocus := input.Attr("autofocus")
					assert.True(t, autofocus)
					for k, v := range c.change {
						if k != "token" && k != "sign_in" {
							assert.Equal(t, v, doc.Find("#dg-"+k).AttrOr("value", ""), "the posted value is shown again")
						}
					}
					if values["token"] != "" {
						assert.Equal(t, "Enter the token again (it was not saved).", strings.TrimSpace(doc.Find("#dg-token-again").Text()))
						assert.Equal(t, "Leave empty to keep the saved token", doc.Find("#dg-token").AttrOr("placeholder", ""))
					}
				})
			}

			t.Run("the posted switch, remove token and hidden fields", func(t *testing.T) {
				require.NotEmpty(t, setting.DependencyGraphSettings(t.Context()).OSVMirrorToken)
				values := maps.Clone(form)
				values["token"], values["remove_token"], values["enabled_shown"], values["max_concurrent_scans"] = "", "on", "1", "17"
				delete(values, "enabled")
				doc := NewHTMLParser(t, post(admin, page+"/settings", values, http.StatusUnprocessableEntity).Body)
				doc.AssertElement(t, "#dependency-graph-enabled[checked]", false) // the switch as posted
				doc.AssertElement(t, "#dg-remove-token[checked]", true)           // the tick as posted
				doc.AssertElement(t, "#dg-remove-token[disabled]", false)
				doc.AssertElement(t, "#dg-remove-token-field.tw-hidden", false)

				// a refused host list under None: the download fields are never hidden by the server
				values = map[string]string{"source": "none", "allowed_hosts": "private"}
				doc = NewHTMLParser(t, post(admin, page+"/settings", values, http.StatusUnprocessableEntity).Body)
				doc.AssertElement(t, "#dg-download-fields.tw-hidden", false)
				doc.AssertElement(t, "#dg-download-fields #dg-allowed_hosts[aria-invalid=true][autofocus]", true)
			})

			t.Run("a refused field in a fold opens it", func(t *testing.T) {
				values := maps.Clone(form)
				values["osv_max_entry_size"] = "2000"
				doc := NewHTMLParser(t, post(admin, page+"/settings", values, http.StatusUnprocessableEntity).Body)
				doc.AssertElement(t, "details#dg-download-limits[open]", true)
				doc.AssertElement(t, "details#dg-repository-limits[open]", false)
			})

			t.Run("someone else saved meanwhile", func(t *testing.T) {
				doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
				shown := doc.Find(`input[name="revision"]`).AttrOr("value", "")
				require.NotEmpty(t, shown)
				// another admin saves after the page was shown
				other := maps.Clone(form)
				other["token"], other["max_concurrent_scans"], other["revision"] = "", "5", shown
				post(admin, page+"/settings", other, http.StatusSeeOther)
				changed := stored()
				values := maps.Clone(form)
				values["token"], values["revision"] = "", shown
				doc = NewHTMLParser(t, post(admin, page+"/settings", values, http.StatusUnprocessableEntity).Body)
				assert.Contains(t, doc.Find("#dg-save-error").Text(), "Someone else changed these settings; review and save again")
				msg := doc.Find("#dg-form-error[role=alert][tabindex='-1'][autofocus]")
				assert.Contains(t, msg.Text(), "Someone else changed these settings", "no field: the message at the top takes the focus")
				assert.Equal(t, changed, stored())
				assert.Equal(t, "2", doc.Find("#dg-max_concurrent_scans").AttrOr("value", ""), "the posted values")
				// saved again from the new form, on purpose
				values["revision"] = doc.Find(`input[name="revision"]`).AttrOr("value", "")
				assert.NotEqual(t, shown, values["revision"])
				post(admin, page+"/settings", values, http.StatusSeeOther)
				assert.Equal(t, 2, setting.DependencyGraphSettings(t.Context()).MaxConcurrentScans)
			})
		})

		t.Run("decimals", func(t *testing.T) {
			values := maps.Clone(form)
			values["token"], values["max_manifest_size"], values["osv_ecosystem_timeout"] = "", "0.5", "0.5"
			post(admin, page+"/settings", values, http.StatusSeeOther)
			cfg := setting.DependencyGraphSettings(t.Context())
			assert.EqualValues(t, 512<<10, cfg.MaxManifestSize, "rounded to the byte")
			assert.Equal(t, 30*time.Second, cfg.OSVEcosystemTimeout, "rounded to the second")
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.Equal(t, "0.5", doc.Find("#dg-max_manifest_size").AttrOr("value", ""))
			assert.Equal(t, "any", doc.Find("#dg-max_manifest_size").AttrOr("step", ""))
			doc.AssertElement(t, "form.dependency-graph-settings[novalidate]", true)
		})

		t.Run("test connection", func(t *testing.T) {
			// back to the app.ini mirror and its token: nothing of the mirror is stored
			post(admin, page+"/settings", appForm, http.StatusSeeOther)
			var c struct {
				MirrorURL string  `json:"mirror_url"`
				TokenEnc  *string `json:"token_enc"`
			}
			require.NoError(t, json.Unmarshal([]byte(stored()), &c))
			assert.Empty(t, c.MirrorURL)
			assert.Nil(t, c.TokenEnc)

			hits.Store(0)
			since := auditMaxID(t)
			post(admin, page+"/test-connection", nil, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "The mirror refused the request.", "the token is sent: the mirror answers 404")
			assert.EqualValues(t, 1, authorized.Load())
			var tested []*audit_model.Entry
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", since, "activity.dependency_graph.connection_tested").Find(&tested))
			require.Len(t, tested, 1)
			e := tested[0]
			assert.Equal(t, audit_model.CategoryActivity, e.Category)
			data := auditData(t, e)
			assert.Equal(t, "status 4xx", data["class"])
			assert.Equal(t, strings.ToLower(srv.URL), data["host"])
			assert.NotContains(t, e.Data, "npm")

			// the page's script asks for the answer inline
			resp := post(admin, page+"/test-connection", map[string]string{"inline": "1"}, http.StatusOK)
			var answer struct {
				OK      bool   `json:"ok"`
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &answer))
			assert.False(t, answer.OK)
			assert.Equal(t, "The mirror refused the request.", answer.Message)

			// a wrong token: 401
			setting.DependencyGraph.OSVMirrorToken = "wrong-token-0123456789"
			post(admin, page+"/test-connection", nil, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "The mirror refused the credentials.")
			setting.DependencyGraph.OSVMirrorToken = token

			// a page host list: never loopback, even through a network that holds it
			for _, hosts := range []string{"art.example", "127.0.0.0/16"} {
				values := maps.Clone(appForm)
				values["allowed_hosts"] = hosts
				post(admin, page+"/settings", values, http.StatusSeeOther)
				before := hits.Load()
				post(admin, page+"/test-connection", nil, http.StatusSeeOther)
				assert.Contains(t, bwFlash(admin), "The mirror's host is not allowed.", hosts)
				assert.Equal(t, before, hits.Load(), hosts)
			}
			post(admin, page+"/settings", appForm, http.StatusSeeOther)

			// read-only maintenance: the test still runs (it changes nothing)
			t.Run("maintenance", func(t *testing.T) {
				defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
				bumpSettingsRevision(t)
				hits.Store(0)
				admin.MakeRequest(t, NewRequestWithValues(t, "POST", page+"/test-connection", nil), http.StatusSeeOther)
				assert.Contains(t, bwFlash(admin), "The mirror refused the request.")
				assert.EqualValues(t, 1, hits.Load())
			})
			bumpSettingsRevision(t)

			// one test per interval
			defer test.MockVariableValue(&vulnerability_service.TestConnectionInterval, time.Hour)()
			post(admin, page+"/test-connection", nil, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "tested a moment ago")
			vulnerability_service.TestConnectionInterval = 0

			// offline: nothing to test
			post(admin, page+"/settings", map[string]string{"source": "none"}, http.StatusSeeOther)
			post(admin, page+"/test-connection", nil, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "the advisory source is None")
		})

		t.Run("the None source", func(t *testing.T) {
			post(admin, page+"/settings", map[string]string{"source": "none"}, http.StatusSeeOther)
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			doc.AssertElement(t, "#advisory-mirror-table", true)
			doc.AssertElement(t, "#advisory-update-now", false)
			assert.Contains(t, doc.Find("#advisory-no-mirror").Text(), "already downloaded are kept")
			assert.Contains(t, doc.Find(`label[for="dg-source-none"]`).Text(), "None: don't download")
		})

		t.Run("remove the token", func(t *testing.T) {
			values := maps.Clone(form)
			post(admin, page+"/settings", values, http.StatusSeeOther)
			require.Equal(t, token, setting.DependencyGraphSettings(t.Context()).OSVMirrorToken)
			since := auditMaxID(t)
			values["token"], values["remove_token"] = "", "on"
			post(admin, page+"/settings", values, http.StatusSeeOther)
			assert.Empty(t, setting.DependencyGraphSettings(t.Context()).OSVMirrorToken)
			e := auditOne(t, since, "admin.dependency_graph.settings_changed")
			assert.Equal(t, true, auditData(t, e)["token_changed"])

			// a token saved for the mirror stays unused under another source, and can be removed there
			post(admin, page+"/settings", form, http.StatusSeeOther)
			post(admin, page+"/settings", map[string]string{"source": "public"}, http.StatusSeeOther)
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.Contains(t, doc.Find("#dg-token-unused").Text(), "will be used again if you switch back")
			doc.AssertElement(t, "#dg-remove-token-unused", true)
			post(admin, page+"/settings", map[string]string{"source": "public", "remove_token": "on"}, http.StatusSeeOther)
			assert.Contains(t, stored(), `"token_enc":""`, "removed: not even app.ini's token is used for the mirror")
		})

		t.Run("live effect", func(t *testing.T) {
			var zipHits atomic.Int32
			zipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				zipHits.Add(1)
				http.NotFound(w, r)
			}))
			defer zipSrv.Close()
			defer test.MockVariableValue(&vulnerability_service.ManualUpdateInterval, time.Duration(0))()
			// no restart: the next "Update now" reads the saved settings, and app.ini for what isn't saved
			defer test.MockVariableValue(&setting.DependencyGraph.OSVMirrorURL, zipSrv.URL+"/osv")()
			post(admin, page+"/settings", map[string]string{"source": "mirror", "mirror_url": zipSrv.URL + "/osv", "sign_in": "none", "update_interval": "12"}, http.StatusSeeOther)
			post(admin, page+"/update-advisories", nil, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "The advisory update was started.")
			require.Eventually(t, func() bool { return !vulnerability_service.Running() }, 30*time.Second, 50*time.Millisecond)
			assert.EqualValues(t, len(dependency.Ecosystems), zipHits.Load())
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.Contains(t, doc.Find("#advisory-mirror").Text(), zipSrv.URL+"/osv")
			assert.Contains(t, doc.Find("#advisory-mirror").Text(), "12h", "the saved interval")
		})

		t.Run("config_invalid is cleared by a save", func(t *testing.T) {
			require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{key: `{"allowed_hosts":"bad host"}`}))
			bumpSettingsRevision(t)
			defer test.MockVariableValue(&vulnerability_service.ManualUpdateInterval, time.Duration(0))()
			post(admin, page+"/update-advisories", nil, http.StatusSeeOther)
			require.Eventually(t, func() bool { return !vulnerability_service.Running() }, 30*time.Second, 50*time.Millisecond)
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.Contains(t, doc.Find("#advisory-mirror-table").Text(), "can't be used")
			post(admin, page+"/settings", map[string]string{"source": "mirror", "mirror_url": srv.URL, "sign_in": "none", "update_interval": "12"}, http.StatusSeeOther)
			doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			assert.NotContains(t, doc.Find("#advisory-mirror-table").Text(), "can't be used")
		})

		t.Run("page", func(t *testing.T) {
			// the form as the page shows it: posted back unchanged, it changes nothing
			formValues := func(doc *HTMLDoc) map[string]string {
				values := map[string]string{}
				doc.Find("form.dependency-graph-settings input[name]").Each(func(_ int, sel *goquery.Selection) {
					name, _ := sel.Attr("name")
					typ, _ := sel.Attr("type")
					if (typ == "radio" || typ == "checkbox") && sel.AttrOr("checked", "-") == "-" {
						return
					}
					values[name] = sel.AttrOr("value", "on")
				})
				return values
			}
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			values := formValues(doc)
			assert.Equal(t, "12", values["update_interval"])
			assert.Equal(t, "mirror", values["source"])
			assert.Equal(t, "none", values["sign_in"])
			assert.Empty(t, values["token"])
			assert.Empty(t, values["allowed_hosts"], "nothing saved: app.ini's list")
			assert.Contains(t, doc.Find("#dg-allowed_hosts-help").Text(), "Empty: the list in app.ini")
			assert.Equal(t, "60", values["scan_timeout"], "the app.ini value")
			assert.Contains(t, doc.Find("#dg-update_interval").Parent().Parent().Find(".dg-app-default").Text(), "app.ini: 24.")
			assert.Empty(t, doc.Find("#dg-scan_timeout").Parent().Parent().Find(".dg-app-default").Text(), "the same as app.ini: no hint")
			assert.Equal(t, "dg-update_interval-unit dg-update_interval-help", strings.TrimSpace(doc.Find("#dg-update_interval").AttrOr("aria-describedby", "")), "the unit and help are announced")
			assert.Contains(t, doc.Find("#dg-user-help").Text(), "Only for Basic sign-in")
			assert.Equal(t, "Test saved settings", strings.TrimSpace(doc.Find("#dependency-graph-test").Text()))
			since, before := auditMaxID(t), stored()
			post(admin, page+"/settings", values, http.StatusSeeOther)
			assert.Contains(t, bwFlash(admin), "Nothing changed.")
			assert.Equal(t, before, stored())
			assert.Equal(t, since, auditMaxID(t))

			// one form: the switch is saved with the settings
			t.Cleanup(func() {
				require.NoError(t, system_model.SetSettings(db.DefaultContext, map[string]string{setting.Config().DependencyGraph.DynKey(): ""}))
				bumpSettingsRevision(t)
			})
			delete(values, "enabled")
			delete(values, "revision")
			values["max_concurrent_scans"] = "3"
			post(admin, page+"/settings", values, http.StatusSeeOther)
			doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			doc.AssertElement(t, "#dependency-graph-enabled[checked]", false)
			assert.Equal(t, 3, setting.DependencyGraphSettings(t.Context()).MaxConcurrentScans)
			values["enabled"] = "on"
			post(admin, page+"/settings", values, http.StatusSeeOther)
			doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			doc.AssertElement(t, "#dependency-graph-enabled[checked]", true)

			// a token in force shows only as "saved"
			values["sign_in"] = "token"
			post(admin, page+"/settings", values, http.StatusSeeOther)
			body := admin.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body.String()
			assert.NotContains(t, body, token)
			doc = NewHTMLParser(t, bytes.NewBufferString(body))
			assert.Contains(t, doc.Find("#dg-token").AttrOr("placeholder", ""), "saved, leave empty to keep it")
			doc.AssertElement(t, "#dg-remove-token", true)
		})

		t.Run("auditor reads", func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", false)
				require.NoError(t, err)
			}()
			doc := NewHTMLParser(t, loginUser(t, "user8").MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK).Body)
			doc.AssertElement(t, "fieldset[disabled] #dg-update_interval", true)
			doc.AssertElement(t, "#dg-source-mirror", false) // the source as text, not as faded radios
			doc.AssertElement(t, `input[name="sign_in"]`, false)
			assert.Contains(t, doc.Find("#dg-source-summary").Text(), "A mirror or proxy")
			assert.Equal(t, "mirror", doc.Find("#dg-source-summary").AttrOr("data-source", ""))
			assert.Contains(t, doc.Find("#dg-sign-in-summary").Text(), "Access token (Bearer)")
			assert.Contains(t, doc.Find("#dg-read-only").Text(), "Read-only: only site administrators can change these settings")
			assert.Equal(t, "A token is saved.", doc.Find("#dg-token").AttrOr("placeholder", ""))
			doc.AssertElement(t, "#dependency-graph-save", false)
			doc.AssertElement(t, "#dependency-graph-test", false)
			doc.AssertElement(t, "#dg-remove-token", false)
			assert.NotContains(t, doc.Find(".dependency-graph-settings").Text(), "Saving is recorded in the audit log")
		})

		t.Run("access", func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", true)
			require.NoError(t, err)
			defer func() {
				_, err := db.GetEngine(t.Context()).Exec("UPDATE `user` SET is_auditor = ? WHERE id = 8", false)
				require.NoError(t, err)
			}()
			auditor := loginUser(t, "user8")
			auditor.MakeRequest(t, NewRequest(t, "GET", page), http.StatusOK)
			user := loginUser(t, "user2")
			before, since := stored(), auditMaxID(t)
			for _, path := range []string{page + "/settings", page + "/test-connection"} {
				auditor.MakeRequest(t, NewRequestWithValues(t, "POST", path, form), http.StatusForbidden)
				user.MakeRequest(t, NewRequestWithValues(t, "POST", path, form), http.StatusForbidden)
				resp := MakeRequest(t, NewRequestWithValues(t, "POST", path, form), http.StatusSeeOther)
				assert.Contains(t, resp.Header().Get("Location"), "/user/login")
			}
			assert.Equal(t, before, stored())
			assert.Equal(t, since, auditMaxID(t))
		})
	})
}
