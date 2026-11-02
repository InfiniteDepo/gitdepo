// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	secretscan_service "forgejo.org/services/secretscan"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keepSecretScanningSettings clears the stored site settings of secret scanning after the test.
func keepSecretScanningSettings(t *testing.T) {
	t.Helper()
	clear := func() {
		_, err := db.GetEngine(db.DefaultContext).In("setting_key", setting.Config().SecretScanning.DynKey(), setting.Config().SecretScanningConfig.DynKey()).Delete(new(system_model.Setting))
		require.NoError(t, err)
		bumpSettingsRevision(t)
	}
	clear()
	t.Cleanup(clear)
}

// keepOrgSecretSettings removes the organization's switch and lock and the repositories' own off switches now and when
// the test ends, so that a failing subtest can't leak a state into later tests of the shard.
func keepOrgSecretSettings(t *testing.T, orgID int64) {
	t.Helper()
	clear := func() {
		_, err := db.GetEngine(db.DefaultContext).Where("user_id = ?", orgID).In("setting_key", secretscan_model.OrgKey, secretscan_model.OrgLockedKey).Delete(new(user_model.Setting))
		require.NoError(t, err)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET secret_scanning_disabled = ? WHERE owner_id = ?", false, orgID)
		require.NoError(t, err)
		bumpSettingsRevision(t)
	}
	clear()
	t.Cleanup(clear)
}

func secretRepoEnabled(t *testing.T, id int64) bool {
	t.Helper()
	return secretscan_service.Enabled(t.Context(), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id}))
}

// The organization page of secret scanning: owners (and site admins) change the switch and the lock; members,
// strangers and anonymous visitors can't. The lock overrides the repository's own switch, and the site switch the
// organization's.
func TestSecretScanningOrgSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	keepSecretScanningSettings(t)
	keepOrgSecretSettings(t, 3)
	const (
		pageURL = "/org/org3/settings/code_security"
		post    = pageURL + "/secret_scanning"
	)
	owner := loginUser(t, "user2")
	admin := loginUser(t, "user1")
	member := loginUser(t, "user4") // a team member of org3, no owner
	stranger := loginUser(t, "user5")

	t.Run("who may open and change it", func(t *testing.T) {
		since := auditMaxID(t)
		for name, s := range map[string]*TestSession{"member": member, "stranger": stranger} {
			s.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusNotFound)
			s.MakeRequest(t, NewRequest(t, "GET", pageURL+"/secret_scanning/repos"), http.StatusNotFound)
			s.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusNotFound)
			assert.True(t, secretRepoEnabled(t, 3), name)
		}
		anon := emptyTestSession(t)
		anon.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusSeeOther)
		anon.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3))
		assert.Equal(t, since, auditMaxID(t), "refused requests record nothing")

		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-enabled[checked]", true)
		doc.AssertElement(t, "#secret-scanning-locked[checked]", false)
		doc.AssertElement(t, "#secret-scanning-site-off", false)
		NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body).AssertElement(t, "#secret-scanning-enabled[checked]", true)
		// a site admin acts as an owner
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3))
		assert.EqualValues(t, 1, auditOne(t, since, "org.secret_scanning.changed").ActorID)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3))
	})

	t.Run("off, audited, and a save without a change records nothing", func(t *testing.T) {
		since := auditMaxID(t)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3))
		e := auditOne(t, since, "org.secret_scanning.changed")
		assert.Equal(t, audit_model.ActorUser, e.ActorType)
		assert.EqualValues(t, 2, e.ActorID)
		assert.Contains(t, e.Data, `"secret_scanning":false`)
		assert.NotContains(t, e.Data, "secret_scanning_locked")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusSeeOther)
		assert.Equal(t, e.ID, auditMaxID(t), "the same switch again writes no entry")
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-enabled[checked]", false)
		assert.Contains(t, doc.Find("#secret-scanning-counts").Text(), "Off for all")
		assert.Contains(t, doc.Find("#secret-scanning-org-lock-modal .content").Text(), "turns secret scanning on in all 3 repositories", "locking while off turns it on everywhere")
		off := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL+"/secret_scanning/repos"), http.StatusOK).Body)
		off.AssertElement(t, "#secret-scanning-off-org-off", true)
		assert.NotContains(t, off.Find(".org-setting-content").Text(), "Lock the setting", "the lock hint is for an organization that is on and unlocked")
		// the repository's page: decided by the organization
		repo := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/code_security"), http.StatusOK).Body)
		assert.Contains(t, repo.Find("#secret-scanning-set-by").Text(), "turns it off for all its repositories")
	})

	t.Run("a repository turns it off; the organization's lock overrides it", func(t *testing.T) {
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		require.True(t, secretRepoEnabled(t, 3))
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security/secret_scanning", map[string]string{}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3), "the repository's own off applies while the organization is unlocked")

		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		counts := doc.Find("#secret-scanning-counts").Text()
		assert.Contains(t, counts, "1 repository was turned off")
		link, ok := doc.Find("#secret-scanning-off-link").Attr("href")
		require.True(t, ok)
		list := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
		assert.Equal(t, 1, list.Find("#secret-scanning-off-list .flex-item").Length())
		assert.Contains(t, list.Find("#secret-scanning-off-list").Text(), "org3/repo3")
		assert.Contains(t, list.Find("#secret-scanning-off-list").Text(), "Turned off by user2")
		assert.Contains(t, list.Find(".org-setting-content").Text(), "Lock the setting", "on and unlocked: the hint shows")
		list.AssertElement(t, "#secret-scanning-off-locked, #secret-scanning-off-org-off", false)
		// the confirmation of the lock says how many it turns on
		assert.Contains(t, doc.Find("#secret-scanning-org-lock-modal .content").Text(), "turns secret scanning on in 1 repository")

		since := auditMaxID(t)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on", "locked": "on"}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3), "the lock applies the switch to every repository")
		assert.Contains(t, auditOne(t, since, "org.secret_scanning.changed").Data, `"secret_scanning_locked":true`)
		lockedList := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL+"/secret_scanning/repos"), http.StatusOK).Body)
		lockedList.AssertElement(t, "#secret-scanning-off-locked", true)
		assert.Contains(t, lockedList.Find("#secret-scanning-off-locked").Text(), "have no effect until the lock is lifted")
		assert.NotContains(t, lockedList.Find(".org-setting-content").Text(), "Lock the setting", "a note replaces the hint")
		repo := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", "/org3/repo3/settings/code_security"), http.StatusOK).Body)
		repo.AssertElement(t, "#secret-scanning-box fieldset[disabled] #secret-scanning-enabled[checked]", true)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security/secret_scanning", map[string]string{}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3), "the repository can't change it while locked")
		doc = NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		assert.Contains(t, doc.Find("#secret-scanning-counts").Text(), "On in")

		// unlocked again: the repository's own off applies again
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3))
		// locked off: nothing is scanned in the organization, whatever the repository says
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"locked": "on"}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3))
		assert.False(t, secretRepoEnabled(t, 32), "another repository of org3")
		assert.True(t, secretRepoEnabled(t, 1), "a repository of another owner")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security/secret_scanning", map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3), "the repository can't turn it on while the organization locks it off")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3), "unlocked: the repository's own off applies again")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/repo3/settings/code_security/secret_scanning", map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3))
	})

	t.Run("the site switch is above the organization's", func(t *testing.T) {
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/secret-scanning/switches", map[string]string{}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.False(t, secretRepoEnabled(t, 3), "the site is off")
		doc := NewHTMLParser(t, owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-site-off", true)
		doc.AssertElement(t, "#secret-scanning-enabled[data-confirm-modal]", false) // nothing is scanned: nothing to confirm
		assert.Contains(t, doc.Find("#secret-scanning-counts").Text(), "No repository is scanned while the site switch is off")
		doc.AssertElement(t, `#secret-scanning-site-off a[href$="/admin/config/secret-scanning"]`, false) // an owner gets no link
		NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body).AssertElement(t, `#secret-scanning-site-off a[href$="/admin/config/secret-scanning"]`, true)
		// the organization may prepare its setting; it has no effect until the site is on
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"locked": "on"}), http.StatusSeeOther)
		assert.False(t, secretRepoEnabled(t, 3))
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/config/secret-scanning/switches", map[string]string{"enabled": "on"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.False(t, secretRepoEnabled(t, 3), "the site is on, the organization is off")
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		assert.True(t, secretRepoEnabled(t, 3))
	})

	t.Run("read-only maintenance refuses it", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		bumpSettingsRevision(t)
		since := auditMaxID(t)
		owner.MakeRequest(t, NewRequestWithValues(t, "POST", post, map[string]string{}), http.StatusSeeOther)
		assertMaintenanceFlash(t, owner)
		assert.True(t, secretRepoEnabled(t, 3))
		assert.Equal(t, since, auditMaxID(t))
	})
}

// The site administration page: the switches and the limits are separate forms. A site admin changes them, an auditor
// reads the page, nobody else opens it. Every save is validated, audited and applies at once.
func TestSecretScanningAdminSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.SecretScanning.Enabled, true)()
	keepSecretScanningSettings(t)
	const (
		pageURL  = "/admin/config/secret-scanning"
		switches = pageURL + "/switches"
		limits   = pageURL + "/limits"
	)
	admin := loginUser(t, "user1")
	setUserFlag(t, 4, "is_auditor", true)
	auditor := loginUser(t, "user4")
	owner := loginUser(t, "user2")
	effective := func() setting.SecretScanningOptions { return setting.SecretScanningSettings(t.Context()) }

	t.Run("who may open and change it", func(t *testing.T) {
		anon := emptyTestSession(t)
		anon.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusSeeOther)
		anon.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{}), http.StatusSeeOther)
		owner.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusForbidden)
		for _, p := range []string{switches, limits} {
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", p, map[string]string{"max_blob_size": "2"}), http.StatusForbidden)
			auditor.MakeRequest(t, NewRequestWithValues(t, "POST", p, map[string]string{"max_blob_size": "2"}), http.StatusForbidden)
		}
		assert.True(t, secretscan_service.SiteEnabled(t.Context()))
		assert.EqualValues(t, 1<<20, effective().MaxBlobSize)

		doc := NewHTMLParser(t, auditor.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-read-only", true)
		doc.AssertElement(t, "#secret-scanning-switches fieldset[disabled]", true)
		doc.AssertElement(t, "#secret-scanning-switches-save", false)
		doc.AssertElement(t, "#secret-scanning-limits-save", false)
		doc = NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-read-only", false)
		doc.AssertElement(t, "#secret-scanning-enabled[checked]", true)
		doc.AssertElement(t, "#secret-scanning-generic[checked]", false)
		assert.Equal(t, "1", valueOf(doc, "#secret-limit-max_blob_size"))
		assert.Equal(t, "300", valueOf(doc, "#secret-limit-scan_timeout"))
		assert.Contains(t, doc.Find("#secret-limit-max_blob_size-default").Text(), "Default from app.ini: 1")
		assert.Contains(t, doc.Find("#secret-limit-max_scan_bytes-default").Text(), "Default from app.ini: 2048")
	})

	t.Run("the switches: audited, applied at once, the limits untouched", func(t *testing.T) {
		since := auditMaxID(t)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"generic": "on"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.False(t, secretscan_service.SiteEnabled(t.Context()), "an unticked box is off")
		assert.True(t, effective().GenericRules)
		assert.True(t, setting.SecretScanning.Enabled, "app.ini only gives the starting value")
		e := auditOne(t, since, "admin.setting.changed")
		assert.Contains(t, e.Data, "secret_scanning.enabled")
		assert.Contains(t, e.Data, `"mode":"off"`)
		assert.Contains(t, e.Data, `"generic_rules":true`)
		doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		doc.AssertElement(t, "#secret-scanning-enabled[checked]", false)
		doc.AssertElement(t, "#secret-scanning-generic[checked]", true)
		doc.AssertElement(t, "#secret-scanning-file-default", true)
		assert.Contains(t, doc.Find(".admin-setting-content > .attached.segment .help").First().Text(), "user1")

		// saving what is in force writes nothing
		since = auditMaxID(t)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"generic": "on"}), http.StatusSeeOther)
		assert.Equal(t, since, auditMaxID(t))
		assert.Contains(t, bwFlash(admin), "Nothing changed")

		admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{"enabled": "on"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.True(t, secretscan_service.SiteEnabled(t.Context()))
		assert.False(t, effective().GenericRules)
	})

	t.Run("the limits: units, bounds, one save", func(t *testing.T) {
		since := auditMaxID(t)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_blob_size": "2.5", "scan_timeout": "90", "max_alerts_per_repo": "500", "max_scan_blobs": ""}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		o := effective()
		assert.EqualValues(t, 5<<19, o.MaxBlobSize, "MiB, with decimals")
		assert.Equal(t, 90*time.Second, o.ScanTimeout)
		assert.EqualValues(t, 500, o.MaxAlertsPerRepo)
		assert.EqualValues(t, 2_000_000, o.MaxScanBlobs, "an empty field keeps what it is")
		assert.True(t, secretscan_service.SiteEnabled(t.Context()), "the limits form never touches the switch")
		e := auditOne(t, since, "admin.setting.changed")
		assert.Contains(t, e.Data, "secret_scanning.config")
		assert.NotContains(t, e.Data, "secret_scanning.enabled")
		doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK).Body)
		assert.Equal(t, "2.5", valueOf(doc, "#secret-limit-max_blob_size"))
		assert.Equal(t, "90", valueOf(doc, "#secret-limit-scan_timeout"))

		// a value equal to app.ini is no override
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_blob_size": "1", "scan_timeout": "300", "max_alerts_per_repo": "10000"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.EqualValues(t, 1<<20, effective().MaxBlobSize)
		assert.EqualValues(t, 10_000, effective().MaxAlertsPerRepo)
		assert.Empty(t, setting.Config().SecretScanningConfig.Value(t.Context()).Limits)
	})

	t.Run("a refused save changes nothing and keeps what was typed", func(t *testing.T) {
		since := auditMaxID(t)
		for name, form := range map[string]map[string]string{
			"above the maximum":     {"max_blob_size": "101"},
			"zero":                  {"scan_timeout": "0"},
			"below the time floor":  {"scan_timeout": "29"},
			"below the size floor":  {"max_blob_size": "0.06"},
			"rounds to zero":        {"max_blob_size": "0.0000001"},
			"below the alert floor": {"max_alerts_per_repo": "99"},
			"negative":              {"max_alerts_per_repo": "-5"},
			"below the bytes floor": {"max_scan_bytes": "0.5"},
			"below the files floor": {"max_scan_blobs": "999"},
			"no locations":          {"max_locations_per_alert": "0"},
			"not a number":          {"max_scan_blobs": "many"},
			"not whole":             {"max_concurrent_scans": "1.5"},
			"one bad, one good":     {"scan_timeout": "60", "max_blob_size": "1000"},
			"two bad":               {"scan_timeout": "5", "max_alerts_per_repo": "7", "max_scan_blobs": "x", "max_blob_size": "2"},
			"not finite":            {"max_scan_bytes": "NaN"},
			"infinite":              {"max_scan_bytes": "Inf"},
			"too large to store":    {"max_scan_bytes": "1e300"},
			"exponent in a count":   {"max_scan_blobs": "1e3"},
			"exponent in a size":    {"max_blob_size": "1e1"},
			"hex":                   {"max_scan_blobs": "0x10"},
			"hex float":             {"max_blob_size": "0x1p3"},
			"separator":             {"max_scan_blobs": "1_0"},
			"separator in a size":   {"max_blob_size": "1_0"},
			"sign in a count":       {"max_scan_blobs": "+5"},
			"sign in a size":        {"max_blob_size": "+2"},
			"point without digits":  {"max_blob_size": "2."},
			"two points":            {"max_blob_size": "1.2.3"},
			"non-ASCII digits":      {"max_scan_blobs": "\u0661\u0662"},
		} {
			resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, form), http.StatusUnprocessableEntity)
			doc := NewHTMLParser(t, resp.Body)
			assert.Contains(t, doc.Find("#secret-scanning-limits-error").Text(), "Nothing was saved.", name)
			for field, text := range form {
				assert.Equal(t, text, valueOf(doc, "#secret-limit-"+field), name+": every typed value stays")
			}
		}
		assert.Equal(t, since, auditMaxID(t), "no refused save wrote anything")
		// padding is trimmed, and a plain number is read as before
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_scan_blobs": " 1000 ", "max_blob_size": "0.0625"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		assert.EqualValues(t, 1000, effective().MaxScanBlobs)
		assert.EqualValues(t, 64<<10, effective().MaxBlobSize, "the floor itself is allowed")
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_scan_blobs": "2000000", "max_blob_size": "1"}), http.StatusSeeOther)
		bumpSettingsRevision(t)
		since = auditMaxID(t)
		assert.Equal(t, since, auditMaxID(t))
		assert.EqualValues(t, 1<<20, effective().MaxBlobSize)
		assert.Equal(t, 300*time.Second, effective().ScanTimeout)
		resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_blob_size": "101"}), http.StatusUnprocessableEntity)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find("#secret-scanning-limits-error").Text(), "Largest file scanned must be at least 64 KiB and at most 100 MiB.")
		resp = admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_scan_bytes": "2000000", "max_locations_per_alert": "10001"}), http.StatusUnprocessableEntity)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find("#secret-scanning-limits-error").Text(), "Most data per scan must be at least 1 MiB and at most 1 TiB.", "the biggest whole unit")
		resp = admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_locations_per_alert": "10001"}), http.StatusUnprocessableEntity)
		assert.Contains(t, NewHTMLParser(t, resp.Body).Find("#secret-scanning-limits-error").Text(), "must be at least 1 and at most 10000.", "no unit on a count")
	})

	t.Run("read-only maintenance refuses both forms", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		bumpSettingsRevision(t)
		since := auditMaxID(t)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", switches, map[string]string{}), http.StatusSeeOther)
		assertMaintenanceFlash(t, admin)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", limits, map[string]string{"max_blob_size": "2"}), http.StatusSeeOther)
		assertMaintenanceFlash(t, admin)
		assert.Equal(t, since, auditMaxID(t))
		assert.True(t, secretscan_service.SiteEnabled(t.Context()))
	})
}

func valueOf(doc *HTMLDoc, selector string) string {
	v, _ := doc.Find(selector).Attr("value")
	return v
}
