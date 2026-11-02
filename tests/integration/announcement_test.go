// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth_model "forgejo.org/models/auth"
	system_model "forgejo.org/models/system"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shownAnnouncements returns the IDs of the announcement banners on a page, in order
func shownAnnouncements(t *testing.T, session *TestSession) []string {
	t.Helper()
	req := NewRequest(t, "GET", "/explore/repos")
	var resp *httptest.ResponseRecorder
	if session == nil {
		resp = MakeRequest(t, req, http.StatusOK)
	} else {
		resp = session.MakeRequest(t, req, http.StatusOK)
	}
	ids := []string{}
	NewHTMLParser(t, resp.Body).Find(".site-announcement").Each(func(_ int, s *goquery.Selection) {
		ids = append(ids, s.AttrOr("data-announcement-id", ""))
	})
	return ids
}

func createAnnouncement(t *testing.T, admin *TestSession, values map[string]string) *system_model.Announcement {
	t.Helper()
	resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/announcements/new", values), http.StatusSeeOther)
	assert.Equal(t, "/admin/announcements", test.RedirectURL(resp))
	return unittest.AssertExistsAndLoadBean(t, &system_model.Announcement{Message: values["message"]})
}

func TestAnnouncements(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	admin := loginUser(t, "user1")
	user := loginUser(t, "user2")

	// only site administrators manage announcements
	user.MakeRequest(t, NewRequest(t, "GET", "/admin/announcements"), http.StatusForbidden)
	user.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/announcements/new", map[string]string{
		"message": "nope", "type": "info", "audience": "everyone",
	}), http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &system_model.Announcement{Message: "nope"})

	assert.Empty(t, shownAnnouncements(t, nil))

	everyone := createAnnouncement(t, admin, map[string]string{
		"message":     "Upgrade on **Monday**",
		"type":        "info",
		"audience":    "everyone",
		"dismissible": "on",
	})
	signedIn := createAnnouncement(t, admin, map[string]string{
		"message":     "Please rotate your tokens",
		"type":        "warning",
		"audience":    "signed_in",
		"dismissible": "on",
	})
	adminsOnly := createAnnouncement(t, admin, map[string]string{
		"message":     "Disk almost full",
		"type":        "critical",
		"audience":    "admins",
		"dismissible": "on",
	})
	assert.Equal(t, int64(1), everyone.CreatedByID)

	id := func(a *system_model.Announcement) string { return fmt.Sprint(a.ID) }

	t.Run("Audience", func(t *testing.T) {
		assert.Equal(t, []string{id(everyone)}, shownAnnouncements(t, nil))
		assert.Equal(t, []string{id(signedIn), id(everyone)}, shownAnnouncements(t, user))
		// critical first
		assert.Equal(t, []string{id(adminsOnly), id(signedIn), id(everyone)}, shownAnnouncements(t, admin))
	})

	t.Run("Rendering", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/explore/repos"), http.StatusOK)
		banner := NewHTMLParser(t, resp.Body).Find(".site-announcement")
		assert.Equal(t, "Monday", banner.Find("strong").Text())
		// anonymous visitors can dismiss dismissible announcements
		assert.Equal(t, 1, banner.Find("form").Length())

		resp = admin.MakeRequest(t, NewRequest(t, "GET", "/explore/repos"), http.StatusOK)
		doc := NewHTMLParser(t, resp.Body)
		doc.AssertElement(t, fmt.Sprintf(`.site-announcement[data-announcement-id="%d"].negative`, adminsOnly.ID), true)
		// critical announcements have no dismiss button even if marked dismissible
		doc.AssertElement(t, fmt.Sprintf(`form[action="/-/announcements/%d/dismiss"]`, adminsOnly.ID), false)
		doc.AssertElement(t, fmt.Sprintf(`form[action="/-/announcements/%d/dismiss"]`, signedIn.ID), true)
	})

	t.Run("Dismiss", func(t *testing.T) {
		dismissURL := fmt.Sprintf("/-/announcements/%d/dismiss", signedIn.ID)
		resp := user.MakeRequest(t, NewRequestWithValues(t, "POST", dismissURL, map[string]string{
			"redirect_to": "/explore/repos",
		}), http.StatusSeeOther)
		assert.Equal(t, "/explore/repos", test.RedirectURL(resp))
		assert.Equal(t, []string{id(everyone)}, shownAnnouncements(t, user))
		// other users still see it
		assert.Equal(t, []string{id(adminsOnly), id(signedIn), id(everyone)}, shownAnnouncements(t, admin))

		// critical announcements cannot be dismissed
		admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/-/announcements/%d/dismiss", adminsOnly.ID)), http.StatusUnprocessableEntity)
		unittest.AssertNotExistsBean(t, &system_model.AnnouncementDismissal{AnnouncementID: adminsOnly.ID})

		// nor can those that are not dismissible
		fixed := createAnnouncement(t, admin, map[string]string{"message": "Fixed", "type": "info", "audience": "everyone"})
		user.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/-/announcements/%d/dismiss", fixed.ID)), http.StatusUnprocessableEntity)
		admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/announcements/%d/delete", fixed.ID)), http.StatusOK)

		// anonymous visitors dismiss with a cookie, not in the database
		MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/-/announcements/%d/dismiss", everyone.ID)), http.StatusSeeOther)
		unittest.AssertNotExistsBean(t, &system_model.AnnouncementDismissal{AnnouncementID: everyone.ID})

		user.MakeRequest(t, NewRequest(t, "POST", "/-/announcements/9999/dismiss"), http.StatusNotFound)

		// the announcement shows again once its message changes
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/announcements/%d", signedIn.ID), map[string]string{
			"message":     "Please rotate your tokens",
			"type":        "warning",
			"audience":    "signed_in",
			"dismissible": "on",
		}), http.StatusSeeOther)
		assert.Equal(t, []string{id(everyone)}, shownAnnouncements(t, user))
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/announcements/%d", signedIn.ID), map[string]string{
			"message":     "Please rotate your tokens by Friday",
			"type":        "warning",
			"audience":    "signed_in",
			"dismissible": "on",
		}), http.StatusSeeOther)
		assert.Equal(t, []string{id(signedIn), id(everyone)}, shownAnnouncements(t, user))
	})

	t.Run("AnonymousDismiss", func(t *testing.T) {
		anon := func(path string, cookies []*http.Cookie, values map[string]string, status int) *httptest.ResponseRecorder {
			var req *RequestWrapper
			if values == nil {
				req = NewRequest(t, "GET", path)
			} else {
				req = NewRequestWithValues(t, "POST", path, values)
			}
			for _, c := range cookies {
				req.AddCookie(c)
			}
			return MakeRequest(t, req, status)
		}
		shown := func(cookies []*http.Cookie) []string {
			ids := []string{}
			NewHTMLParser(t, anon("/explore/repos", cookies, nil, http.StatusOK).Body).Find(".site-announcement").Each(func(_ int, s *goquery.Selection) {
				ids = append(ids, s.AttrOr("data-announcement-id", ""))
			})
			return ids
		}
		dismissCookie := func(resp *httptest.ResponseRecorder) *http.Cookie {
			for _, c := range resp.Result().Cookies() {
				if c.Name == "announcements_dismissed" {
					return c
				}
			}
			return nil
		}

		notice := createAnnouncement(t, admin, map[string]string{"message": "Anon notice", "type": "info", "audience": "everyone", "dismissible": "on"})
		critical := createAnnouncement(t, admin, map[string]string{"message": "Anon critical", "type": "critical", "audience": "everyone", "dismissible": "on"})
		defer func() {
			admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/announcements/%d/delete", notice.ID)), http.StatusOK)
			admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/announcements/%d/delete", critical.ID)), http.StatusOK)
		}()
		dismissURL := fmt.Sprintf("/-/announcements/%d/dismiss", notice.ID)

		// AnonymousButton and AnonymousCritical
		doc := NewHTMLParser(t, anon("/explore/repos", nil, nil, http.StatusOK).Body)
		doc.AssertElement(t, fmt.Sprintf(`form[action="/-/announcements/%d/dismiss"]`, notice.ID), true)
		doc.AssertElement(t, fmt.Sprintf(`form[action="/-/announcements/%d/dismiss"]`, critical.ID), false)
		resp := anon(fmt.Sprintf("/-/announcements/%d/dismiss", critical.ID), nil, map[string]string{}, http.StatusUnprocessableEntity)
		assert.Nil(t, dismissCookie(resp))

		// unknown announcements set no cookie
		resp = anon("/-/announcements/9999/dismiss", nil, map[string]string{}, http.StatusNotFound)
		assert.Nil(t, dismissCookie(resp))

		// AnonymousDismiss
		resp = anon(dismissURL, nil, map[string]string{"redirect_to": "/explore/repos"}, http.StatusSeeOther)
		assert.Equal(t, "/explore/repos", test.RedirectURL(resp))
		cookie := dismissCookie(resp)
		require.NotNil(t, cookie)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		assert.Equal(t, setting.SessionConfig.CookiePath, cookie.Path)
		assert.Equal(t, setting.SessionConfig.Secure, cookie.Secure)
		assert.Positive(t, cookie.MaxAge)
		unittest.AssertNotExistsBean(t, &system_model.AnnouncementDismissal{AnnouncementID: notice.ID})

		cookies := []*http.Cookie{cookie}
		assert.NotContains(t, shown(cookies), id(notice))
		assert.Contains(t, shown(cookies), id(critical))
		assert.Contains(t, shown(nil), id(notice))

		// AnonymousRedirect: only local redirects
		resp = anon(dismissURL, nil, map[string]string{"redirect_to": "https://example.com/"}, http.StatusSeeOther)
		assert.Equal(t, setting.AppSubURL+"/", test.RedirectURL(resp))

		// AnonymousTextChange
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/announcements/%d", notice.ID), map[string]string{
			"message": "Anon notice, changed", "type": "info", "audience": "everyone", "dismissible": "on",
		}), http.StatusSeeOther)
		assert.Contains(t, shown(cookies), id(notice))

		// a signed-in dismissal sets no cookie
		resp = user.MakeRequest(t, NewRequestWithValues(t, "POST", dismissURL, map[string]string{}), http.StatusSeeOther)
		assert.Nil(t, dismissCookie(resp))
	})

	t.Run("TimeWindow", func(t *testing.T) {
		format := func(d time.Duration) string {
			return time.Now().Add(d).In(setting.DefaultUILocation).Format("2006-01-02T15:04")
		}
		future := createAnnouncement(t, admin, map[string]string{
			"message": "Coming soon", "type": "info", "audience": "everyone", "start_time": format(time.Hour),
		})
		past := createAnnouncement(t, admin, map[string]string{
			"message": "Already over", "type": "info", "audience": "everyone", "end_time": format(-time.Hour),
		})
		current := createAnnouncement(t, admin, map[string]string{
			"message": "Happening now", "type": "info", "audience": "everyone",
			"start_time": format(-time.Hour), "end_time": format(time.Hour),
		})
		assert.NotZero(t, future.StartUnix)
		assert.NotZero(t, past.EndUnix)
		assert.Equal(t, []string{id(current), id(everyone)}, shownAnnouncements(t, nil))

		// the end must come after the start
		resp := admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/admin/announcements/new", map[string]string{
			"message": "Backwards", "type": "info", "audience": "everyone",
			"start_time": format(time.Hour), "end_time": format(-time.Hour),
		}), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "The end must be after the start.")
		unittest.AssertNotExistsBean(t, &system_model.Announcement{Message: "Backwards"})

		// the admin list shows the status of each announcement
		resp = admin.MakeRequest(t, NewRequest(t, "GET", "/admin/announcements"), http.StatusOK)
		body := resp.Body.String()
		assert.Contains(t, body, "Scheduled")
		assert.Contains(t, body, "Ended")
		assert.Contains(t, body, "Active")
	})

	t.Run("Delete", func(t *testing.T) {
		resp := admin.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/admin/announcements/%d/delete", everyone.ID)), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "/admin/announcements")
		unittest.AssertNotExistsBean(t, &system_model.Announcement{ID: everyone.ID})
		assert.NotContains(t, shownAnnouncements(t, nil), id(everyone))
	})
}

func TestAPIAnnouncements(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	adminReadToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteAdmin)

	create := func(t *testing.T, token string, opts api.CreateAnnouncementOption, status int) *api.Announcement {
		t.Helper()
		resp := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/admin/announcements", opts).AddTokenAuth(token), status)
		if status != http.StatusCreated {
			return nil
		}
		a := new(api.Announcement)
		DecodeJSON(t, resp, a)
		return a
	}

	t.Run("Permissions", func(t *testing.T) {
		opts := api.CreateAnnouncementOption{Message: "hi", Type: "info", Audience: "everyone"}
		create(t, userToken, opts, http.StatusForbidden)
		create(t, adminReadToken, opts, http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/announcements").AddTokenAuth(userToken), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/announcements"), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/announcements").AddTokenAuth(adminReadToken), http.StatusOK)
	})

	t.Run("Validation", func(t *testing.T) {
		create(t, adminToken, api.CreateAnnouncementOption{Message: "hi", Type: "loud", Audience: "everyone"}, http.StatusUnprocessableEntity)
		create(t, adminToken, api.CreateAnnouncementOption{Message: "hi", Type: "info", Audience: "friends"}, http.StatusUnprocessableEntity)
		create(t, adminToken, api.CreateAnnouncementOption{Type: "info", Audience: "everyone"}, http.StatusUnprocessableEntity)
		start := time.Now().Add(time.Hour)
		end := time.Now()
		create(t, adminToken, api.CreateAnnouncementOption{Message: "hi", Type: "info", Audience: "everyone", StartAt: &start, EndAt: &end}, http.StatusUnprocessableEntity)
		unittest.AssertCount(t, &system_model.Announcement{}, 0)
	})

	t.Run("CRUD", func(t *testing.T) {
		end := time.Now().Add(time.Hour).Truncate(time.Second)
		a := create(t, adminToken, api.CreateAnnouncementOption{
			Message: "Maintenance tonight", Type: "warning", Audience: "everyone", Dismissible: true, EndAt: &end,
		}, http.StatusCreated)
		assert.Equal(t, "Maintenance tonight", a.Message)
		assert.Equal(t, "warning", a.Type)
		assert.Equal(t, "everyone", a.Audience)
		assert.True(t, a.Dismissible)
		assert.Nil(t, a.StartAt)
		require.NotNil(t, a.EndAt)
		assert.True(t, end.Equal(*a.EndAt))

		url := fmt.Sprintf("/api/v1/admin/announcements/%d", a.ID)
		resp := MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(adminToken), http.StatusOK)
		got := new(api.Announcement)
		DecodeJSON(t, resp, got)
		assert.Equal(t, a.ID, got.ID)

		resp = MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/announcements").AddTokenAuth(adminToken), http.StatusOK)
		var list []*api.Announcement
		DecodeJSON(t, resp, &list)
		require.Len(t, list, 1)
		assert.Equal(t, "1", resp.Header().Get("X-Total-Count"))

		// edit only some fields, and remove the end time
		message := "Maintenance tomorrow"
		zero := time.Time{}
		resp = MakeRequest(t, NewRequestWithJSON(t, "PATCH", url, api.EditAnnouncementOption{Message: &message, EndAt: &zero}).AddTokenAuth(adminToken), http.StatusOK)
		DecodeJSON(t, resp, got)
		assert.Equal(t, "Maintenance tomorrow", got.Message)
		assert.Equal(t, "warning", got.Type)
		assert.Nil(t, got.EndAt)

		empty := ""
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", url, api.EditAnnouncementOption{Message: &empty}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)
		badType := "loud"
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", url, api.EditAnnouncementOption{Type: &badType}).AddTokenAuth(adminToken), http.StatusUnprocessableEntity)

		// the active announcements for the current user
		active := func(t *testing.T, token string) []*api.Announcement {
			t.Helper()
			req := NewRequest(t, "GET", "/api/v1/announcements")
			if token != "" {
				req.AddTokenAuth(token)
			}
			var list []*api.Announcement
			DecodeJSON(t, MakeRequest(t, req, http.StatusOK), &list)
			return list
		}
		critical := create(t, adminToken, api.CreateAnnouncementOption{Message: "Admins only", Type: "critical", Audience: "admins"}, http.StatusCreated)
		assert.Len(t, active(t, ""), 1)
		assert.Len(t, active(t, userToken), 1)
		adminActive := active(t, adminToken)
		require.Len(t, adminActive, 2)
		assert.Equal(t, critical.ID, adminActive[0].ID)

		// dismissed ones are left out
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/-/announcements/%d/dismiss", a.ID)), http.StatusSeeOther)
		assert.Empty(t, active(t, userToken))

		MakeRequest(t, NewRequest(t, "DELETE", url).AddTokenAuth(userToken), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", url).AddTokenAuth(adminToken), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(adminToken), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "DELETE", url).AddTokenAuth(adminToken), http.StatusNotFound)
		unittest.AssertCount(t, &system_model.AnnouncementDismissal{}, 0)
	})
}
