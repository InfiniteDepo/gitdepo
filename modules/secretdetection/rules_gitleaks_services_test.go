// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	digits    = "0123456789"
	upperHex  = "0123456789ABCDEF"
	bech32    = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
	b64uEqual = b64u + "="
)

// gitleaksServiceRuleTests are the samples of rules_gitleaks_services.go,
// after gitleaks' own true and false positives. Every token is built from
// parts.
func gitleaksServiceRuleTests() []ruleTest {
	uuid := fake(8, hexa) + "-" + fake(4, hexa) + "-" + fake(4, hexa) + "-" + fake(4, hexa) + "-" + fake(12, hexa)
	set := func(name, value string) string { return name + ` = "` + value + `"` }
	teams := func(last string) string {
		return "https://acme.webhook.office.com/webhookb2/" + uuid + "@" + uuid + "/IncomingWebhook/" + fake(32, lowerAlnum) + "/" + last
	}
	// random hex as real Plaid values are (fake's are all distinct, so of
	// the highest entropy)
	rnd := rand.New(rand.NewPCG(7, 8))
	randHex := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = hexa[rnd.IntN(16)]
		}
		return string(b)
	}
	var plaidIDs, plaidSecrets []string
	for range 8 {
		plaidIDs = append(plaidIDs, set("PLAID_CLIENT_ID", randHex(24)))
		plaidSecrets = append(plaidSecrets, set("PLAID_SECRET", randHex(30)))
	}
	sentryOrg := "sntrys_" + "eyJpYXQiO" + fake(40, alnum) + "LCJyZWdpb25fdXJs" + fake(40, alnum) + "_" + fake(43, alnum)
	return []ruleTest{
		// Chat and messaging
		{"discord-api-token", []string{set("discord_token", fake(64, hexa))}, []string{set("discord_token", strings.Repeat("0", 64)), set("token", fake(64, hexa))}},
		{"discord-client-secret", []string{set("DISCORD_CLIENT_SECRET", fake(32, b64u))}, []string{set("discord", strings.Repeat("0", 32)), set("discord_secret", fake(31, alnum))}},
		{
			"telegram-bot-api-token",
			[]string{"TELEGRAM_BOT_TOKEN=" + fake(10, digits) + ":A" + fake(34, b64u), set("telegramToken", fake(5, digits)+":A"+fake(34, alnum))},
			[]string{set("telegram", fake(4, digits)+":A"+fake(34, alnum)), set("telegram", fake(10, digits)+":a"+fake(34, alnum)), set("telegram", fake(17, digits)+":A"+fake(34, alnum))},
		},
		{"mattermost-access-token", []string{set("mattermost_token", fake(26, alnum))}, []string{set("mattermost_token", fake(25, alnum)), set("mattermost", strings.Repeat("ab", 13))}},
		{
			"microsoft-teams-webhook",
			[]string{"url: " + teams(uuid), `"` + teams(uuid) + `"`},
			[]string{teams(fake(12, hexa)), "https://acme.webhook.office.com/webhookb2/" + uuid + "/IncomingWebhook/" + fake(32, lowerAlnum)},
		},
		{"gitter-access-token", []string{set("GITTER_TOKEN", fake(40, b64u))}, []string{set("gitter", fake(39, alnum)), set("gitter", strings.Repeat("x", 40))}},
		{"sendbird-access-id", []string{set("sendbird_app_id", uuid)}, []string{set("app_id", uuid), set("sendbird", strings.Repeat("0", 8)+"-0000-0000-0000-"+strings.Repeat("0", 12))}},
		{"sendbird-access-token", []string{set("SENDBIRD_API_KEY", fake(40, hexa))}, []string{set("sendbird", fake(39, hexa)), set("token", fake(40, hexa))}},
		{"messagebird-api-token", []string{set("message_bird_key", fake(25, alnum)), set("MESSAGEBIRD_API_KEY", fake(25, alnum))}, []string{set("messagebird", fake(24, alnum))}},
		{"messagebird-client-id", []string{set("messagebird_client_id", uuid)}, []string{set("bird_client_id", uuid)}},
		{
			"twilio-api-key",
			[]string{"TWILIO_API_KEY=SK" + fake(32, hexa), `"SK` + fake(32, upperHex) + `"`},
			[]string{"SK" + fake(31, hexa), "sk" + fake(32, hexa), "TASK" + fake(32, hexa), "SK" + strings.Repeat("ab", 16), "SK" + fake(33, hexa)},
		},
		{"intercom-api-key", []string{set("intercom_access_token", fake(60, b64uEqual))}, []string{set("intercom", fake(59, alnum))}},

		// Payments, banking and crypto exchanges
		{
			"stripe-live-key",
			[]string{"STRIPE_KEY=sk_prod_" + fake(24, alnum), "rk_prod_" + fake(24, alnum)},
			[]string{"sk_prod_" + strings.Repeat("a", 24), "sk_preprod_" + fake(24, alnum)},
		},
		{
			"square-access-token",
			[]string{"ARG token=sq0atp-" + fake(22, b64u), "ARG token=EAAA" + fake(60, b64u), `"EAAA` + fake(40, b64u) + `"`},
			[]string{
				"aws-cli@sha256:" + "eaaa" + fake(60, hexa),
				"x/EAAA" + fake(40, alnum) + "+" + fake(10, alnum),
				"EAAA" + fake(21, alnum),
				"EAAA" + fake(61, alnum),
				" = 'EAAA" + fake(30, alnum) + "=" + fake(8, alnum) + "'",
				"square = 'EAAA" + fake(30, alnum) + "?b=" + fake(8, alnum) + "'",
			},
		},
		{
			"square-secret",
			[]string{"SQUARE_APP_SECRET=sq0csp-" + fake(43, b64u), `secret: "sq0csp-` + fake(43, alnum) + `"`},
			[]string{"sq0csp-" + fake(42, alnum), "sq0csp-" + fake(44, alnum), "sq0csp-" + strings.Repeat("a", 43), "xsq0csp-" + fake(43, alnum)},
		},
		{
			"flutterwave-secret-key",
			[]string{"FLW_SECRET_KEY=FLWSECK_TEST-" + fake(32, "abcdefgh0123456789") + "-X"},
			[]string{"FLWSECK_TEST-" + fake(32, "abcdefgh0123456789") + "-Y", "FLWSECK_TEST-" + fake(32, "ijklmnop0123456789") + "-X"},
		},
		{
			"flutterwave-encryption-key",
			[]string{"FLW_ENCRYPTION_KEY=FLWSECK_TEST-" + fake(12, "abcdefgh0123456789")},
			[]string{"FLWSECK_TEST-" + fake(13, "abcdefgh0123456789"), "FLWSECK_TEST" + fake(12, "abcdefgh0123456789")},
		},
		{"gocardless-api-token", []string{set("gocardless_token", "live_"+fake(40, b64uEqual))}, []string{set("gocardless_token", "sandbox_"+fake(40, alnum)), set("token", "live_"+fake(40, alnum))}},
		{"plaid-api-token", []string{set("PLAID_ACCESS_TOKEN", "access-sandbox-"+uuid)}, []string{set("plaid_token", "access-staging-"+uuid)}},
		{"plaid-client-id", append(plaidIDs, set("PLAID_CLIENT_ID", fake(24, alnum))), []string{set("plaid_client_id", strings.Repeat("ab12", 6))}},
		{"plaid-secret-key", append(plaidSecrets, set("PLAID_SECRET", fake(30, alnum))), []string{set("plaid_secret", strings.Repeat("ab1", 10))}},
		{"coinbase-access-token", []string{set("COINBASE_API_KEY", fake(64, b64u))}, []string{set("coinbase", fake(63, alnum))}},
		{"kraken-access-token", []string{set("kraken_api_key", fake(56, b64)+fake(30, alnum)+"==")}, []string{set("kraken", fake(79, alnum))}},
		{"kucoin-access-token", []string{set("KUCOIN_KEY", fake(24, hexa))}, []string{set("kucoin", fake(23, hexa))}},
		{"kucoin-secret-key", []string{set("kucoin_secret", uuid)}, []string{set("secret", uuid)}},
		{"bittrex-api-key", []string{set("BITTREX_API_KEY", fake(32, alnum)), set("bittrex_secret", fake(32, alnum))}, []string{set("bittrex", fake(33, alnum))}},
		{"finicity-api-token", []string{set("finicity_app_key", fake(32, hexa))}, []string{set("finicity", fake(32, alnum))}},
		{"finicity-client-secret", []string{set("FINICITY_SECRET", fake(20, alnum))}, []string{set("finicity_secret", fake(21, alnum))}},
		{"finnhub-access-token", []string{set("finnhub_token", fake(20, alnum))}, []string{set("finnhub", strings.Repeat("ab", 10))}},
		{
			"duffel-api-token",
			[]string{"DUFFEL=duffel_test_" + fake(43, b64uEqual), "duffel_live_" + fake(43, alnum)},
			[]string{"duffel_beta_" + fake(43, alnum), "duffel_live_" + fake(42, alnum)},
		},
		{
			"shippo-api-token",
			[]string{"SHIPPO=shippo_live_" + fake(40, hexa), "shippo_test_" + fake(40, upperHex)},
			[]string{"shippo_live_" + fake(39, hexa), "shippo_live_" + strings.Repeat("0", 40)},
		},
		{
			"easypost-api-token",
			[]string{"EASYPOST_API_KEY=EZAK" + fake(54, alnum)},
			[]string{"...6wqX6fNUXA/rYqRvfQ+" + "EZAK" + fake(54, alnum) + "/3VmWq", "EZAK" + fake(53, alnum)},
		},
		{
			"easypost-test-api-token",
			[]string{"EASYPOST_TEST_KEY=EZTK" + fake(54, alnum)},
			[]string{"...6wqX6fNUXA/rYqRvfQ+" + "EZTK" + fake(54, alnum) + "/3VmWq", "eztk" + fake(54, alnum)},
		},

		// Monitoring and observability
		{"datadog-access-token", []string{set("DATADOG_APP_KEY", fake(40, alnum))}, []string{set("datadog", fake(39, alnum)), set("app_key", fake(40, alnum))}},
		{
			"dynatrace-api-token",
			[]string{"DT_API_TOKEN=dt0c01." + fake(24, upperAlnum) + "." + fake(64, alnum)},
			[]string{"dt0c01." + fake(24, upperAlnum) + "." + fake(63, alnum), "dt0c01." + strings.Repeat("A", 24) + "." + strings.Repeat("a", 64)},
		},
		{"new-relic-user-api-key", []string{set("NEW_RELIC_API_KEY", "NRAK-"+fake(27, upperAlnum))}, []string{set("api_key", "NRAK-"+fake(27, upperAlnum)), set("newrelic", "NRAK-"+fake(26, upperAlnum))}},
		{"new-relic-user-api-id", []string{set("newrelic_api_id", fake(64, alnum))}, []string{set("newrelic", fake(63, alnum))}},
		{"new-relic-insert-key", []string{set("new_relic_insert_key", "NRII-"+fake(32, alnum))}, []string{set("insert_key", "NRII-"+fake(32, alnum))}},
		{"sentry-access-token", []string{set("SENTRY_AUTH_TOKEN", fake(64, hexa))}, []string{set("sentry", fake(63, hexa))}},
		{
			"sentry-org-token",
			[]string{"SENTRY_AUTH_TOKEN=" + sentryOrg},
			[]string{"sntrys_" + fake(90, alnum) + "_" + fake(43, alnum), sentryOrg[:len(sentryOrg)-1], sentryOrg + "a"},
		},
		{
			"sentry-user-token",
			[]string{"SENTRY_TOKEN=sntryu_" + fake(64, hexa)},
			[]string{"sntryu_" + fake(63, hexa), "sntryu_" + fake(65, hexa), "sntryu_" + strings.Repeat("a", 64)},
		},
		{
			"grafana-api-key",
			[]string{"GRAFANA_API_KEY=eyJrIjoi" + fake(80, alnum) + "=="},
			[]string{"eyJrIjoi" + fake(69, alnum), "eyjrijoi" + fake(80, alnum)},
		},
		{
			"grafana-cloud-api-token",
			[]string{"token: glc_" + fake(60, b64) + "="},
			[]string{"glc_" + strings.Repeat("x", 68), "glc_" + strings.Repeat("1", 42) + "=", "void GLC_CreateLightmapTextureArray(void);"},
		},
		{
			"grafana-service-account-token",
			[]string{"GRAFANA_TOKEN=glsa_" + fake(32, alnum) + "_" + fake(8, hexa)},
			[]string{"glsa_" + strings.Repeat("X", 32) + "_AAAAAAAA", "glsa_" + fake(32, alnum) + "_" + fake(8, alnum[20:])},
		},
		{
			"sumologic-access-id",
			[]string{set("SUMOLOGIC_ACCESSID", "su"+fake(12, alnum)), set("sumo_access_id", "su"+fake(12, alnum))},
			[]string{"sumObj = su" + fake(12, alnum), set("sumologic_access_id", ""), set("sumo_id", "sa"+fake(12, alnum))},
		},
		{
			"sumologic-access-token",
			[]string{set("SUMO_ACCESS_KEY", fake(64, alnum))},
			[]string{"sumOfExposures = " + fake(64, alnum) + ";", "SUMO_ACCESS_KEY: AbCeFG123", set("SUMO_ACCESS_KEY", strings.Repeat("x", 64))},
		},
		{"launchdarkly-access-token", []string{set("LAUNCHDARKLY_SDK_KEY", fake(40, b64uEqual))}, []string{set("launchdarkly", fake(41, alnum)), "LAUNCHDARKLY_MOBILE_KEY_SHA1=" + fake(40, hexa)}},

		// Email
		{
			"sendgrid-api-token",
			[]string{"SENDGRID_API_KEY=SG." + fake(22, b64u) + "." + fake(43, b64u), "Use SG." + fake(22, alnum) + "." + fake(43, alnum) + "."},
			[]string{"SG." + fake(22, alnum) + "." + fake(42, alnum), "msg." + fake(22, alnum) + "." + fake(43, alnum), "sg." + fake(22, alnum) + "." + fake(43, alnum)},
		},
		{
			"sendinblue-api-token",
			[]string{"BREVO_API_KEY=xkeysib-" + fake(64, hexa) + "-" + fake(16, alnum)},
			[]string{"xkeysib-" + fake(64, hexa) + "-" + fake(15, alnum), "xkeysib-" + fake(64, alnum) + "-" + fake(16, alnum)},
		},
		{
			"mailchimp-api-key",
			[]string{set("MAILCHIMP_API_KEY", fake(32, hexa)+"-us18"), "mailchimp.apiKey: " + fake(32, hexa) + "-us12", set("mailchimp_key", fake(32, hexa)+"-us6")},
			[]string{set("mailchimp", fake(32, hexa)+"-eu18"), set("api_key", fake(32, hexa)+"-us18")},
		},
		{"mailgun-private-api-token", []string{set("MAILGUN_API_KEY", "key-"+fake(32, hexa))}, []string{set("mailgun", "key-"+fake(31, hexa)), set("api_key", "key-"+fake(32, hexa))}},
		{
			"mailgun-signing-key",
			[]string{set("mailgun_signing_key", fake(32, "abcdefgh0123456789")+"-"+fake(8, hexa)+"-"+fake(8, hexa))},
			[]string{set("mailgun", fake(32, "ijklmnop0123456789")+"-"+fake(8, hexa)+"-"+fake(8, hexa))},
		},

		// SaaS and developer services
		{"adafruit-api-key", []string{set("ADAFRUIT_IO_KEY", fake(32, b64u))}, []string{set("adafruit", fake(31, alnum))}},
		{"adobe-client-id", []string{set("adobe_client_id", fake(32, hexa))}, []string{set("adobe", strings.Repeat("0", 32))}},
		{"adobe-client-secret", []string{"ADOBE_CLIENT_SECRET=p8e-" + fake(32, alnum)}, []string{"p8e-" + fake(31, alnum), "p8e-" + strings.Repeat("a", 32)}},
		{
			"age-secret-key",
			[]string{"# created: 2026\nAGE-SECRET-KEY-1" + fake(58, bech32)},
			[]string{"AGE-SECRET-KEY-1" + fake(57, bech32), "AGE-SECRET-KEY-1" + fake(58, upperAlnum[:26])},
		},
		{
			"airtable-api-key",
			[]string{set("AIRTABLE_API_KEY", fake(17, alnum)), set("AIRTABLE_API_KEY", "key"+fake(14, alnum))},
			[]string{set("airtable", fake(18, alnum)), "AIRTABLE_BASE_ID=app" + fake(14, alnum), `airtable_table_id: "tbl` + fake(14, alnum) + `"`, "const airtableView = 'viw" + fake(14, alnum) + "'"},
		},
		{
			"airtable-personal-access-token",
			[]string{"AIRTABLE_TOKEN=pat" + fake(14, alnum) + "." + fake(64, hexa), `"pat` + fake(14, alnum) + "." + fake(64, hexa) + `"`},
			[]string{"pat" + fake(14, alnum) + "." + fake(63, hexa), "xpat" + fake(14, alnum) + "." + fake(64, hexa), "Pat" + fake(14, alnum) + "." + fake(64, hexa), "path/to/pattern." + fake(64, hexa)},
		},
		{"algolia-api-key", []string{set("ALGOLIA_ADMIN_KEY", fake(32, alnum))}, []string{set("algolia", fake(31, alnum))}},
		{"asana-client-secret", []string{set("asana_client_secret", fake(32, alnum))}, []string{set("asana", fake(16, digits))}},
		{
			"authress-service-client-access-key",
			[]string{
				"AUTHRESS_KEY=sc_" + fake(20, alnum) + "." + fake(5, alnum) + ".acc_" + fake(20, alnum) + "." + fake(60, b64),
				"authress_" + fake(10, alnum) + "." + fake(4, alnum) + ".acc-" + fake(16, alnum) + "." + fake(40, b64u),
			},
			[]string{"sc_" + fake(20, alnum) + "." + fake(5, alnum) + ".ACC_" + fake(20, alnum) + "." + fake(60, b64), "next_" + fake(20, alnum) + "." + fake(5, alnum) + ".acc_" + fake(20, alnum) + "." + fake(60, alnum)},
		},
		{
			"beamer-api-token",
			[]string{set("BEAMER_API_KEY", "b_"+fake(44, b64uEqual))},
			[]string{"│   ├── R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu", set("beamer", "c_"+fake(44, alnum))},
		},
		{
			"cisco-meraki-api-key",
			[]string{set("MERAKI_API_KEY", fake(40, hexa)), set("meraki_dashboard_key", fake(40, hexa))},
			[]string{"meraki: " + strings.Repeat("a", 10) + strings.Repeat("1", 10) + strings.Repeat("b", 10) + strings.Repeat("2", 10), "meraki-api-key: " + fake(40, upperHex), "ReactNativeCameraKit: " + fake(40, hexa)},
		},
		{
			"clickhouse-cloud-api-secret-key",
			[]string{"key = 4b1d" + fake(38, alnum)},
			[]string{"key = 4b1d" + strings.Repeat("X", 38), "key = adf4b1d" + fake(38, alnum), "sha256:" + fake(20, hexa) + "4b1d" + fake(40, hexa)},
		},
		{"confluent-access-token", []string{set("CONFLUENT_API_KEY", fake(16, upperAlnum))}, []string{set("confluent", fake(17, alnum))}},
		{"confluent-secret-key", []string{set("confluent_secret", fake(64, alnum))}, []string{set("confluent", fake(63, alnum))}},
		{"contentful-delivery-api-token", []string{set("CONTENTFUL_ACCESS_TOKEN", fake(43, b64u))}, []string{set("contentful", fake(42, alnum))}},
		{"dropbox-api-token", []string{set("dropbox_app_secret", fake(15, lowerAlnum))}, []string{set("dropbox", fake(14, alnum))}},
		{"dropbox-long-lived-api-token", []string{set("DROPBOX_TOKEN", fake(11, alnum)+"AAAAAAAAAA"+fake(43, b64u))}, []string{set("dropbox", fake(11, alnum)+"AAAAAAAAAB"+fake(43, alnum))}},
		{"dropbox-short-lived-api-token", []string{set("dropbox_token", "sl."+fake(135, b64u))}, []string{set("dropbox_token", "sl."+fake(134, alnum))}},
		{
			"etsy-access-token",
			[]string{set("ETSY_API_KEY", fake(24, lowerAlnum)), set("etsy_key", fake(24, alnum))},
			[]string{`SetSysctl = "` + fake(24, alnum) + `"`, set("etsy", fake(23, alnum))},
		},
		{"facebook-secret", []string{set("FACEBOOK_APP_SECRET", fake(32, hexa))}, []string{set("facebook", strings.Repeat("0", 32))}},
		{
			"facebook-access-token",
			[]string{set("facebook_token", fake(16, digits)+"|"+fake(32, b64u)), "facebook: " + fake(15, digits) + "%" + fake(30, alnum)},
			[]string{set("token", fake(16, digits)+"|"+fake(32, alnum)), set("facebook", fake(14, digits)+"|"+fake(32, alnum))},
		},
		{
			"facebook-page-access-token",
			[]string{"FACEBOOK_TOKEN=EAAM" + fake(150, alnum), `value: "EAAC` + fake(100, alnum) + `"`},
			[]string{"eaaa" + fake(36, hexa), "checksum: eaac" + fake(124, hexa), "EAAM" + fake(99, alnum)},
		},
		{"fastly-api-token", []string{set("FASTLY_API_TOKEN", fake(32, b64u))}, []string{set("fastly", fake(31, alnum)), `fastly_purge_key: "` + fake(32, hexa) + `"`}},
		{"flickr-access-token", []string{set("flickr_api_key", fake(32, alnum))}, []string{set("flickr", fake(33, alnum))}},
		{"frameio-api-token", []string{"FRAMEIO_TOKEN=fio-u-" + fake(64, b64uEqual)}, []string{"fio-u-" + fake(63, alnum), "fio-u-" + strings.Repeat("a", 64)}},
		{
			"freemius-secret-key",
			[]string{
				"$config = array(\n\t\"secret_key\" => \"sk_" + fake(29, b64) + "\",\n);",
				"'SECRET_KEY' => 'sk_" + fake(29, alnum) + "'",
				"'secret_key'" + strings.Repeat(" ", 40) + "=> 'sk_" + fake(29, alnum) + "',", // an aligned array
			},
			[]string{"secret_key => \"sk_" + fake(29, alnum) + "\"", "\"secret_key\" => sk_" + fake(29, alnum) + ",", "\"other_key\" => \"sk_" + fake(29, alnum) + "\""},
		},
		{"freshbooks-access-token", []string{set("FRESHBOOKS_TOKEN", fake(64, alnum))}, []string{set("freshbooks", fake(65, alnum))}},
		{"hubspot-api-key", []string{set("HUBSPOT_API_KEY", strings.ToUpper(uuid)), set("hubspot_token", uuid), "url?hapikey=" + uuid + " ", "https://api.hubapi.local/contacts/v1/lists?hapikey=" + uuid + "&count=2", "lists?hapikey=" + uuid + "#top", "lists?hapikey=" + uuid}, []string{set("api_key", uuid), set("hubspot_form_id", uuid), set("hubspot_portal", uuid)}},
		{
			"intra42-client-secret",
			[]string{"INTRA_SECRET=s-s4t2ud-" + fake(64, hexa), "s-s4t2af-" + fake(64, hexa)},
			[]string{"s-s4t2ud-" + fake(63, hexa), "s-s4t2xx-" + fake(64, hexa)},
		},
		{"linear-api-key", []string{"LINEAR_API_KEY=lin_api_" + fake(40, alnum)}, []string{"lin_api_" + fake(39, alnum), "lin_api_" + strings.Repeat("a", 40)}},
		{
			"linear-client-secret",
			[]string{set("LINEAR_CLIENT_SECRET", fake(32, hexa))},
			[]string{"background: linear-gradient(#" + fake(6, hexa) + ", #" + fake(6, hexa) + ");", set("linear", fake(31, hexa))},
		},
		{"linkedin-client-id", []string{set("LINKEDIN_CLIENT_ID", fake(14, lowerAlnum))}, []string{set("linkedin", fake(13, alnum))}},
		{"linkedin-client-secret", []string{set("linked_in_secret", fake(16, alnum))}, []string{set("linkedin", fake(17, alnum))}},
		{
			"lob-api-key",
			[]string{set("LOB_API_KEY", "live_"+fake(35, hexa)), set("lob_key", "test_"+fake(35, hexa))},
			[]string{set("lob_key", "prod_"+fake(35, hexa)), set("api_key", "live_"+fake(35, hexa)), set("lob", "live_"+fake(34, hexa))},
		},
		{"looker-client-id", []string{set("LOOKER_CLIENT_ID", fake(20, alnum))}, []string{set("looker", fake(21, alnum))}},
		{"looker-client-secret", []string{set("looker_client_secret", fake(24, alnum))}, []string{set("looker", fake(23, alnum))}},
		{
			"maxmind-license-key",
			[]string{"MAXMIND_LICENSE_KEY=" + fake(6, alnum) + "_" + fake(29, alnum) + "_mmk"},
			[]string{fake(6, alnum) + "_" + fake(28, alnum) + "_mmk", fake(6, alnum) + "_" + fake(29, alnum) + "_MMK"},
		},
		{
			"notion-api-token",
			[]string{"NOTION_TOKEN=ntn_" + fake(11, digits) + fake(35, alnum)},
			[]string{"ntn_" + fake(11, digits), "ntn_" + fake(56, digits), "ntn_" + fake(11, digits) + "abc"},
		},
		{"nytimes-access-token", []string{set("NYTIMES_API_KEY", fake(32, b64u)), set("new-york-times-key", fake(32, alnum))}, []string{set("nytimes", fake(33, alnum))}},
		{
			"okta-access-token",
			[]string{set("OKTA_API_TOKEN", "00"+fake(40, b64u)), set("oktaKey", "00"+fake(40, alnum))},
			[]string{"oktaKey = " + strings.Repeat("0", 35) + "TUVWXYZ", "rookTable = 00" + fake(40, alnum)},
		},
		{
			"planetscale-token",
			[]string{"PLANETSCALE_TOKEN=pscale_tkn_" + fake(43, b64u), "pscale_oauth_" + fake(32, alnum), "password: pscale_pw_" + fake(43, b64u)},
			[]string{"pscale_tkn_" + fake(31, alnum), "pscale_key_" + fake(43, alnum)},
		},
		{"postman-api-token", []string{"POSTMAN_API_KEY=PMAK-" + fake(24, hexa) + "-" + fake(34, hexa)}, []string{"PMAK-" + fake(24, hexa) + "-" + fake(33, hexa), "pmak-" + fake(24, hexa) + "-" + fake(34, hexa)}},
		{"rapidapi-access-token", []string{set("X_RAPIDAPI_KEY", fake(50, b64u))}, []string{set("rapidapi", fake(49, alnum))}},
		{
			"readme-api-token",
			[]string{"README_API_KEY=rdme_" + fake(70, lowerAlnum)},
			[]string{"const API_KEY = 'rdme_" + strings.Repeat("X", 70) + "';", "rdme_" + strings.Repeat("x", 70), "rdme_" + fake(69, lowerAlnum)},
		},
		{
			"settlemint-access-token",
			[]string{`token := "sm_aat_` + fake(16, alnum) + `"`, "sm_pat_" + fake(16, alnum), "sm_sat_" + fake(16, alnum)},
			[]string{`token := "` + fake(16, alnum) + `"`, `token := "sm_pat_` + fake(10, alnum) + `"`},
		},
		{
			"shopify-token",
			[]string{"SHOPIFY_TOKEN=shpat_" + fake(32, hexa), "shpca_" + fake(32, hexa), "shppa_" + fake(32, upperHex), "shpss_" + fake(32, hexa)},
			[]string{"shpat_" + fake(31, hexa), "shpxx_" + fake(32, hexa), "shpat_" + strings.Repeat("0", 32)},
		},
		{"sidekiq-secret", []string{"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=" + fake(8, hexa) + ":" + fake(8, hexa)}, []string{"BUNDLE_GEMS__CONTRIBSYS__COM=" + fake(8, hexa) + ":" + fake(7, hexa)}},
		{
			"sidekiq-sensitive-url",
			[]string{"source \"https://" + fake(8, hexa) + ":" + fake(8, hexa) + "@gems.contribsys.com/\"", "http://" + fake(8, hexa) + ":" + fake(8, hexa) + "@enterprise.contribsys.com#", "https://" + fake(8, hexa) + ":" + fake(8, hexa) + "@gems.contribsys.com\n", "https://" + fake(8, hexa) + ":" + fake(8, hexa) + "@GEMS.CONTRIBSYS.COM/"},
			[]string{"https://" + fake(8, hexa) + ":" + fake(8, hexa) + "@gems.contribsys.company", "https://user:pass@gems.contribsys.com/"},
		},
		{"snyk-api-token", []string{set("SNYK_TOKEN", uuid), set("snyk_api_key", uuid)}, []string{set("snyk_org", uuid)}},
		{"squarespace-access-token", []string{set("SQUARESPACE_API_KEY", uuid)}, []string{set("square_key", uuid)}},
		{"trello-access-token", []string{set("TRELLO_TOKEN", fake(32, alnum)), set("trello_api_key", fake(20, alnum)+"-"+fake(11, alnum)), set("TRELLO_TOKEN", fake(64, hexa)), "trello_token: " + fake(64, hexa) + "\n"}, []string{set("trello", fake(31, alnum)), set("trello", strings.Repeat("ab", 16))}},
		{"twitch-api-token", []string{set("TWITCH_CLIENT_SECRET", fake(30, lowerAlnum))}, []string{set("twitch", fake(31, alnum))}},
		{"twitter-api-key", []string{set("TWITTER_API_KEY", fake(25, alnum))}, []string{set("twitter", fake(26, alnum))}},
		{"twitter-api-secret", []string{set("twitter_api_secret", fake(50, alnum))}, []string{set("twitter", fake(49, alnum))}},
		{"twitter-access-token", []string{set("TWITTER_ACCESS_TOKEN", fake(19, digits)+"-"+fake(30, alnum))}, []string{set("twitter", fake(14, digits)+"-"+fake(30, alnum))}},
		{"twitter-access-secret", []string{set("twitter_access_secret", fake(45, alnum))}, []string{set("twitter", fake(44, alnum))}},
		{
			"twitter-bearer-token",
			[]string{set("TWITTER_BEARER_TOKEN", strings.Repeat("A", 22)+fake(60, alnum)+"%3D"+fake(30, alnum))},
			[]string{set("twitter", strings.Repeat("A", 21)+"B"+fake(80, alnum))},
		},
		{"typeform-api-token", []string{set("TYPEFORM_TOKEN", "tfp_"+fake(59, b64u))}, []string{set("token", "tfp_"+fake(59, alnum)), set("typeform", "tfp_"+fake(58, alnum))}},
		{
			"yandex-access-token",
			[]string{set("YANDEX_IAM_TOKEN", "t1."+fake(200, b64u)+"."+fake(86, b64u))},
			[]string{set("yandex", "t1."+fake(40, alnum)+"."+fake(85, alnum)), set("token", "t1."+fake(40, alnum)+"."+fake(86, alnum))},
		},
		{"yandex-api-key", []string{set("YANDEX_API_KEY", "AQVN"+fake(36, b64u))}, []string{set("yandex", "AQVN"+fake(34, alnum))}},
		{"yandex-aws-access-token", []string{set("yandex_access_key", "YC"+fake(38, b64u))}, []string{set("yandex", "YC"+fake(37, alnum))}},
		{"zendesk-secret-key", []string{set("ZENDESK_API_TOKEN", fake(40, alnum))}, []string{set("zendesk", fake(39, alnum)), "zendesk_ticket_hash = " + fake(40, hexa)}},
	}
}

// Text full of the new rules' short or common keywords (sk, sg., pat, lob,
// eaaa, 4b1d, sc_, ext_) is scanned whole and fast, and a token after it is
// found.
func TestServiceRuleKeywordsAreCheap(t *testing.T) {
	d := defaultRulesDetector(t)
	for name, unit := range map[string]string{
		"sk":     "task SK SKSK ask Sk ",
		"sk hex": "SK" + strings.Repeat("a", 31) + " ",
		// these pass the hit check, so the regex runs on every one
		"SK shape":   "SK" + fake(32, hexa) + "x ",
		"EAAA shape": "EAAA" + fake(22, b64u) + "+ ",
		"lob shape":  "lob = live_" + fake(35, hexa) + "x ",
		"sg":         "msg.SG. MSG.x sg.",
		"pat":        "path pattern pat. Pat " + "pat" + strings.Repeat("a", 14) + ". ",
		"lob":        "global blob lob = live_ lob_test_" + strings.Repeat("a", 34) + " ",
		"eaaa":       "EAAA eaaa EAAM EAAC ",
		"4b1d":       "4b1d 4B1D ",
		"sc ext":     "sc_ ext_ next_ text_ scauth_ authress_ ",
		"twitter":    "twitter = x ",
		"facebook":   "facebook = 123456789012345|",
		"mmk":        "_mmk",
		"duplicate":  "sm_aat_ sm_pat_ shpat_ glc_ rdme_ ntn_ ",
	} {
		content := append(repeatTo(unit, 2<<20/slowdown), []byte("\nghp_"+fake(36, alnum)+"\n")...)
		start := time.Now()
		fs, complete := d.Scan(content)
		assert.Less(t, time.Since(start), 2*time.Second*slowdown, name)
		assert.True(t, complete, name)
		assert.Equal(t, 1, countRuleIn(fs, "github-token"), name)
	}
}

// Twilio's documented call, curl -u SK<id>:<secret>, is reported as the pair,
// so the finding covers the secret and not only the key's ID.
func TestCurlUserPairCoversServiceID(t *testing.T) {
	d := defaultRulesDetector(t)
	secret := fake(32, alnum)
	content := "curl -X POST https://api.local -u SK" + fake(32, hexa) + ":" + secret + " -d x=1"
	fs := scanOf(d, []byte(content))
	if assert.Len(t, fs, 1) {
		assert.Equal(t, "curl-auth-user", fs[0].RuleID)
		assert.Contains(t, content[fs[0].Start:fs[0].End], secret)
	}
}
