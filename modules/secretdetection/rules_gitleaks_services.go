// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// NOTICE: the rules below are adapted from gitleaks v8.30.1 under the MIT
// licence; its full text and the list of changes are in rules_gitleaks.go.

package secretdetection

import (
	"bytes"
	"strings"
)

const uuidPattern = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// gitleaksServiceRules: chat, SaaS, payment, monitoring and email services.
var gitleaksServiceRules = []Rule{
	// Chat and messaging
	{
		ID: "discord-api-token", Name: "Discord API token", Type: "discord",
		Keywords:    []string{"discord"},
		Regex:       assignRegex(`discord`, `[a-fA-F0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "discord-client-secret", Name: "Discord client secret", Type: "discord",
		Keywords:    []string{"discord"},
		Regex:       assignRegex(`discord`, `[A-Za-z0-9=_-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "telegram-bot-api-token", Name: "Telegram bot token", Type: "telegram",
		Keywords:    []string{"telegr"},
		Regex:       assignRegex(`telegr`, `[0-9]{5,16}:A[A-Za-z0-9_-]{34}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "mattermost-access-token", Name: "Mattermost access token", Type: "mattermost",
		Keywords:    []string{"mattermost"},
		Regex:       assignRegex(`mattermost`, `[A-Za-z0-9]{26}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "microsoft-teams-webhook", Name: "Microsoft Teams webhook URL", Type: "microsoft-teams",
		Keywords:    []string{"webhook.office.com"},
		Regex:       `(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 300,
	},
	{
		ID: "gitter-access-token", Name: "Gitter access token", Type: "gitter",
		Keywords:    []string{"gitter"},
		Regex:       assignRegex(`gitter`, `[A-Za-z0-9_-]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "sendbird-access-id", Name: "Sendbird application ID", Type: "sendbird",
		Keywords:    []string{"sendbird"},
		Regex:       assignRegex(`sendbird`, uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "sendbird-access-token", Name: "Sendbird API token", Type: "sendbird",
		Keywords:    []string{"sendbird"},
		Regex:       assignRegex(`sendbird`, `[a-fA-F0-9]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "messagebird-api-token", Name: "MessageBird API key", Type: "messagebird",
		Keywords:    []string{"messagebird", "message-bird", "message_bird"},
		Regex:       assignRegex(`message[_-]?bird`, `[A-Za-z0-9]{25}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "messagebird-client-id", Name: "MessageBird client ID", Type: "messagebird",
		Keywords:    []string{"messagebird", "message-bird", "message_bird"},
		Regex:       assignRegex(`message[_-]?bird`, uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twilio-api-key", Name: "Twilio API key", Type: "twilio",
		Keywords:    []string{"sk"},
		Regex:       `(SK[0-9a-fA-F]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 40, Anchored: true, HitCheck: shapeHit(32, isHex, "SK"),
	},
	{
		ID: "intercom-api-key", Name: "Intercom access token", Type: "intercom",
		Keywords:    []string{"intercom"},
		Regex:       assignRegex(`intercom`, `[A-Za-z0-9=_-]{60}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},

	// Payments, banking and crypto exchanges
	{
		// sq0atp- or EAAA; + and / count as glued and the token must end as
		// gitleaks' does (a quote, a blank, ; or the end), so base64 data is no
		// token.
		ID: "square-access-token", Name: "Square access token", Type: "square",
		Keywords:    []string{"sq0atp-", "eaaa"},
		Regex:       `((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|\z)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars + "+/", Window: 72, Anchored: true, HitCheck: shapeHit(22, isWordOrDash, "EAAA", "sq0atp-"),
	},
	{
		ID: "square-secret", Name: "Square OAuth application secret", Type: "square",
		Keywords:    []string{"sq0csp-"},
		Regex:       `(sq0csp-[\w-]{43})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 56, Anchored: true, HitCheck: prefixHit(50, "sq0csp-"),
	},
	{
		ID: "flutterwave-secret-key", Name: "Flutterwave secret key", Type: "flutterwave",
		Keywords:    []string{"flwseck_test-"},
		Regex:       `(FLWSECK_TEST-[a-hA-H0-9]{32}-X)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 40, Anchored: true, HitCheck: prefixHit(47, "FLWSECK_TEST-"),
	},
	{
		ID: "flutterwave-encryption-key", Name: "Flutterwave encryption key", Type: "flutterwave",
		Keywords:    []string{"flwseck_test-"},
		Regex:       `(FLWSECK_TEST-[a-hA-H0-9]{12})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 16, Anchored: true, HitCheck: prefixHit(25, "FLWSECK_TEST-"),
	},
	{
		ID: "gocardless-api-token", Name: "GoCardless access token", Type: "gocardless",
		Keywords:    []string{"gocardless"},
		Regex:       assignRegex(`gocardless`, `live_[A-Za-z0-9=_-]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "plaid-api-token", Name: "Plaid access token", Type: "plaid",
		Keywords:    []string{"plaid"},
		Regex:       assignRegex(`plaid`, `access-(?:sandbox|development|production)-`+uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "plaid-client-id", Name: "Plaid client ID", Type: "plaid",
		Keywords:    []string{"plaid"},
		Regex:       assignRegex(`plaid`, `[A-Za-z0-9]{24}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "plaid-secret-key", Name: "Plaid secret", Type: "plaid",
		Keywords:    []string{"plaid"},
		Regex:       assignRegex(`plaid`, `[A-Za-z0-9]{30}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "coinbase-access-token", Name: "Coinbase access token", Type: "coinbase",
		Keywords:    []string{"coinbase"},
		Regex:       assignRegex(`coinbase`, `[A-Za-z0-9_-]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "kraken-access-token", Name: "Kraken API key", Type: "kraken",
		Keywords:    []string{"kraken"},
		Regex:       assignRegex(`kraken`, `[A-Za-z0-9/=_+-]{80,90}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "kucoin-access-token", Name: "KuCoin API key", Type: "kucoin",
		Keywords:    []string{"kucoin"},
		Regex:       assignRegex(`kucoin`, `[a-fA-F0-9]{24}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "kucoin-secret-key", Name: "KuCoin API secret", Type: "kucoin",
		Keywords:    []string{"kucoin"},
		Regex:       assignRegex(`kucoin`, uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// gitleaks' bittrex-access-key and bittrex-secret-key have one shape.
		ID: "bittrex-api-key", Name: "Bittrex API key or secret", Type: "bittrex",
		Keywords:    []string{"bittrex"},
		Regex:       assignRegex(`bittrex`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "finicity-api-token", Name: "Finicity API key", Type: "finicity",
		Keywords:    []string{"finicity"},
		Regex:       assignRegex(`finicity`, `[a-fA-F0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "finicity-client-secret", Name: "Finicity client secret", Type: "finicity",
		Keywords:    []string{"finicity"},
		Regex:       assignRegex(`finicity`, `[A-Za-z0-9]{20}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "finnhub-access-token", Name: "Finnhub API key", Type: "finnhub",
		Keywords:    []string{"finnhub"},
		Regex:       assignRegex(`finnhub`, `[A-Za-z0-9]{20}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "duffel-api-token", Name: "Duffel API token", Type: "duffel",
		Keywords:    []string{"duffel_test_", "duffel_live_"},
		Regex:       `(duffel_(?:test|live)_[A-Za-z0-9=_-]{43})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 48, Anchored: true, HitCheck: prefixHit(55, "duffel_test_", "duffel_live_"),
	},
	{
		ID: "shippo-api-token", Name: "Shippo API token", Type: "shippo",
		Keywords:    []string{"shippo_live_", "shippo_test_"},
		Regex:       `(shippo_(?:live|test)_[a-fA-F0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(52, "shippo_live_", "shippo_test_"),
	},
	{
		ID: "easypost-api-token", Name: "EasyPost API key", Type: "easypost",
		Keywords:    []string{"ezak"},
		Regex:       `(EZAK[A-Za-z0-9]{54})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", Window: 64, Anchored: true, HitCheck: prefixHit(58, "EZAK"),
	},
	{
		ID: "easypost-test-api-token", Name: "EasyPost test API key", Type: "easypost",
		Keywords:    []string{"eztk"},
		Regex:       `(EZTK[A-Za-z0-9]{54})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", Window: 64, Anchored: true, HitCheck: prefixHit(58, "EZTK"),
	},

	// Monitoring and observability
	{
		ID: "datadog-access-token", Name: "Datadog access token", Type: "datadog",
		Keywords:    []string{"datadog"},
		Regex:       assignRegex(`datadog`, `[A-Za-z0-9]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "dynatrace-api-token", Name: "Dynatrace API token", Type: "dynatrace",
		Keywords:    []string{"dt0c01."},
		Regex:       `(dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars, Window: 96, Anchored: true, HitCheck: prefixHit(96, "dt0c01."),
	},
	{
		ID: "new-relic-user-api-key", Name: "New Relic user API key", Type: "new-relic",
		Keywords:    []string{"nrak-"},
		Regex:       assignRegex(`new[_-]?relic`, `NRAK-[A-Za-z0-9]{27}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "new-relic-user-api-id", Name: "New Relic user API ID", Type: "new-relic",
		Keywords:    []string{"new-relic", "newrelic", "new_relic"},
		Regex:       assignRegex(`new[_-]?relic`, `[A-Za-z0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "new-relic-insert-key", Name: "New Relic insert key", Type: "new-relic",
		Keywords:    []string{"nrii-"},
		Regex:       assignRegex(`new[_-]?relic`, `NRII-[A-Za-z0-9-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "sentry-access-token", Name: "Sentry access token", Type: "sentry",
		Keywords:    []string{"sentry"},
		Regex:       assignRegex(`sentry`, `[a-fA-F0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// base64 JSON with "iat" first and a "region_url", then _ and 43 bytes
		ID: "sentry-org-token", Name: "Sentry organization token", Type: "sentry",
		Keywords:    []string{"sntrys_eyjpyxqio"},
		Regex:       `(sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43})`,
		SecretGroup: 1, MinEntropy: 4.5, TokenChars: alnumChars + "+/", Window: 512, Anchored: true, HitCheck: prefixHit(96, "sntrys_eyJpYXQiO"),
	},
	{
		ID: "sentry-user-token", Name: "Sentry user token", Type: "sentry",
		Keywords:    []string{"sntryu_"},
		Regex:       `(sntryu_[a-f0-9]{64})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(71, "sntryu_"),
	},
	{
		ID: "grafana-api-key", Name: "Grafana API key", Type: "grafana",
		Keywords:    []string{"eyjrijoi"},
		Regex:       `(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", Window: 416, Anchored: true, HitCheck: prefixHit(78, "eyJrIjoi"),
	},
	{
		ID: "grafana-cloud-api-token", Name: "Grafana Cloud API token", Type: "grafana",
		Keywords:    []string{"glc_"},
		Regex:       `(glc_[A-Za-z0-9+/]{32,400}={0,3})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", Window: 416, Anchored: true, HitCheck: prefixHit(36, "glc_"),
	},
	{
		ID: "grafana-service-account-token", Name: "Grafana service account token", Type: "grafana",
		Keywords:    []string{"glsa_"},
		Regex:       `(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(46, "glsa_"),
	},
	{
		// Sumo, SUMO, sumo: not sumOfValues
		ID: "sumologic-access-id", Name: "Sumo Logic access ID", Type: "sumologic",
		Keywords:    []string{"sumo"},
		Regex:       assignRegex(`(?-i:[Ss]umo|SUMO)`, `su[A-Za-z0-9]{12}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "sumologic-access-token", Name: "Sumo Logic access key", Type: "sumologic",
		Keywords:    []string{"sumo"},
		Regex:       assignRegex(`(?-i:[Ss]umo|SUMO)`, `[A-Za-z0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "launchdarkly-access-token", Name: "LaunchDarkly access token", Type: "launchdarkly",
		Keywords:    []string{"launchdarkly"},
		Regex:       assignRegex(`launchdarkly`, `[A-Za-z0-9=_-]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Check: notHex, // a hex value is a digest
	},

	// Email
	{
		ID: "sendgrid-api-token", Name: "SendGrid API key", Type: "sendgrid",
		Keywords:    []string{"sg."},
		Regex:       `(SG\.[A-Za-z0-9=_.-]{66})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "_.-", TrailingOK: ".", Window: 72, Anchored: true, HitCheck: prefixHit(69, "SG."),
	},
	{
		ID: "sendinblue-api-token", Name: "Brevo (Sendinblue) API key", Type: "sendinblue",
		Keywords:    []string{"xkeysib-"},
		Regex:       `(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 96, Anchored: true, HitCheck: prefixHit(89, "xkeysib-"),
	},
	{
		ID: "mailchimp-api-key", Name: "Mailchimp API key", Type: "mailchimp",
		Keywords:    []string{"mailchimp"},
		Regex:       assignRegex(`mailchimp`, `[a-fA-F0-9]{32}-us\d{1,2}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "mailgun-private-api-token", Name: "Mailgun private API key", Type: "mailgun",
		Keywords:    []string{"mailgun"},
		Regex:       assignRegex(`mailgun`, `key-[a-fA-F0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "mailgun-signing-key", Name: "Mailgun webhook signing key", Type: "mailgun",
		Keywords:    []string{"mailgun"},
		Regex:       assignRegex(`mailgun`, `[a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},

	// SaaS and developer services
	{
		ID: "adafruit-api-key", Name: "Adafruit IO key", Type: "adafruit",
		Keywords:    []string{"adafruit"},
		Regex:       assignRegex(`adafruit`, `[A-Za-z0-9_-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "adobe-client-id", Name: "Adobe client ID", Type: "adobe",
		Keywords:    []string{"adobe"},
		Regex:       assignRegex(`adobe`, `[a-fA-F0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "adobe-client-secret", Name: "Adobe client secret", Type: "adobe",
		Keywords:    []string{"p8e-"},
		Regex:       `(p8e-[A-Za-z0-9]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 40, Anchored: true, HitCheck: prefixHit(36, "p8e-"),
	},
	{
		ID: "age-secret-key", Name: "age secret key", Type: "age",
		Keywords:    []string{"age-secret-key-1"},
		Regex:       `(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 64, Anchored: true, HitCheck: prefixHit(74, "AGE-SECRET-KEY-1"),
	},
	{
		ID: "airtable-api-key", Name: "Airtable API key", Type: "airtable",
		Keywords:    []string{"airtable"},
		Regex:       assignRegex(`airtable`, `[A-Za-z0-9]{17}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
		Allowlist: []string{`^(?:app|tbl|viw|fld|rec|sel|usr|wsp)`}, // base, table, view … IDs
	},
	{
		// gitleaks gates it on the word airtable anywhere in the file; here
		// on its own shape: pat, 14 alphanumerics, a dot and 64 hex digits.
		ID: "airtable-personal-access-token", Name: "Airtable personal access token", Type: "airtable",
		Keywords:    []string{"pat"},
		Regex:       `(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 80, Anchored: true, HitCheck: airtablePATHit,
	},
	{
		ID: "algolia-api-key", Name: "Algolia API key", Type: "algolia",
		Keywords:    []string{"algolia"},
		Regex:       assignRegex(`algolia`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "asana-client-secret", Name: "Asana client secret", Type: "asana",
		Keywords:    []string{"asana"},
		Regex:       assignRegex(`asana`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "authress-service-client-access-key", Name: "Authress service client access key", Type: "authress",
		Keywords:    []string{"sc_", "ext_", "scauth_", "authress_"},
		Regex:       `((?:sc|ext|scauth|authress)_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.acc[_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+/_=-]{30,120})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars + "+/", Window: 200, Anchored: true, HitCheck: prefixHit(56, "sc_", "ext_", "scauth_", "authress_"),
	},
	{
		ID: "beamer-api-token", Name: "Beamer API key", Type: "beamer",
		Keywords:    []string{"beamer"},
		Regex:       assignRegex(`beamer`, `b_[A-Za-z0-9=_-]{44}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// Meraki, meraki, MERAKI: not CameraKit
		ID: "cisco-meraki-api-key", Name: "Cisco Meraki API key", Type: "cisco-meraki",
		Keywords:    []string{"meraki"},
		Regex:       assignRegex(`(?-i:[Mm]eraki|MERAKI)`, `[0-9a-f]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "clickhouse-cloud-api-secret-key", Name: "ClickHouse Cloud API secret", Type: "clickhouse",
		Keywords:    []string{"4b1d"},
		Regex:       `(4b1d[A-Za-z0-9]{38})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 40, Anchored: true, HitCheck: prefixHit(42, "4b1d"),
	},
	{
		ID: "confluent-access-token", Name: "Confluent API key", Type: "confluent",
		Keywords:    []string{"confluent"},
		Regex:       assignRegex(`confluent`, `[A-Za-z0-9]{16}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "confluent-secret-key", Name: "Confluent API secret", Type: "confluent",
		Keywords:    []string{"confluent"},
		Regex:       assignRegex(`confluent`, `[A-Za-z0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "contentful-delivery-api-token", Name: "Contentful delivery API token", Type: "contentful",
		Keywords:    []string{"contentful"},
		Regex:       assignRegex(`contentful`, `[A-Za-z0-9=_-]{43}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "dropbox-api-token", Name: "Dropbox API secret", Type: "dropbox",
		Keywords:    []string{"dropbox"},
		Regex:       assignRegex(`dropbox`, `[A-Za-z0-9]{15}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "dropbox-long-lived-api-token", Name: "Dropbox long-lived API token", Type: "dropbox",
		Keywords:    []string{"dropbox"},
		Regex:       assignRegex(`dropbox`, `[A-Za-z0-9]{11}AAAAAAAAAA[A-Za-z0-9_=-]{43}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "dropbox-short-lived-api-token", Name: "Dropbox short-lived API token", Type: "dropbox",
		Keywords:    []string{"dropbox"},
		Regex:       assignRegex(`dropbox`, `sl\.[A-Za-z0-9=_-]{135}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// Etsy, etsy, ETSY: not SetSysctl
		ID: "etsy-access-token", Name: "Etsy API key", Type: "etsy",
		Keywords:    []string{"etsy"},
		Regex:       assignRegex(`(?-i:ETSY|[Ee]tsy)`, `[A-Za-z0-9]{24}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "facebook-secret", Name: "Facebook app secret", Type: "facebook",
		Keywords:    []string{"facebook"},
		Regex:       assignRegex(`facebook`, `[a-fA-F0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// An app access token, app ID|app secret; gitleaks takes it anywhere
		// in a file that says facebook, here near the word.
		ID: "facebook-access-token", Name: "Facebook app access token", Type: "facebook",
		Keywords:    []string{"facebook"},
		Regex:       `([0-9]{15,16}[|%][0-9A-Za-z_-]{27,40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: assignWindow,
	},
	{
		ID: "facebook-page-access-token", Name: "Facebook page access token", Type: "facebook",
		Keywords:    []string{"eaam", "eaac"},
		Regex:       `(EAA[MC][A-Za-z0-9]{100,})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars, Window: 1024, Anchored: true, HitCheck: prefixHit(104, "EAAM", "EAAC"),
	},
	{
		ID: "fastly-api-token", Name: "Fastly API token", Type: "fastly",
		Keywords:    []string{"fastly"},
		Regex:       assignRegex(`fastly`, `[A-Za-z0-9=_-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Check: notHex,
	},
	{
		ID: "flickr-access-token", Name: "Flickr API key", Type: "flickr",
		Keywords:    []string{"flickr"},
		Regex:       assignRegex(`flickr`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "frameio-api-token", Name: "Frame.io API token", Type: "frameio",
		Keywords:    []string{"fio-u-"},
		Regex:       `(fio-u-[A-Za-z0-9=_-]{64})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 72, Anchored: true, HitCheck: prefixHit(70, "fio-u-"),
	},
	{
		// PHP: 'secret_key' => 'sk_…', also in an aligned array
		ID: "freemius-secret-key", Name: "Freemius secret key", Type: "freemius",
		Keywords:    []string{"secret_key"},
		Regex:       `(?i:["']secret_key["']\s{0,40}=>\s{0,8}["'])(sk_\S{29})["']`,
		SecretGroup: 1, MinEntropy: 3, Window: 128,
	},
	{
		ID: "freshbooks-access-token", Name: "FreshBooks access token", Type: "freshbooks",
		Keywords:    []string{"freshbooks"},
		Regex:       assignRegex(`freshbooks`, `[A-Za-z0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// hapikey is a query parameter, so & and # end the key too
		ID: "hubspot-api-key", Name: "HubSpot API key", Type: "hubspot",
		Keywords:    []string{"hubspot", "hapikey"},
		Regex:       strings.Replace(assignRegex(`hubspot[_.-]?(?:api[_.-]?)?(?:key|token)|hapikey`, uuidPattern), `(?:[\x60'"\s;]`, `(?:[\x60'"\s;&#]`, 1),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "intra42-client-secret", Name: "42 intra client secret", Type: "intra42",
		Keywords:    []string{"s-s4t2ud-", "s-s4t2af-"},
		Regex:       `(s-s4t2(?:ud|af)-[a-fA-F0-9]{64})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(73, "s-s4t2ud-", "s-s4t2af-"),
	},
	{
		ID: "linear-api-key", Name: "Linear API key", Type: "linear",
		Keywords:    []string{"lin_api_"},
		Regex:       `(lin_api_[A-Za-z0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(48, "lin_api_"),
	},
	{
		ID: "linear-client-secret", Name: "Linear client secret", Type: "linear",
		Keywords:    []string{"linear"},
		Regex:       assignRegex(`linear`, `[a-fA-F0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "linkedin-client-id", Name: "LinkedIn client ID", Type: "linkedin",
		Keywords:    []string{"linkedin", "linked_in", "linked-in"},
		Regex:       assignRegex(`linked[_-]?in`, `[A-Za-z0-9]{14}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "linkedin-client-secret", Name: "LinkedIn client secret", Type: "linkedin",
		Keywords:    []string{"linkedin", "linked_in", "linked-in"},
		Regex:       assignRegex(`linked[_-]?in`, `[A-Za-z0-9]{16}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// The name holds lob (also in global, blob): it runs only where a
		// live_ or test_ value with 35 hex digits follows the hit.
		ID: "lob-api-key", Name: "Lob API key", Type: "lob",
		Keywords:    []string{"lob"},
		Regex:       assignRegex(`lob`, `(?:live|test)_[a-fA-F0-9]{35}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Anchored: true, HitCheck: lobHit,
	},
	{
		ID: "looker-client-id", Name: "Looker client ID", Type: "looker",
		Keywords:    []string{"looker"},
		Regex:       assignRegex(`looker`, `[A-Za-z0-9]{20}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "looker-client-secret", Name: "Looker client secret", Type: "looker",
		Keywords:    []string{"looker"},
		Regex:       assignRegex(`looker`, `[A-Za-z0-9]{24}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "maxmind-license-key", Name: "MaxMind license key", Type: "maxmind",
		Keywords:    []string{"_mmk"},
		Regex:       `([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars, Window: 48,
	},
	{
		ID: "notion-api-token", Name: "Notion API token", Type: "notion",
		Keywords:    []string{"ntn_"},
		Regex:       `(ntn_[0-9]{11}[A-Za-z0-9]{35})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars, Window: 56, Anchored: true, HitCheck: prefixHit(50, "ntn_"),
	},
	{
		ID: "nytimes-access-token", Name: "New York Times API key", Type: "nytimes",
		Keywords:    []string{"nytimes", "new-york-times", "newyorktimes"},
		Regex:       assignRegex(`nytimes|new-york-times|newyorktimes`, `[A-Za-z0-9=_-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// Okta, okta, OKTA: not rookTable
		ID: "okta-access-token", Name: "Okta API token", Type: "okta",
		Keywords:    []string{"okta"},
		Regex:       assignRegex(`(?-i:[Oo]kta|OKTA)`, `00[\w=-]{40}`),
		SecretGroup: 1, MinEntropy: 4, Window: assignWindow,
	},
	{
		// gitleaks' planetscale-api-token, -oauth-token and -password
		ID: "planetscale-token", Name: "PlanetScale token or password", Type: "planetscale",
		Keywords:    []string{"pscale_tkn_", "pscale_oauth_", "pscale_pw_"},
		Regex:       `(pscale_(?:tkn|oauth|pw)_[\w=.-]{32,64})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars + ".", Window: 80, Anchored: true, HitCheck: prefixHit(42, "pscale_tkn_", "pscale_oauth_", "pscale_pw_"),
	},
	{
		ID: "postman-api-token", Name: "Postman API key", Type: "postman",
		Keywords:    []string{"pmak-"},
		Regex:       `(PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 64, Anchored: true, HitCheck: prefixHit(64, "PMAK-"),
	},
	{
		ID: "rapidapi-access-token", Name: "RapidAPI key", Type: "rapidapi",
		Keywords:    []string{"rapidapi"},
		Regex:       assignRegex(`rapidapi`, `[A-Za-z0-9_-]{50}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "readme-api-token", Name: "ReadMe API key", Type: "readme",
		Keywords:    []string{"rdme_"},
		Regex:       `(rdme_[a-z0-9]{70})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(75, "rdme_"),
	},
	{
		// gitleaks' settlemint application, personal and service tokens
		ID: "settlemint-access-token", Name: "SettleMint access token", Type: "settlemint",
		Keywords:    []string{"sm_aat_", "sm_pat_", "sm_sat_"},
		Regex:       `(sm_(?:aat|pat|sat)_[A-Za-z0-9]{16})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 24, Anchored: true, HitCheck: prefixHit(23, "sm_aat_", "sm_pat_", "sm_sat_"),
	},
	{
		// gitleaks' four shopify rules: access, custom app, private app
		// tokens and the shared secret
		ID: "shopify-token", Name: "Shopify access token or shared secret", Type: "shopify",
		Keywords:    []string{"shpat_", "shpca_", "shppa_", "shpss_"},
		Regex:       `(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 40, Anchored: true, HitCheck: prefixHit(38, "shpat_", "shpca_", "shppa_", "shpss_"),
	},
	{
		// 8:8 hex digits: random ones are below entropy 3 one time in twenty.
		ID: "sidekiq-secret", Name: "Sidekiq Pro or Enterprise credentials", Type: "sidekiq",
		Keywords:    []string{"bundle_enterprise__contribsys__com", "bundle_gems__contribsys__com"},
		Regex:       assignRegex(`bundle_(?:enterprise|gems)__contribsys__com`, `[a-fA-F0-9]{8}:[a-fA-F0-9]{8}`),
		SecretGroup: 1, MinEntropy: 2.5, Window: assignWindow,
	},
	{
		ID: "sidekiq-sensitive-url", Name: "Sidekiq Pro or Enterprise credentials in a URL", Type: "sidekiq",
		Keywords:    []string{"gems.contribsys.com", "enterprise.contribsys.com"},
		Regex:       `(?i:https?://)([a-fA-F0-9]{8}:[a-fA-F0-9]{8})@(?i:(?:gems|enterprise)\.contribsys\.com)(?:[/#?:\s'"\x60]|$)`,
		SecretGroup: 1, MinEntropy: 2.5, Window: 48,
	},
	{
		ID: "snyk-api-token", Name: "Snyk API token", Type: "snyk",
		Keywords:    []string{"snyk"},
		Regex:       assignRegex(`snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)`, uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "squarespace-access-token", Name: "Squarespace API key", Type: "squarespace",
		Keywords:    []string{"squarespace"},
		Regex:       assignRegex(`squarespace`, uuidPattern),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// the 32-character key (gitleaks) or the 64-hex user token (trufflehog)
		ID: "trello-access-token", Name: "Trello API key or token", Type: "trello",
		Keywords:    []string{"trello"},
		Regex:       assignRegex(`trello`, `[a-fA-F0-9]{64}|[A-Za-z0-9-]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitch-api-token", Name: "Twitch API token", Type: "twitch",
		Keywords:    []string{"twitch"},
		Regex:       assignRegex(`twitch`, `[A-Za-z0-9]{30}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitter-api-key", Name: "Twitter API key", Type: "twitter",
		Keywords:    []string{"twitter"},
		Regex:       assignRegex(`twitter`, `[A-Za-z0-9]{25}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitter-api-secret", Name: "Twitter API secret", Type: "twitter",
		Keywords:    []string{"twitter"},
		Regex:       assignRegex(`twitter`, `[A-Za-z0-9]{50}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitter-access-token", Name: "Twitter access token", Type: "twitter",
		Keywords:    []string{"twitter"},
		Regex:       assignRegex(`twitter`, `[0-9]{15,25}-[A-Za-z0-9]{20,40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitter-access-secret", Name: "Twitter access token secret", Type: "twitter",
		Keywords:    []string{"twitter"},
		Regex:       assignRegex(`twitter`, `[A-Za-z0-9]{45}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "twitter-bearer-token", Name: "Twitter bearer token", Type: "twitter",
		Keywords:    []string{"twitter"},
		Regex:       assignRegex(`twitter`, `A{22}[A-Za-z0-9%]{80,100}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "typeform-api-token", Name: "Typeform personal access token", Type: "typeform",
		Keywords:    []string{"tfp_"},
		Regex:       assignRegex(`typeform`, `tfp_[A-Za-z0-9_.=-]{59}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// An IAM token is a few hundred bytes.
		ID: "yandex-access-token", Name: "Yandex Cloud IAM token", Type: "yandex",
		Keywords:    []string{"yandex"},
		Regex:       assignRegex(`yandex`, `t1\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]{86}={0,2}`),
		SecretGroup: 1, MinEntropy: 3, Window: 1024,
	},
	{
		ID: "yandex-api-key", Name: "Yandex Cloud API key", Type: "yandex",
		Keywords:    []string{"yandex"},
		Regex:       assignRegex(`yandex`, `AQVN[A-Za-z0-9_-]{35,38}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "yandex-aws-access-token", Name: "Yandex Cloud static access key", Type: "yandex",
		Keywords:    []string{"yandex"},
		Regex:       assignRegex(`yandex`, `YC[A-Za-z0-9_-]{38}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "zendesk-secret-key", Name: "Zendesk API token", Type: "zendesk",
		Keywords:    []string{"zendesk"},
		Regex:       assignRegex(`zendesk`, `[A-Za-z0-9]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Check: notHex,
	},
}

// shapeHit: the hit is one of prefixes in its real case followed by at least
// n bytes ok accepts, for prefixes common in ordinary text (sk, EAAA).
func shapeHit(n int, ok func(byte) bool, prefixes ...string) func(_, c []byte, p int) bool {
	return func(_, c []byte, p int) bool {
		for _, s := range prefixes {
			if bytes.HasPrefix(c[p:], []byte(s)) {
				return run(c, p+len(s), n, ok) >= n
			}
		}
		return false
	}
}

func isWordOrDash(b byte) bool { return isWord(b) || b == '-' }

// airtablePATHit: pat, 14 bytes, a dot and 64 lowercase hex digits.
func airtablePATHit(_, c []byte, p int) bool {
	return p+18 < len(c) && string(c[p:p+3]) == "pat" && c[p+17] == '.' && run(c, p+18, 64, isHexLower) >= 64
}

// lobHit: live_ or test_ and 35 hex digits within 64 bytes after the hit.
func lobHit(lower, _ []byte, p int) bool {
	for i := p; i < min(len(lower), p+64); i++ {
		if (bytes.HasPrefix(lower[i:], []byte("live_")) || bytes.HasPrefix(lower[i:], []byte("test_"))) && run(lower, i+5, 35, isHex) >= 35 {
			return true
		}
	}
	return false
}
