// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letters    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// gitleaksRuleTests are the samples of the rules ported from gitleaks
// (rules_gitleaks.go), after gitleaks' own true and false positives. Every
// token is built from parts.
func gitleaksRuleTests() []ruleTest {
	uuid := fake(8, hexa) + "-" + fake(4, hexa) + "-" + fake(4, hexa) + "-" + fake(4, hexa) + "-" + fake(12, hexa)
	k8s := func(head, data string) string { return "apiVersion: v1\n" + head + data }
	k8sValue := base64.StdEncoding.EncodeToString([]byte(fake(24, alnum)))
	curlPw := fake(16, alnum)
	op := fake(32, upperAlnum)
	// a Secret as kubectl prints it: data (keys in order) before kind
	k8sDataFirst := func(data string) string {
		return "apiVersion: v1\ndata:\n" + data + "kind: Secret\nmetadata:\n  name: x\n"
	}
	var manyKeys strings.Builder
	for i := range 35 {
		fmt.Fprintf(&manyKeys, "  key%02d: %s\n", i, k8sValue)
	}
	nugetAdd := func(key, value string) string { return "<add key=\"" + key + "\" value=\"" + value + "\" />" }
	return []ruleTest{
		{
			"openai-api-key",
			[]string{
				"OPENAI_API_KEY=sk-" + fake(20, alnum) + "T3Blbk" + "FJ" + fake(20, alnum),
				`key = "sk-proj-` + fake(74, b64u) + "T3Blbk" + "FJ" + fake(74, b64u) + `"`,
				"sk-svcacct-" + fake(58, b64u) + "T3Blbk" + "FJ" + fake(58, b64u),
			},
			[]string{"sk-" + fake(20, alnum) + "T3Blbk" + "FJ" + fake(19, alnum), "sk-" + strings.Repeat("x", 20) + "T3Blbk" + "FJ" + strings.Repeat("x", 20)},
		},
		{
			"anthropic-api-key",
			[]string{"ANTHROPIC_API_KEY=sk-ant-api03-" + fake(93, b64u) + "AA", `"sk-ant-admin01-` + fake(93, b64u) + `AA"`},
			[]string{"sk-ant-api03-" + fake(93, b64u) + "AB", "sk-ant-api03-" + fake(92, b64u) + "AA", "sk-ant-api03-" + strings.Repeat("a", 93) + "AA"},
		},
		{
			"huggingface-token",
			[]string{"HF_TOKEN=hf_" + fake(34, letters), `token: "api_org_` + fake(34, letters) + `"`},
			[]string{
				"- (id)hf_requiredCharacteristicTypesForDisplayMetadata;",
				`"desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2"`,
				"hf_" + strings.Repeat("x", 34),
				"hf_" + fake(33, letters) + "1",
				"api_org_" + strings.Repeat("X", 34),
			},
		},
		{
			"perplexity-api-key",
			[]string{"PERPLEXITY_API_KEY=pplx-" + fake(48, alnum)},
			[]string{"pplx-" + fake(47, alnum), "pplx-" + strings.Repeat("a1", 24)},
		},
		{
			"cohere-api-token",
			[]string{`cohere_api_token = "` + fake(40, alnum) + `"`, "export CO_API_KEY=" + fake(40, alnum)},
			[]string{"cohere_api_token = " + fake(39, alnum), "co_api_key = " + strings.Repeat("ab12", 10), "key = " + fake(40, alnum)},
		},
		{
			"privateai-api-token",
			[]string{`privateai_api_token = "` + fake(32, lowerAlnum) + `"`, "PRIVATE_AI_KEY: " + fake(32, lowerAlnum)},
			[]string{"privateai_api_token = " + strings.Repeat("ab", 16), "private_ai_key = " + fake(31, lowerAlnum)},
		},
		{
			"aws-amazon-bedrock-api-key-long-lived",
			[]string{"AWS_BEARER_TOKEN_BEDROCK=ABSK" + fake(120, b64) + "=", "ABSK" + fake(250, b64)},
			[]string{"ABSK" + fake(100, b64), "absk" + fake(120, b64)},
		},
		{
			"aws-amazon-bedrock-api-key-short-lived",
			[]string{"AWS_BEARER_TOKEN_BEDROCK=bedrock-api-key-" + base64.StdEncoding.EncodeToString([]byte("bedrock.amazonaws.com/?Action=CallWithBearerToken&X-Amz-Signature="+fake(64, hexa)))},
			[]string{"bedrock-api-key-", "bedrock-api-key-" + base64.StdEncoding.EncodeToString([]byte("bedrock.amazonaws.com")), "bedrock-api-key-" + base64.StdEncoding.EncodeToString([]byte("bedrock.amazonaws.cox/?Action="+fake(80, alnum)))},
		},
		{
			"npm-access-token",
			[]string{"//registry.npmjs.org/:_authToken=npm_" + fake(36, alnum)},
			[]string{"npm_" + fake(35, alnum), "npm_" + strings.Repeat("x", 36), "my_npm_" + fake(36, alnum) + "_x"},
		},
		{
			"pypi-upload-token",
			[]string{"password = pypi-AgEIcHlwaS5vcmc" + fake(70, b64u)},
			[]string{"pypi-AgEIcHlwaS5vcmc" + fake(40, b64u), "pypi-AgEIcHlwaS5vcmx" + fake(70, b64u)},
		},
		{
			"rubygems-api-token",
			[]string{"GEM_HOST_API_KEY: rubygems_" + fake(48, hexa)},
			[]string{"rubygems_" + fake(47, hexa), "rubygems_" + strings.Repeat("0", 48)},
		},
		{
			"nuget-config-password",
			[]string{nugetAdd("ClearTextPassword", fake(16, alnum)), nugetAdd("Password", fake(12, b64))},
			[]string{
				`<add key="ClearTextPassword" value="XXXXXXXXXXX" />`,
				`<add key="ClearTextPassword" value="abc" />`,
				`<add key="ClearTextPassword" value="%TestSourcePassword%" />`,
				`<add key="ClearTextPassword" value="$(NUGET_PASSWORD)" />`,
				`<add key="ClearTextPassword" value="$(NuGet.Password)" />`,
				`<add key="ClearTextPassword" value="#{NugetPassword}#" />`,
				`<add key="ClearTextPassword" value="33f!!lloppa" />`,
				`<add key="Username" value="` + fake(16, alnum) + `" />`,
			},
		},
		{
			"clojars-api-token",
			[]string{`token = "CLOJARS_` + fake(60, alnum) + `"`},
			[]string{"CLOJARS_" + fake(59, alnum), "clojars_" + fake(60, alnum)},
		},
		{
			"artifactory-api-key",
			[]string{"ARTIFACTORY_API_KEY=AKCp" + fake(69, alnum)},
			[]string{"AKCp" + fake(68, alnum), "akcp" + fake(69, alnum), "AKCp" + strings.Repeat("ab", 34) + "c"},
		},
		{
			"artifactory-reference-token",
			[]string{"token: cmVmd" + fake(59, alnum)},
			[]string{"cmVmd" + fake(58, alnum), "cmVmd" + strings.Repeat("A", 59)},
		},
		{
			"jfrog-api-key",
			[]string{"--set artifactory.password=" + fake(73, alnum), `jfrog_key: "` + fake(73, alnum) + `"`},
			[]string{"jfrog_key: " + fake(72, alnum), "key: " + fake(73, alnum)},
		},
		{
			"jfrog-identity-token",
			[]string{`jfrogToken="` + fake(64, alnum) + `"`, "<jfrogToken>\n    " + fake(64, alnum) + "\n</jfrogToken>"},
			[]string{"artifactory_sha256: " + sha256Hex("x"), "jfrog_token: " + fake(63, alnum)},
		},
		{
			"docker-hub-token",
			[]string{"DOCKERHUB_TOKEN=dckr_pat_" + fake(27, b64u), "dckr_oat_" + fake(32, b64u)},
			[]string{"dckr_pat_" + fake(26, alnum), "dckr_pat_" + strings.Repeat("x", 27)},
		},
		{
			"digitalocean-token",
			[]string{"DIGITALOCEAN_TOKEN=dop_v1_" + fake(64, hexa), `"doo_v1_` + fake(64, hexa) + `"`, "dor_v1_" + fake(64, hexa)},
			[]string{"dop_v1_" + fake(63, hexa), "dop_v1_" + strings.Repeat("0", 64), "dox_v1_" + fake(64, hexa)},
		},
		{
			"heroku-api-key",
			[]string{"heroku_token: '" + uuid + "'", `herokuApiKey := "` + uuid + `"`, `HEROKU_API_KEY ?= "` + uuid + `"`},
			[]string{"HEROKU_APP_ID=" + uuid, "token: " + uuid},
		},
		{
			"heroku-api-key-v2",
			[]string{"HEROKU_API_KEY=HRKU-AA" + fake(58, b64u)},
			[]string{"HRKU-AA" + fake(57, alnum), "hrku-aa" + fake(58, alnum)},
		},
		{
			"flyio-access-token",
			[]string{`FLY_API_TOKEN="fo1_` + fake(43, b64u) + `"`, "FlyV1 fm2_" + fake(120, b64) + "==", "fm1r_" + fake(110, b64)},
			[]string{
				`api_key = "fo1_` + strings.Repeat("x", 43) + `"`,
				"MINIDUMP_SYSMEMINFO1_PERF_CCTOTALDIRTYPAGES_CCDIRTYPAGETHRESHOLD: u32",
				`value="7SWa-Fo1_` + fake(43, b64u) + `"`,
				"fm2_" + fake(80, b64),
			},
		},
		{
			"netlify-access-token",
			[]string{"netlify_token: '" + fake(43, b64u) + "'", `NETLIFY_AUTH_TOKEN ?= "` + fake(40, alnum) + `"`},
			[]string{"NETLIFY_SITE_ID=" + uuid, "netlify_token: " + fake(39, alnum)},
		},
		{
			"cloudflare-api-key",
			[]string{"CLOUDFLARE_TOKEN=" + fake(40, b64u), `cloudflare_api_token: "` + fake(40, alnum) + `"`},
			[]string{"CLOUDFLARE_ZONE_ID=" + fake(32, hexa), "token=" + fake(40, b64u), "cloudflare_commit: " + fake(40, hexa)},
		},
		{
			"cloudflare-global-api-key",
			[]string{"CLOUDFLARE_API_KEY=" + fake(37, hexa)},
			[]string{"CLOUDFLARE_API_KEY=" + fake(36, hexa), "api_key=" + fake(37, hexa)},
		},
		{
			"cloudflare-origin-ca-key",
			[]string{"CF_ORIGIN_CA_KEY=v1.0-" + fake(24, hexa) + "-" + fake(146, hexa)},
			[]string{"v1.0-" + fake(24, hexa) + "-" + fake(145, hexa)},
		},
		{
			"alibaba-access-key-id",
			[]string{"ALIBABA_ACCESS_KEY_ID=LTAI" + fake(20, alnum)},
			[]string{"LTAI" + fake(19, alnum), "ltai" + fake(20, alnum), "xLTAI" + fake(20, alnum)},
		},
		{
			"alibaba-secret-key",
			[]string{"alibaba_token: '" + fake(30, alnum) + "'", `ALIBABA_SECRET ?= "` + fake(30, alnum) + `"`},
			[]string{"alibaba_region: " + fake(29, alnum), "secret: " + fake(30, alnum)},
		},
		{
			"hashicorp-tf-api-token",
			[]string{`token = "` + fake(14, alnum) + ".atlasv1." + fake(64, b64u) + `"`},
			[]string{fake(14, alnum) + ".atlasv1." + fake(50, b64u), fake(14, alnum) + ".atlasv1." + strings.Repeat("x", 64)},
		},
		{
			"vault-token",
			[]string{"VAULT_TOKEN=hvs." + fake(95, b64u), `"hvb.` + fake(150, b64u) + `"`},
			[]string{"hvs." + strings.Repeat("x", 95), "hvs." + fake(60, b64u), "s." + fake(24, alnum)},
		},
		{
			"pulumi-api-token",
			[]string{"PULUMI_ACCESS_TOKEN=pul-" + fake(40, hexa)},
			[]string{`<img src="./assets/vipul-` + fake(40, hexa) + `.png">`, "pul-" + fake(39, hexa)},
		},
		{
			"doppler-api-token",
			[]string{"DOPPLER_TOKEN=dp.pt." + fake(43, alnum)},
			[]string{"dp.pt." + fake(42, alnum), "dp.pt." + strings.Repeat("ab", 21) + "c"},
		},
		{
			"1password-secret-key",
			[]string{"A3-" + op[:6] + "-" + op[6:17] + "-" + op[17:22] + "-" + op[22:27] + "-" + op[27:32], "A3-" + op[:6] + "-" + op[6:12] + "-" + op[12:17] + "-" + op[17:22] + "-" + op[22:27] + "-" + op[27:32]},
			[]string{"A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX", "A3-xXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX", "a3-" + fake(6, upperAlnum) + "-" + fake(11, upperAlnum) + "-" + fake(5, upperAlnum) + "-" + fake(5, upperAlnum) + "-" + fake(5, upperAlnum)},
		},
		{
			"1password-service-account-token",
			[]string{"export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ" + fake(300, b64)},
			[]string{"OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6...", "ops_eyJ" + strings.Repeat("x", 300)},
		},
		{
			"kubernetes-secret-yaml",
			[]string{
				k8s("kind: Secret\nmetadata:\n  name: db\ntype: Opaque\n", "data:\n  password: "+k8sValue+"\n"),
				k8s("kind: \"secret\"\n", "data:\n  # base64\n  password: '"+k8sValue+"'"),
				k8s("kind: Secret\n", "data:\n  .dockercfg: |\n    "+k8sValue+"\n"),
			},
			[]string{
				k8s("kind: Secret\n", "data:\n  htpasswd: ''\n"),
				k8s("kind: Secret\n", "data:\n  htpasswd: {{ .Values.htpasswd | b64enc }}\n"),
				k8s("kind: ConfigMap\n", "data:\n  password: "+k8sValue+"\n"),
				k8s("kind: Secret\nmetadata:\n  name: x\n---\napiVersion: v1\nkind: ConfigMap\n", "data:\n  key: "+k8sValue+"\n"),
				"apiVersion: v1\ndata:\n  key: " + k8sValue + "\n---\nkind: Secret\n",
				k8s("kind: SecretList\n", "data:\n  password: "+k8sValue+"\n"),
				k8s("kind: Secret\nmetadata:\n  name: "+k8sValue+"\n", "stringData:\n  password: plain\n"),
			},
		},
		{
			"kubernetes-secret-yaml-data-first",
			[]string{
				"apiVersion: v1\ndata:\n  password: " + k8sValue + "\n  username: YWRtaW4=\nkind: Secret\nmetadata:\n  name: db-user-pass\n",
				"apiVersion: v1\r\ndata:\r\n  extra: \"" + k8sValue + "\"\r\nkind: \"Secret\"\r\n",
				"apiVersion: v1\ndata:\n  .dockercfg: >\n    " + k8sValue + "\nmetadata:\n  name: x\ntype: kubernetes.io/dockercfg\nkind: Secret",
				// a TLS Secret: kind is more than 4 KiB after data:
				k8sDataFirst("  tls.crt: " + base64.StdEncoding.EncodeToString([]byte(fake(2400, alnum))) +
					"\n  tls.key: " + base64.StdEncoding.EncodeToString([]byte(fake(1800, alnum))) + "\n"),
				k8sDataFirst(manyKeys.String()),
			},
			[]string{
				// data: must follow a newline, so these are missed (see the rule)
				"data:\n  key: " + k8sValue + "\nkind: Secret\n",
				"\ufeffdata:\n  key: " + k8sValue + "\nkind: Secret\n",
				"apiVersion: v1\ndata:\n  key: " + k8sValue + "\n---\nkind: Secret\n",
				"apiVersion: v1\nmetadata:\n  name: " + k8sValue + "\nkind: Secret\n",
				"apiVersion: v1\ndata:\n  key: " + k8sValue + "\nkind: ConfigMap\n",
			},
		},
		{
			"databricks-api-token",
			[]string{"DATABRICKS_TOKEN=dapi" + fake(32, hexa), "token: dapi" + fake(32, hexa) + "-2"},
			[]string{"dapi" + fake(31, hexa), "xdapi" + fake(32, hexa)},
		},
		{
			"openshift-user-token",
			[]string{"oc login --token=sha256~" + fake(43, b64u) + " --server=https://api.cluster:6443"},
			[]string{`token="sha256~XXXXXXXXXX_PUT_YOUR_TOKEN_HERE_XXXXXXXXXXXX"`, "sha256~" + fake(42, alnum)},
		},
		{
			"scalingo-api-token",
			[]string{"SCALINGO_API_TOKEN=tk-us-" + fake(48, b64u)},
			[]string{"tk-us-" + fake(47, alnum), "tk-us-" + strings.Repeat("x", 48)},
		},
		{
			"infracost-api-token",
			[]string{"INFRACOST_API_KEY=ico-" + fake(32, alnum)},
			[]string{"favico-" + fake(32, alnum), "ico-" + fake(31, alnum), "assets.r7.com/" + fake(16, hexa) + ".ico-" + fake(32, alnum) + ".png"},
		},
		{
			"prefect-api-token",
			[]string{"PREFECT_API_KEY=pnu_" + fake(36, alnum)},
			[]string{"pnu_" + fake(35, alnum), "pnu_" + strings.Repeat("x", 36)},
		},
		{
			"defined-networking-api-token",
			[]string{"DNKEY=dnkey-" + fake(26, alnum) + "-" + fake(52, alnum)},
			[]string{"dnkey-" + fake(26, alnum) + "-" + fake(40, alnum)},
		},
		{
			"bitbucket-client-id",
			[]string{"bitbucket_token: '" + fake(32, alnum) + "'", `BITBUCKET_CLIENT_ID := "` + fake(32, alnum) + `"`},
			[]string{"BITBUCKET_COMMIT=" + fake(40, hexa), "client_id: " + fake(32, alnum), "bitbucket_md5: " + fake(32, hexa)},
		},
		{
			"bitbucket-client-secret",
			[]string{`bitbucket_TOKEN = "` + fake(64, b64u) + `"`, `"bitbucket_secret" => "` + fake(64, alnum) + `"`},
			[]string{"bitbucket_secret: " + fake(63, alnum), "secret: " + fake(64, alnum)},
		},
		{
			"atlassian-api-token",
			[]string{"JIRA_API_TOKEN=ATATT3" + fake(186, b64u)},
			[]string{"ATATT3" + fake(150, b64u), "getPagesInConfluenceSpace,searchConfluenceUsingCql"},
		},
		{
			"atlassian-api-token-legacy",
			[]string{"atlassian_token: " + fake(20, lowerAlnum) + fake(4, hexa), `JIRA_TOKEN ::= "` + fake(20, alnum) + fake(4, hexa) + `"`},
			[]string{"jira_token: " + strings.Repeat("ab", 12), "jira_issue: " + fake(25, lowerAlnum), "token: " + fake(20, lowerAlnum) + fake(4, hexa)},
		},
		{
			"gitlab-session-cookie",
			[]string{`gitlabToken := "_gitlab_session=` + fake(32, lowerAlnum) + `"`},
			[]string{"_gitlab_session=" + fake(31, lowerAlnum), "_gitlab_session=" + strings.Repeat("0", 32)},
		},
		{
			"codecov-access-token",
			[]string{"CODECOV_TOKEN=" + fake(32, alnum), "codecov_token: '" + fake(32, alnum) + "'"},
			[]string{"codecov_token: " + fake(31, alnum), "token: " + fake(32, alnum)},
		},
		{
			"travisci-access-token",
			[]string{"travis_token: '" + fake(22, alnum) + "'", `System.setProperty("TRAVIS_TOKEN", "` + fake(22, alnum) + `")`},
			[]string{"travis_token: " + fake(21, alnum), "TRAVIS_COMMIT=" + fake(40, hexa)},
		},
		{
			"sonar-api-token",
			[]string{"SONAR_TOKEN=squ_" + fake(40, hexa), "sqp_" + fake(40, hexa), "sqa_" + fake(40, hexa)},
			[]string{"squ_" + fake(39, hexa), "sqx_" + fake(40, hexa)},
		},
		{
			"sonar-api-token-legacy",
			[]string{"sonar.login=" + fake(40, alnum), `String sonarToken = "` + fake(40, b64u) + `";`},
			[]string{"sonar.host=" + fake(40, alnum), "sonar_token=" + fake(39, alnum)},
		},
		{
			"droneci-access-token",
			[]string{`System.setProperty("DRONECI_TOKEN", "` + fake(32, alnum) + `")`, "droneci_TOKEN = '" + fake(32, alnum) + "'"},
			[]string{"droneci_token = " + fake(31, alnum), "drone_token = " + fake(32, alnum)},
		},
		{
			"sourcegraph-access-token",
			[]string{"SRC_ACCESS_TOKEN=sgp_" + fake(16, hexa) + "_" + fake(40, hexa), "sgp_local_" + fake(40, hexa), "sgp_" + fake(40, hexa)},
			[]string{"sgp_" + fake(39, hexa), "sourcegraph: " + fake(40, hexa)},
		},
		{
			"harness-api-key",
			[]string{"harness_token: pat." + fake(22, b64u) + "." + fake(24, alnum) + "." + fake(20, alnum), `"sat.` + fake(22, b64u) + "." + fake(24, alnum) + "." + fake(20, alnum) + `"`},
			[]string{"pat." + fake(22, b64u) + "." + fake(24, alnum) + "." + fake(19, alnum), "spat." + fake(22, b64u) + "." + fake(24, alnum) + "." + fake(20, alnum)},
		},
		{
			"octopus-deploy-api-key",
			[]string{"OCTOPUS_API_KEY=API-" + fake(26, upperAlnum)},
			[]string{
				`msgstr "GSSAPI-VIRHEKAPSELOINTIMERKKIJONO."`,
				"https://sonarcloud.io/api/project_badges/measure?project=Garden-Coin_API-CalculadoraDeInvestimentos",
				"https://fog-ringer-f42.notion.site/API-" + fake(32, "0123456789ABCDEF"),
				"./archive/gifs/api-" + fake(26, lowerAlnum) + ".gif",
			},
		},
		{
			"circleci-personal-token",
			[]string{"CIRCLE_TOKEN=CCIPAT_" + fake(22, alnum) + "_" + fake(40, hexa)},
			[]string{"CCIPAT_" + fake(22, alnum) + "_" + fake(39, hexa), "ccipat_" + fake(22, alnum) + "_" + fake(40, hexa)},
		},
		{
			"buildkite-api-token",
			[]string{"BUILDKITE_API_TOKEN=bkua_" + fake(40, lowerAlnum)},
			[]string{"bkua_" + fake(39, lowerAlnum), "bkua_" + strings.Repeat("a", 40)},
		},
		{
			"curl-auth-header",
			[]string{
				`curl -H "Authorization: Bearer ` + fake(32, b64) + `" https://api.local/v1`,
				"curl -X POST https://api.local \\\n  -H 'Content-Type: application/json' \\\n  -H 'Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("api:"+fake(20, alnum))) + "' \\\n",
				`curl --header "X-Api-Key: ` + uuid + `" https://api.local`,
				`curl -H "Authorization: Token ` + fake(40, hexa) + `x" https://api.local`,
				// uppercase tokens that start with a letter
				`curl -H "X-API-Key: A` + strings.ToUpper(fake(31, hexa)) + `" https://api.local`,
				`curl -H "Authorization: Bearer B` + fake(31, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") + `" https://api.local`,
				`curl -H "Authorization: Bearer C` + fake(39, upperAlnum) + `" https://api.local`,
			},
			[]string{
				`curl https://api.local -H "Authorization: Bearer XXXXXXXXXXXX"`,
				`curl --header "Authorization: Basic ..."`,
				`curl -H "Authorization: Bearer <Openverse API token>"`,
				`curl -H "Authorization: Token **********"`,
				`curl -H "apikey: $API_KEY"`,
				`curl -H "Authorization: Bearer $(gcloud auth print-access-token)"`,
				`curl -H "Authorization: Bearer YOUR_API_KEY"`,
				`curl -H "Authorization: Bearer ACCESS_TOKEN"`,
				`curl -H "Authorization: Bearer REPLACE_WITH_TOKEN"`,
				`curl -H "Authorization: Bearer MY_API_TOKEN2"`,
				`curl -H "X-Api-Key: APIKEYVALUE"`,
				`curl -H "Authorization: Bearer access-token"`,
				`curl -H "Authorization: Bearer token123456"`,
				`curl -H "Authorization: Bearer my.jwt.token"`,
				`curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."`,
				`curl -H 'Authorization: token ghp_REDACTED_REDACTED'`,
				`curl https://api.local` + strings.Repeat("\n echo", 6) + ` -H "Authorization: Bearer ` + fake(32, b64) + `"`, // too many lines later
			},
		},
		{
			"curl-auth-user",
			[]string{
				"curl --cacert ca.crt -u elastic" + ":" + curlPw + " https://localhost:9200",
				"curl -k -X POST https://local/rest \\\n  -H 'Content-type: text/plain' \\\n  -u developer:" + curlPw,
				"curl -s --user 'api" + ":" + curlPw + "' \\\n    https://api.mailgun.net/v3",
				`curl -s -v --user "j.smith:` + curlPw + `" "https://api.local/user/me"`,
				"curl --user kevin" + ":'" + curlPw + "' -iX PATCH",
				"curl -u admin" + ":x" + curlPw + " https://api.local",
				"curl -u admin" + ":testing" + curlPw + " https://api.local",
				"curl -u admin" + ":pass" + curlPw + " https://api.local",
				"curl -u 'deploy bot'" + ":" + curlPw + " https://api.local",
				`curl -u "deploy bot` + ":" + curlPw + `" https://api.local`,
				// gitleaks' Watson sample
				`curl -X PUT -u "{` + uuid + `}":"{` + fake(14, alnum) + `}" https://stream.local/api`,
				"curl -u 'admin" + ":%ab%" + curlPw + "' https://api.local",
				"curl -u 'admin" + ":{x}" + curlPw + "' https://api.local",
				"curl -u 'admin" + ":{" + curlPw + "}' https://api.local",
				"curl -u admin" + ":" + curlPw + ":test https://api.local",
				"curl -u admin" + ":" + curlPw + ":xxx https://api.local",
			},
			[]string{
				"curl -i -u 'test:test'",
				`curl -sL --user "$1:$2" "$3"`,
				"curl -u <user:password> https://test.com/endpoint",
				"curl --user neo4j:[PASSWORD] http://[IP]:7474/db/data/",
				`curl -u "myusername" http://localhost:15130/api/check_user/`,
				"curl -u username:token",
				`curl -u "${_username}:${_password}"`,
				`curl -k -X POST -I -u "SRVC_JENKINS:${APPID}"`,
				`curl -u ":" https://localhost:9200`,
				`curl --user "xxx:yyy"`,
				`curl -XGET -i -u "${{ env.ELK_ID }}:${{ build.env.ELK_PASS }}"`,
				`curl -X POST --user "$(cat ./login.txt):$(cat ./password.txt)"`,
				"curl http://127.0.0.1:5000/file --user user:pass --digest",
				`curl --silent --insecure --user ${f5user}:${f5pass} \`,
				`curl --user "src@gmail.com" --upload-file out.txt`,
				"curl -u admin:%PASSWORD% https://api.local",
				"curl -u admin:$(cat pw.txt) https://api.local",
				"curl -u 'admin:{password}' https://api.local",
				"curl -u admin:{api_key} https://api.local",
				`curl -u "deploy bot:changeme" https://api.local`,
				"curl -u admin:admin https://api.local",
				"curl -u guest:'guest' https://api.local",
				"curl -u 'admin:x' https://api.local",
				"curl -X POST http://local:8080/serve\n\necho -n '{}' >/dev/udp/127.0.0.1/41234\n\nnc -u -l 41234",
			},
		},
	}
}

func TestFirebaseSampleKeysArePlaceholders(t *testing.T) {
	d := allRulesDetector(t)
	for _, k := range firebaseSampleKeys {
		assert.Zero(t, countRule(d, "apiKey: \"AIza"+k+"\"", "gcp-api-key"), k)
	}
	assert.Equal(t, 1, countRule(d, "apiKey: \"AIza"+firebaseSampleKeys[0][:30]+"Q1w2e\"", "gcp-api-key"))
}

// A known token in a curl header is reported as that token, once.
func TestCurlHeaderLeavesKnownTokensToTheirRule(t *testing.T) {
	d := allRulesDetector(t)
	fs := scanOf(d, []byte(`curl -H "Authorization: Bearer ghp_`+fake(36, alnum)+`" https://api.local`))
	if assert.Len(t, fs, 1) {
		assert.Equal(t, "github-token", fs[0].RuleID)
	}
}

// Text full of the new rules' common keywords (curl commands, kind:, api-,
// a3-, pat.) is scanned whole and fast, and a token after it is found.
func TestPortedRuleKeywordsAreCheap(t *testing.T) {
	d := defaultRulesDetector(t)
	for name, unit := range map[string]string{
		"curl":                "curl -H 'Accept: text/plain' -u me https://api-a3-x.local/pat.sat. \\\n",
		"kind":                "kind: Secret\ndata:\n  key: ''\n",
		"kind lines":          "kind: Secret\n",
		"data before kind":    "data:\n  k: QUFBQUFBQUFBQUFB\nkind: Foo\n",
		"curl with variables": "curl -H \"Authorization: Bearer $TOKEN\" -u \"$USER:$PASS\" https://api.local\n",
	} {
		content := append(repeatTo(unit, 2<<20/slowdown), []byte("\nghp_"+fake(36, alnum)+"\n")...)
		start := time.Now()
		fs, complete := d.Scan(content)
		assert.Less(t, time.Since(start), 2*time.Second*slowdown, name)
		assert.True(t, complete, name)
		assert.Equal(t, 1, countRuleIn(fs, "github-token"), name)
	}
}

// Every ported rule runs near its keywords only, and an anchored one behind a
// hit check (an inline comment once swallowed the infracost rule's fields).
func TestGitleaksRulesAreWindowed(t *testing.T) {
	for _, r := range slices.Concat(gitleaksRules, gitleaksServiceRules, curlHeaderRules, curlUserRules) {
		assert.Positive(t, r.Window, r.ID)
		assert.True(t, !r.Anchored || r.HitCheck != nil, r.ID)
	}
}

// Kubernetes Secrets with CRLF line ends and a blank line between kind and
// data, either order.
func TestKubernetesSecretCRLF(t *testing.T) {
	d := allRulesDetector(t)
	v := base64.StdEncoding.EncodeToString([]byte(fake(24, alnum)))
	for _, s := range []string{
		"apiVersion: v1\r\nkind: Secret\r\nmetadata:\r\n  name: x\r\n\r\ndata:\r\n  password: " + v + "\r\n",
		"apiVersion: v1\r\ndata:\r\n  password: " + v + "\r\n\r\nkind: Secret\r\nmetadata:\r\n  name: x\r\n",
	} {
		assert.Equal(t, 1, countRule(d, s, "kubernetes-secret-yaml"), "%q", s)
	}
}

// keywordGate finds exactly the keywords a search per keyword finds, at their
// first offset, and next gives every later one: overlapping, shared and
// one-byte keywords included.
func TestKeywordGateMatchesHasKeyword(t *testing.T) {
	defer func(v int) { keptHitsBase = v }(keptHitsBase)
	r := rand.New(rand.NewPCG(5, 6))
	var sets [][]string
	for _, rule := range BuiltinRules() {
		sets = append(sets, rule.Keywords)
	}
	sets = append(sets, []string{"q"}, []string{"ab", "aba", "b"}, []string{"ab"})
	var g keywordGate
	ids := make([][]int, len(sets))
	var words []string
	for i, ks := range sets {
		ids[i] = g.add(ks)
		words = append(words, ks...)
	}
	for range 2000 {
		var b strings.Builder
		for range r.IntN(8) {
			switch w := words[r.IntN(len(words))]; r.IntN(3) {
			case 0:
				b.WriteString(w)
			case 1:
				b.WriteString(w[:r.IntN(len(w))])
			default:
				for range r.IntN(6) {
					b.WriteByte("ab-_.: "[r.IntN(7)])
				}
			}
		}
		text := []byte(b.String())
		// keptHitsBase 0 makes the gate stop keeping hits early, so next
		// also searches on from where the kept ones end.
		keptHitsBase = 1024 * r.IntN(2)
		h := g.find(text)
		found := h.first
		for i, ks := range sets {
			assert.Equal(t, hasKeyword(text, ks), slices.ContainsFunc(ids[i], func(id int) bool { return found[id] >= 0 }), "%q in %q", ks, text)
			for j, k := range ks {
				assert.Equal(t, bytes.Index(text, []byte(k)), found[ids[i][j]], "%q in %q", k, text)
				// every occurrence, twice: rules that share a keyword ask
				// for it from the start again
				var want []int
				for off := 0; ; {
					i := bytes.Index(text[off:], []byte(k))
					if i < 0 {
						break
					}
					want = append(want, off+i)
					off += i + 1
				}
				for range 2 {
					var got []int
					for p := h.next(ids[i][j], 0); p >= 0; p = h.next(ids[i][j], p+1) {
						got = append(got, p)
					}
					assert.Equal(t, want, got, "%q in %q", k, text)
				}
			}
		}
	}
}
