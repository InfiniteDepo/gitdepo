# Search engines and AI assistants

gitdepo tells search engines (SEO) and AI assistants or answer engines (AEO) what a public page is. Nothing here exposes more than the page already shows to an anonymous visitor.

## What every page has

- `<link rel="canonical">`: the absolute URL of the page under `ROOT_URL`, without its query except a `page` number above 1, so sort, tab and filter variants of a list share one URL. A user or organization profile and a repository home use the entity's own URL, so `/User2/Repo1` and `/user2/repo1` share one.
- `<meta name="description">`: the repository description on repository pages, the bio on user and organization profiles, else `[ui.meta] DESCRIPTION`.
- OpenGraph (`og:*`) and `twitter:card` (`summary_large_image` where a summary card image exists, else `summary`). The fallback `og:image` is absolute.

## Structured data (schema.org JSON-LD)

| Page | Type | Shown when |
|---|---|---|
| Home (anonymous landing page) | `WebSite`, with a `SearchAction` on Explore when Explore is public | always |
| Repository home | `SoftwareSourceCode`: name, description, topics as keywords, URL, HTTPS clone URL, created and updated dates, owner | the repository is public and its owner's visibility is public |
| User or organization profile | `ProfilePage` with a `Person` or `Organization`: display name, login, URL, avatar, bio | the visibility is public |

E-mail addresses, private and limited content are never included. Check a page with Google's [Rich Results Test](https://search.google.com/test/rich-results) or the [Schema Markup Validator](https://validator.schema.org).

## Crawler files

- `/robots.txt` ends with a `Sitemap:` line when the sitemap is public (`[other] ENABLE_SITEMAP` on, and neither `REQUIRE_SIGNIN_VIEW` nor Explore's `REQUIRE_SIGNIN_VIEW` set). `custom/public/robots.txt` replaces the whole file, as before.
- `/sitemap.xml` indexes public repositories, users and, new in gitdepo, public organizations that are not archived (`/explore/organizations/sitemap-N.xml`); `DISABLE_USERS_PAGE`/`DISABLE_ORGANIZATIONS_PAGE` leave their part out.
- `/llms.txt` ([llmstxt.org](https://llmstxt.org)) is a short Markdown overview for AI assistants: the instance name and description, the Explore pages, the REST API and its reference, and the sitemap. With `REQUIRE_SIGNIN_VIEW` it only says sign-in is required. `custom/public/llms.txt` replaces it.
