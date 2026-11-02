# Design tokens and company themes

The company look is a set of CSS custom properties in `web_src/css/tokens.css`, used by four themes in `web_src/css/themes/`:

| Theme | Built from |
|-------|------------|
| `company-light` | `forgejo-light` + tokens |
| `company-dark` | `forgejo-dark` + tokens + dark semantic values |
| `company-auto` | light, or dark when the OS prefers dark |
| `company-high-contrast` | `company-light` with stronger semantic values (targets WCAG AAA) |

Each theme imports the matching Forgejo theme and only overrides what changes the look, so upstream fixes still apply.

## Tokens

**Primitives** (the same in every theme):

- Colour: `--blue-50..900`, `--neutral-0..950`, `--red-50..900`, `--amber-50..900`, `--green-50..900`
- Type: `--font-ui`, `--font-code`, `--text-xs/sm/base/lg/xl/2xl`, `--leading-tight/normal`
- Space (4px base): `--space-1..8`
- Shape: `--radius-sm/md/lg/full`, `--shadow-sm/md`
- Motion: `--duration-fast/normal`

**Semantic** (set per theme): `--surface`, `--surface-raised`, `--surface-sunken`, `--text`, `--text-muted`, `--text-on-primary`, `--border`, `--border-strong`, `--primary`, `--primary-hover`, `--primary-active`, `--danger`, `--warning`, `--success` (each with `-bg` and `-text`), `--focus-ring`, `--code-bg`, `--diff-add-bg`, `--diff-add-word`, `--diff-del-bg`, `--diff-del-word`, `--label-text`, `--label-bg`.

`tokens.css` maps Forgejo's variables (`--color-primary*`, `--color-body`, `--color-text*`, `--color-error-*`, `--color-diff-*`, `--border-radius`, …) onto the semantic tokens, so existing templates use them without changes.

## Using them

- In new CSS, use semantic tokens (`color: var(--text-muted)`), not primitives or hex values. A primitive in component CSS won't follow light, dark and high contrast.
- To change the palette, edit the primitives in `tokens.css`. To change what a role looks like in one theme, edit that theme's semantic values.
- The UI font is the system stack. For a company font, self-host it under `custom/public/assets/` and set `--fonts-override` in a theme.

## Contrast

`web_src/js/company-contrast.test.js` checks each semantic text/background pair: 4.5:1 for text (7:1 in high contrast) and 3:1 for focus ring and strong borders. It runs with `make test-frontend`, or on its own:

```sh
npx vitest run web_src/js/company-contrast.test.js
```

When you add a semantic token that is drawn as text or as a UI boundary, add its pair to the test.

## Default themes

The company themes are the default: `[ui] DEFAULT_THEME` is `company-auto`, and `THEMES` lists the four company themes first, followed by the upstream Forgejo and Gitea themes. To go back to the upstream look, set in the deployment's `app.ini`:

```ini
[ui]
DEFAULT_THEME = forgejo-auto
```

Users choose a theme in Settings → Appearance.

## Branding

The default logo, favicon and app name are gitdepo's (see [`branding.md`](branding.md)). To use your own, put `logo.svg`, `logo.png`, `favicon.svg` and `favicon.png` in `custom/public/assets/img/`, and set `APP_NAME` in `app.ini`.
