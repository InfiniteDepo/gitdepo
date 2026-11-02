// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package drawio

import (
	"encoding/json" //nolint:depguard // modules/json has no SetEscapeHTML
	"errors"
	"fmt"
	"html"
	"io"
	"strings"

	"forgejo.org/modules/markup"
	"forgejo.org/modules/setting"
)

func init() {
	markup.RegisterRenderer(Renderer{})
}

// ViewerPath is the vendored draw.io viewer (jgraph/drawio v32.0.2, Apache-2.0).
const ViewerPath = "/assets/vendor/drawio/viewer-static-32.0.2.min.js"

// Renderer implements markup.Renderer for draw.io diagrams. Its output only
// runs inside the sandboxed iframe served by the "/render" route.
type Renderer struct{}

// Name implements markup.Renderer
func (Renderer) Name() string {
	return "drawio"
}

// Extensions implements markup.Renderer
func (Renderer) Extensions() []string {
	if !setting.DrawioEnabled {
		return nil
	}
	return []string{".drawio", ".drawio.xml"}
}

// SanitizerRules implements markup.Renderer
func (Renderer) SanitizerRules() []setting.MarkupSanitizerRule {
	return nil
}

// SanitizerDisabled implements markup.ExternalRenderer
func (Renderer) SanitizerDisabled() bool {
	return true
}

// DisplayInIFrame implements markup.ExternalRenderer
func (Renderer) DisplayInIFrame() bool {
	return true
}

// Render implements markup.Renderer
func (Renderer) Render(ctx *markup.RenderContext, input io.Reader, output io.Writer) error {
	// The viewer must never run on Forgejo's origin, e.g. for a README.drawio rendered by type.
	if !ctx.InStandalonePage {
		return errors.New("drawio: can only be rendered in a standalone page")
	}

	data, err := io.ReadAll(io.LimitReader(input, setting.UI.MaxDisplayFileSize+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > setting.UI.MaxDisplayFileSize {
		return fmt.Errorf("drawio: file is larger than %d bytes", setting.UI.MaxDisplayFileSize)
	}

	var cfg strings.Builder
	enc := json.NewEncoder(&cfg)
	enc.SetEscapeHTML(false) // the attribute is HTML-escaped below
	if err := enc.Encode(map[string]any{
		"xml":      string(data),
		"toolbar":  "zoom layers pages",
		"nav":      true,
		"lightbox": false,
		"resize":   true,
	}); err != nil {
		return err
	}

	_, err = fmt.Fprintf(output, `<div class="mxgraph" data-mxgraph="%s"></div>
<script>window.onDrawioViewerLoad=()=>{mxStencilRegistry.allowEval=false;mxStencilRegistry.dynamicLoading=false;mxStyleRegistry.dynamicLoading=false;GraphViewer.processElements()}</script>
<script src="%s%s"></script>
`, html.EscapeString(cfg.String()), setting.StaticURLPrefix, ViewerPath)
	return err
}
