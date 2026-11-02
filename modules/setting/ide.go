// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"os"
	"path/filepath"
)

// IDE holds the Web IDE settings, [ide]. The IDE's files are not in the binary: they are served from AssetsPath.
var IDE = struct {
	Enabled     bool
	MaxFileSize int64
	AssetsPath  string
}{}

func loadIDEFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("ide")
	IDE.Enabled = sec.Key("ENABLED").MustBool(true)
	IDE.MaxFileSize = sec.Key("MAX_FILE_SIZE").MustInt64(UI.MaxDisplayFileSize)
	IDE.AssetsPath = sec.Key("ASSETS_PATH").MustString(filepath.Join(StaticRootPath, "public", "assets", "ide"))
	if !filepath.IsAbs(IDE.AssetsPath) {
		IDE.AssetsPath = filepath.Join(AppWorkPath, IDE.AssetsPath)
	}
}

// IDEAvailable reports whether the Web IDE is on and its files are deployed.
func IDEAvailable() bool {
	if !IDE.Enabled {
		return false
	}
	_, err := os.Stat(filepath.Join(IDE.AssetsPath, "ide.js"))
	return err == nil
}
