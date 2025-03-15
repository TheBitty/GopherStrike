package pkg

import (
	"GopherStrike/pkg/tools/osint"
)

// RunOSINTTool executes the OSINT tool
func RunOSINTTool() error {
	return osint.RunOSINTScanner()
}
