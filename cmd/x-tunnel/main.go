package main

import "x-tunnel/internal/app"

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

func main() {
	app.SetBuildInfo(buildVersion, buildCommit, buildDate)
	app.Main()
}
