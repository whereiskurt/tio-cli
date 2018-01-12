package main

import (
	"github.com/whereiskurt/tio-cli/cmd/vulnerability"
	//"os"
)

func main() {
	//argsWithProg := os.Args

	//TODO: Add a check for either 'vuln|webapp'. Current only supporting vulnerability
	tio.VulnExecute()

	return
}
