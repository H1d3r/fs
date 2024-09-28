package main

import (
	"fmt"
	"fs/Plugins"
	"fs/config"
	"time"
)

func main() {
	var Info config.ScannerCfg
	start := time.Now()
	config.Flag(&Info)
	config.Parse(&Info)
	Plugins.Scan(Info)
	config.Stopfs("Scan over")
	fmt.Printf("[*] time: %s\n", time.Since(start))
}
