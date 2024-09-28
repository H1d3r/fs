package config

import (
	"fmt"
	"os"
)

func Stopfs(reason string) {
	s := fmt.Sprintf("[-] %v, fs exit", reason)
	fmt.Println(s)
	os.Exit(0)
}
