package clean

import (
	"fmt"
	"os"
)

var Verbose bool

func Logf(format string, args ...any) {
	if !Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
