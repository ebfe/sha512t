package main

import (
	"flag"
	"fmt"
	"github.com/ebfe/sha512t"
	"io"
	"os"
)

var t = flag.Int("t", 256, "t param");

func main() {
	flag.Parse()

	sha := sha512t.New(*t)
	_, err := io.Copy(sha, os.Stdin)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", sha.Sum(nil))
}
