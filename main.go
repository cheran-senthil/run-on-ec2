package main

import (
	"github.com/cheran-senthil/run-on-ec2/cmd"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	cmd.Execute()
}
