// +build darwin dragonfly freebsd linux netbsd openbsd

package agent

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func ListenAndServe() {
	var defaultPath string
	if cacheDir, err := os.UserCacheDir(); err == nil {
		defaultPath = filepath.Join(cacheDir, "yubikey-agent.sock")
	}
	socketPath := flag.String("l", defaultPath, "path of the UNIX socket to listen on")
	flag.Parse()

	a := &Agent{}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	os.Remove(*socketPath)
	l, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}
	fmt.Printf("export SSH_AUTH_SOCK=%q\n", *socketPath)

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}
