package agent

import (
	"flag"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow         = kernel32.NewProc("GetConsoleWindow")
	getCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	showWindowAsync          = user32.NewProc("ShowWindowAsync")
)

const (
	swHide = 0
)

func ListenAndServe() {
	console, _, _ := getConsoleWindow.Call()
	if console == 0 {
		return
	}

	var consoleProcessID uint32
	getWindowThreadProcessId.Call(console, uintptr(unsafe.Pointer(&consoleProcessID)))
	currentProcessID, _, _ := getCurrentProcessId.Call()
	if uint32(currentProcessID) == consoleProcessID {
		showWindowAsync.Call(console)
	}

	defaultPath := "\\\\.\\\\pipe\\\\openssh-ssh-agent"
	socketPath := flag.String("l", defaultPath, "path of the UNIX socket to listen on")
	verbose := flag.Bool("v", false, "log output to C:/tmp/yubikey-agent.log")
	flag.Parse()

	if *verbose {
		f, err := os.OpenFile("C:/tmp/yubikey-agent.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalln("error opening file:", err)
		}
		defer f.Close()

		log.SetOutput(f)
	}

	l, err := winio.ListenPipe(*socketPath, nil)
	if err != nil {
		log.Fatalln("Failed to listen on Windows pipe:", err)
	}

	a := &Agent{}

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
