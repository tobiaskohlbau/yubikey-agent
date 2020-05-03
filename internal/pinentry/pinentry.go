package pinentry // import "filippo.io/yubikey-agent/internal/pinentry"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrCancel is returned when the user explicitly aborts the password
// request.
var ErrCancel = errors.New("pinentry: Cancel")

// Request describes what the user should see during the request for
// their password.
type Request struct {
	Desc, Prompt, OK, Cancel, Error string
}

func (r *Request) GetPIN() (pin string, outerr error) {
	bin, err := exec.LookPath("pinentry")
	if err != nil {
		return "", fmt.Errorf("failed to find pinentry executable: %w", err)
	}
	cmd := exec.Command(bin)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer cmd.Wait()
	defer stdin.Close()
	br := bufio.NewReader(stdout)
	lineb, _, err := br.ReadLine()
	if err != nil {
		return "", fmt.Errorf("Failed to get getpin greeting")
	}
	line := string(lineb)
	if !strings.HasPrefix(line, "OK") {
		return "", fmt.Errorf("getpin greeting said %q", line)
	}
	set := func(cmd string, val string) {
		if val == "" {
			return
		}
		fmt.Fprintf(stdin, "%s %s\n", cmd, val)
		line, _, err := br.ReadLine()
		if err != nil {
			panic("Failed to " + cmd)
		}
		if string(line) != "OK" {
			panic("Response to " + cmd + " was " + string(line))
		}
	}
	set("SETPROMPT", r.Prompt)
	set("SETDESC", r.Desc)
	set("SETOK", r.OK)
	set("SETCANCEL", r.Cancel)
	set("SETERROR", r.Error)
	fmt.Fprintf(stdin, "GETPIN\n")
	lineb, _, err = br.ReadLine()
	if err != nil {
		return "", fmt.Errorf("Failed to read line after GETPIN: %v", err)
	}
	line = string(lineb)
	if strings.HasPrefix(line, "D ") {
		return line[2:], nil
	}
	if strings.HasPrefix(line, "ERR 83886179 ") {
		return "", ErrCancel
	}
	return "", fmt.Errorf("GETPIN response didn't start with D; got %q", line)
}

func runPass(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v error: %v, %s", bin, err, out)
	}
	return nil
}