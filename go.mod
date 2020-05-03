module filippo.io/yubikey-agent

go 1.14

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/go-piv/piv-go v1.4.1-0.20200426040337-bf7b63063bf0
	golang.org/x/crypto v0.0.0-20200429183012-4b2356b1ed79
	golang.org/x/sys v0.0.0-20200420163511-1957bb5e6d1f
)

replace github.com/go-piv/piv-go => ../../go-piv/piv-go
