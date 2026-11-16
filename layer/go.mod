module github.com/Chargetronic/imatra.test_harness/layer

go 1.24

require github.com/eclipse/paho.mqtt.golang v1.5.0

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
)

// golang.org is not always reachable from build sandboxes; same code from the GitHub mirrors.
replace golang.org/x/net => github.com/golang/net v0.33.0

replace golang.org/x/sync => github.com/golang/sync v0.10.0
