package mint

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// We use this environment variable to control logging.  It should be a
// comma-separated list of log tags (see below) or "*" to enable all logging.
const logConfigVar = "MINT_LOG"

// Pre-defined log types
const (
	logTypeCrypto    = "crypto"
	logTypeHandshake = "handshake"
	logTypeIO        = "io"
)

var (
	logFunction = log.Printf
	logAll      = false
	logSettings = map[string]bool{}
)

func init() {
	parseLogEnv(os.Environ())
}

func parseLogEnv(env []string) {
	for _, stmt := range env {
		if strings.HasPrefix(stmt, logConfigVar+"=") {
			val := stmt[len(logConfigVar)+1:]

			if val == "*" {
				logAll = true
			} else {
				for _, t := range strings.Split(val, ",") {
					logSettings[t] = true
				}
			}
		}
	}
}

func logf(tag string, format string, args ...interface{}) {
	if logAll || logSettings[tag] {
		fullFormat := fmt.Sprintf("[%s] %s", tag, format)
		logFunction(fullFormat, args...)
	}
}

//func dumpCryptoContext(role string, ctx cryptoContext) {
//	fmt.Printf("===== BEGIN CRYPTO CONTEXT [%s] =====\n", role)
//	fmt.Printf("state: %d\n", ctx.state)
//	fmt.Printf("suite: %04x\n", ctx.suite)
//	/* Params omitted */
//	fmt.Printf("zero:  %x\n", ctx.zero)
//
//	fmt.Printf("resumptionHash:     %x\n", ctx.resumptionHash)
//	fmt.Printf("pskSecret:          %x\n", ctx.pskSecret)
//	fmt.Printf("dhSecret:           %x\n", ctx.dhSecret)
//
//	fmt.Printf("h1:                 %x\n", ctx.h1)
//	fmt.Printf("hE:                 %x\n", ctx.hE)
//	fmt.Printf("h2:                 %x\n", ctx.h2)
//	fmt.Printf("h3:                 %x\n", ctx.h3)
//	fmt.Printf("h4:                 %x\n", ctx.h4)
//	fmt.Printf("h5:                 %x\n", ctx.h5)
//	fmt.Printf("h6:                 %x\n", ctx.h6)
//
//	fmt.Printf("earlySecret:        %x\n", ctx.earlySecret)
//	fmt.Printf("earlyTrafficSecret: %x\n", ctx.earlyTrafficSecret)
//	/* TODO: early handshake keys */
//	/* TODO: early application keys */
//
//	fmt.Printf("earlyFinishedKey:   %x\n", ctx.earlyFinishedKey)
//	fmt.Printf("earlyFinishedData:  %x\n", ctx.earlyFinishedData)
//
//	fmt.Printf("handshakeSecret:        %x\n", ctx.handshakeSecret)
//	fmt.Printf("handshakeTrafficSecret: %x\n", ctx.handshakeTrafficSecret)
//	/* TODO: handshake keys */
//
//	fmt.Printf("serverFinishedKey:   %x\n", ctx.serverFinishedKey)
//	fmt.Printf("serverFinishedData:  %x\n", ctx.serverFinishedData)
//
//	fmt.Printf("clientFinishedKey:   %x\n", ctx.clientFinishedKey)
//	fmt.Printf("clientFinishedData:  %x\n", ctx.clientFinishedData)
//
//	fmt.Printf("masterSecret:        %x\n", ctx.masterSecret)
//	fmt.Printf("trafficSecret:       %x\n", ctx.trafficSecret)
//	/* TODO: traffic keys */
//	fmt.Printf("exporterSecret:      %x\n", ctx.exporterSecret)
//	fmt.Printf("resumptionSecret:    %x\n", ctx.resumptionSecret)
//	fmt.Printf("resumptionPSK:       %x\n", ctx.resumptionPSK)
//	fmt.Printf("resumptionContext:   %x\n", ctx.resumptionContext)
//
//	fmt.Printf("===== END CRYPTO CONTEXT [%s] =====\n", role)
//}
