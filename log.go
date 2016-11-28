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
	logTypeCrypto      = "crypto"
	logTypeHandshake   = "handshake"
	logTypeNegotiation = "negotiation"
	logTypeIO          = "io"
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

func dumpCryptoContext(role string, ctx cryptoContext) {
	logf(logTypeCrypto, "[%s] ===== BEGIN CRYPTO CONTEXT =====\n", role)
	logf(logTypeCrypto, "[%s] state: %d\n", role, ctx.state)
	logf(logTypeCrypto, "[%s] suite: %04x\n", role, ctx.suite)
	/* Omitted: Params */
	logf(logTypeCrypto, "[%s] zero:  %x\n", role, ctx.zero)

	logf(logTypeCrypto, "[%s] h2:                 %x\n", role, ctx.h2)
	logf(logTypeCrypto, "[%s] h3:                 %x\n", role, ctx.h3)
	logf(logTypeCrypto, "[%s] h4:                 %x\n", role, ctx.h4)
	logf(logTypeCrypto, "[%s] h5:                 %x\n", role, ctx.h5)
	logf(logTypeCrypto, "[%s] h6:                 %x\n", role, ctx.h6)

	logf(logTypeCrypto, "[%s] pskSecret:           %x\n", role, ctx.pskSecret)
	logf(logTypeCrypto, "[%s] earlySecret:         %x\n", role, ctx.earlySecret)
	logf(logTypeCrypto, "[%s] binderKey:           %x\n", role, ctx.binderKey)
	logf(logTypeCrypto, "[%s] earlyTrafficSecret:  %x\n", role, ctx.earlyTrafficSecret)
	logf(logTypeCrypto, "[%s] earlyExporterSecret: %x\n", role, ctx.earlyExporterSecret)
	/* Omitted: early application keys */

	logf(logTypeCrypto, "[%s] dhSecret:                     %x\n", role, ctx.dhSecret)
	logf(logTypeCrypto, "[%s] handshakeSecret:              %x\n", role, ctx.handshakeSecret)
	logf(logTypeCrypto, "[%s] clientHandshakeTrafficSecret: %x\n", role, ctx.clientHandshakeTrafficSecret)
	logf(logTypeCrypto, "[%s] serverHandshakeTrafficSecret: %x\n", role, ctx.serverHandshakeTrafficSecret)
	/* Omitted: client handshake keys */
	/* Omitted: server handshake keys */

	logf(logTypeCrypto, "[%s] masterSecret:        %x\n", role, ctx.masterSecret)
	logf(logTypeCrypto, "[%s] serverFinishedKey:   %x\n", role, ctx.serverFinishedKey)
	logf(logTypeCrypto, "[%s] serverFinishedData:  %x\n", role, ctx.serverFinishedData)
	logf(logTypeCrypto, "[%s] clientFinishedKey:   %x\n", role, ctx.clientFinishedKey)
	logf(logTypeCrypto, "[%s] clientFinishedData:  %x\n", role, ctx.clientFinishedData)

	logf(logTypeCrypto, "[%s] clientTrafficSecret: %x\n", role, ctx.clientTrafficSecret)
	logf(logTypeCrypto, "[%s] serverTrafficSecret: %x\n", role, ctx.serverTrafficSecret)
	/* Omitted: client traffic keys */
	/* Omitted: server traffic keys */
	logf(logTypeCrypto, "[%s] exporterSecret:      %x\n", role, ctx.exporterSecret)
	logf(logTypeCrypto, "[%s] resumptionSecret:    %x\n", role, ctx.resumptionSecret)

	logf(logTypeCrypto, "[%s] ===== END CRYPTO CONTEXT =====\n", role)
}
