package mint

import (
	"fmt"
	"testing"
)

var logLine = ""

func testLogFunction(format string, v ...interface{}) {
	logLine = fmt.Sprintf(format, v...)
}

func TestLogging(t *testing.T) {
	originalLogFunction := logFunction
	originalLogAll := logAll
	originalLogSettings := logSettings

	logAll = false
	logSettings = map[string]bool{}
	env := []string{"MINT_LOG=*"}
	parseLogEnv(env)
	assert(t, logAll, "Failed to parse wildcard log directive")
	assert(t, len(logSettings) == 0, "Mistakenly set log settings")

	logAll = false
	logSettings = map[string]bool{}
	env = []string{"MINT_LOG=foo,bar"}
	parseLogEnv(env)
	assert(t, !logAll, "Mistakenly set logAll")
	assert(t, logSettings["foo"] && logSettings["bar"], "Failed to parse string log directive")

	logFunction = testLogFunction
	logAll = false
	logSettings = map[string]bool{"foo": true}

	// Test that we print matching lines
	logLine = ""
	logf("foo", "This is an integer: %d", 1)
	assertEquals(t, logLine, "[foo] This is an integer: 1")

	// Test that we ignore non-matching lines
	logLine = ""
	logf("bar", "This is an integer: %d", 1)
	assertEquals(t, logLine, "")

	// Test that logAll enables all
	logAll = true
	logLine = ""
	logf("bar", "This is an integer: %d", 1)
	assertEquals(t, logLine, "[bar] This is an integer: 1")

	// Restore original values for globals
	logFunction = originalLogFunction
	logAll = originalLogAll
	logSettings = originalLogSettings
}
