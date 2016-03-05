package mint

import (
	"testing"
)

func TestAlert(t *testing.T) {
	assertEquals(t, alertCloseNotify.String(), "close notify")
	assertEquals(t, alertCloseNotify.Error(), "close notify")
	assertEquals(t, alert(0xff).String(), "alert(255)")
}
