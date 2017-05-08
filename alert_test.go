package mint

import (
	"testing"
)

func TestAlert(t *testing.T) {
	assertEquals(t, AlertCloseNotify.String(), "close notify")
	assertEquals(t, AlertCloseNotify.Error(), "close notify")
	assertEquals(t, Alert(0xfe).String(), "alert(254)")
}
