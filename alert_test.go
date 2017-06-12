package mint

import (
	"testing"
)

func TestAlert(t *testing.T) {
	assertEquals(t, AlertCloseNotify.String(), "close notify")
	assertEquals(t, AlertCloseNotify.Error(), "close notify")
	assertEquals(t, Alert(0xfd).String(), "alert(253)")
}
