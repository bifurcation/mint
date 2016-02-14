package mint

type recordType byte

const (
	recordTypeAlert           recordType = 21
	recordTypeHandshake       recordType = 22
	recordTypeApplicationData recordType = 23
)
