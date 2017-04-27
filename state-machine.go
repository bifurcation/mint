package mint

type State interface {
	Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert)
}

// Client State Machine
//
//                            START <----+
//             Send ClientHello |        | Recv HelloRetryRequest
//          /                   v        |
//         |                  WAIT_SH ---+
//     Can |                    | Recv ServerHello
//    send |                    V
//   early |                 WAIT_EE
//    data |                    | Recv EncryptedExtensions
//         |           +--------+--------+
//         |     Using |                 | Using certificate
//         |       PSK |                 v
//         |           |            WAIT_CERT_CR
//         |           |        Recv |       | Recv CertificateRequest
//         |           | Certificate |       v
//         |           |             |    WAIT_CERT
//         |           |             |       | Recv Certificate
//         |           |             v       v
//         |           |              WAIT_CV
//         |           |                 | Recv CertificateVerify
//         |           +> WAIT_FINISHED <+
//         |                  | Recv Finished
//         \                  |
//                            | [Send EndOfEarlyData]
//                            | [Send Certificate [+ CertificateVerify]]
//                            | Send Finished
//  Can send                  v
//  app data -->          CONNECTED
//  after
//  here

type ClientStateStart struct{}

func (state ClientStateStart) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Build ClientHello
	nextState := ClientStateWaitSH{}
	toSend := []HandshakeMessageBody{&ClientHelloBody{}}
	return nextState, toSend, AlertNoAlert
}

type ClientStateWaitSH struct{}

func (state ClientStateWaitSH) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	switch hm.Type() {
	case HandshakeTypeHelloRetryRequest:
		// TODO: Process HRR
		return ClientStateStart{}.Next(nil)

	case HandshakeTypeServerHello:
		// TODO: Process ServerHello
		nextState := ClientStateWaitEE{}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitEE struct {
	UsingPSK bool
}

func (state ClientStateWaitEE) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeEncryptedExtensions {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process extensions

	if state.UsingPSK {
		nextState := ClientStateWaitFinished{}
		return nextState, nil, AlertNoAlert
	}

	nextState := ClientStateWaitCertCR{}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCertCR struct{}

func (state ClientStateWaitCertCR) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO
	switch hm.Type() {
	case HandshakeTypeCertificate:
		// TODO: Process Certificate
		nextState := ClientStateWaitCV{}
		return nextState, nil, AlertNoAlert

	case HandshakeTypeCertificateRequest:
		// TODO: Process CertificateRequest
		nextState := ClientStateWaitCert{}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitCert struct{}

func (state ClientStateWaitCert) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificate {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process Certificate

	nextState := ClientStateWaitCV{}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCV struct{}

func (state ClientStateWaitCV) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificateVerify {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process CertificateVerify

	nextState := ClientStateWaitFinished{}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitFinished struct{}

func (state ClientStateWaitFinished) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeFinished {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Verify Finished

	nextState := StateConnected{}
	toSend := []HandshakeMessageBody{
		&EndOfEarlyDataBody{},
		&CertificateBody{},
		&CertificateVerifyBody{},
		&ClientHelloBody{},
	}
	return nextState, toSend, AlertNoAlert
}

// Server State Machine
//
//                              START <-----+
//               Recv ClientHello |         | Send HelloRetryRequest
//                                v         |
//                             RECVD_CH ----+
//                                | Select parameters
//                                v
//                             NEGOTIATED
//                                | Send ServerHello
//                                | Send EncryptedExtensions
//                                | [Send CertificateRequest]
// Can send                       | [Send Certificate + CertificateVerify]
// app data -->                   | Send Finished
// after                 +--------+--------+
// here         No 0-RTT |                 | 0-RTT
//                       |                 v
//                       |             WAIT_EOED <---+
//                       |            Recv |   |     | Recv
//                       |  EndOfEarlyData |   |     | early data
//                       |                 |   +-----+
//                       +> WAIT_FLIGHT2 <-+
//                                |
//                       +--------+--------+
//               No auth |                 | Client auth
//                       |                 |
//                       |                 v
//                       |             WAIT_CERT
//                       |        Recv |       | Recv Certificate
//                       |       empty |       v
//                       | Certificate |    WAIT_CV
//                       |             |       | Recv
//                       |             v       | CertificateVerify
//                       +-> WAIT_FINISHED <---+
//                                | Recv Finished
//                                v
//                            CONNECTED
//
// NB: Not using state RECVD_CH

type ServerStateStart struct {
	SendHRR bool
}

func (state ServerStateStart) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeClientHello {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process ClientHello

	if state.SendHRR {
		nextState := ServerStateStart{}
		toSend := []HandshakeMessageBody{&HelloRetryRequestBody{}}
		return nextState, toSend, AlertNoAlert
	}

	return ServerStateNegotiated{}.Next(nil)
}

type ServerStateNegotiated struct {
	Using0xRTT bool
}

func (state ServerStateNegotiated) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Negotiate from CH, SH

	toSend := []HandshakeMessageBody{
		&ServerHelloBody{},
		&EncryptedExtensionsBody{},
		&CertificateRequestBody{},
		&CertificateBody{},
		&CertificateVerifyBody{},
		&FinishedBody{},
	}

	if state.Using0xRTT {
		nextState := ServerStateWaitEOED{}
		return nextState, toSend, AlertNoAlert
	}

	nextState, moreToSend, alert := ServerStateWaitFlight2{}.Next(nil)
	toSend = append(toSend, moreToSend...)
	return nextState, toSend, alert
}

type ServerStateWaitEOED struct{}

func (state ServerStateWaitEOED) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeEndOfEarlyData {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Rekey to handshake keys

	return ServerStateWaitFlight2{}.Next(nil)
}

type ServerStateWaitFlight2 struct {
	UsingClientAuth bool
}

func (state ServerStateWaitFlight2) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO

	if state.UsingClientAuth {
		nextState := ServerStateWaitCert{}
		return nextState, nil, AlertNoAlert
	}

	nextState := ServerStateWaitFinished{}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCert struct {
	CertificateEmpty bool
}

func (state ServerStateWaitCert) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificate {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO

	if state.CertificateEmpty {
		nextState := ServerStateWaitFinished{}
		return nextState, nil, AlertNoAlert
	}

	nextState := ServerStateWaitCV{}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCV struct{}

func (state ServerStateWaitCV) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificateVerify {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO

	nextState := ServerStateWaitFinished{}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitFinished struct{}

func (state ServerStateWaitFinished) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeFinished {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Verify Finished

	nextState := StateConnected{}
	return nextState, nil, AlertNoAlert
}

// Connected state is symmetric between client and server (NB: Might need a
// notation as to which role is being played)
type StateConnected struct{}

func (state StateConnected) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	switch hm.Type() {
	case HandshakeTypeKeyUpdate:
		// TODO: Handle KeyUpdate
		return state, nil, AlertNoAlert
	case HandshakeTypeNewSessionTicket:
		// TODO: Handle KeyUpdate
		return state, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}
