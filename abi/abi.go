// Package abi defines the portable JSON contract shared by hosts and plugins.
package abi

import "encoding/json"

const Version = 1
const MaxJSON = 1 << 20

type Operation string

const (
	CreatePayment  Operation = "create_payment"
	QueryPayment   Operation = "query_payment"
	ClosePayment   Operation = "close_payment"
	Refund         Operation = "refund"
	QueryRefund    Operation = "query_refund"
	VerifyCallback Operation = "verify_callback"
	FetchStatement Operation = "fetch_statement"
	ParseStatement Operation = "parse_statement"
)

var PaymentOperations = []Operation{CreatePayment, QueryPayment, ClosePayment, Refund, QueryRefund, VerifyCallback}

func (o Operation) Payment() bool {
	for _, v := range PaymentOperations {
		if o == v {
			return true
		}
	}
	return false
}

type Money struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}
type PaymentInput struct {
	OrderID string `json:"order_id"`
	Money   Money  `json:"money"`
}
type CreatePaymentInput struct {
	OrderID     string `json:"order_id"`
	Money       Money  `json:"money"`
	Method      string `json:"method"`
	BankMode    string `json:"bank_mode,omitempty"`
	Instruction string `json:"instruction,omitempty"`
	CallbackURL string `json:"callback_url"`
}
type RefundInput struct {
	OrderID  string `json:"order_id"`
	RefundID string `json:"refund_id"`
	Money    Money  `json:"money"`
}
type CallbackInput struct {
	OrderID  string              `json:"order_id"`
	Money    Money               `json:"money"`
	Method   string              `json:"method"`
	RawQuery []byte              `json:"raw_query,omitempty"`
	Headers  map[string][]string `json:"headers"`
	Body     []byte              `json:"body"`
	SourceIP string              `json:"source_ip,omitempty"`
}
type Call struct {
	Input     json.RawMessage `json:"input"`
	Responses []Response      `json:"responses"`
}
type Request struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}
type Response struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// Step is an exclusive union. Error is a final result outcome, never a third step kind.
type Step struct {
	Request *Request `json:"request,omitempty"`
	Result  *Result  `json:"result,omitempty"`
}
type Result struct {
	Outcome  string          `json:"outcome"` // completed, rejected, unknown, error
	Code     string          `json:"code,omitempty"`
	Payment  *PaymentOutput  `json:"payment,omitempty"`
	Refund   *RefundOutput   `json:"refund,omitempty"`
	Callback *CallbackOutput `json:"callback,omitempty"`
}
type PaymentOutput struct {
	OrderID    string `json:"order_id"`
	UpstreamID string `json:"upstream_id"`
	Money      Money  `json:"money"`
	Status     string `json:"status"`
	URL        string `json:"url,omitempty"`
	QRCode     string `json:"qrcode,omitempty"`
	PaidAt     string `json:"paid_at,omitempty"`
}
type RefundOutput struct {
	OrderID          string `json:"order_id"`
	RefundID         string `json:"refund_id"`
	UpstreamRefundID string `json:"upstream_refund_id"`
	Money            Money  `json:"money"`
	Status           string `json:"status"`
}
type CallbackOutput struct {
	EventID    string   `json:"event_id"`
	OrderID    string   `json:"order_id"`
	UpstreamID string   `json:"upstream_id"`
	Money      Money    `json:"money"`
	Status     string   `json:"status"`
	Ack        Response `json:"ack"`
}

// Parts are bytes (base64 in JSON) or a declared secret reference, exclusively.
type Part struct {
	Data   []byte `json:"data,omitempty"`
	Secret string `json:"secret,omitempty"`
}
type SignRequest struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key,omitempty"`
	Parts     []Part `json:"parts"`
}
type VerifyRequest struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	Parts     []Part `json:"parts"`
	Signature string `json:"signature"`
}
type ConfigRequest struct {
	Name string `json:"name"`
}
type EqualRequest struct {
	A string `json:"a"`
	B string `json:"b"`
}
type LogRequest struct {
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// HostReply never carries secret bytes; failure aborts execution in the host.
type HostReply struct {
	Value json.RawMessage `json:"value"`
}
