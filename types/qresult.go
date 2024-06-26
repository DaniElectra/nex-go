package types

import (
	"fmt"
	"strings"
)

var errorMask = 1 << 31

// QResult is an implementation of rdv::qResult.
// Determines the result of an operation.
// If the MSB is set the result is an error, otherwise success
type QResult struct {
	Code uint32
}

// WriteTo writes the QResult to the given writable
func (r *QResult) WriteTo(writable Writable) {
	writable.WritePrimitiveUInt32LE(r.Code)
}

// ExtractFrom extracts the QResult from the given readable
func (r *QResult) ExtractFrom(readable Readable) error {
	code, err := readable.ReadPrimitiveUInt32LE()
	if err != nil {
		return fmt.Errorf("Failed to read QResult code. %s", err.Error())
	}

	r.Code = code

	return nil
}

// Copy returns a pointer to a copy of the QResult. Requires type assertion when used
func (r *QResult) Copy() RVType {
	return NewQResult(r.Code)
}

// Equals checks if the input is equal in value to the current instance
func (r *QResult) Equals(o RVType) bool {
	if _, ok := o.(*QResult); !ok {
		return false
	}

	return r.Code == o.(*QResult).Code
}

// IsSuccess returns true if the QResult is a success
func (r *QResult) IsSuccess() bool {
	return int(r.Code)&errorMask == 0
}

// IsError returns true if the QResult is a error
func (r *QResult) IsError() bool {
	return int(r.Code)&errorMask != 0
}

// String returns a string representation of the struct
func (r *QResult) String() string {
	return r.FormatToString(0)
}

// FormatToString pretty-prints the struct data using the provided indentation level
func (r *QResult) FormatToString(indentationLevel int) string {
	indentationValues := strings.Repeat("\t", indentationLevel+1)
	indentationEnd := strings.Repeat("\t", indentationLevel)

	var b strings.Builder

	b.WriteString("QResult{\n")

	if r.IsSuccess() {
		b.WriteString(fmt.Sprintf("%scode: %d (success)\n", indentationValues, r.Code))
	} else {
		b.WriteString(fmt.Sprintf("%scode: %d (error)\n", indentationValues, r.Code))
	}

	b.WriteString(fmt.Sprintf("%s}", indentationEnd))

	return b.String()
}

// NewQResult returns a new QResult
func NewQResult(code uint32) *QResult {
	return &QResult{code}
}

// NewQResultSuccess returns a new QResult set as a success
func NewQResultSuccess(code uint32) *QResult {
	return NewQResult(uint32(int(code) & ^errorMask))
}

// NewQResultError returns a new QResult set as an error
func NewQResultError(code uint32) *QResult {
	return NewQResult(uint32(int(code) | errorMask))
}
