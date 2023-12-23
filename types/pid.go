package types

import (
	"fmt"
	"strings"
)

// PID represents a unique number to identify a user
//
// The true size of this value depends on the client version.
// Legacy clients (WiiU/3DS) use a uint32, whereas modern clients (Nintendo Switch) use a uint64.
// Value is always stored as the higher uint64, the consuming API should assert accordingly
type PID struct {
	pid uint64 // TODO - Replace this with PrimitiveU64?
}

// WriteTo writes the bool to the given writable
func (p *PID) WriteTo(writable Writable) {
	if writable.PIDSize() == 8 {
		writable.WritePrimitiveUInt64LE(p.pid)
	} else {
		writable.WritePrimitiveUInt32LE(uint32(p.pid))
	}
}

// ExtractFrom extracts the bool to the given readable
func (p *PID) ExtractFrom(readable Readable) error {
	var pid uint64
	var err error

	if readable.PIDSize() == 8 {
		pid, err = readable.ReadPrimitiveUInt64LE()
	} else {
		p, e := readable.ReadPrimitiveUInt32LE()

		pid = uint64(p)
		err = e
	}

	if err != nil {
		return err
	}

	p.pid = pid

	return nil
}

// Copy returns a pointer to a copy of the PID. Requires type assertion when used
func (p PID) Copy() RVType {
	return NewPID(p.pid)
}

// Equals checks if the input is equal in value to the current instance
func (p *PID) Equals(o RVType) bool {
	if _, ok := o.(*PID); !ok {
		return false
	}

	return p.pid == o.(*PID).pid
}

// Value returns the numeric value of the PID as a uint64 regardless of client version
func (p *PID) Value() uint64 {
	return p.pid
}

// LegacyValue returns the numeric value of the PID as a uint32, for legacy clients
func (p *PID) LegacyValue() uint32 {
	return uint32(p.pid)
}

// String returns a string representation of the struct
func (p *PID) String() string {
	return p.FormatToString(0)
}

// FormatToString pretty-prints the struct data using the provided indentation level
func (p *PID) FormatToString(indentationLevel int) string {
	indentationValues := strings.Repeat("\t", indentationLevel+1)
	indentationEnd := strings.Repeat("\t", indentationLevel)

	var b strings.Builder

	b.WriteString("PID{\n")

	switch v := any(p.pid).(type) {
	case uint32:
		b.WriteString(fmt.Sprintf("%spid: %d (legacy)\n", indentationValues, v))
	case uint64:
		b.WriteString(fmt.Sprintf("%spid: %d (modern)\n", indentationValues, v))
	}

	b.WriteString(fmt.Sprintf("%s}", indentationEnd))

	return b.String()
}

// TODO - Should this take in a default value, or take in nothing and have a "SetFromData"-kind of method?
// NewPID returns a PID instance. The size of PID depends on the client version
func NewPID[T uint32 | uint64](pid T) *PID {
	switch v := any(pid).(type) {
	case uint32:
		return &PID{pid: uint64(v)}
	case uint64:
		return &PID{pid: v}
	}

	// * This will never happen because Go will
	// * not compile any code where "pid" is not
	// * a uint32/uint64, so it will ALWAYS get
	// * caught by the above switch-case. This
	// * return is only here because Go won't
	// * compile without a default return
	return nil
}
