package types

import (
	"fmt"
)

// VariantTypes holds a mapping of RVTypes that are accessible in a Variant
var VariantTypes = make(map[uint8]RVType)

// RegisterVariantType registers a RVType to be accessible in a Variant
func RegisterVariantType(id uint8, rvType RVType) {
	VariantTypes[id] = rvType
}

// Variant is a type which can old many other types
type Variant struct {
	TypeID uint8 // TODO - Replace this with PrimitiveU8?
	Type   RVType
}

// WriteTo writes the Variant to the given writable
func (v *Variant) WriteTo(writable Writable) {
	writable.WritePrimitiveUInt8(v.TypeID)
	v.Type.WriteTo(writable)
}

// ExtractFrom extracts the Variant to the given readable
func (v *Variant) ExtractFrom(readable Readable) error {
	typeID, err := readable.ReadPrimitiveUInt8()
	if err != nil {
		return fmt.Errorf("Failed to read Variant type ID. %s", err.Error())
	}

	v.TypeID = typeID

	if _, ok := VariantTypes[v.TypeID]; !ok {
		return fmt.Errorf("Invalid Variant type ID %d", v.TypeID)
	}

	v.Type = VariantTypes[v.TypeID].Copy()

	return v.Type.ExtractFrom(readable)
}

// Copy returns a pointer to a copy of the Variant. Requires type assertion when used
func (v *Variant) Copy() RVType {
	copied := NewVariant()

	copied.TypeID = v.TypeID
	copied.Type = v.Type.Copy()

	return copied
}

// Equals checks if the input is equal in value to the current instance
func (v *Variant) Equals(o RVType) bool {
	if _, ok := o.(*Variant); !ok {
		return false
	}

	other := o.(*Variant)

	if v.TypeID != other.TypeID {
		return false
	}

	return v.Type.Equals(other.Type)
}

// TODO - Should this take in a default value, or take in nothing and have a "SetFromData"-kind of method?
// NewVariant returns a new Variant
func NewVariant() *Variant {
	return &Variant{}
}
