package massa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
)

// Args is a util for serializing parameters for smart
// contract calls.

// TODO: Add methods for array, serializable, bool etc...
// TODO: Maybe replace big.Int with decimal.Decimal...

var (
	ErrOutOfRange = errors.New("slice index out of range")
)

// {
// 	STRING,
// 	BOOL,
// 	U8,
// 	U32,
// 	U64,
// 	I128,
// 	U128,
// 	U256,
// 	I32,
// 	I64,
// 	F32,
// 	F64,
// 	ARRAY,
// 	UINT8ARRAY,
// 	SERIALIZABLE,
// 	SERIALIZABLE_OBJECT_ARRAY,
// }

func MaxI128() *big.Int {
	val, _ := big.NewInt(0).SetString("0x7fffffffffffffffffffffffffffffff", 0)
	// log.Fatal(success)
	return val
}

func MinI128() *big.Int {
	val, _ := big.NewInt(0).SetString("-170141183460469231731687303715884105728", 10)
	return val
}

func MaxU128() *big.Int {
	val, _ := big.NewInt(0).SetString("0xffffffffffffffffffffffffffffffff", 0)
	return val
}

func MinU128() *big.Int {
	return big.NewInt(0)
}

func MaxU256() *big.Int {
	val, _ := big.NewInt(0).SetString("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
	return val
}

func MinU256() *big.Int {
	return big.NewInt(0)
}

type paramType interface {
	isParamType()
}

type Uint8 uint8
type Uint32 uint32
type Uint64 uint64
type Uint128 [2]uint64
type Uint256 [4]uint64
type Int32 int32
type Int64 int64
type Int128 [2]uint64
type String string

func (Uint8) isParamType()   {}
func (Uint32) isParamType()  {}
func (Uint64) isParamType()  {}
func (Uint128) isParamType() {}
func (Uint256) isParamType() {}
func (Int32) isParamType()   {}
func (Int64) isParamType()   {}
func (Int128) isParamType()  {}
func (String) isParamType()  {}

func NewU128(i *big.Int) (Uint128, error) {
	if i.Cmp(MaxU128()) == 1 || i.Cmp(MinU128()) == -1 {
		return Uint128{}, fmt.Errorf("provided big.Int is out of valid Uint128 range")
	}

	var (
		res = Uint128{}
		b   = make([]byte, 16)
	)

	i.FillBytes(b)

	res[0] = binary.BigEndian.Uint64(b[:8])
	res[1] = binary.BigEndian.Uint64(b[8:])

	return res, nil
}

func NewU256(i *big.Int) (Uint256, error) {
	if i.Cmp(MaxU256()) == 1 || i.Cmp(MinU256()) == -1 {
		return Uint256{}, fmt.Errorf("provided big.Int is out of valid Uint256 range")
	}

	var (
		res = Uint256{}
		b   = make([]byte, 32)
	)

	i.FillBytes(b)

	res[0] = binary.BigEndian.Uint64(b[:8])
	res[1] = binary.BigEndian.Uint64(b[8:16])
	res[2] = binary.BigEndian.Uint64(b[16:24])
	res[3] = binary.BigEndian.Uint64(b[24:])

	return res, nil
}

func NewI128(i *big.Int) (Int128, error) {
	if i.Cmp(MaxI128()) == 1 || i.Cmp(MinI128()) == -1 {
		return Int128{}, fmt.Errorf("provided big.Int is out of valid Int128 range")
	}

	var (
		res = Int128{}
		b   = make([]byte, 16)
	)

	i.FillBytes(b)

	res[0] = binary.BigEndian.Uint64(b[:8])
	res[1] = binary.BigEndian.Uint64(b[8:])

	// Convert unsigned value to it's two's complement
	if i.Sign() < 0 {
		// Flip all bits
		res[0] = ^res[0]
		res[1] = ^res[1]

		// Add 1
		res[1]++
		// Carry over
		if res[1] == 0 {
			res[0]++
		}
	}

	return res, nil
}

func (z Uint8) serialize() []byte {
	return []byte{byte(z)}
}

func (z Uint32) serialize() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(z))
	return b
}

func (z Uint64) serialize() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(z))
	return b
}

func (z Uint128) serialize() []byte {
	var b = make([]byte, 16)
	binary.LittleEndian.PutUint64(b[:8], z[1])
	binary.LittleEndian.PutUint64(b[8:], z[0])
	return b
}

func (z Uint256) serialize() []byte {
	var b = make([]byte, 32)
	binary.LittleEndian.PutUint64(b[:8], z[3])
	binary.LittleEndian.PutUint64(b[8:16], z[2])
	binary.LittleEndian.PutUint64(b[16:24], z[1])
	binary.LittleEndian.PutUint64(b[24:], z[0])
	log.Printf("b: %v", b)
	return b
}

func (z Int32) serialize() []byte {
	b := make([]byte, 4)
	// We can convert to a uint32 here without issue
	// since the conversion only changes the type and
	// not the underlying binary in memory.
	binary.LittleEndian.PutUint32(b, uint32(z))
	return b
}

func (z Int64) serialize() []byte {
	b := make([]byte, 8)
	// We can convert to a uint64 here without issue
	// since the conversion only changes the type and
	// not the underlying binary in memory.
	binary.LittleEndian.PutUint64(b, uint64(z))
	return b
}

func (z Int128) serialize() []byte {
	var b = make([]byte, 16)
	binary.LittleEndian.PutUint64(b[:8], z[1])
	binary.LittleEndian.PutUint64(b[8:], z[0])
	log.Printf("b: %v", b)
	return b
}

func (z String) serialize() []byte {
	return []byte(z)
}

type param struct {
	sum paramType
}

type Args struct {
	serialized []byte
	offset     int
	paramsList []param
}

// To add a number param we serialize it, add it's length
// in bytes to the offset, append it to the result, and
// append the param to the arguments slice.
//
// To get a param we read the appropriate number of
// bytes from the current offset and then increment the
// offset by the number of bytes read.

func (a *Args) AddUint8(val uint8) {
	a.offset++
	a.serialized = append(a.serialized, Uint8(val).serialize()...)
	a.paramsList = append(a.paramsList, param{sum: Uint8(val)})
}

func (a *Args) AddUint32(val uint32) {
	a.offset += 4
	a.serialized = append(a.serialized, Uint32(val).serialize()...)
	a.paramsList = append(a.paramsList, param{sum: Uint32(val)})
}

func (a *Args) AddUint64(val uint64) {
	a.offset += 8
	a.serialized = append(a.serialized, Uint64(val).serialize()...)
	a.paramsList = append(a.paramsList, param{sum: Uint64(val)})
}

func (a *Args) AddUint128(val Uint128) {
	a.offset += 16
	a.serialized = append(a.serialized, val.serialize()...)
	a.paramsList = append(a.paramsList, param{sum: val})
}

func (a *Args) AddUint256(val Uint256) {
	a.offset += 32
	a.serialized = append(a.serialized, val.serialize()...)
	a.paramsList = append(a.paramsList, param{sum: val})
}

func (a *Args) AddInt32(val int32) {
	a.offset += 4
	a.serialized = append(a.serialized, Int32(val).serialize()...)
	a.paramsList = append(a.paramsList, param{sum: Int32(val)})
}

func (a *Args) AddInt64(val int64) {
	a.offset += 8
	a.serialized = append(a.serialized, Int64(val).serialize()...)
	a.paramsList = append(a.paramsList, param{sum: Int64(val)})
}

func (a *Args) AddInt128(val Int128) {
	a.offset += 16
	a.serialized = append(a.serialized, val.serialize()...)
	a.paramsList = append(a.paramsList, param{sum: val})
}

func (a *Args) AddFloat32(val float64) {
	panic("Not implemented yet, don't call.")
}

func (a *Args) AddFloat64(val float64) {
	panic("Not implemented yet, don't call.")
}

func (a *Args) AddString(val String) {
	ser := val.serialize()
	a.offset += len(ser)
	a.serialized = append(a.serialized, val.serialize()...)
	a.paramsList = append(a.paramsList, param{sum: val})
}

func (a *Args) AddBool(val bool) {

}

func (a *Args) AddByteSlice(val []byte) {

}

func (a *Args) NextUint8() (uint8, error) {
	if a.offset >= len(a.serialized) {
		return 0, ErrOutOfRange
	}
	res := uint8(a.serialized[a.offset])
	a.offset++
	return res, nil
}
