package massa

import (
	"log"
	"math/big"
	"testing"
)

func TestOutOfRangeParams(t *testing.T) {

	// I128
	_, err := NewI128(MaxI128().Add(MaxI128(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	_, err = NewI128(big.NewInt(0).Sub(MinI128(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	// U128
	_, err = NewU128(big.NewInt(0).Add(MaxU128(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	_, err = NewU128(big.NewInt(0).Sub(MinU128(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	// U256
	_, err = NewU256(big.NewInt(0).Add(MaxU256(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	_, err = NewU256(big.NewInt(0).Sub(MinU256(), big.NewInt(1)))
	if err == nil {
		t.Errorf("expected err, got nil")
	}

}

func TestSerialize(t *testing.T) {

	// u8
	u8Val := 233
	expectedSer := []byte{0xe9}
	u8Ser := Uint8(u8Val).serialize()
	for i, b := range u8Ser {
		if b != expectedSer[i] {
			t.Errorf("failed serializing uint8")
		}
	}

	// u32
	u32Val := 3573690285
	expectedSer = []byte{0xad, 0x2f, 0x02, 0xd5}
	u32Ser := Uint32(u32Val).serialize()
	for i, b := range u32Ser {
		if b != expectedSer[i] {
			t.Errorf("failed serializing uint32 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// u64
	u64Val := 24928359027684354
	expectedSer = []byte{0x02, 0xb4, 0xad, 0xe0, 0x35, 0x90, 0x58, 0x00}
	u64Ser := Uint64(u64Val).serialize()
	for i, b := range u64Ser {
		if b != expectedSer[i] {
			t.Errorf("failed serializing uint64 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// u128
	// 463116865018452738579035 ->  5B 1A 54 9C F8 3B 95 9D 11 62 00 00 00 00 00 00
	bi, _ := big.NewInt(0).SetString("463116865018452738579035", 10)
	expectedSer = []byte{
		0x5b, 0x1a, 0x54, 0x9c, 0xf8, 0x3b, 0x95, 0x9d,
		0x11, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	u128, err := NewU128(bi)
	if err != nil {
		t.Errorf("failed getting new Uint128")
	}
	for i, b := range u128.serialize() {
		if b != expectedSer[i] {
			t.Errorf("failed serializing uint128 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// u256
	// 9838135246829341594278986703867435213428185823840253 -> FD 07 E2 76 BC F1 DB 40 A0 20 29 43 B9 E6 30 CE BF 05 7A 86 4B 1A
	bi, _ = big.NewInt(0).SetString("9838135246829341594278986703867435213428185823840253", 10)
	expectedSer = []byte{
		0xfd, 0x07, 0xe2, 0x76, 0xbc, 0xf1, 0xdb, 0x40,
		0xa0, 0x20, 0x29, 0x43, 0xb9, 0xe6, 0x30, 0xce,
		0xbf, 0x05, 0x7a, 0x86, 0x4b, 0x1A, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	u256, err := NewU256(bi)
	if err != nil {
		t.Errorf("failed getting new Uint256")
	}
	for i, b := range u256.serialize() {
		if b != expectedSer[i] {
			t.Errorf("failed serializing uint256 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// i128
	// 463116865018452738579035 ->  5B 1A 54 9C F8 3B 95 9D 11 62 00 00 00 00 00 00
	bi, _ = big.NewInt(0).SetString("463116865018452738579035", 10)
	expectedSer = []byte{
		0x5b, 0x1a, 0x54, 0x9c, 0xf8, 0x3b, 0x95, 0x9d,
		0x11, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	i128, err := NewI128(bi)
	if err != nil {
		t.Errorf("failed getting new Uint128")
	}
	for i, b := range i128.serialize() {
		if b != expectedSer[i] {
			t.Errorf("failed serializing int128 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// -463116865018452738579035 -> A5 E5 AB 63 07 C4 6A 62 EE 9D FF FF FF FF FF FF
	bi, _ = big.NewInt(0).SetString("-463116865018452738579035", 10)
	expectedSer = []byte{
		0xa5, 0xe5, 0xab, 0x63, 0x07, 0xc4, 0x6a, 0x62,
		0xee, 0x9d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	i128, err = NewI128(bi)
	if err != nil {
		t.Errorf("failed getting new Uint128")
	}
	for i, b := range i128.serialize() {
		if b != expectedSer[i] {
			t.Errorf("failed serializing int128 at byte (%d), expected (%x), got (%x)", i, expectedSer[i], b)
		}
	}

	// String
	log.Printf("test tring bytes: %v", string("testString"))

}

func TestAddRemoveArgs(t *testing.T) {
	t.Fail()
}

func TestThing(t *testing.T) {

	// i128, err := NewI128(big.NewInt(0).Sub(MaxI128(), big.NewInt(6565656565)))
	i128, err := NewI128(big.NewInt(-2))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("i128: %v", i128)

	val := big.NewInt(0).Sub(MaxU128(), big.NewInt(6565656565))
	u128, err := NewU128(val)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("val: %s", val.Text(2))

	_ = u128.serialize()

	bi, _ := big.NewInt(0).SetString("-463116865018452738579035", 10)
	i128, err = NewI128(bi)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("i128: %v", i128)

}
