package massa

import (
	"encoding/binary"
	"fmt"

	"github.com/njones/base58"
	"github.com/zeebo/blake3"
)

type OperationType int

const (
	OpType_Transaction OperationType = iota
	OpType_BuyRoll
	OpType_SellRoll
	OpType_ExecuteSC
	OpType_CallSC
)

type OperationData interface {
	isOperationData()
	Type() OperationType
}

type TxData struct {
	fee           uint64
	amount        uint64
	recipientAddr string
}

type CallData struct {
	Fee            uint64
	MaxGas         uint64
	Coins          uint64
	TargetAddress  string
	TargetFunction string
	Parameter      []byte
}

func (t TxData) isOperationData()   {}
func (c CallData) isOperationData() {}

func (t TxData) Type() OperationType {
	return OpType_Transaction
}

func (c CallData) Type() OperationType {
	return OpType_CallSC
}

func compactBytesForOperation(opData OperationData, expiryPeriod uint64) ([]byte, error) {
	var (
		resultBytes        []byte
		feeBytes           []byte
		expiryPeriodBytes  []byte
		operationTypeBytes []byte
	)

	opType := opData.Type()

	expiryPeriodBytes = binary.AppendUvarint(expiryPeriodBytes, expiryPeriod)
	operationTypeBytes = binary.AppendUvarint(operationTypeBytes, uint64(opType))

	switch opData := opData.(type) {
	case TxData:

		// Varint encode the fee
		feeBytes = binary.AppendUvarint(feeBytes, opData.fee)

		// Varint encode the amount
		var amountBytes []byte
		amountBytes = binary.AppendUvarint(amountBytes, opData.amount)

		// Get recipient address bytes
		recipientAddrBytes, err := addressToBytes(opData.recipientAddr, true)
		if err != nil {
			return nil, fmt.Errorf("failed converting address to bytes: %w", err)
		}

		resultBytes = append(resultBytes, feeBytes...)
		resultBytes = append(resultBytes, expiryPeriodBytes...)
		resultBytes = append(resultBytes, operationTypeBytes...)
		resultBytes = append(resultBytes, recipientAddrBytes...)
		resultBytes = append(resultBytes, amountBytes...)

		return resultBytes, nil

	case CallData:

		// Encode fee
		feeBytes = binary.AppendUvarint(feeBytes, opData.Fee)

		// Encode maxGas
		var maxGasBytes []byte
		maxGasBytes = binary.AppendUvarint(maxGasBytes, opData.MaxGas)

		// Encode coins
		var coinsBytes []byte
		coinsBytes = binary.AppendUvarint(coinsBytes, opData.Coins)

		// Encode target address
		targetAddressBytes, err := addressToBytes(opData.TargetAddress, false)
		if err != nil {
			return nil, fmt.Errorf("failed converting address to bytes")
		}

		// Encode target function (utf-8)
		targetFunctionBytes := []byte(opData.TargetFunction)

		// Encode target function length
		var targetFuncLenBytes []byte
		targetFuncLenBytes = binary.AppendUvarint(targetFuncLenBytes, uint64(len(targetFunctionBytes)))

		// Serialize params
		// Done before passing...

		// Encode params
		// Done before passing...
		var paramsBytes = opData.Parameter

		// Encode params length
		var paramsLengthBytes []byte
		paramsLengthBytes = binary.AppendUvarint(paramsLengthBytes, uint64(len(paramsBytes)))

		resultBytes = append(resultBytes, feeBytes...)
		resultBytes = append(resultBytes, expiryPeriodBytes...)
		resultBytes = append(resultBytes, operationTypeBytes...)
		resultBytes = append(resultBytes, maxGasBytes...)
		resultBytes = append(resultBytes, coinsBytes...)
		resultBytes = append(resultBytes, targetAddressBytes...)
		resultBytes = append(resultBytes, targetFuncLenBytes...)
		resultBytes = append(resultBytes, targetFunctionBytes...)
		resultBytes = append(resultBytes, paramsLengthBytes...)
		resultBytes = append(resultBytes, paramsBytes...)

		return resultBytes, nil
	}

	return nil, fmt.Errorf("unknown operation data passed")
}

func getBytesToHash(chainId uint64, pubKeyBytes []byte, opBytes []byte) []byte {
	var chainIdBytes []byte
	chainIdBytes = binary.BigEndian.AppendUint64(chainIdBytes, chainId)

	var resultBytes []byte
	resultBytes = append(resultBytes, chainIdBytes...)
	resultBytes = append(resultBytes, pubKeyBytes...)
	resultBytes = append(resultBytes, opBytes...)

	return resultBytes
}

func signOpDigest(acc MassaAccount, digest []byte) MassaSignature {

	// // Hash payload with blake3
	// hasher := blake3.New()
	// hasher.Write(payload)
	// digest := hasher.Sum(nil)

	// Sign hash digest
	sig := acc.Sign(digest)

	// Encode signature
	encoded := encodeBytes(sig, acc.priv.Version)

	// Verison
	var version []byte
	version = binary.AppendUvarint(version, acc.priv.Version)

	// Serialized
	var serialized []byte
	serialized = append(serialized, version...)
	serialized = append(serialized, sig...)

	return MassaSignature{
		Encoded:    encoded,
		Serialized: serialized,
		PublicKey:  acc.pub.Encoded,
	}
}

func serializeOperation(caller MassaAccount, opData OperationData, expiryPeriod, chainId uint64) ([]byte, string, error) {

	// Build compact bytes
	opContentBytes, err := compactBytesForOperation(opData, expiryPeriod)
	if err != nil {
		return nil, "", fmt.Errorf("failed compacitng operation bytes: %w", err)
	}

	var serializedPub []byte
	serializedPub = binary.AppendUvarint(serializedPub, caller.priv.Version)
	serializedPub = append(serializedPub, caller.pub.Key...)

	// Hash operation content
	opContentHash := hashOpContents(getBytesToHash(chainId, serializedPub, opContentBytes))

	// Sign operation
	massaSig := signOpDigest(caller, opContentHash)

	// Serialize operation
	var serializedOp = []byte{}
	serializedOp = append(serializedOp, massaSig.Serialized...)
	serializedOp = append(serializedOp, serializedPub...)
	serializedOp = append(serializedOp, opContentBytes...)

	// Encode operation id
	var serializedOpId = []byte{}
	serializedOpId = binary.AppendUvarint(serializedOpId, caller.priv.Version)
	serializedOpId = append(serializedOpId, opContentHash...)

	opId := OPERATION_ID_PREFIX + base58.BitcoinEncoding.EncodeToString(serializedOpId)

	return serializedOp, opId, nil
}

func hashOpContents(payload []byte) []byte {
	// Hash payload with blake3
	hasher := blake3.New()
	hasher.Write(payload)
	return hasher.Sum(nil)
}

// For now this func just hardcodes a fee that is likely to
// to result in the tx being accepted, later on it can look
// at past blocks to actually estimate a fee.
//
// TODO: Implement actual fee estimation...
func estimateFee() uint64 {
	// Return 10,000,000 nMAS
	return 1e7
}
