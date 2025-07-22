package utils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/brevis-network/zk-utils/common/proof"
	"github.com/celer-network/goutils/log"
	ec "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type TransactionData struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *ec.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
}

type TransactionDataWithVRS struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *ec.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList types.AccessList
	V          *big.Int
	R          *big.Int
	S          *big.Int
}

type LegacyTransactionData struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *ec.Address `rlp:"nil"`
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
	Pad1     *big.Int
	Pad2     *big.Int
}

type LegacyTransactionDataWithVRS struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       *ec.Address `rlp:"nil"`
	Value    *big.Int
	Data     []byte
	V        *big.Int
	R        *big.Int
	S        *big.Int
}

type ReceiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             *types.Bloom
	Logs              []*types.Log
}

func DecodeTransactionData(encoded []byte) (transactionData *TransactionData, err error) {
	if len(encoded) == 0 {
		err = fmt.Errorf("empty transaction rlp")
		return
	}
	if encoded[0] != 2 {
		err = fmt.Errorf("invalid rlp prefix for transaction type 2")
		return
	}
	encoded = encoded[1:]

	err = rlp.DecodeBytes(encoded, &transactionData)
	return
}

func DecodeTransactionDataWithVRS(encoded []byte) (transactionData *TransactionDataWithVRS, err error) {
	if len(encoded) == 0 {
		err = fmt.Errorf("empty transaction rlp")
		return
	}
	if encoded[0] != 2 {
		err = fmt.Errorf("invalid rlp prefix for transaction type 2")
		return
	}
	encoded = encoded[1:]

	err = rlp.DecodeBytes(encoded, &transactionData)
	return
}

func ExtractTransactionData(
	transactionType uint,
	unsignedTxRlp string,
	transactionDataVRS *TransactionDataWithVRS,
) (proof.TransactionExtraInfo, error) {
	unsignedTxRlpBytes := Hex2Bytes(unsignedTxRlp)
	transactionData, err := DecodeTransactionData(unsignedTxRlpBytes)
	if err != nil {
		return proof.TransactionExtraInfo{}, err
	}

	result := proof.TransactionExtraInfo{
		ChainId:              transactionData.ChainID.Uint64(),
		Nonce:                transactionData.Nonce,
		MaxPriorityFeePerGas: hexutil.Encode(transactionData.GasTipCap.Bytes()),
		MaxFeePerGas:         hexutil.Encode(transactionData.GasFeeCap.Bytes()),
		GasLimit:             transactionData.Gas,
		From:                 "",
		To:                   hexutil.Encode(transactionData.To.Bytes()),
		Value:                hexutil.Encode(transactionData.Value.Bytes()),
	}
	if transactionData.ChainID.Cmp(transactionDataVRS.ChainID) != 0 ||
		transactionData.Nonce != transactionDataVRS.Nonce ||
		transactionData.GasTipCap.Cmp(transactionDataVRS.GasTipCap) != 0 ||
		transactionData.GasFeeCap.Cmp(transactionDataVRS.GasFeeCap) != 0 ||
		transactionData.To.Cmp(*transactionDataVRS.To) != 0 ||
		transactionData.Value.Cmp(transactionDataVRS.Value) != 0 {
		return proof.TransactionExtraInfo{}, fmt.Errorf("invalid unsigned tx rlp with mpt leaf value")
	}

	from, err := RecoverSignerAddress(unsignedTxRlpBytes, transactionDataVRS.V, transactionDataVRS.R, transactionDataVRS.S, transactionType, transactionData.ChainID)
	if err != nil {
		return proof.TransactionExtraInfo{}, err
	}

	result.From = hexutil.Encode(from)
	return result, nil
}

func DecodeLegacyTransactionData(encoded []byte) (transactionData *LegacyTransactionData, err error) {
	err = rlp.Decode(bytes.NewReader(encoded), &transactionData)
	return
}

func DecodeLegacyTransactionDataWithVRS(encoded []byte) (transactionData *LegacyTransactionDataWithVRS, err error) {
	err = rlp.Decode(bytes.NewReader(encoded), &transactionData)
	return
}

func ExtractLegacyTransactionData(
	transactionType uint,
	unsignedTxRlp string,
	transactionDataVRS *LegacyTransactionDataWithVRS) (proof.TransactionExtraInfo, error) {
	unsignedTxRlpBytes := Hex2Bytes(unsignedTxRlp)

	transactionData, err := DecodeLegacyTransactionData(unsignedTxRlpBytes)
	if err != nil {
		return proof.TransactionExtraInfo{}, err
	}

	// Please refer https://github.com/brevis-network/brevis-gateway/blob/10367e054301eb6e1bf2d1021973711d89d0703e/query/sdk_query.go#L332-L338

	result := proof.TransactionExtraInfo{
		ChainId:              transactionData.ChainID.Uint64(),
		Nonce:                transactionData.Nonce,
		MaxPriorityFeePerGas: hexutil.Encode(transactionData.GasPrice.Bytes()),
		MaxFeePerGas:         "0x00",
		GasLimit:             transactionData.Gas,
		From:                 "",
		To:                   hexutil.Encode(transactionData.To.Bytes()),
		Value:                hexutil.Encode(transactionData.Value.Bytes()),
	}
	if transactionData.ChainID.Uint64() != 1 ||
		transactionData.Nonce != transactionDataVRS.Nonce ||
		transactionData.GasPrice.Cmp(transactionDataVRS.GasPrice) != 0 ||
		transactionData.To.Cmp(*transactionDataVRS.To) != 0 ||
		transactionData.Value.Cmp(transactionDataVRS.Value) != 0 {
		return proof.TransactionExtraInfo{}, fmt.Errorf("invalid unsigned tx rlp with mpt leaf value")
	}

	from, err := RecoverSignerAddress(unsignedTxRlpBytes, transactionDataVRS.V, transactionDataVRS.R, transactionDataVRS.S, transactionType, transactionData.ChainID)
	if err != nil {
		return proof.TransactionExtraInfo{}, err
	}

	result.From = hexutil.Encode(from)
	return result, nil
}

func DecodeReceiptRLP(encoded []byte, transactionType int) (receiptRlp *ReceiptRLP, err error) {
	if transactionType == 2 {
		if len(encoded) == 0 {
			err = fmt.Errorf("empty receipt rlp")
			return
		}
		if encoded[0] != 2 {
			err = fmt.Errorf("invalid rlp prefix for transaction type 2")
			return
		}
		encoded = encoded[1:]
	}
	err = rlp.Decode(bytes.NewReader(encoded), &receiptRlp)
	return
}

func RecoverSignerAddress(unsignedTxBytes []byte, V, R, S *big.Int, transactionType uint, chainID *big.Int) ([]byte, error) {
	preImage := crypto.Keccak256(unsignedTxBytes)

	var sigBytes []byte

	if transactionType == types.LegacyTxType {
		actualV := V.Uint64() - 35 - chainID.Uint64()*2
		V = new(big.Int).SetUint64(actualV)
	}

	var rBuf [32]byte
	var sBuf [32]byte
	sigBytes = append(sigBytes, R.FillBytes(rBuf[:])...)
	sigBytes = append(sigBytes, S.FillBytes(sBuf[:])...)
	if V.Int64() == 0 {
		sigBytes = append(sigBytes, 0)
	} else {
		sigBytes = append(sigBytes, V.Bytes()...)
	}

	uncompressedPublicKey, err := crypto.Ecrecover(preImage, sigBytes)
	if err != nil {
		log.Errorf("Failed to ecrecover %s\n", err.Error())
		return nil, err
	}
	publicKey, err := crypto.UnmarshalPubkey(uncompressedPublicKey)
	if err != nil {
		log.Errorf("Failed to unmarshal pubkey %s\n", err.Error())
		return nil, err
	}
	signer := crypto.PubkeyToAddress(*publicKey)
	return signer[:], nil
}

func ValidateTransactionExtraInfo(info1, info2 proof.TransactionExtraInfo) error {
	if info1.ChainId != info2.ChainId {
		return fmt.Errorf("invalid tx exinfo ChainId: %d, %d", info1.ChainId, info2.ChainId)
	}
	if info1.Nonce != info2.Nonce {
		return fmt.Errorf("invalid tx exinfo Nonce: %d, %d", info1.Nonce, info2.Nonce)
	}
	if info1.MaxPriorityFeePerGas != info2.MaxPriorityFeePerGas {
		return fmt.Errorf("invalid tx exinfo MaxPriorityFeePerGas: %s, %s", info1.MaxPriorityFeePerGas, info2.MaxPriorityFeePerGas)
	}
	if info1.MaxFeePerGas != info2.MaxFeePerGas {
		return fmt.Errorf("invalid tx exinfo MaxFeePerGas: %s, %s", info1.MaxFeePerGas, info2.MaxFeePerGas)
	}
	if info1.GasLimit != info2.GasLimit {
		return fmt.Errorf("invalid tx exinfo GasLimit: %d, %d", info1.GasLimit, info2.GasLimit)
	}
	if info1.From != info2.From {
		return fmt.Errorf("invalid tx exinfo From: %s, %s", info1.From, info2.From)
	}
	if info1.To != info2.To {
		return fmt.Errorf("invalid tx exinfo To: %s, %s", info1.To, info2.To)
	}
	if info1.Value != info2.Value {
		return fmt.Errorf("invalid tx exinfo Value: %s, %s", info1.Value, info2.Value)
	}
	return nil
}

func Hex2Bytes(s string) (b []byte) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	// hex.DecodeString expects an even-length string
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ = hex.DecodeString(s)
	return b
}

func Hex2Hash(s string) ec.Hash {
	return ec.BytesToHash(Hex2Bytes(s))
}

// Hex2Addr accepts hex string with or without 0x prefix and return Addr
func Hex2Addr(s string) ec.Address {
	return ec.BytesToAddress(Hex2Bytes(s))
}
