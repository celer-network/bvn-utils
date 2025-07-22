package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/brevis-network/zk-utils/common/proof"
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	ec "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func ValidateRequest(requestId string, targetChainId uint64, dataHost string, ssl bool, ethClient *ethclient.Client) (pass bool, sdkQueryInfo *proof.SDKQueryProvingInfo, err error) {
	credential := insecure.NewCredentials()
	if ssl {
		credential = credentials.NewTLS(&tls.Config{})
	}
	conn, err := grpc.Dial(dataHost, grpc.WithTransportCredentials(credential))
	if err != nil {
		return false, nil, err
	}
	gc := gwproto.NewGatewayClient(conn)

	response, err := gc.GetQueryInfoForOP(context.Background(), &gwproto.GetQueryInfoForOPRequest{
		QueryHash:     requestId,
		TargetChainId: targetChainId,
	})
	if err != nil {
		return false, nil, err
	}

	err = json.Unmarshal(response.QueryInfo, &sdkQueryInfo)
	if err != nil {
		return false, nil, err
	}
	if ec.HexToHash(requestId) != ec.HexToHash(sdkQueryInfo.Hash) {
		return false, nil, fmt.Errorf("malicious data host")
	}
	pass, err = validateQueryInfo(sdkQueryInfo, ethClient)
	if err != nil {
		return false, nil, err
	}
	return
}

func validateQueryInfo(queryInfo *proof.SDKQueryProvingInfo, ethClient *ethclient.Client) (pass bool, err error) {
	pass = false
	err = nil

	var hashes [][]byte
	for _, info := range queryInfo.ReceiptInfos {
		hash, err0 := ValidateReceiptInfo(info, ethClient)
		if err0 != nil {
			err = err0
			return
		}
		hashes = append(hashes, hash)
	}

	shashes, err0 := ValidateStorageInfos(queryInfo.StorageSlotInfos, ethClient)
	if err0 != nil {
		err = err0
		return
	}
	hashes = append(hashes, shashes...)

	for _, info := range queryInfo.TransactionInfos {
		hash, err0 := ValidateTxInfo(info, ethClient)
		if err0 != nil {
			err = err0
			return
		}
		hashes = append(hashes, hash)
	}

	inputCommitmentBigInts := make([]*big.Int, len(queryInfo.AppCircuitInfo.InputCommitments))
	if queryInfo.AppCircuitInfo != nil {
		// Check app circuit info valid
		if len(queryInfo.AppCircuitInfo.Toggles) != len(queryInfo.AppCircuitInfo.InputCommitments) {
			err = fmt.Errorf("unmatched app circuit toggles and input commitments length")
			return
		}

		if len(queryInfo.AppCircuitInfo.InputCommitments) < len(hashes) {
			err = fmt.Errorf("unmatched app circuit input commitments and real data length")
			return
		}

		subproofIndex := 0
		for i, value := range queryInfo.AppCircuitInfo.Toggles {
			inputCommitmentBytes := Hex2Bytes(queryInfo.AppCircuitInfo.InputCommitments[i])
			switch value {
			case 0:
				inputCommitmentBigInts[i] = new(big.Int).SetBytes(inputCommitmentBytes)
			case 1:
				valueA := new(big.Int).SetBytes(inputCommitmentBytes)
				valueB := new(big.Int).SetBytes(hashes[subproofIndex])
				if valueA.Cmp(valueB) != 0 {
					err = fmt.Errorf("app circuit input commitment[%d] %s does not match subproof hash %s", i, hexutil.Encode(inputCommitmentBytes), hexutil.Encode(hashes[subproofIndex]))
					return
				}
				subproofIndex += 1
				inputCommitmentBigInts[i] = valueA
			default:
				err = fmt.Errorf("invalid toggle value %d", value)
				return
			}
		}

		if subproofIndex != len(hashes) {
			err = fmt.Errorf("not all subproof hash used: %d, %d", subproofIndex, len(hashes))
			return
		}
	} else {
		err = fmt.Errorf("missing app circuit info")
		return
	}

	root, err0 := CalPoseidonBn254MerkleTreeRoot(inputCommitmentBigInts)
	if err0 != nil {
		err = err0
		return
	}

	rootHash := ec.BytesToHash(root.Bytes())
	if Hex2Hash(queryInfo.AppCircuitInfo.InputCommitmentsRoot) != rootHash {
		err = fmt.Errorf("invalid input commitments root: %s, result: %s", queryInfo.AppCircuitInfo.InputCommitmentsRoot, rootHash.Hex())
		return
	}

	vkHash := Hex2Hash(queryInfo.AppCircuitInfo.VerifyingKey)
	appCommitHash := Hex2Hash(queryInfo.AppCircuitInfo.OutputCommitment)
	input := []byte{}
	input = append(input, vkHash.Bytes()...)
	input = append(input, rootHash.Bytes()...)
	input = append(input, appCommitHash.Bytes()...)

	pass = hexutil.Encode(crypto.Keccak256(input)) == queryInfo.Hash
	return
}

func ValidateReceiptInfo(
	info *proof.SDKQueryProvingInfoForReceipt,
	ethClient *ethclient.Client,
) ([]byte, error) {
	receipt, err := ethClient.TransactionReceipt(context.Background(), utils.Hex2Hash(info.TransactionHash))
	if err != nil {
		log.Errorf("Failed to find receipt info for tx: %s: %s", info.TransactionHash, err.Error())
		return nil, err
	}

	if receipt.BlockNumber.Uint64() != info.BlockNumber {
		return nil, fmt.Errorf("receipt %s's block number %d not match onchain %d", info.TransactionHash, info.BlockNumber, receipt.BlockNumber.Uint64())
	}

	baseFee, blkTime, err := getBlockBaseFeeAndTime(receipt.BlockNumber, ethClient)
	if err != nil {
		log.Errorf("Failed to get block base fee: %s: %s", info.TransactionHash, err.Error())
		return nil, err
	}
	if baseFee.Cmp(utils.Var2BigInt(info.BlockBaseFee)) != 0 {
		return nil, fmt.Errorf("info block base fee %s and onchain base fee %s not match", info.BlockBaseFee, baseFee.String())
	}
	if blkTime != info.BlockTime {
		return nil, fmt.Errorf("info block time %d and onchain block time %d not match", info.BlockTime, blkTime)
	}

	if !(strings.HasPrefix(info.MPTKey, "0x") || strings.HasPrefix(info.MPTKey, "0X")) {
		info.MPTKey = "0x" + info.MPTKey
	}
	mptKey := calculateMPTKeyWithIndex(receipt.TransactionIndex)
	if mptKey.Cmp(utils.Var2BigInt(info.MPTKey)) != 0 {
		return nil, fmt.Errorf("info mpt key %s not match tx index %d", info.MPTKey, receipt.TransactionIndex)
	}

	for _, info := range info.LogExtractInfos {
		if int(info.LogIndex) >= len(receipt.Logs) {
			return nil, fmt.Errorf("info log index out of bound %+v", info)
		}

		log := receipt.Logs[int(info.LogIndex)]
		if log.Address.Cmp(Hex2Addr(info.ContractAddress)) != 0 {
			return nil, fmt.Errorf("info log address %s and contract address %s not match", log.Address.Hex(), info.ContractAddress)
		}

		if len(log.Topics) != int(info.FieldNumInTopic) {
			return nil, fmt.Errorf("topics length not match actual: %d, json input: %d", len(log.Topics), info.FieldNumInTopic)
		}
		if len(log.Topics) == 0 {
			return nil, fmt.Errorf("info topic length is 0")
		}
		if log.Topics[0].Cmp(Hex2Hash(info.LogTopic0)) != 0 {
			return nil, fmt.Errorf("info log Topics[0] %s and logTopic0 %s not match", log.Topics[0].Hex(), info.LogTopic0)
		}

		if info.ValueFromTopic {
			if int(info.ValueIndex) >= len(log.Topics) {
				return nil, fmt.Errorf("topic index out of bound")
			}
			if log.Topics[info.ValueIndex].Cmp(Hex2Hash(info.Value)) != 0 {
				return nil, fmt.Errorf("info log Topics[%d] %s and Value %s not match", info.ValueIndex, log.Topics[info.ValueIndex].Hex(), info.Value)
			}
		} else {
			if int(info.ValueIndex*32+32) > len(log.Data) {
				return nil, fmt.Errorf("value out of bound")
			}

			if ec.BytesToHash(log.Data[info.ValueIndex*32:info.ValueIndex*32+32]).Cmp(Hex2Hash(info.Value)) != 0 {
				return nil, fmt.Errorf("info log Data[%d:%d] 0x%x and Value %s not match", info.ValueIndex*32, info.ValueIndex*32+32, log.Data[info.ValueIndex*32:info.ValueIndex*32+32], info.Value)
			}
		}
	}

	hash, err := proof.MiMCHashReceiptCustomInputs(info)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func ValidateStorageInfos(
	infos []*proof.SDKQueryProvingInfoForStorageSlot,
	ethClient *ethclient.Client,
) ([][]byte, error) {
	var hashes [][]byte
	infoMap := make(map[string]map[uint64][]*proof.SDKQueryProvingInfoForStorageSlot)
	for _, info := range infos {
		if infoMap[info.AccountAddress] == nil {
			infoMap[info.AccountAddress] = make(map[uint64][]*proof.SDKQueryProvingInfoForStorageSlot)
		}
		infoMap[info.AccountAddress][info.BlockNumber] = append(infoMap[info.AccountAddress][info.BlockNumber], info)

		hash, err := proof.MiMCHashStorageCustomInputs(info)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}

	for accountAddr, outer := range infoMap {
		for blkNum, inner := range outer {
			var keys []string
			for _, slot := range inner {
				keys = append(keys, slot.Slot)
			}
			result, err := gethclient.New(ethClient.Client()).GetProof(context.Background(), utils.Hex2Addr(accountAddr), keys, new(big.Int).SetUint64(blkNum))
			if err != nil {
				log.Errorf("failed to get proof for account %s at blkNum %d, err: %s", accountAddr, blkNum, err)
				return nil, err
			}

			valueMap := make(map[ec.Hash]string)
			for _, sProof := range result.StorageProof {
				valueMap[ec.HexToHash(sProof.Key)] = sProof.Value.String()
			}

			baseFee, blkTime, err := getBlockBaseFeeAndTime(big.NewInt(int64(blkNum)), ethClient)
			if err != nil {
				log.Errorf("Failed to get block base fee: %d: %s", blkNum, err.Error())
				return nil, err
			}

			for _, slot := range inner {
				if baseFee.Cmp(utils.Var2BigInt(slot.BlockBaseFee)) != 0 {
					return nil, fmt.Errorf("slot block base fee %s and onchain base fee %s not match", slot.BlockBaseFee, baseFee.String())
				}
				if blkTime != slot.BlockTime {
					return nil, fmt.Errorf("slot block time %d and onchain block time %d not match", slot.BlockTime, blkTime)
				}
				if slot.SlotValue != valueMap[ec.HexToHash(slot.Slot)] {
					return nil, fmt.Errorf("slot %s's value %s not match onchain %s", slot.Slot, slot.SlotValue, valueMap[ec.HexToHash(slot.Slot)])
				}
			}
		}
	}

	return hashes, nil
}

func ValidateTxInfo(
	info *proof.SDKQueryProvingInfoForTransaction,
	ethClient *ethclient.Client,
) ([]byte, error) {
	tx, isPending, err := ethClient.TransactionByHash(context.Background(), utils.Hex2Hash(info.TransactionHash))
	if err != nil {
		log.Errorf("cannot get transaction by hash, err %s", err.Error())
		return nil, err
	}
	if isPending {
		return nil, fmt.Errorf("pending transaction not supported: %s", info.TransactionHash)
	}
	if tx.Type() != types.DynamicFeeTxType && tx.Type() != types.LegacyTxType {
		return nil, fmt.Errorf("tx(%s)unsupported transaction type", info.TransactionHash)
	}

	receipt, err := ethClient.TransactionReceipt(context.Background(), utils.Hex2Hash(info.TransactionHash))
	if err != nil {
		log.Errorf("Failed to find receipt info for tx %s: err %s", info.TransactionHash, err)
		return nil, err
	}

	if receipt.BlockNumber.Uint64() != info.BlockNumber {
		return nil, fmt.Errorf("tx %s's block number %d not match onchain %d", info.TransactionHash, info.BlockNumber, receipt.BlockNumber.Uint64())
	}

	if receipt.Status != 1 /*successful*/ {
		return nil, fmt.Errorf("tx %s's receipt status is not success", info.TransactionHash)
	}

	b, _ := tx.MarshalBinary()
	leafRaw := bytes.Join([][]byte{Hex2Bytes(info.MPTLeafRlpPrefix), b}, []byte{})
	if crypto.Keccak256Hash(leafRaw) != Hex2Hash(info.LeafHash) {
		return nil, fmt.Errorf("info leafHash %s not match calc result", info.LeafHash)
	}

	baseFee, blkTime, err := getBlockBaseFeeAndTime(receipt.BlockNumber, ethClient)
	if err != nil {
		log.Errorf("Failed to get block base fee: %s: %s", info.TransactionHash, err.Error())
		return nil, err
	}
	if baseFee.Cmp(utils.Var2BigInt(info.BlockBaseFee)) != 0 {
		return nil, fmt.Errorf("info block base fee %s and onchain base fee %s not match", info.BlockBaseFee, baseFee.String())
	}
	if blkTime != info.BlockTime {
		return nil, fmt.Errorf("info block time %d and onchain block time %d not match", info.BlockTime, blkTime)
	}

	if !(strings.HasPrefix(info.MPTKey, "0x") || strings.HasPrefix(info.MPTKey, "0X")) {
		info.MPTKey = "0x" + info.MPTKey
	}
	mptKey := calculateMPTKeyWithIndex(receipt.TransactionIndex)
	if mptKey.Cmp(utils.Var2BigInt(info.MPTKey)) != 0 {
		return nil, fmt.Errorf("info mpt key %s not match tx index %d", info.MPTKey, receipt.TransactionIndex)
	}

	hash, err := proof.MiMCHashTxCustomInputs(info)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func CalPoseidonBn254MerkleTreeRoot(leafs []*big.Int) (*big.Int, error) {
	if !CheckNumberPowerOfTwo(len(leafs)) {
		return nil, fmt.Errorf("not pow of 2, %d", len(leafs))
	}
	hasher := utils.NewPoseidonBn254()
	elementCount := len(leafs)
	for {
		if elementCount == 1 {
			return leafs[0], nil
		}
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(leafs[2*i])
			hasher.Write(leafs[2*i+1])
			result, err := hasher.Sum()
			if err != nil {
				return nil, fmt.Errorf("fail to hash in CalPoseidonBn254MerkleTree, err: %v", err)
			}
			leafs[i] = result
		}
		elementCount = elementCount / 2
	}
}

func CheckNumberPowerOfTwo(n int) bool {
	return n&(n-1) == 0
}

func getBlockBaseFeeAndTime(blkNum *big.Int, ec *ethclient.Client) (baseFee *big.Int, blkTime uint64, err error) {
	header, err := ec.HeaderByNumber(context.Background(), blkNum)
	if err != nil {
		return nil, 0, err
	}
	baseFee = header.BaseFee
	blkTime = header.Time
	return
}

func calculateMPTKeyWithIndex(txIdx uint) *big.Int {
	var indexBuf []byte
	keyIndex := rlp.AppendUint64(indexBuf[:0], uint64(txIdx))
	return new(big.Int).SetBytes(keyIndex)
}
