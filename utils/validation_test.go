package utils

import (
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"
)

func TestValidateRequest(t *testing.T) {
	rpcc, err := rpc.Dial("https://ethereum-rpc.publicnode.com") // for storage test, should use infura rpc to avoid getting proof error
	assert.NoError(t, err)
	ec := ethclient.NewClient(rpcc)
	pass, _, err := ValidateRequest("0xba4bf5d8ad606b1a1cce2423b72d45de297085b0df5fa020b2f9b47e4ea161b2", 421614, "52.13.236.124:11080", false, ec)
	assert.NoError(t, err)
	assert.Equal(t, true, pass)
}
