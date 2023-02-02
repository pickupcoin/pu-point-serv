package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"math/big"
)

// Decimals() (0x313ce567)
func (this *Eth) GetTokenDecimals(cntrAddr common.Address) (uint8, error) {
	resp, err := this.RpcClient.Call("eth_call", map[string]interface{}{
		"data": "0x313ce567",
		"to":   cntrAddr,
	}, "latest")

	switch {
	case err != nil:
		return 0, err
	case resp.Error != nil:
		return 0, resp.Error
	case resp.Result == nil:
		return 0, errors.New("no result in JSON-RPC response")
	default:
		b, ret := new(big.Int).SetString(resp.Result.(string)[2:], 16)
		if ret != true {
			return 0, errors.New("SetString: no result in JSON-RPC response")
		}
		return uint8(b.Uint64()), nil
	}
}

// "70a08231": "balanceOf(address)",
func (this *Eth) GetTokenBalanceOf(cntrAddr common.Address, ownerAddr common.Address) (balance *big.Int, err error) {
	resp, err := this.RpcClient.Call("eth_call", map[string]interface{}{
		"data": "0x70a08231000000000000000000000000" + ownerAddr.String()[2:],
		"to":   cntrAddr,
	}, "latest")

	switch {
	case err != nil:
		return nil, err
	case resp.Error != nil:
		return nil, resp.Error
	case resp.Result == nil:
		return nil, errors.New("no result in JSON-RPC response")
	default:
		b, ret := new(big.Int).SetString(resp.Result.(string)[2:], 16)
		if ret != true {
			return nil, errors.New("SetString: no result in JSON-RPC response")
		}
		return b, nil
	}
}
