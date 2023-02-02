package eth

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ybbus/jsonrpc/v2"
	"math/big"
)

type Eth struct {
	host      string
	//client    *ethclient.Client
	RpcClient jsonrpc.RPCClient
}

func New(rawUrl string) (*Eth, error) {
	//client, err := ethclient.Dial(rawurl)
	//if err != nil {
	//	fmt.Printf("Failed to connect to eth: %v", err)
	//	return nil, err
	//}
	rpcClient := jsonrpc.NewClient(rawUrl)
	return &Eth{host: rawUrl, RpcClient: rpcClient}, nil
}

func (this *Eth) GetBalance(address string) (balance *big.Int, err error) {
	resp, err := this.RpcClient.Call("eth_getBalance", address, "latest")
	if err != nil {
		return
	}
	b, _ := new(big.Int).SetString(resp.Result.(string)[2:], 16)
	return b, nil
}

func (this *Eth) GetTxByHash(hash string) (tx model.Tx, err error) {
	response, err := this.RpcClient.Call("eth_getTransactionByHash", hash)
	if err != nil {
		return
	}
	// log.Printf("%+v\n\n\n", response.Result)
	err = response.GetObject(&tx)
	if err != nil {
		return
	}
	return
}



func (this *Eth) GetBlockByNumber(number *big.Int) (*Block, error) {
	rpcResp, err := this.RpcClient.Call("eth_getBlockByNumber", fmt.Sprintf("0x%x", number.Uint64()), true)
	//b, err := this.client.BlockByNumber(context.Background(), number)
	if err != nil {
		return nil, err
	}

	if rpcResp.Result != nil {
		var body *rpcBlock
		var head *BHeader

		data, _ := json.Marshal(rpcResp.Result)

		if err := json.Unmarshal(data, &head); err != nil {
			return nil, err
		}
		//fmt.Println(data)
		err = json.Unmarshal(data, &body)

		// Load uncles because they are not included in the block response.
		var uncles []*BHeader
		if len(body.UncleHashes) > 0 {
			uncles = make([]*BHeader, len(body.UncleHashes))
			reqs := make([]*jsonrpc.RPCRequest, len(body.UncleHashes))
			for i := range reqs {
				reqs[i] = &jsonrpc.RPCRequest{
					Method: "eth_getUncleByBlockHashAndIndex",
					Params: []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				}
			}
			uncleData, err := this.RpcClient.CallBatch(reqs)
			if err != nil {
				return nil, err
			}
			fmt.Println(uncleData)
			fmt.Println(uncles)

			err = json.Unmarshal(data, &body)
			for i := range uncleData {
				uncleMarshal, _ := json.Marshal(uncleData[i].Result)

				err = json.Unmarshal(uncleMarshal, &uncles[i])
				uncles[i].Hash()
				if uncles[i] == nil {
					return nil, fmt.Errorf("got null header for uncle %d of block %x", i, body.Hash[:])
				}
			}
		}
		// Fill the sender cache of transactions in the block.
		txs := make([]*types.Transaction, len(body.Transactions))
		for i, tx := range body.Transactions {
			if tx.From != nil {
				setSenderFromServer(tx.tx, *tx.From, body.Hash)
			}
			txs[i] = tx.tx
		}

		return NewBlockWithHeader(head).WithBody(txs, uncles), nil
	}

	return nil, nil
}

func (this *Eth) GetUncleBlockByBlockNumberAndIndex(blockNo uint64, idx int) (interface{}, error) {
	b, err := this.RpcClient.Call("eth_getUncleByBlockNumberAndIndex", fmt.Sprintf("0x%x", blockNo), fmt.Sprintf("0x%x", idx))
	if err != nil {
		return "", err
	}

	return b.Result, nil
}
