package types

import (
	"github.com/pickupcoin/pu-point-serv/util"
	"math/big"
)

type BlockData struct {
	Height         int64    `json:"height"`
	Timestamp      int64    `json:"timestamp"`
	Difficulty     int64    `json:"difficulty"`
	TotalShares    int64    `json:"shares"`
	Uncle          bool     `json:"uncle"`
	UncleHeight    int64    `json:"uncleHeight"`
	Orphan         bool     `json:"orphan"`
	Hash           string   `json:"hash"`
	Nonce          string   `json:"-"`
	PowHash        string   `json:"-"`
	MixDigest      string   `json:"-"`
	Reward         *big.Int `json:"-"`
	ExtraReward    *big.Int `json:"-"`
	ImmatureReward string   `json:"-"`
	RewardString   string   `json:"reward"`
	RoundHeight    int64    `json:"-"`
	CandidateKey   string
	ImmatureKey    string
	State		   int
}

type MinerCharts struct {
	Timestamp      int64  `json:"x"`
	TimeFormat     string `json:"timeFormat"`
	MinerHash      int64  `json:"minerHash"`
	MinerLargeHash int64  `json:"minerLargeHash"`
	WorkerOnline   string `json:"workerOnline"`
	Share			int64 `json:"minerShare"`
	MinerReportHash int64 `json:"minerReportHash"`
}

type RewardData struct {
	Height    int64   `json:"blockheight"`
	Timestamp int64   `json:"timestamp"`
	BlockHash string  `json:"blockhash"`
	Reward    int64   `json:"reward"`
	Percent   float64 `json:"percent"`
	Immature  bool    `json:"immature"`
}

type TransactionData struct {
	BlockNumber 		string	`json:"blockNumber"`
	Timestamp 			string  `json:"timestamp"`
	Hash 				string  `json:"hash"`
	Nonce    			string  `json:"nonce"`
	BlockHash   		string 	`json:"blockHash"`
	TransactionIndex  	string  `json:"transactionIndex"`
	From  				string  `json:"from"`
	To  				string  `json:"to"`
	Value  				string  `json:"value"`
	Gas  				string  `json:"gas"`
	GasPrice  			string  `json:"gasPrice"`
	IsError  			string  `json:"isError"`
	TxReceiptStatus  	string  `json:"txreceipt_status"`
	Input  				string  `json:"input"`
	ContractAddress  	string  `json:"contractAddress"`
	CumulativeGasUsed  	string  `json:"cumulativeGasUsed"`
	GasUsed  			string  `json:"gasUsed"`
	Confirmations  		string  `json:"confirmations"`
	MethodId  			string  `json:"methodId"`
	FunctionName  		string  `json:"functionName"`
}

type CreditsImmatrue struct {
	Addr string
	Amount int64
}

type InboundIpList struct {
	Ip      string
	Allowed bool // true: allow false: deny
	Desc	string
}

type InboundIdList struct {
	Id      string
	Allowed bool // true: allow false: deny
	Alarm	string	// none, slack, mail
	Desc	string
}

type UserInfo struct {
	Username string `json:"username"`
	Access string `json:"access"`
}

type DevSubList struct {
	DevAddr 	string
	SubAddr 	string
	Amount		int64
}

var (
	ConstDgcSymbol = "token:"
)


func (b *BlockData) RewardInShannon() int64 {
	reward := new(big.Int).Div(b.Reward, util.Shannon)
	return reward.Int64()
}

func (b *BlockData) SerializeHash() string {
	if len(b.Hash) > 0 {
		return b.Hash
	} else {
		return "0x0"
	}
}

func (b *BlockData) RoundKey() string {
	return util.Join(b.RoundHeight, b.Hash)
}

func (b *BlockData) Key() string {
	return util.Join(b.UncleHeight, b.Orphan, b.Nonce, b.SerializeHash(), b.Timestamp, b.Difficulty, b.TotalShares, b.Reward)
}

