package flashbots_client

import (
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type Bundle struct {
	transactions      []*types.Transaction
	blocknumber       uint64
	minTimestamp      uint64
	maxTimestamp      uint64
	revertingTxHashes []string
	replacementUuid   string
	builders          []string

	bundleHash common.Hash
}

func NewBundle() *Bundle {
	return &Bundle{
		blocknumber: 0,
	}
}

func NewBundleWithTransactions(transactions []*types.Transaction) *Bundle {
	return &Bundle{
		transactions: transactions,
		blocknumber:  0,
	}
}

func (b *Bundle) Transactions() []*types.Transaction {
	return b.transactions
}

func (b *Bundle) BlockNumber() uint64 {
	return b.blocknumber
}

func (b *Bundle) MinTimestamp() uint64 {
	return b.minTimestamp
}

func (b *Bundle) MaxTimestamp() uint64 {
	return b.maxTimestamp
}

func (b *Bundle) RevertingTxHashes() []string {
	return b.revertingTxHashes
}

func (b *Bundle) ReplacementUuid() string {
	return b.replacementUuid
}

func (b *Bundle) BundleHash() common.Hash {
	return b.bundleHash
}

func (b *Bundle) Builders() []string {
	return b.builders
}

func (b *Bundle) AddTransaction(tx *types.Transaction) {
	b.transactions = append(b.transactions, tx)
}

func (b *Bundle) AddTransactions(txs []*types.Transaction) {
	b.transactions = append(b.transactions, txs...)
}

// SetBlockNumber sets the block number for which this bundle is valid
// If set to 0, the bundle is valid for the next block
func (b *Bundle) SetBlockNumber(blocknumber uint64) {
	b.blocknumber = blocknumber
}

// SetMinTimestamp sets the minimum timestamp for which this bundle is valid, in seconds since the unix epoch
func (b *Bundle) SetMinTimestamp(minTimestamp uint64) error {
	if b.maxTimestamp != 0 && minTimestamp > b.maxTimestamp {
		return errors.New("minTimestamp must be less than maxTimestamp")
	}

	b.minTimestamp = minTimestamp
	return nil
}

// SetMaxTimestamp sets the maximum timestamp for which this bundle is valid, in seconds since the unix epoch
func (b *Bundle) SetMaxTimestamp(maxTimestamp uint64) error {
	if b.minTimestamp != 0 && maxTimestamp < b.minTimestamp {
		return errors.New("maxTimestamp must be greater than minTimestamp")
	}
	if maxTimestamp < uint64(time.Now().Unix()) {
		return errors.New("maxTimestamp must be in the future")
	}

	b.maxTimestamp = maxTimestamp
	return nil
}

// SetRevertingTxHash sets one transaction hash that is allowed to revert
func (b *Bundle) SetRevertingTxHash(revertingTxHash string) {
	b.revertingTxHashes = append(b.revertingTxHashes, revertingTxHash)
}

// SetRevertingTxHashes sets the list of transaction hashes that are allowed to revert
func (b *Bundle) SetRevertingTxHashes(revertingTxHashes []string) {
	b.revertingTxHashes = revertingTxHashes
}

// SetReplacementUuid sets the replacement UUID for this bundle that can be used to cancel/replace this bundle
func (b *Bundle) SetReplacementUuid(replacementUuid string) error {
	if b.replacementUuid != "" {
		return errors.New("replacement UUID already set")
	}

	b.replacementUuid = replacementUuid
	return nil
}

func (b *Bundle) MaximumGasFeePaid() (feePaid *big.Int) {
	feePaid = big.NewInt(0)
	for _, tx := range b.transactions {
		feePaid.Add(feePaid, tx.Cost())
	}

	return feePaid
}
