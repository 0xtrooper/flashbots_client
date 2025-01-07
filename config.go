package flashbots_client

type FlasbotsNetork string

var FlashbotsUrlPerNetwork = map[uint64]string{
	1:        "https://relay.flashbots.net",
	5:        "https://relay-goerli.flashbots.net",
	11155111: "https://relay-sepolia.flashbots.net",
	17000:    "https://relay-holesky.flashbots.net",
}

const (
	JsonRpcParseError     = -32700
	JsonRpcInvalidRequest = -32600
	JsonRpcMethodNotFound = -32601
	JsonRpcInvalidParams  = -32602
	JsonRpcInternalError  = -32603
)
