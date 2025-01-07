# Flashbots Client (WIP)

This project is a work in progress. The goal is to provide a high-level wrapper for interacting with Flashbots, abstracting away most of the complexity involved.

## Overview

Flashbots Client aims to simplify the process of sending and simulating bundles on the Flashbots network. It provides a set of easy-to-use functions to interact with Flashbots, making it accessible for developers to integrate Flashbots into their applications.

> **Note:** This project targets similar functionality as the [ethers-provider-flashbots-bundle](https://github.com/flashbots/ethers-provider-flashbots-bundle) TypeScript package, but for the Go programming language.

## Features

- Send bundles to Flashbots
- Simulate bundle execution
- Wait for bundle inclusion
- Update fee refund recipient
- Duplicate bundles
- Get bundle statistics
- Cancel bundles
- To be extended...

## Installation

To install the Flashbots Client, use the following command:

```sh
go get github.com/yourusername/flashbots_client
```

## Usage

### Creating a Client

To create a new Flashbots client, you need to provide an Ethereum RPC URL and a searcher secret (ECDSA private key):

```go
package main

import (
    "log"
    "github.com/yourusername/flashbots_client"
    "github.com/ethereum/go-ethereum/crypto"
)

func main() {
    ethRpcUrl := "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
    searcherSecret, err := crypto.HexToECDSA("YOUR_PRIVATE_KEY")
    if err != nil {
        log.Fatalf("Failed to create private key: %v", err)
    }

    client, err := flashbots_client.NewClient(ethRpcUrl, searcherSecret)
    if err != nil {
        log.Fatalf("Failed to create Flashbots client: %v", err)
    }

    // Use the client...
}
```

### Sending a Bundle

To send a bundle, create a `Bundle` object and use the `SendBundle` method:

```go
bundle := flashbots_client.NewBundle()
// Add transactions to the bundle
// bundle.AddTransaction(tx)

bundleHash, err := client.SendBundle(bundle)
if err != nil {
    log.Fatalf("Failed to send bundle: %v", err)
}

log.Printf("Bundle sent with hash: %s", bundleHash.Hex())
```

### Simulating a Bundle

To simulate a bundle, use the `SimulateBundle` method:

```go
simulationResult, success, err := client.SimulateBundle(bundle, 0)
if err != nil {
    log.Fatalf("Failed to simulate bundle: %v", err)
}

if success {
    log.Println("Simulation successful")
} else {
    log.Println("Simulation failed")
}
```

### Getting Bundle Statistics

To get statistics for a bundle, use the `GetBundleStatsV2` method:

```go
stats, err := client.GetBundleStatsV2(bundle)
if err != nil {
    log.Fatalf("Failed to get bundle stats: %v", err)
}

log.Printf("Bundle stats: %+v", stats)
```

### Canceling a Bundle

To cancel a bundle, use the `CancelBundle` method:

```go
err := client.CancelBundle(bundle.ReplacementUuid())
if err != nil {
    log.Fatalf("Failed to cancel bundle: %v", err)
}

log.Println("Bundle canceled successfully")
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is open source and available under the [MIT License](LICENSE).