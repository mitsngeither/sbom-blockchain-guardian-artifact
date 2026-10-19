import "dotenv/config";
import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { configVariable, defineConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthersPlugin],
  paths: {
    tests: {
      mocha: "testJS",
    },
  },
  solidity: {
    profiles: {
      default: {
        version: "0.8.28",
      },
      production: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    hardhatOp: {
      type: "edr-simulated",
      chainType: "op",
    },
    // Local Geth dev chain. Key from DEVNET_PRIVATE_KEY; without it there is no signer.
    devnet: {
      type: "http",
      chainType: "l1",
      chainId: 1337,
      url: process.env.DEVNET_RPC_URL ?? "http://127.0.0.1:8545",
      accounts: process.env.DEVNET_PRIVATE_KEY
        ? [process.env.DEVNET_PRIVATE_KEY]
        : [],
    },
    guardian: {
      type: "http",
      chainType: "l1",
      chainId: 1337,
      url: configVariable("RPC_URL"),
      accounts: [configVariable("PRIVATE_KEY")],
    },
    sepolia: {
      type: "http",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_PRIVATE_KEY")],
      chainId: 11155111,
    },
  },
});
