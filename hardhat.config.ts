import * as dotenv from "dotenv";

import {HardhatUserConfig, task} from "hardhat/config";
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-verify";
import "@openzeppelin/hardhat-upgrades";
import "@typechain/hardhat";
import "hardhat-gas-reporter";
import "solidity-coverage";

dotenv.config();

task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
    const accounts = await hre.ethers.getSigners();
    for (const account of accounts) {
        console.log(account.address);
    }
});

const config: HardhatUserConfig = {
    solidity: {
        compilers: [
            {
                version: "0.8.26",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 100000,
                    },
                    viaIR: true
                },
            },
        ],
    },
    networks: {
        localhost: {
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        forking: {
            url: "http://127.0.0.1:8545",
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        blast: {
            url: "https://rpc.blast.io",
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        fantom: {
            url: "https://rpc.ftm.tools",
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        fantom_test: {
            url: "https://rpc.testnet.fantom.network/",
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        sepolia: {
            url: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        mainnet: {
            url: `https://ethereum.publicnode.com`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        bsc: {
            url: `https://bsc.rpc.blxrbdn.com`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        polygon: {
            url: `https://polygon-rpc.com/`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        arbitrum: {
            url: `https://arb1.arbitrum.io/rpc`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        avax: {
            url: `https://ava-mainnet.public.blastapi.io/ext/bc/C/rpc`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        kava: {
            url: `https://evm.kava.io`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        zkevm: {
            url: `https://zkevm-rpc.com`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        op: {
            url: `https://optimism.llamarpc.com	`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
        base: {
            url: `https://base.llamarpc.com`,
            accounts: [process.env.NEW_MAIN_DEPLOYER!],
        },
    },
    sourcify: {
        enabled: false,
    },
    gasReporter: {
        enabled: process.env.REPORT_GAS !== undefined,
        currency: "USD",
    },
    etherscan: {
        apiKey: {
            polygon: process.env.POLYGON_API_KEY!,
            blast: process.env.BLAST_API_KEY!,
            sepolia: process.env.ETHERSCAN_API_KEY!
        },
        customChains: [
            {
                network: "blast",
                chainId: 81457,
                urls: {
                    apiURL: "https://api.blastscan.io/api",
                    browserURL: "https://blastscan.io",
                },
            },
            {
                network: "sepolia",
                chainId: 11155111,
                urls: {
                    apiURL: "https://api-sepolia.etherscan.io/api",
                    browserURL: "https://sepolia.etherscan.io",
                },
            },
        ],
    },
};

export default config;
