# CloudChain Blockchain Forensics Tool (BETA VERSION)

Advanced blockchain forensics and security analysis tool for CloudChain (Hedera/EVM-compatible networks) with AI-powered investigation capabilities.

## Features

- **Multi-chain Support**: EVM-compatible blockchains including Hedera, Ethereum, Polygon, Arbitrum, Avalanche, BSC, and more
- **Transaction Analysis**: Pattern detection, fund flow tracking, anomaly detection
- **Smart Contract Auditing**: Automated vulnerability scanning with multiple tools
- **ML-powered Detection**: TensorFlow Lite models for fraud detection
- **AI Investigator**: LangChain-based AI agent for investigative assistance
- **Access Control**: Authorized users only - no economic gain permitted

## Supported Blockchains (EVM-Compatible)

| Network | Chain ID | Finality | Status |
|---------|----------|----------|--------|
| **Hedera** | 295 | ~2-3s | Primary |
| Ethereum | 1 | ~12-15min | Supported |
| Polygon | 137 | ~2s | Supported |
| Arbitrum One | 42161 | ~10min | Supported |
| Optimism | 10 | ~2s | Supported |
| Avalanche C-Chain | 43114 | ~2s | Supported |
| BSC | 56 | ~3s | Supported |
| Base | 8453 | ~2s | Supported |
| Fantom | 250 | ~2s | Supported |
| Cronos | 25 | ~5s | Supported |
| Linea | 59144 | ~2s | Supported |
| zkSync Era | 324 | ~2s | Supported |

**Note**: Hedera has faster finality (~2-3 seconds) compared to Ethereum's ~12-15 minutes.

## Installation

```bash
cd blockchain-forensics
pip install -r requirements.txt
```

## Usage

### Basic Analysis
```bash
python main.py --address <wallet_address> --network hedera
```

### Smart Contract Audit
```bash
python smart-contract-audit/hedera_audit.py --contract <contract_address>
```

### Run All Audit Tools
```bash
cd smart-contract-audit/tools
./setup_audit_tools.sh
```

## Project Structure

```
blockchain-forensics/
├── main.py                    # Main entry point
├── src/
│   ├── access_control.py      # Authorization module
│   ├── blockchain_analyzer.py # Transaction analysis
│   ├── blockscout_client.py   # Multi-chain data fetching
│   ├── ml_models.py           # ML model utilities
│   ├── tflite_models.py       # TensorFlow Lite models
│   └── ai_investigator.py     # LangChain AI agent
├── config/
│   └── blockchain_config.json # Network configurations
├── smart-contract-audit/
│   ├── hedera_audit.py        # Hedera-specific audit
│   ├── tools/                 # Audit tools
│   │   ├── slither/           # Static analyzer
│   │   ├── mythril/           # Symbolic execution
│   │   ├── smartbugs/         # Multi-tool framework
│   │   ├── securify/          # Static analysis
│   │   ├── foundry/           # Testing framework
│   │   └── ...
│   └── audits/                # Audit reports output
└── templates/
    └── security_audit_report.md
```

## Audit Tools Included

- **Slither** - Static analyzer (multiple versions)
- **Mythril** - Symbolic execution
- **SmartBugs** - Multi-tool framework
- **Securify** - Static analysis
- **Foundry** - Testing framework
- **Aether** - Security analysis
- **Manticore** - Symbolic execution
- **Solhint** - Linter
- And more...

## Requirements

- Python 3.8+
- TensorFlow Lite
- LangChain
- Web3.py
- Requests

## Disclaimer

This tool is for authorized forensic analysis only. No economic gain permitted for analysts.
