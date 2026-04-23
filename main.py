#!/usr/bin/env python3
"""
Blockchain Forensics Tool - Main Orchestrator
RESTRICTED ACCESS: Only individuals selected by the tool owner can use this system.
No economic gain is permitted for forensic analysts.
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.access_control import ForensicAccessControl
from src.blockchain_analyzer import BlockchainForensicsAnalyzer
from src.tflite_models import ForensicScriptEngine, create_and_convert_models
from src.blockscout_client import BlockscoutClient, MultiChainForensicsFetcher

class ForensicToolOrchestrator:
    """
    Main orchestrator for the blockchain forensics tool
    Enforces access control and coordinates all modules
    """
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = config_dir
        self.access_control = ForensicAccessControl(f"{config_dir}/authorized_users.json")
        self.analyzer = BlockchainForensicsAnalyzer(f"{config_dir}/blockchain_config.json")
        self.script_engine = ForensicScriptEngine()
        self.blockscout = {}
        self.current_user = None
        
        # Create default config if needed
        self.ensure_config()
    
    def ensure_config(self):
        """Ensure configuration files exist"""
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Check if authorized users file exists
        if not os.path.exists(f"{self.config_dir}/authorized_users.json"):
            print("\n" + "="*60)
            print("INITIAL SETUP REQUIRED")
            print("="*60)
            print("\nThis is the FIRST TIME the tool is running.")
            print("You need to configure the authorized users.")
            print("\nTo add authorized users, edit:")
            print(f"  {self.config_dir}/authorized_users.json")
            print("\nIMPORTANT: Only add users YOU personally select.")
            print("NO economic gain is permitted for forensic analysts.")
            print("="*60 + "\n")
    
    def authenticate(self, user_id: str) -> bool:
        """Authenticate a user"""
        if self.access_control.is_authorized(user_id):
            self.current_user = user_id
            return True
        return False
    
    def login_interactive(self) -> bool:
        """Interactive login prompt"""
        print("\n" + "="*60)
        print("BLOCKCHAIN FORENSICS TOOL - LOGIN")
        print("="*60)
        print("\nThis tool is RESTRICTED to authorized users only.")
        print("No economic gain is permitted for forensic analysts.\n")
        
        user_id = input("Enter your user ID: ").strip()
        
        if self.authenticate(user_id):
            print(f"\nWelcome, {user_id}!")
            return True
        else:
            print("\nACCESS DENIED")
            print("Your user ID is not authorized to use this tool.")
            print("Contact the tool owner to request access.")
            return False
    
    def setup_network(self, network: str, api_key: str = ""):
        """Setup Blockscout network"""
        self.blockscout[network] = BlockscoutClient(network, api_key)
    
    def investigate_address(self, address: str, network: str = "ethereum") -> Dict:
        """Investigate a blockchain address"""
        if not self.current_user:
            raise PermissionError("User not authenticated")
        
        print(f"\n[INVESTIGATION] Starting investigation for: {address}")
        
        # Fetch address data from Blockscout
        transactions = []
        if network in self.blockscout:
            client = self.blockscout[network]
            print(f"[FETCH] Querying {network} Blockscout...")
            transactions = client.get_address_transactions(address, limit=100)
            print(f"[FETCH] Retrieved {len(transactions)} transactions")
        
        # Run analysis
        print("[ANALYSIS] Running pattern analysis...")
        pattern_results = self.analyzer.analyze_transaction_patterns(transactions)
        
        print("[ANALYSIS] Calculating address risk...")
        address_analysis = self.analyzer.analyze_address(address, transactions)
        
        print("[ANALYSIS] Checking legal compliance...")
        compliance = self.analyzer.check_legal_compliance(address, transactions)
        
        # Run script engine
        print("[ANALYSIS] Running forensic scripts...")
        script_results = self.script_engine.evaluate_address({
            "address": address,
            "transaction_count": len(transactions),
            "failed_tx_ratio": 0.05,
            "contract_creation_count": 0,
            "token_holdings_count": 0,
            "mixer_interaction": False,
            "exchange_interaction": True,
            "age_days": 365,
            "balance_usd": 0,
            "incoming_tx_count": len([t for t in transactions if t.get("to", "").lower() == address.lower()]),
            "outgoing_tx_count": len([t for t in transactions if t.get("from", "").lower() == address.lower()])
        })
        
        # Generate report
        print("[REPORT] Generating forensic report...")
        report = self.analyzer.generate_forensic_report(address, transactions)
        
        # Add script engine results
        report["script_engine_analysis"] = script_results
        report["investigator_user"] = self.current_user
        report["network"] = network
        
        return report
    
    def investigate_transaction(self, tx_hash: str, network: str = "ethereum") -> Dict:
        """Investigate a specific transaction"""
        if not self.current_user:
            raise PermissionError("User not authenticated")
        
        print(f"\n[INVESTIGATION] Investigating transaction: {tx_hash}")
        
        if network not in self.blockscout:
            raise ValueError(f"Network {network} not configured")
        
        # Get transaction details
        tx_data = self.blockscout[network].get_transaction_info(tx_hash)
        
        if not tx_data:
            return {"error": "Transaction not found"}
        
        # Run analysis
        results = self.script_engine.evaluate_transaction(tx_data)
        
        # Generate report
        report = {
            "transaction_hash": tx_hash,
            "network": network,
            "investigator": self.current_user,
            "timestamp": datetime.now().isoformat(),
            "transaction_data": tx_data,
            "analysis_results": results,
            "risk_assessment": {
                "anomaly_detected": any(r.get("type") == "anomaly_detection" for r in results),
                "triggers": [r.get("description") for r in results if r.get("description")]
            }
        }
        
        return report
    
    def run_batch_investigation(self, addresses: List[str], network: str = "ethereum") -> Dict:
        """Run investigation on multiple addresses"""
        if not self.current_user:
            raise PermissionError("User not authenticated")
        
        print(f"\n[BATCH] Investigating {len(addresses)} addresses...")
        
        results = {
            "batch_id": datetime.now().isoformat(),
            "investigator": self.current_user,
            "network": network,
            "addresses_analyzed": len(addresses),
            "findings": []
        }
        
        for addr in addresses:
            try:
                report = self.investigate_address(addr, network)
                results["findings"].append(report)
            except Exception as e:
                print(f"Error investigating {addr}: {e}")
        
        # Summary
        high_risk_count = sum(1 for f in results["findings"] 
                            if f.get("summary", {}).get("overall_risk_score", 0) > 0.7)
        
        results["summary"] = {
            "total_addresses": len(addresses),
            "high_risk": high_risk_count,
            "medium_risk": len(addresses) - high_risk_count
        }
        
        return results
    
    def export_report(self, report: Dict, filepath: str):
        """Export report to file"""
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[EXPORT] Report saved to: {filepath}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Blockchain Forensics Tool - Restricted Access"
    )
    
    parser.add_argument("--user", "-u", help="User ID for authentication")
    parser.add_argument("--address", "-a", help="Address to investigate")
    parser.add_argument("--transaction", "-t", help="Transaction hash to investigate")
    parser.add_argument("--network", "-n", default="ethereum", 
                       choices=["ethereum", "polygon", "bsc", "avalanche", "arbitrum", "optimism"],
                       help="Blockchain network")
    parser.add_argument("--api-key", help="Blockscout API key")
    parser.add_argument("--output", "-o", help="Output file for report")
    parser.add_argument("--setup-models", action="store_true", help="Setup TFLite models")
    parser.add_argument("--login", action="store_true", help="Interactive login")
    
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = ForensicToolOrchestrator()
    
    # Setup models if requested
    if args.setup_models:
        print("Setting up TensorFlow Lite models...")
        create_and_convert_models()
        return
    
    # Authenticate
    if args.login:
        if not orchestrator.login_interactive():
            sys.exit(1)
    elif args.user:
        if not orchestrator.authenticate(args.user):
            print("ERROR: User not authorized")
            sys.exit(1)
    else:
        print("ERROR: Must login with --login or specify --user")
        parser.print_help()
        sys.exit(1)
    
    # Setup network
    orchestrator.setup_network(args.network, args.api_key or "")
    
    # Run investigation
    if args.address:
        report = orchestrator.investigate_address(args.address, args.network)
        print("\n" + "="*60)
        print("INVESTIGATION REPORT")
        print("="*60)
        print(json.dumps(report, indent=2, default=str))
        
        if args.output:
            orchestrator.export_report(report, args.output)
    
    elif args.transaction:
        report = orchestrator.investigate_transaction(args.transaction, args.network)
        print("\n" + "="*60)
        print("TRANSACTION INVESTIGATION")
        print("="*60)
        print(json.dumps(report, indent=2, default=str))
        
        if args.output:
            orchestrator.export_report(report, args.output)
    
    else:
        print("\nNo investigation target specified.")
        print("Use --address <address> or --transaction <hash>")
        parser.print_help()


if __name__ == "__main__":
    main()
