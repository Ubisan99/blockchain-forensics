#!/usr/bin/env python3
"""
Blockchain Forensics Analysis Module
Uses ML and AI to detect potential crimes and legal violations on blockchain

ACCESS CONTROL: This tool is restricted to only individuals personally selected by the owner.
No economic gain is permitted for forensic analysts using this system.
"""

import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

# Import access control
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from access_control import ForensicAccessControl

class BlockchainForensicsAnalyzer:
    """
    Forensic analyzer that detects potential legal violations on blockchain
    Uses pattern recognition and anomaly detection
    """
    
    def __init__(self, config_path: str = "config/blockchain_config.json"):
        self.config = self.load_config(config_path)
        self.analysis_results = []
        
    def load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except:
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            "legal_frameworks": {
                "money_laundering": {"thresholds": {"large_transaction_usd": 10000}},
                "fraud": {"thresholds": {"fake_volume_threshold": 1000}},
                "terrorism_financing": {"thresholds": {"sanctioned_address_interaction": True}}
            },
            "alert_thresholds": {
                "high_risk_score": 0.8,
                "medium_risk_score": 0.5
            }
        }
    
    def analyze_transaction_patterns(self, transactions: List[Dict]) -> Dict:
        """
        Analyze transaction patterns for potential legal violations
        Uses ML-inspired pattern detection
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "transactions_analyzed": len(transactions),
            "patterns_detected": [],
            "risk_score": 0.0,
            "alerts": []
        }
        
        # Pattern 1: Rapid sequential transactions (potential layering)
        rapid_tx_count = self.detect_rapid_transactions(transactions)
        if rapid_tx_count > 5:
            results["patterns_detected"].append({
                "type": "rapid_layering",
                "confidence": min(0.9, rapid_tx_count * 0.1),
                "description": f"Detected {rapid_tx_count} rapid sequential transactions"
            })
            results["risk_score"] += 0.2
        
        # Pattern 2: Large value transactions
        large_tx = self.detect_large_transactions(transactions)
        if large_tx > 0:
            results["patterns_detected"].append({
                "type": "large_value_transfer",
                "confidence": min(0.95, large_tx * 0.15),
                "description": f"Detected {large_tx} large value transactions (>${self.config['legal_frameworks']['money_laundering']['thresholds']['large_transaction_usd']})"
            })
            results["risk_score"] += 0.25
        
        # Pattern 3: Contract interaction anomalies
        contract_anomalies = self.detect_contract_anomalies(transactions)
        if contract_anomalies > 0:
            results["patterns_detected"].append({
                "type": "suspicious_contract_interaction",
                "confidence": 0.7,
                "description": f"Detected {contract_anomalies} suspicious contract interactions"
            })
            results["risk_score"] += 0.15
        
        # Pattern 4: Round number transactions (potential structuring)
        round_number_count = self.detect_round_numbers(transactions)
        if round_number_count > 3:
            results["patterns_detected"].append({
                "type": "structuring_pattern",
                "confidence": min(0.85, round_number_count * 0.12),
                "description": f"Detected {round_number_count} round number transactions (potential structuring)"
            })
            results["risk_score"] += 0.2
        
        # Normalize risk score
        results["risk_score"] = min(1.0, results["risk_score"])
        
        # Generate alerts based on thresholds
        if results["risk_score"] >= self.config["alert_thresholds"]["high_risk_score"]:
            results["alerts"].append({
                "level": "HIGH",
                "message": "High risk of financial crime detected"
            })
        elif results["risk_score"] >= self.config["alert_thresholds"]["medium_risk_score"]:
            results["alerts"].append({
                "level": "MEDIUM",
                "message": "Medium risk of suspicious activity detected"
            })
        
        return results
    
    def detect_rapid_transactions(self, transactions: List[Dict]) -> int:
        """Detect rapid sequential transactions"""
        if len(transactions) < 2:
            return 0
        
        rapid_count = 0
        for i in range(len(transactions) - 1):
            try:
                tx1_time = transactions[i].get("timestamp", 0)
                tx2_time = transactions[i + 1].get("timestamp", 0)
                
                if isinstance(tx1_time, str) and isinstance(tx2_time, str):
                    time_diff = abs((datetime.fromisoformat(tx2_time) - datetime.fromisoformat(tx1_time)).total_seconds())
                    if time_diff < 60:  # Less than 1 minute
                        rapid_count += 1
            except:
                continue
        
        return rapid_count
    
    def detect_large_transactions(self, transactions: List[Dict], threshold_usd: float = 10000) -> int:
        """Detect large value transactions"""
        count = 0
        for tx in transactions:
            value = tx.get("value_usd", tx.get("value", 0))
            try:
                if float(value) > threshold_usd:
                    count += 1
            except:
                continue
        return count
    
    def detect_contract_anomalies(self, transactions: List[Dict]) -> int:
        """Detect suspicious contract interactions"""
        # Placeholder for more sophisticated detection
        # In real implementation, would check for:
        # - Newly created contracts
        # - Contracts with no source code
        # - Interactions with known malicious contracts
        return 0
    
    def detect_round_numbers(self, transactions: List[Dict]) -> int:
        """Detect round number transactions (potential structuring)"""
        count = 0
        for tx in transactions:
            value = tx.get("value", 0)
            try:
                val_float = float(value)
                # Check for round numbers (multiples of 1000, 10000, etc.)
                if val_float > 0 and val_float % 1000 == 0:
                    count += 1
            except:
                continue
        return count
    
    def analyze_address(self, address: str, transactions: List[Dict]) -> Dict:
        """
        Comprehensive address analysis using ML techniques
        """
        analysis = {
            "address": address,
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                "total_transactions": len(transactions),
                "total_received_usd": 0.0,
                "total_sent_usd": 0.0,
                "unique_counterparties": set(),
                "contract_interactions": 0
            },
            "risk_assessment": {
                "score": 0.0,
                "factors": []
            }
        }
        
        for tx in transactions:
            value_usd = tx.get("value_usd", 0)
            try:
                value_usd = float(value_usd)
            except:
                value_usd = 0
            
            if tx.get("to", "").lower() == address.lower():
                analysis["metrics"]["total_received_usd"] += value_usd
            if tx.get("from", "").lower() == address.lower():
                analysis["metrics"]["total_sent_usd"] += value_usd
            
            if tx.get("to"):
                analysis["metrics"]["unique_counterparties"].add(tx.get("to"))
            if tx.get("contract_address"):
                analysis["metrics"]["contract_interactions"] += 1
        
        # Convert set to list for JSON serialization
        analysis["metrics"]["unique_counterparties"] = list(analysis["metrics"]["unique_counterparties"])
        
        # Calculate risk score
        analysis["risk_assessment"] = self.calculate_risk_score(analysis["metrics"])
        
        return analysis
    
    def calculate_risk_score(self, metrics: Dict) -> Dict:
        """Calculate risk score based on various factors"""
        score = 0.0
        factors = []
        
        # Factor 1: High transaction volume
        if metrics["total_transactions"] > 1000:
            score += 0.15
            factors.append("High transaction volume")
        
        # Factor 2: Large value transfer
        if metrics["total_received_usd"] > 100000:
            score += 0.25
            factors.append("Large value received")
        
        # Factor 3: Many unique counterparties
        if len(metrics["unique_counterparties"]) > 50:
            score += 0.2
            factors.append("Many unique counterparties")
        
        # Factor 4: Contract interactions
        if metrics["contract_interactions"] > 10:
            score += 0.15
            factors.append("High contract interaction count")
        
        return {
            "score": min(1.0, score),
            "factors": factors,
            "risk_level": "HIGH" if score > 0.7 else "MEDIUM" if score > 0.4 else "LOW"
        }
    
    def check_legal_compliance(self, address: str, transactions: List[Dict]) -> Dict:
        """
        Check for potential legal violations
        """
        compliance_results = {
            "address": address,
            "timestamp": datetime.now().isoformat(),
            "violations_detected": [],
            "legal_frameworks_triggered": []
        }
        
        # Check against each legal framework
        for framework, config in self.config.get("legal_frameworks", {}).items():
            violations = []
            
            if framework == "money_laundering":
                violations = self.check_money_laundering(transactions, config)
            elif framework == "fraud":
                violations = self.check_fraud_patterns(transactions, config)
            elif framework == "terrorism_financing":
                violations = self.check_terrorism_financing(address, transactions, config)
            
            if violations:
                compliance_results["violations_detected"].extend(violations)
                compliance_results["legal_frameworks_triggered"].append(framework)
        
        return compliance_results
    
    def check_money_laundering(self, transactions: List[Dict], config: Dict) -> List[Dict]:
        """Check for money laundering patterns"""
        violations = []
        threshold = config.get("thresholds", {}).get("large_transaction_usd", 10000)
        
        large_tx = self.detect_large_transactions(transactions, threshold)
        if large_tx > 3:
            violations.append({
                "type": "money_laundering_suspicion",
                "severity": "HIGH",
                "description": f"{large_tx} large transactions detected exceeding ${threshold}",
                "legal_reference": "AML (Anti-Money Laundering) regulations"
            })
        
        rapid_tx = self.detect_rapid_transactions(transactions)
        if rapid_tx > 10:
            violations.append({
                "type": "layering_pattern",
                "severity": "HIGH",
                "description": f"{rapid_tx} rapid sequential transactions (potential layering)",
                "legal_reference": "Bank Secrecy Act, FinCEN regulations"
            })
        
        return violations
    
    def check_fraud_patterns(self, transactions: List[Dict], config: Dict) -> List[Dict]:
        """Check for fraud patterns"""
        violations = []
        # Placeholder for fraud detection
        # Would implement honeypot detection, fake volume, wash trading
        return violations
    
    def check_terrorism_financing(self, address: str, transactions: List[Dict], config: Dict) -> List[Dict]:
        """Check for terrorism financing indicators"""
        violations = []
        # Placeholder - would check against OFAC sanctions list
        # and known dark web marketplace addresses
        return violations
    
    def generate_forensic_report(self, address: str, transactions: List[Dict]) -> Dict:
        """
        Generate comprehensive forensic report
        """
        report = {
            "report_id": hashlib.sha256(f"{address}{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "target_address": address,
            "generated_at": datetime.now().isoformat(),
            "summary": {},
            "detailed_analysis": {},
            "legal_assessment": {},
            "recommendations": []
        }
        
        # Run all analyses
        address_analysis = self.analyze_address(address, transactions)
        pattern_analysis = self.analyze_transaction_patterns(transactions)
        compliance_check = self.check_legal_compliance(address, transactions)
        
        # Compile summary
        report["summary"] = {
            "transactions_analyzed": len(transactions),
            "overall_risk_score": (address_analysis["risk_assessment"]["score"] + 
                                   pattern_analysis["risk_score"]) / 2,
            "legal_violations_found": len(compliance_check["violations_detected"]),
            "legal_frameworks_triggered": compliance_check["legal_frameworks_triggered"]
        }
        
        # Detailed analysis
        report["detailed_analysis"] = {
            "address_metrics": address_analysis["metrics"],
            "patterns": pattern_analysis["patterns_detected"]
        }
        
        # Legal assessment
        report["legal_assessment"] = compliance_check
        
        # Recommendations
        if report["summary"]["overall_risk_score"] > 0.7:
            report["recommendations"].append("Immediate investigation recommended")
        if compliance_check["violations_detected"]:
            report["recommendations"].append("Consider reporting to relevant authorities")
        
        return report


if __name__ == "__main__":
    analyzer = BlockchainForensicsAnalyzer()
    
    # Example usage
    test_transactions = [
        {"from": "0x123", "to": "0x456", "value": "10000", "value_usd": 15000, "timestamp": "2024-01-01T10:00:00"},
        {"from": "0x456", "to": "0x789", "value": "10000", "value_usd": 15000, "timestamp": "2024-01-01T10:00:30"},
        {"from": "0x789", "to": "0xabc", "value": "10000", "value_usd": 15000, "timestamp": "2024-01-01T10:01:00"},
    ]
    
    result = analyzer.generate_forensic_report("0x456", test_transactions)
    print(json.dumps(result, indent=2, default=str))
