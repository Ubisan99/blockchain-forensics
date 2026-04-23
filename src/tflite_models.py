#!/usr/bin/env python3
"""
Lightweight ML Models using TensorFlow Lite for Blockchain Forensics
Optimized for mobile/edge deployment with low resource usage
"""

import os
import json
import numpy as np
from typing import Dict, List, Tuple, Optional, Callable
from datetime import datetime
import hashlib

# TensorFlow Lite imports
try:
    import tensorflow as tf
    tflite_available = tf.lite
    TFLITE_AVAILABLE = True
except ImportError:
    TFLITE_AVAILABLE = False
    print("Warning: TensorFlow Lite not available, using NumPy fallback")


class LiteAnomalyDetector:
    """
    Lightweight TensorFlow Lite model for transaction anomaly detection
    Optimized for low-resource environments
    """
    
    FEATURE_COUNT = 9
    
    def __init__(self, model_path: str = "models/anomaly_detector.tflite"):
        self.model_path = model_path
        self.interpreter = None
        self.input_index = None
        self.output_index = None
        
        if TFLITE_AVAILABLE and os.path.exists(model_path):
            self.load_model()
        else:
            # Create lightweight fallback model
            self.use_fallback = True
    
    def load_model(self):
        """Load TensorFlow Lite model"""
        if not TFLITE_AVAILABLE:
            return
            
        try:
            self.interpreter = tf.lite.Interpreter(model_path=self.model_path)
            self.interpreter.allocate_tensors()
            
            self.input_index = self.interpreter.get_input_details()[0]['index']
            self.output_index = self.interpreter.get_output_details()[0]['index']
            self.use_fallback = False
            print(f"Loaded TFLite model from {self.model_path}")
        except Exception as e:
            print(f"Could not load TFLite model: {e}")
            self.use_fallback = True
    
    def extract_features(self, transaction: Dict) -> np.ndarray:
        """Extract 9 features from transaction"""
        features = np.zeros(self.FEATURE_COUNT, dtype=np.float32)
        
        # Feature 0: Normalized value (USD millions)
        features[0] = min(float(transaction.get("value_usd", 0)) / 1_000_000, 10.0)
        
        # Feature 1: Gas price (Gwei / 500)
        gas_price = float(transaction.get("gas_price", 0)) / 1e9
        features[1] = min(gas_price / 500, 2.0)
        
        # Feature 2: Gas used (normalized)
        features[2] = min(float(transaction.get("gas_used", 21000)) / 500_000, 1.0)
        
        # Feature 3: Input data length (normalized)
        features[3] = min(len(transaction.get("input", "")) / 10_000, 1.0)
        
        # Feature 4: Hour of day (normalized)
        try:
            ts = transaction.get("timestamp", "")
            if ts:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                features[4] = dt.hour / 24.0
        except:
            features[4] = 0.5
        
        # Feature 5: Day of week (normalized)
        try:
            ts = transaction.get("timestamp", "")
            if ts:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                features[5] = dt.weekday() / 7.0
        except:
            features[5] = 0.5
        
        # Feature 6: Contract interaction (0 or 1)
        features[6] = 1.0 if transaction.get("contract_address") else 0.0
        
        # Feature 7: Token transfer count (normalized)
        features[7] = min(float(transaction.get("token_transfer_count", 0)) / 10, 1.0)
        
        # Feature 8: Unique addresses interacted (normalized)
        features[8] = min(float(transaction.get("unique_addresses", 0)) / 50, 1.0)
        
        return features
    
    def detect(self, transaction: Dict) -> Tuple[float, bool]:
        """Detect if transaction is anomalous"""
        if not self.use_fallback and self.interpreter:
            return self._detect_tflite(transaction)
        else:
            return self._detect_fallback(transaction)
    
    def _detect_tflite(self, transaction: Dict) -> Tuple[float, bool]:
        """Run inference on TFLite model"""
        features = self.extract_features(transaction).reshape(1, -1)
        
        self.interpreter.set_tensor(self.input_index, features)
        self.interpreter.invoke()
        
        output = self.interpreter.get_tensor(self.output_index)
        probability = float(output[0][0])
        
        return probability, probability > 0.7
    
    def _detect_fallback(self, transaction: Dict) -> Tuple[float, bool]:
        """Fallback rule-based detection"""
        score = 0.0
        
        # High value detection
        if float(transaction.get("value_usd", 0)) > 100_000:
            score += 0.25
        
        # Unusual gas price
        gas_price = float(transaction.get("gas_price", 0)) / 1e9
        if gas_price > 300 or gas_price < 1:
            score += 0.2
        
        # Large input data
        if len(transaction.get("input", "")) > 5000:
            score += 0.15
        
        # Contract creation
        if transaction.get("creates"):
            score += 0.2
        
        # Token transfers
        if transaction.get("token_transfer_count", 0) > 5:
            score += 0.15
        
        return min(score, 1.0), score > 0.5


class LiteRiskScorer:
    """
    Lightweight TensorFlow Lite model for address risk scoring
    """
    
    FEATURE_COUNT = 10
    
    def __init__(self, model_path: str = "models/risk_scorer.tflite"):
        self.model_path = model_path
        self.interpreter = None
        self.use_fallback = True
        
        if TFLITE_AVAILABLE and os.path.exists(model_path):
            self.load_model()
    
    def load_model(self):
        """Load TensorFlow Lite model"""
        if not TFLITE_AVAILABLE:
            return
            
        try:
            self.interpreter = tf.lite.Interpreter(model_path=self.model_path)
            self.interpreter.allocate_tensors()
            self.use_fallback = False
        except Exception as e:
            print(f"Could not load TFLite model: {e}")
    
    def extract_features(self, address_data: Dict) -> np.ndarray:
        """Extract 10 features from address data"""
        features = np.zeros(self.FEATURE_COUNT, dtype=np.float32)
        
        # 0: Transaction count (normalized)
        features[0] = min(float(address_data.get("transaction_count", 0)) / 10_000, 1.0)
        
        # 1: Failed tx ratio
        features[1] = float(address_data.get("failed_tx_ratio", 0))
        
        # 2: Contract creation count (normalized)
        features[2] = min(float(address_data.get("contract_creation_count", 0)) / 10, 1.0)
        
        # 3: Token holdings count (normalized)
        features[3] = min(float(address_data.get("token_holdings_count", 0)) / 100, 1.0)
        
        # 4: Mixer interaction
        features[4] = 1.0 if address_data.get("mixer_interaction") else 0.0
        
        # 5: Exchange interaction
        features[5] = 1.0 if address_data.get("exchange_interaction") else 0.0
        
        # 6: Age in years (normalized, max 10 years)
        features[6] = min(float(address_data.get("age_days", 0)) / 3650, 1.0)
        
        # 7: Balance USD (normalized, max $10M)
        features[7] = min(float(address_data.get("balance_usd", 0)) / 10_000_000, 1.0)
        
        # 8: Incoming tx count (normalized)
        features[8] = min(float(address_data.get("incoming_tx_count", 0)) / 5000, 1.0)
        
        # 9: Outgoing tx count (normalized)
        features[9] = min(float(address_data.get("outgoing_tx_count", 0)) / 5000, 1.0)
        
        return features
    
    def score(self, address_data: Dict) -> float:
        """Calculate risk score 0.0 - 1.0"""
        if not self.use_fallback and self.interpreter:
            return self._score_tflite(address_data)
        else:
            return self._score_fallback(address_data)
    
    def _score_tflite(self, address_data: Dict) -> float:
        """Run TFLite inference"""
        features = self.extract_features(address_data).reshape(1, -1)
        
        input_idx = self.interpreter.get_input_details()[0]['index']
        output_idx = self.interpreter.get_output_details()[0]['index']
        
        self.interpreter.set_tensor(input_idx, features)
        self.interpreter.invoke()
        
        output = self.interpreter.get_tensor(output_idx)
        return float(output[0][0])
    
    def _score_fallback(self, address_data: Dict) -> float:
        """Fallback risk calculation"""
        score = 0.0
        
        # Failed transaction ratio
        if address_data.get("failed_tx_ratio", 0) > 0.3:
            score += 0.2
        
        # Mixer interaction (major risk factor)
        if address_data.get("mixer_interaction"):
            score += 0.4
        
        # Very new address with high activity
        age_days = float(address_data.get("age_days", 0))
        tx_count = float(address_data.get("transaction_count", 0))
        
        if age_days < 30 and tx_count > 100:
            score += 0.25
        
        # High balance
        if float(address_data.get("balance_usd", 0)) > 10_000_000:
            score += 0.15
        
        return min(max(score, 0.0), 1.0)


class ForensicScriptEngine:
    """
    Scripting engine for blockchain forensics investigations
    Allows defining custom detection rules and automated workflows
    """
    
    def __init__(self):
        self.rules: List[Dict] = []
        self.results: List[Dict] = []
        self.anomaly_detector = LiteAnomalyDetector()
        self.risk_scorer = LiteRiskScorer()
    
    def register_rule(self, name: str, condition: Callable, action: Callable, 
                      severity: str = "medium") -> str:
        """
        Register a custom detection rule
        Returns rule ID
        """
        rule_id = hashlib.sha256(f"{name}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        rule = {
            "id": rule_id,
            "name": name,
            "condition": condition,
            "action": action,
            "severity": severity,
            "enabled": True,
            "trigger_count": 0
        }
        
        self.rules.append(rule)
        return rule_id
    
    def unregister_rule(self, rule_id: str) -> bool:
        """Unregister a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule["id"] == rule_id:
                self.rules.pop(i)
                return True
        return False
    
    def enable_rule(self, rule_id: str, enabled: bool = True):
        """Enable or disable a rule"""
        for rule in self.rules:
            if rule["id"] == rule_id:
                rule["enabled"] = enabled
                break
    
    def evaluate_transaction(self, transaction: Dict) -> List[Dict]:
        """Evaluate a transaction against all rules"""
        results = []
        
        # Run ML anomaly detection
        anomaly_prob, is_anomalous = self.anomaly_detector.detect(transaction)
        
        if is_anomalous:
            results.append({
                "type": "anomaly_detection",
                "severity": "high",
                "probability": anomaly_prob,
                "description": f"Anomalous transaction detected (probability: {anomaly_prob:.2f})"
            })
        
        # Run custom rules
        for rule in self.rules:
            if not rule["enabled"]:
                continue
                
            try:
                if rule["condition"](transaction):
                    rule["trigger_count"] += 1
                    action_result = rule["action"](transaction)
                    
                    results.append({
                        "type": "rule_triggered",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "result": action_result
                    })
            except Exception as e:
                print(f"Error in rule {rule['name']}: {e}")
        
        return results
    
    def evaluate_address(self, address_data: Dict) -> Dict:
        """Evaluate an address for risk"""
        risk_score = self.risk_scorer.score(address_data)
        
        results = {
            "address": address_data.get("address", "unknown"),
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score > 0.7 else "MEDIUM" if risk_score > 0.4 else "LOW",
            "triggers": []
        }
        
        # Check against rules
        for rule in self.rules:
            if not rule["enabled"]:
                continue
                
            try:
                if rule["condition"](address_data):
                    rule["trigger_count"] += 1
                    results["triggers"].append({
                        "rule_name": rule["name"],
                        "severity": rule["severity"]
                    })
            except:
                pass
        
        return results
    
    def run_investigation_script(self, script: List[Dict], data: Dict) -> Dict:
        """
        Run a predefined investigation script
        Script is a list of steps: {"step": "analyze", "params": {...}}
        """
        investigation_results = {
            "started_at": datetime.now().isoformat(),
            "steps_completed": [],
            "findings": []
        }
        
        for step in script:
            step_name = step.get("step")
            params = step.get("params", {})
            
            try:
                if step_name == "analyze_transactions":
                    txs = data.get("transactions", [])
                    for tx in txs:
                        findings = self.evaluate_transaction(tx)
                        investigation_results["findings"].extend(findings)
                
                elif step_name == "score_address":
                    findings = self.evaluate_address(data)
                    investigation_results["findings"].append(findings)
                
                elif step_name == "filter_by_severity":
                    min_severity = params.get("min_severity", "low")
                    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    min_level = severity_order.get(min_severity, 0)
                    
                    filtered = []
                    for f in investigation_results["findings"]:
                        f_level = severity_order.get(f.get("severity", "low"), 0)
                        if f_level >= min_level:
                            filtered.append(f)
                    
                    investigation_results["findings"] = filtered
                
                elif step_name == "generate_alerts":
                    alerts = []
                    for f in investigation_results["findings"]:
                        if f.get("severity") in ["high", "critical"]:
                            alerts.append(f)
                    investigation_results["alerts"] = alerts
                
                investigation_results["steps_completed"].append(step_name)
                
            except Exception as e:
                investigation_results["error"] = f"Step {step_name} failed: {str(e)}"
        
        investigation_results["completed_at"] = datetime.now().isoformat()
        
        return investigation_results


# Built-in detection rules
def create_builtin_rules():
    """Create standard forensic detection rules"""
    rules = []
    
    # Rule: Large transaction detection
    rules.append({
        "name": "large_transaction",
        "condition": lambda tx: float(tx.get("value_usd", 0)) > 50_000,
        "action": lambda tx: f"Large transaction: ${tx.get('value_usd', 0)}",
        "severity": "medium"
    })
    
    # Rule: Newly created contract interaction
    rules.append({
        "name": "new_contract_interaction",
        "condition": lambda tx: tx.get("contract_age_days", 999) < 7 and tx.get("contract_address"),
        "action": lambda tx: f"Interacted with contract created {tx.get('contract_age_days')} days ago",
        "severity": "high"
    })
    
    # Rule: Suspicious timing (late night transactions)
    rules.append({
        "name": "suspicious_timing",
        "condition": lambda tx: _check_suspicious_time(tx),
        "action": lambda tx: "Transaction during suspicious hours (2-5 AM UTC)",
        "severity": "low"
    })
    
    # Rule: Rapid transactions
    rules.append({
        "name": "rapid_transactions",
        "condition": lambda tx: tx.get("time_since_previous", 999) < 30,
        "action": lambda tx: f"Rapid transaction: {tx.get('time_since_previous')} seconds since last",
        "severity": "medium"
    })
    
    return rules


def _check_suspicious_time(tx: Dict) -> bool:
    """Check if transaction is during suspicious hours"""
    try:
        ts = tx.get("timestamp", "")
        if ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            # 2 AM to 5 AM UTC is often suspicious
            return 2 <= dt.hour < 5
    except:
        pass
    return False


# Export functions for creating TFLite models
def create_and_convert_models(output_dir: str = "models"):
    """
    Create and convert TensorFlow models to TFLite format
    """
    os.makedirs(output_dir, exist_ok=True)
    
    if not TFLITE_AVAILABLE:
        print("TensorFlow Lite not available, skipping model conversion")
        return
    
    # Create anomaly detector model
    print("Creating anomaly detector model...")
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(32, activation='relu', input_shape=(9,)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    # Convert to TFLite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    
    tflite_model = converter.convert()
    
    with open(f"{output_dir}/anomaly_detector.tflite", "wb") as f:
        f.write(tflite_model)
    
    print(f"Saved anomaly detector to {output_dir}/anomaly_detector.tflite")
    
    # Create risk scorer model
    print("Creating risk scorer model...")
    model2 = tf.keras.Sequential([
        tf.keras.layers.Dense(24, activation='relu', input_shape=(10,)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(12, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    
    model2.compile(optimizer='adam', loss='mse', metrics=['mae'])
    
    converter2 = tf.lite.TFLiteConverter.from_keras_model(model2)
    converter2.optimizations = [tf.lite.Optimize.DEFAULT]
    
    tflite_model2 = converter2.convert()
    
    with open(f"{output_dir}/risk_scorer.tflite", "wb") as f:
        f.write(tflite_model2)
    
    print(f"Saved risk scorer to {output_dir}/risk_scorer.tflite")


if __name__ == "__main__":
    # Test the system
    engine = ForensicScriptEngine()
    
    # Test transaction
    test_tx = {
        "value_usd": 150000,
        "gas_price": 80000000000,
        "gas_used": 65000,
        "input": "0x" + "a" * 1000,
        "timestamp": "2024-01-15T03:30:00",
        "contract_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f4f2E1"
    }
    
    results = engine.evaluate_transaction(test_tx)
    print("\nTransaction analysis results:")
    for r in results:
        print(f"  - [{r.get('severity')}] {r.get('description', r.get('type'))}")
    
    # Test address
    test_addr = {
        "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f4f2E1",
        "transaction_count": 500,
        "failed_tx_ratio": 0.02,
        "contract_creation_count": 3,
        "token_holdings_count": 15,
        "mixer_interaction": False,
        "exchange_interaction": True,
        "age_days": 180,
        "balance_usd": 250000,
        "incoming_tx_count": 200,
        "outgoing_tx_count": 300
    }
    
    risk = engine.evaluate_address(test_addr)
    print(f"\nAddress risk score: {risk['risk_score']} ({risk['risk_level']})")
    
    # Test script execution
    test_script = [
        {"step": "analyze_transactions"},
        {"step": "filter_by_severity", "params": {"min_severity": "medium"}},
        {"step": "generate_alerts"}
    ]
    
    test_data = {
        "transactions": [test_tx]
    }
    
    investigation = engine.run_investigation_script(test_script, test_data)
    print(f"\nInvestigation steps completed: {investigation['steps_completed']}")
    print(f"Findings: {len(investigation['findings'])}")
