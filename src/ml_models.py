#!/usr/bin/env python3
"""
ML Models for Blockchain Forensics
Uses TensorFlow for anomaly detection and transaction pattern analysis
"""

import os
import json
import numpy as np
from typing import Dict, List, Tuple, Optional
from datetime import datetime

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, optimizers
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("Warning: TensorFlow not available. Using fallback ML methods.")

class TransactionAnomalyDetector:
    """
    ML model to detect anomalous transactions using deep learning
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_names = [
            "value_usd", "gas_price", "gas_used", "input_data_length",
            "timestamp_hour", "day_of_week", "contract_interaction",
            "token_transfer_count", "unique_addresses_interacted"
        ]
        
        if TENSORFLOW_AVAILABLE:
            if model_path and os.path.exists(model_path):
                self.load_model(model_path)
            else:
                self.build_model()
    
    def build_model(self):
        """Build the anomaly detection model"""
        if not TENSORFLOW_AVAILABLE:
            self.model = None
            return
            
        # Build a neural network for anomaly detection
        self.model = models.Sequential([
            layers.Input(shape=(len(self.feature_names),)),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(16, activation='relu'),
            layers.Dense(8, activation='relu'),
            layers.Dense(1, activation='sigmoid')  # Output: anomaly probability
        ])
        
        self.model.compile(
            optimizer=optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
    
    def extract_features(self, transaction: Dict) -> np.ndarray:
        """Extract features from a transaction"""
        features = []
        
        # Value in USD
        features.append(float(transaction.get("value_usd", 0)) / 1000000)  # Normalize
        
        # Gas price
        gas_price = float(transaction.get("gas_price", 0)) / 1e9  # Convert to Gwei
        features.append(gas_price / 500)  # Normalize
        
        # Gas used
        features.append(float(transaction.get("gas_used", 0)) / 500000)
        
        # Input data length
        input_data = transaction.get("input", "")
        features.append(len(input_data) / 1000)
        
        # Timestamp features
        try:
            timestamp = transaction.get("timestamp", "")
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                features.append(dt.hour / 24)
                features.append(dt.weekday() / 7)
            else:
                features.extend([0.5, 0.5])
        except:
            features.extend([0.5, 0.5])
        
        # Contract interaction
        features.append(1.0 if transaction.get("contract_address") else 0.0)
        
        # Token transfer count
        features.append(float(transaction.get("token_transfers", 0)) / 10)
        
        # Unique addresses
        features.append(float(transaction.get("unique_addresses", 0)) / 50)
        
        return np.array(features)
    
    def detect_anomaly(self, transaction: Dict) -> Tuple[float, bool]:
        """
        Detect if a transaction is anomalous
        Returns: (anomaly_probability, is_anomalous)
        """
        if self.model is None or not TENSORFLOW_AVAILABLE:
            # Fallback: rule-based detection
            return self.fallback_anomaly_detection(transaction)
        
        features = self.extract_features(transaction).reshape(1, -1)
        probability = float(self.model.predict(features, verbose=0)[0][0])
        
        return probability, probability > 0.7
    
    def fallback_anomaly_detection(self, transaction: Dict) -> Tuple[float, bool]:
        """Fallback rule-based anomaly detection"""
        score = 0.0
        
        # High value
        if float(transaction.get("value_usd", 0)) > 100000:
            score += 0.3
        
        # Unusual gas price
        gas_price = float(transaction.get("gas_price", 0)) / 1e9
        if gas_price > 200 or gas_price < 1:
            score += 0.2
        
        # Large input data (potential contract interaction)
        input_len = len(transaction.get("input", ""))
        if input_len > 5000:
            score += 0.2
        
        # Contract creation
        if transaction.get("contract_address") and transaction.get("creates"):
            score += 0.2
        
        return min(score, 1.0), score > 0.5
    
    def train(self, transactions: List[Dict], labels: List[int], epochs: int = 50):
        """Train the model on labeled transactions"""
        if self.model is None or not TENSORFLOW_AVAILABLE:
            print("Model not available for training")
            return
        
        features = np.array([self.extract_features(tx) for tx in transactions])
        labels = np.array(labels)
        
        self.model.fit(
            features, labels,
            epochs=epochs,
            batch_size=32,
            validation_split=0.2,
            verbose=1
        )
    
    def save_model(self, path: str):
        """Save the trained model"""
        if self.model and TENSORFLOW_AVAILABLE:
            self.model.save(path)
    
    def load_model(self, path: str):
        """Load a trained model"""
        if TENSORFLOW_AVAILABLE and os.path.exists(path):
            self.model = keras.models.load_model(path)


class AddressRiskScorer:
    """
    ML model to score address risk using ensemble methods
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_names = [
            "transaction_count", "failed_tx_ratio", "contract_creation_count",
            "token_holdings_count", "mixer_interaction", "exchange_interaction",
            "age_days", "balance_usd", "incoming_tx_count", "outgoing_tx_count"
        ]
        
        if TENSORFLOW_AVAILABLE:
            if model_path and os.path.exists(model_path):
                self.load_model(model_path)
            else:
                self.build_model()
    
    def build_model(self):
        """Build the risk scoring model"""
        if not TENSORFLOW_AVAILABLE:
            self.model = None
            return
        
        self.model = models.Sequential([
            layers.Input(shape=(len(self.feature_names),)),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(16, activation='relu'),
            layers.Dense(8, activation='relu'),
            layers.Dense(1, activation='sigmoid')  # Risk score 0-1
        ])
        
        self.model.compile(
            optimizer=optimizers.Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
    
    def extract_features(self, address_data: Dict) -> np.ndarray:
        """Extract features from address data"""
        features = []
        
        features.append(float(address_data.get("transaction_count", 0)) / 10000)
        features.append(float(address_data.get("failed_tx_ratio", 0)))
        features.append(float(address_data.get("contract_creation_count", 0)) / 10)
        features.append(float(address_data.get("token_holdings_count", 0)) / 100)
        
        # Interaction flags
        features.append(1.0 if address_data.get("mixer_interaction") else 0.0)
        features.append(1.0 if address_data.get("exchange_interaction") else 0.0)
        
        # Age
        features.append(float(address_data.get("age_days", 0)) / 3650)  # Max 10 years
        
        # Balance
        features.append(float(address_data.get("balance_usd", 0)) / 10000000)
        
        # Transaction counts
        features.append(float(address_data.get("incoming_tx_count", 0)) / 5000)
        features.append(float(address_data.get("outgoing_tx_count", 0)) / 5000)
        
        return np.array(features)
    
    def calculate_risk_score(self, address_data: Dict) -> float:
        """
        Calculate risk score for an address
        Returns score between 0 (low risk) and 1 (high risk)
        """
        if self.model is None or not TENSORFLOW_AVAILABLE:
            return self.fallback_risk_calculation(address_data)
        
        features = self.extract_features(address_data).reshape(1, -1)
        risk_score = float(self.model.predict(features, verbose=0)[0][0])
        
        return risk_score
    
    def fallback_risk_calculation(self, address_data: Dict) -> float:
        """Fallback rule-based risk calculation"""
        score = 0.0
        
        # Failed transaction ratio
        if address_data.get("failed_tx_ratio", 0) > 0.3:
            score += 0.2
        
        # Mixer interaction
        if address_data.get("mixer_interaction"):
            score += 0.4
        
        # Exchange interaction (could be legitimate or illicit)
        if address_data.get("exchange_interaction"):
            score -= 0.1  # Generally lowers risk
        
        # Balance
        balance_usd = float(address_data.get("balance_usd", 0))
        if balance_usd > 10000000:  # > $10M
            score += 0.2
        
        # Age (new addresses are riskier)
        age_days = float(address_data.get("age_days", 0))
        if age_days < 30:
            score += 0.3
        elif age_days < 90:
            score += 0.15
        
        return min(max(score, 0.0), 1.0)


class PatternClassifier:
    """
    Classifier for identifying specific transaction patterns
    Uses TensorFlow for multi-class classification
    """
    
    PATTERN_TYPES = [
        "normal",           # Normal transaction
        "layering",         # Money laundering - layering
        "smurfing",         # Structuring to avoid reporting
        "integration",      # Money laundering - integration
        "pump_dump",        # Pump and dump scheme
        "rug_pull",         # DeFi rug pull
        "honeypot",         # Honeypot scam
        "phishing",         # Phishing attack
        "mixer",            # Mixer/tumbler usage
        "bridge_exploit"    # Cross-chain bridge exploit
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.num_classes = len(self.PATTERN_TYPES)
        
        if TENSORFLOW_AVAILABLE:
            if model_path and os.path.exists(model_path):
                self.load_model(model_path)
            else:
                self.build_model()
    
    def build_model(self):
        """Build pattern classification model"""
        if not TENSORFLOW_AVAILABLE:
            self.model = None
            return
        
        self.model = models.Sequential([
            layers.Input(shape=(20,)),  # 20 features
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(16, activation='relu'),
            layers.Dense(self.num_classes, activation='softmax')
        ])
        
        self.model.compile(
            optimizer=optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
    
    def classify_transaction_sequence(self, transactions: List[Dict]) -> Dict:
        """
        Classify a sequence of transactions
        Returns pattern type and confidence
        """
        if self.model is None or not TENSORFLOW_AVAILABLE:
            return self.fallback_classification(transactions)
        
        # Extract sequence features
        features = self.extract_sequence_features(transactions)
        features = np.array(features).reshape(1, -1)
        
        # Pad if needed
        if features.shape[1] < 20:
            features = np.pad(features, ((0, 0), (0, 20 - features.shape[1])))
        
        probabilities = self.model.predict(features, verbose=0)[0]
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])
        
        return {
            "pattern_type": self.PATTERN_TYPES[predicted_class],
            "confidence": confidence,
            "all_probabilities": {
                pattern: float(prob) 
                for pattern, prob in zip(self.PATTERN_TYPES, probabilities)
            }
        }
    
    def extract_sequence_features(self, transactions: List[Dict]) -> List[float]:
        """Extract features from transaction sequence"""
        features = []
        
        if not transactions:
            return [0.0] * 20
        
        # Basic statistics
        values = [float(tx.get("value_usd", 0)) for tx in transactions]
        features.append(np.mean(values) / 1000000 if values else 0)
        features.append(np.std(values) / 1000000 if values else 0)
        
        # Transaction count
        features.append(len(transactions) / 100)
        
        # Time distribution
        timestamps = []
        for tx in transactions:
            try:
                ts = tx.get("timestamp", "")
                if ts:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except:
                pass
        
        if len(timestamps) > 1:
            time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                         for i in range(len(timestamps)-1)]
            features.append(np.mean(time_diffs) / 3600)  # Average hours between txs
        else:
            features.append(0)
        
        # Contract interactions
        contract_count = sum(1 for tx in transactions if tx.get("contract_address"))
        features.append(contract_count / len(transactions))
        
        # Add more features to reach 20
        while len(features) < 20:
            features.append(0.0)
        
        return features[:20]
    
    def fallback_classification(self, transactions: List[Dict]) -> Dict:
        """Fallback rule-based classification"""
        # Simple heuristics as fallback
        value_count = len([tx for tx in transactions 
                         if float(tx.get("value_usd", 0)) > 10000])
        
        if value_count > 5:
            return {
                "pattern_type": "layering",
                "confidence": 0.7,
                "all_probabilities": {"layering": 0.7, "normal": 0.3}
            }
        
        return {
            "pattern_type": "normal",
            "confidence": 0.6,
            "all_probabilities": {"normal": 0.6}
        }
    
    def save_model(self, path: str):
        """Save the trained model"""
        if self.model and TENSORFLOW_AVAILABLE:
            self.model.save(path)
    
    def load_model(self, path: str):
        """Load a trained model"""
        if TENSORFLOW_AVAILABLE and os.path.exists(path):
            self.model = keras.models.load_model(path)


# Pre-trained model download (placeholder)
def download_pretrained_models():
    """
    Download pre-trained models for blockchain forensics
    In production, these would be downloaded from a secure source
    """
    print("Preparing to download pre-trained models...")
    print("Note: In production, models should be from verified sources")
    print("Models will be saved to: models/")
    
    # This is a placeholder
    # Actual implementation would download from verified sources
    pass


if __name__ == "__main__":
    # Test the models
    detector = TransactionAnomalyDetector()
    scorer = AddressRiskScorer()
    classifier = PatternClassifier()
    
    # Test transaction
    test_tx = {
        "value_usd": 15000,
        "gas_price": 50000000000,
        "gas_used": 21000,
        "input": "0x",
        "timestamp": "2024-01-01T12:00:00",
        "contract_address": None
    }
    
    anomaly_prob, is_anomalous = detector.detect_anomaly(test_tx)
    print(f"Anomaly detection: probability={anomaly_prob}, is_anomalous={is_anomalous}")
    
    # Test address risk
    test_address = {
        "transaction_count": 150,
        "failed_tx_ratio": 0.05,
        "contract_creation_count": 2,
        "token_holdings_count": 5,
        "mixer_interaction": False,
        "exchange_interaction": True,
        "age_days": 365,
        "balance_usd": 50000,
        "incoming_tx_count": 80,
        "outgoing_tx_count": 70
    }
    
    risk_score = scorer.calculate_risk_score(test_address)
    print(f"Address risk score: {risk_score}")
