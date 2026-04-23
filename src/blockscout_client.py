#!/usr/bin/env python3
"""
Blockscout API Client for Blockchain Forensics
Integrates with Blockscout explorers to fetch transaction and address data
"""

import json
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import time

class BlockscoutClient:
    """
    Client for interacting with Blockscout API
    Supports multiple networks (Ethereum, Polygon, BSC, etc.)
    """
    
    def __init__(self, network: str = "ethereum", api_key: str = ""):
        self.network = network.lower()
        self.api_key = api_key
        self.base_url = self.get_base_url()
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Blockchain-Forensics-Tool/1.0"
        })
        if api_key:
            self.session.headers["x-api-key"] = api_key
    
    def get_base_url(self) -> str:
        """Get Blockscout API base URL for the network"""
        urls = {
            "ethereum": "https://blockscout.com/eth/mainnet/api",
            "polygon": "https://blockscout.com/polygon/mainnet/api",
            "bsc": "https://blockscout.com/binance/smart_chain/api",
            "avalanche": "https://blockscout.com/avalanche/mainnet/api",
            "arbitrum": "https://blockscout.com/arbitrum/mainnet/api",
            "optimism": "https://blockscout.com/optimism/mainnet/api",
            "fantom": "https://blockscout.com/fantom/mainnet/api",
            "celo": "https://blockscout.com/celo/mainnet/api"
        }
        return urls.get(self.network, urls["ethereum"])
    
    def make_request(self, endpoint: str, params: Dict = None, retries: int = 3) -> Optional[Dict]:
        """Make API request with retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(retries):
            try:
                response = self.session.get(url, params=params, timeout=30)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                print(f"Request attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"Final request failed for {endpoint}")
                    return None
        return None
    
    def get_address_info(self, address: str) -> Optional[Dict]:
        """
        Get comprehensive address information from Blockscout
        """
        endpoint = f"/addresses/{address}"
        result = self.make_request(endpoint)
        
        if result:
            return {
                "address": address,
                "balance": result.get("balance"),
                "coin_balance": result.get("coin_balance"),
                "hash": result.get("hash"),
                "contract_creator": result.get("contract_creator"),
                "token_transfers_count": result.get("token_transfers_count"),
                "transactions_count": result.get("transactions_count"),
                "gas_used": result.get("gas_used"),
                "last_updated": result.get("fetched_at"),
                "nonce": result.get("nonce"),
                "domain_names": result.get("domain_names", [])
            }
        return None
    
    def get_address_transactions(self, address: str, page: int = 1, 
                                  limit: int = 50) -> List[Dict]:
        """
        Get transactions for an address
        """
        endpoint = f"/addresses/{address}/transactions"
        params = {"page": page, "limit": limit}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_address_token_transfers(self, address: str, page: int = 1, 
                                     limit: int = 50) -> List[Dict]:
        """
        Get token transfers for an address
        """
        endpoint = f"/addresses/{address}/token-transfers"
        params = {"page": page, "limit": limit}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_transaction_info(self, tx_hash: str) -> Optional[Dict]:
        """
        Get detailed transaction information
        """
        endpoint = f"/transactions/{tx_hash}"
        result = self.make_request(endpoint)
        
        if result:
            return {
                "hash": result.get("hash"),
                "block_number": result.get("block"),
                "timestamp": result.get("timestamp"),
                "from": result.get("from"),
                "to": result.get("to"),
                "value": result.get("value"),
                "gas_price": result.get("gas_price"),
                "gas_used": result.get("gas_used"),
                "gas_limit": result.get("gas"),
                "input": result.get("input"),
                "status": result.get("status"),
                "logs": result.get("logs", []),
                "token_transfers": result.get("token_transfers", [])
            }
        return None
    
    def get_block_transactions(self, block_number: int, page: int = 1, 
                               limit: int = 50) -> List[Dict]:
        """
        Get all transactions in a block
        """
        endpoint = f"/blocks/{block_number}/transactions"
        params = {"page": page, "limit": limit}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def search_addresses(self, query: str) -> List[Dict]:
        """
        Search for addresses by name/address
        """
        endpoint = "/addresses"
        params = {"q": query}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_contract_abi(self, address: str) -> Optional[Dict]:
        """
        Get contract ABI if verified
        """
        endpoint = f"/contracts/{address}"
        result = self.make_request(endpoint)
        
        if result:
            return {
                "address": address,
                "name": result.get("name"),
                "compiler_version": result.get("compiler_version"),
                "optimization_enabled": result.get("optimization_enabled"),
                "abi": result.get("abi")
            }
        return None
    
    def get_token_info(self, token_address: str) -> Optional[Dict]:
        """
        Get token information (ERC-20/ERC-721)
        """
        endpoint = f"/tokens/{token_address}"
        result = self.make_request(endpoint)
        
        if result:
            return {
                "address": token_address,
                "name": result.get("name"),
                "symbol": result.get("symbol"),
                "type": result.get("type"),
                "decimals": result.get("decimals"),
                "total_supply": result.get("total_supply"),
                "holders_count": result.get("holders_count"),
                "transfers_count": result.get("transfers_count")
            }
        return None
    
    def get_token_holders(self, token_address: str, page: int = 1, 
                          limit: int = 50) -> List[Dict]:
        """
        Get token holders
        """
        endpoint = f"/tokens/{token_address}/holders"
        params = {"page": page, "limit": limit}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_tx_internal_transactions(self, tx_hash: str) -> List[Dict]:
        """
        Get internal transactions for a transaction
        """
        endpoint = f"/transactions/{tx_hash}/internal-transactions"
        
        result = self.make_request(endpoint)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_address_balance_history(self, address: str, 
                                     days: int = 30) -> List[Dict]:
        """
        Get balance history for an address (if available)
        """
        endpoint = f"/addresses/{address}/balance-history"
        params = {"from": days}
        
        result = self.make_request(endpoint, params)
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_contract_methods(self, address: str) -> List[Dict]:
        """
        Get list of contract read/write methods
        """
        endpoint = f"/contracts/{address}/methods"
        result = self.make_request(endpoint)
        
        if result and "items" in result:
            return result["items"]
        return []
    
    def get_contract_reads(self, address: str, method: str = "") -> Optional[Dict]:
        """
        Read contract state (view functions)
        """
        endpoint = f"/contracts/{address}/read"
        if method:
            endpoint += f"/{method}"
        
        result = self.make_request(endpoint)
        return result


class MultiChainForensicsFetcher:
    """
    Fetch forensics data from multiple blockchain networks
    """
    
    def __init__(self):
        self.clients: Dict[str, BlockscoutClient] = {}
    
    def add_network(self, network: str, api_key: str = ""):
        """Add a network to query"""
        self.clients[network] = BlockscoutClient(network, api_key)
    
    def fetch_address_across_chains(self, address: str) -> Dict[str, Optional[Dict]]:
        """
        Fetch address information across all configured networks
        """
        results = {}
        
        for network, client in self.clients.items():
            try:
                info = client.get_address_info(address)
                results[network] = info
                print(f"Fetched {address} from {network}")
            except Exception as e:
                print(f"Error fetching from {network}: {e}")
                results[network] = None
        
        return results
    
    def fetch_transactions_across_chains(self, address: str, 
                                         limit: int = 50) -> Dict[str, List[Dict]]:
        """
        Fetch transactions across all configured networks
        """
        results = {}
        
        for network, client in self.clients.items():
            try:
                txs = client.get_address_transactions(address, limit=limit)
                results[network] = txs
                print(f"Fetched {len(txs)} txs from {network}")
            except Exception as e:
                print(f"Error fetching txs from {network}: {e}")
                results[network] = []
        
        return results


if __name__ == "__main__":
    # Example usage
    client = BlockscoutClient("ethereum")
    
    # Get information for a sample address
    # Replace with actual address to test
    test_address = "0x0000000000000000000000000000000000000000"
    
    print(f"Fetching info for {test_address}...")
    info = client.get_address_info(test_address)
    
    if info:
        print(json.dumps(info, indent=2, default=str))
    else:
        print("Could not fetch address info")
