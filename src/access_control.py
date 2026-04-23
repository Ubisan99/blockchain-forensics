#!/usr/bin/env python3
"""
Access Control Module for Blockchain Forensics Tool
Implements strict access control as per user requirements:
- Only selected individuals (specified by user) can use the tool
- No economic gain permitted for forensic analysts
"""

import json
import os
from typing import List, Set
from datetime import datetime

class ForensicAccessControl:
    def __init__(self, authorized_users_file: str = "config/authorized_users.json"):
        self.authorized_users_file = authorized_users_file
        self.authorized_users: Set[str] = set()
        self.load_authorized_users()
        
    def load_authorized_users(self):
        """Load list of authorized users from configuration file"""
        try:
            if os.path.exists(self.authorized_users_file):
                with open(self.authorized_users_file, 'r') as f:
                    data = json.load(f)
                    self.authorized_users = set(data.get("authorized_users", []))
            else:
                # Create default config file if it doesn't exist
                self.create_default_config()
        except Exception as e:
            print(f"Warning: Could not load authorized users: {e}")
            self.authorized_users = set()
    
    def create_default_config(self):
        """Create default authorized users configuration"""
        default_config = {
            "authorized_users": [],  # To be populated by user
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "note": "ONLY ADD USERS THAT YOU PERSONALLY SELECT. NO ECONOMIC GAIN PERMITTED FOR FORENSIC ANALYSTS."
        }
        
        os.makedirs(os.path.dirname(self.authorized_users_file), exist_ok=True)
        with open(self.authorized_users_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        self.authorized_users = set()
    
    def add_authorized_user(self, user_identifier: str) -> bool:
        """
        Add an authorized user (only to be called by the tool owner)
        Returns True if successful
        """
        if not user_identifier or not isinstance(user_identifier, str):
            return False
            
        self.authorized_users.add(user_identifier.strip())
        self.save_authorized_users()
        return True
    
    def remove_authorized_user(self, user_identifier: str) -> bool:
        """
        Remove an authorized user (only to be called by the tool owner)
        Returns True if successful
        """
        if user_identifier in self.authorized_users:
            self.authorized_users.remove(user_identifier)
            self.save_authorized_users()
            return True
        return False
    
    def is_authorized(self, user_identifier: str) -> bool:
        """
        Check if a user is authorized to use the forensic tool
        Returns True if authorized, False otherwise
        """
        if not user_identifier:
            return False
        return user_identifier.strip() in self.authorized_users
    
    def get_authorized_users(self) -> List[str]:
        """Get list of all authorized users"""
        return list(self.authorized_users)
    
    def save_authorized_users(self):
        """Save authorized users to configuration file"""
        try:
            config_data = {
                "authorized_users": list(self.authorized_users),
                "created_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "note": "ONLY ADD USERS THAT YOU PERSONALLY SELECT. NO ECONOMIC GAIN PERMITTED FOR FORENSIC ANALYSTS."
            }
            
            os.makedirs(os.path.dirname(self.authorized_users_file), exist_ok=True)
            with open(self.authorized_users_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Error saving authorized users: {e}")
    
    def validate_no_economic_gain(self, user_identifier: str, transaction_data: dict) -> bool:
        """
        Validate that no economic gain is being sought by the forensic analyst
        This is a placeholder for more sophisticated economic gain detection
        """
        # In a real implementation, this would check for:
        # - Suspicious transactions to the analyst's addresses
        # - Unexplained wealth increases
        # - Payment for forensic services
        # For now, we rely on the user's assurance and the access control
        
        # Log the check for audit purposes
        print(f"[ACCESS CONTROL] Economic gain validation performed for user: {user_identifier}")
        return True  # Placeholder - in reality would perform actual checks

# Example usage (to be customized by the user)
if __name__ == "__main__":
    # Initialize access control
    ac = ForensicAccessControl()
    
    # Example: Add an authorized user (replace with actual user selection)
    # ac.add_authorized_user("your_specific_identifier_here")
    
    # Check authorization
    test_user = "example_user"
    if ac.is_authorized(test_user):
        print(f"User {test_user} is authorized")
    else:
        print(f"User {test_user} is NOT authorized")
        print("To authorize a user, use: ac.add_authorized_user('user_identifier')")
        print("Remember: Only add users that YOU have personally selected.")
        print("No economic gain is permitted for forensic analysts.")
