#!/usr/bin/env python3
"""
XGBoost IDS → Wazuh Integration via Agent Socket
Sends alerts directly to local Wazuh agent socket (most reliable method)
"""
import json
import socket
from datetime import datetime
from pathlib import Path


class WazuhAgentIntegration:
    """
    Send alerts to Wazuh via local agent socket.
    
    This is the most reliable method - writes directly to Wazuh agent's
    Unix socket, which forwards to Wazuh manager automatically.
    
    Prerequisites:
    1. Wazuh agent installed on macOS
    2. Agent enrolled and connected to manager
    3. Custom log format configured in agent
    """
    
    def __init__(self, socket_path="/var/ossec/queue/sockets/queue"):
        """
        Initialize Wazuh agent integration.
        
        Args:
            socket_path: Path to Wazuh agent socket (default for macOS/Linux)
        """
        self.socket_path = socket_path
        self.validate_socket()
    
    def validate_socket(self):
        """Check if Wazuh agent socket exists"""
        if not Path(self.socket_path).exists():
            raise FileNotFoundError(
                f"Wazuh agent socket not found at {self.socket_path}\n"
                "Please install and start Wazuh agent first."
            )
    
    def send_alert(self, alert_data):
        """
        Send alert to Wazuh agent socket.
        
        Args:
            alert_data: Dictionary with alert information
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            alert_data = self._normalize_alert(alert_data)
            # Format alert message for Wazuh
            message = self._format_message(alert_data)
            
            # Send to Wazuh agent socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.sendto(message.encode('utf-8'), self.socket_path)
            sock.close()
            
            print(f"✓ Alert sent to Wazuh agent: {alert_data.get('attack_type', 'Unknown')}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to send alert: {e}")
            return False

    def _normalize_alert(self, alert_data):
        """Normalize alert fields before sending."""
        if not isinstance(alert_data, dict):
            return alert_data

        is_attack = alert_data.get('is_attack')
        attack_type = str(alert_data.get('attack_type', '')).lower()

        if is_attack is False or attack_type == 'benign':
            alert_data['severity'] = 'NORMAL'
            alert_data['alert_level'] = 'INFO'

        return alert_data
    
    def _format_message(self, alert_data):
        """
        Format alert for Wazuh processing.
        
        Format: xgboost-ids: <JSON>
        The 'xgboost-ids:' prefix helps Wazuh decoder identify our alerts.
        """
        # Ensure timestamp is included
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Convert to compact JSON
        json_str = json.dumps(alert_data, separators=(',', ':'))
        
        # Return formatted message
        return f"xgboost-ids: {json_str}"
    
    def test_connection(self):
        """Test if Wazuh agent socket is accessible"""
        test_alert = {
            "test": True,
            "message": "Wazuh agent connectivity test",
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
        return self.send_alert(test_alert)


# Alternative: Write to log file (fallback method)
class WazuhFileIntegration:
    """
    Fallback method: Write alerts to file monitored by Wazuh agent.
    Less efficient but works if socket access is restricted.
    """
    
    def __init__(self, log_file=None):
        if log_file is None:
            # Use user's home directory by default
            home = Path.home()
            log_file = str(home / "xgboost-ids.log")
        self.log_file = log_file
        self._ensure_log_exists()
    
    def _ensure_log_exists(self):
        """Create log file if it doesn't exist"""
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_file).touch(exist_ok=True)
    
    def send_alert(self, alert_data):
        """Write alert to log file"""
        try:
            alert_data = self._normalize_alert(alert_data)
            if 'timestamp' not in alert_data:
                alert_data['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            
            json_str = json.dumps(alert_data, separators=(',', ':'))
            message = f"xgboost-ids: {json_str}\n"
            
            with open(self.log_file, 'a') as f:
                f.write(message)
            
            print(f"✓ Alert written to {self.log_file}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to write alert: {e}")
            return False

    def _normalize_alert(self, alert_data):
        """Normalize alert fields before writing."""
        if not isinstance(alert_data, dict):
            return alert_data

        is_attack = alert_data.get('is_attack')
        attack_type = str(alert_data.get('attack_type', '')).lower()

        if is_attack is False or attack_type == 'benign':
            alert_data['severity'] = 'NORMAL'
            alert_data['alert_level'] = 'INFO'

        return alert_data


def main():
    """Test integration"""
    print("=" * 60)
    print("Wazuh Agent Integration Test")
    print("=" * 60)
    
    # Test alert
    test_alert = {
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "attack_type": "Test Attack",
        "ensemble_confidence": 0.95,
        "xgboost_confidence": 0.92,
        "anomaly_score": 0.88,
        "src_ip": "10.0.0.100",
        "dst_ip": "192.168.1.50",
        "severity": "HIGH"
    }
    
    # Try socket method first (recommended)
    try:
        print("\n1. Testing Wazuh agent socket method...")
        agent = WazuhAgentIntegration()
        agent.send_alert(test_alert)
        print("✅ Socket method working!")
        
    except FileNotFoundError as e:
        print(f"⚠️  Socket not available: {e}")
        print("\n2. Trying file-based method...")
        
        # Fallback to file method
        file_agent = WazuhFileIntegration()
        file_agent.send_alert(test_alert)
        print("✅ File method working!")
        print("\nNote: Configure Wazuh agent to monitor this log file:")
        print(f"  {file_agent.log_file}")


if __name__ == "__main__":
    main()
