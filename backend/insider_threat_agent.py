import json
import logging
from datetime import datetime
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
logger = logging.getLogger("InsiderThreatAgent")

class InsiderThreatAgent:
    """
    AI-powered Insider Threat Detection Agent.
    
    Future Integration:
    - OpenClaw will orchestrate detection workflows and escalation pipelines.
    - NemoClaw will enforce policy restrictions and sandbox suspicious sessions.
    """
    
    def __init__(self):
        self.risk_levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        logger.info("Insider Threat Agent initialized.")

    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyzes employee activity logs for suspicious patterns."""
        # user -> {threats: list, max_severity: str, remediations: list, last_ip: str, failed_logins: int, total_actions: int}
        user_profiles = {}
        
        for log in logs:
            user = log.get("username", "Unknown")
            action = log.get("action_type", "")
            resource = log.get("accessed_resource", "")
            status = log.get("login_status", "")
            ip_address = log.get("ip_address", "")
            timestamp_str = log.get("timestamp", "")
            download_count = log.get("file_download_count", 0)
            
            if user not in user_profiles:
                user_profiles[user] = {
                    "threats": set(),
                    "max_severity": "LOW",
                    "remediations": set(),
                    "last_ip": None,
                    "failed_logins": 0,
                    "total_actions": 0
                }
                
            profile = user_profiles[user]
            profile["total_actions"] += 1
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                hour = timestamp.hour
            except Exception:
                hour = 12 # Default to normal working hours if parsing fails

            def escalate_severity(severity):
                if self.risk_levels[severity] > self.risk_levels[profile["max_severity"]]:
                    profile["max_severity"] = severity

            # 1. Repeated Failed Logins
            if action == "login" and status == "failed":
                profile["failed_logins"] += 1
                if profile["failed_logins"] >= 3:
                    profile["threats"].add("Repeated failed logins")
                    escalate_severity("HIGH")
                    profile["remediations"].update(["Require MFA", "Temporarily lock account"])
            elif action == "login" and status == "success":
                profile["failed_logins"] = 0 # Reset on success
            
            # 2. Logins at Unusual Hours
            if action == "login" and status == "success" and (hour < 5 or hour >= 23):
                profile["threats"].add("Login at unusual hours")
                escalate_severity("MEDIUM")
                profile["remediations"].add("Require admin approval")

            # 3. Impossible Travel / Sudden IP Changes
            if action == "login" and status == "success":
                last_ip = profile["last_ip"]
                if last_ip and last_ip != ip_address:
                    profile["threats"].add("Impossible travel / Sudden IP change")
                    escalate_severity("HIGH")
                    profile["remediations"].add("Quarantine session")
                profile["last_ip"] = ip_address

            # 4. Mass Downloads
            if action == "download" and download_count > 50:
                profile["threats"].add(f"Mass download ({download_count} files)")
                escalate_severity("CRITICAL")
                profile["remediations"].update(["Notify SOC/security team", "Quarantine session"])
                
            # 5. Access to Sensitive Systems
            sensitive_resources = ["customer_db", "financial_records", "source_code_repo", "hr_payroll", "admin_panel"]
            if resource in sensitive_resources:
                profile["threats"].add(f"Access to sensitive system: {resource}")
                escalate_severity("MEDIUM")
                profile["remediations"].add("Require MFA")

            # 6. Privilege Escalation Attempts
            if action == "privilege_escalation_attempt":
                profile["threats"].add("Privilege escalation attempt")
                escalate_severity("CRITICAL")
                profile["remediations"].update(["Temporarily lock account", "Notify SOC/security team"])
                
            # 7. Unusual Access Frequency Spikes
            if profile["total_actions"] >= 10:
                profile["threats"].add("Unusual access frequency spike")
                escalate_severity("MEDIUM")
                profile["remediations"].add("Require admin approval")

        reports = []
        for user, profile in user_profiles.items():
            if profile["threats"]:
                reports.append({
                    "user": user,
                    "threat_type": ", ".join(profile["threats"]),
                    "explanation": f"Multiple anomalies detected for user {user} including high-risk actions.",
                    "severity": profile["max_severity"],
                    "recommended_action": ", ".join(profile["remediations"])
                })

        return reports

    def print_report(self, reports: List[Dict[str, Any]]):
        """Generates a readable security report."""
        if not reports:
            print("\n✅ [OK] No suspicious insider activity detected.")
            return
            
        print("\n" + "="*80)
        print("🚨 INSIDER THREAT SECURITY REPORT 🚨")
        print("="*80)
        
        for idx, report in enumerate(reports, 1):
            print(f"\n[Incident #{idx}]")
            print(f"👤 User:               {report['user']}")
            print(f"⚠️  Threat Type:        {report['threat_type']}")
            print(f"📊 Severity:           {report['severity']}")
            print(f"📝 Explanation:        {report['explanation']}")
            print(f"🛡️  Recommended Action: {report['recommended_action']}")
        print("\n" + "="*80)

def main():
    agent = InsiderThreatAgent()
    
    # Mock employee activity logs
    mock_logs = [
        # Normal activity - Should not be flagged unless it hits frequency spikes
        {
            "username": "alice.smith",
            "timestamp": "2026-05-16T09:15:00",
            "ip_address": "192.168.1.50",
            "accessed_resource": "marketing_assets",
            "action_type": "login",
            "login_status": "success",
            "file_download_count": 0
        },
        # Repeated failed logins
        {
            "username": "bob.jones",
            "timestamp": "2026-05-16T10:01:00",
            "ip_address": "192.168.1.102",
            "accessed_resource": "vpn",
            "action_type": "login",
            "login_status": "failed",
            "file_download_count": 0
        },
        {
            "username": "bob.jones",
            "timestamp": "2026-05-16T10:02:00",
            "ip_address": "192.168.1.102",
            "accessed_resource": "vpn",
            "action_type": "login",
            "login_status": "failed",
            "file_download_count": 0
        },
        {
            "username": "bob.jones",
            "timestamp": "2026-05-16T10:03:00",
            "ip_address": "192.168.1.102",
            "accessed_resource": "vpn",
            "action_type": "login",
            "login_status": "failed",
            "file_download_count": 0
        },
        # Login at unusual hours
        {
            "username": "charlie.brown",
            "timestamp": "2026-05-16T03:45:00",
            "ip_address": "10.0.0.15",
            "accessed_resource": "internal_wiki",
            "action_type": "login",
            "login_status": "success",
            "file_download_count": 0
        },
        # Mass downloads & sensitive access
        {
            "username": "diana.prince",
            "timestamp": "2026-05-16T14:20:00",
            "ip_address": "172.16.0.42",
            "accessed_resource": "customer_db",
            "action_type": "download",
            "login_status": "success",
            "file_download_count": 500
        },
        # Impossible travel
        {
            "username": "eve.adams",
            "timestamp": "2026-05-16T08:00:00",
            "ip_address": "203.0.113.5", # NY
            "accessed_resource": "email",
            "action_type": "login",
            "login_status": "success",
            "file_download_count": 0
        },
        {
            "username": "eve.adams",
            "timestamp": "2026-05-16T09:00:00",
            "ip_address": "198.51.100.22", # Tokyo
            "accessed_resource": "email",
            "action_type": "login",
            "login_status": "success",
            "file_download_count": 0
        },
        # Privilege escalation attempt
        {
            "username": "frank.castle",
            "timestamp": "2026-05-16T16:30:00",
            "ip_address": "10.1.2.3",
            "accessed_resource": "admin_panel",
            "action_type": "privilege_escalation_attempt",
            "login_status": "failed",
            "file_download_count": 0
        },
        # Access frequency spike (11 quick actions)
        *[
            {
                "username": "grace.hopper",
                "timestamp": f"2026-05-16T11:{10+i:02d}:00",
                "ip_address": "192.168.1.200",
                "accessed_resource": "public_repo",
                "action_type": "read",
                "login_status": "success",
                "file_download_count": 1
            } for i in range(11)
        ]
    ]

    logger.info("Starting log analysis...")
    reports = agent.analyze_logs(mock_logs)
    agent.print_report(reports)

if __name__ == "__main__":
    main()
