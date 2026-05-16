import os
import time
import argparse
from supply_chain_guard import SupplyChainGuard

class MorpheusAgent:
    """
    The Morpheus Security Agent.
    
    This agent acts as an autonomous entity in the NemoClaw/OpenClaw ecosystem.
    It utilizes the SupplyChainGuard tool to continuously or on-demand monitor 
    the project for supply chain vulnerabilities, typosquatting, and malicious 
    network behavior.
    """
    def __init__(self, name="MorpheusAgent", target_dir="."):
        self.name = name
        self.target_dir = target_dir
        self.guard = SupplyChainGuard(self.target_dir)

    def run_scan(self):
        """Executes a single security scan using the guard tool."""
        print(f"🤖 [{self.name}] Initiating deep security scan on directory: '{os.path.abspath(self.target_dir)}'...")
        self.guard.findings = []  # Clear previous findings
        self.guard.scan()
        print(f"🤖 [{self.name}] Scan complete. Detected {len(self.guard.findings)} potential issues.")
        return self.guard.findings

    def generate_report(self):
        """Outputs the detailed security report."""
        self.guard.report()

    def start_autonomous_monitoring(self, interval_seconds=3600):
        """Runs the agent in a continuous monitoring loop."""
        print(f"🤖 [{self.name}] Starting autonomous monitoring mode...")
        print(f"🤖 [{self.name}] Scan interval set to {interval_seconds} seconds.")
        try:
            while True:
                findings = self.run_scan()
                if findings:
                    print(f"🤖 [{self.name}] ⚠️ CRITICAL: Vulnerabilities detected! Triggering alerts...")
                    self.generate_report()
                    # In the future: OpenClaw integration would trigger a workflow here
                    # e.g., send_telegram_alert(findings) or quarantine_packages()
                else:
                    print(f"🤖 [{self.name}] ✅ System is secure. Sleeping until next cycle...")
                
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print(f"\n🤖 [{self.name}] Autonomous monitoring stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Morpheus Security Agent")
    parser.add_argument("--dir", default=".", help="Target directory to monitor")
    parser.add_argument("--monitor", action="store_true", help="Run in continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=3600, help="Interval between scans in seconds (if monitoring)")
    args = parser.parse_args()

    agent = MorpheusAgent(target_dir=args.dir)
    
    if args.monitor:
        agent.start_autonomous_monitoring(interval_seconds=args.interval)
    else:
        agent.run_scan()
        agent.generate_report()
