import os
import json
import re
import argparse
from typing import List, Dict, Any

# ==============================================================================
# Future NemoClaw / OpenClaw Integration Notes:
# ==============================================================================
# - OpenClaw will orchestrate this scanning process, generate the security
#   reports, and present an optional remediation workflow to the user.
# - NemoClaw will enforce policies based on these findings. It will actively
#   block unsafe actions (e.g., stopping an `npm install` if a malicious
#   `preinstall` script is detected), require approval for outbound network
#   calls, and keep the execution agent strictly sandboxed.
# ==============================================================================

class Finding:
    """Represents a single security vulnerability finding."""
    def __init__(self, finding_type: str, severity: str, file_path: str, line_number: int, explanation: str, remediation: str):
        self.finding_type = finding_type
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.explanation = explanation
        self.remediation = remediation

class SupplyChainGuard:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.findings: List[Finding] = []
        
        # Lists for risky pattern detection
        self.suspicious_scripts = ['preinstall', 'postinstall', 'install', 'prepare']
        self.popular_packages = ['requests', 'flask', 'django', 'numpy', 'pandas', 'express', 'react', 'lodash']
        
        # Regex patterns for network and command executions
        self.network_cmd_patterns = {
            'requests.get': r'requests\.get\(',
            'requests.post': r'requests\.post\(',
            'urllib': r'urllib\.',
            'fetch(': r'fetch\(',
            'axios': r'axios\.',
            'subprocess': r'subprocess\.',
            'os.system': r'os\.system\(',
            'curl': r'curl ',
            'wget': r'wget ',
            'eval': r'eval\(',
            'exec': r'exec\('
        }
        self.compiled_patterns = {k: re.compile(v) for k, v in self.network_cmd_patterns.items()}

    def is_typosquatting(self, package_name: str) -> bool:
        """
        Simple check to see if a package name is suspiciously similar
        to a popular package (1 character difference).
        """
        package_name = package_name.lower()
        if package_name in self.popular_packages:
            return False
            
        for pop in self.popular_packages:
            # Check for length match and exactly 1 character difference
            if len(package_name) == len(pop):
                diffs = sum(1 for a, b in zip(package_name, pop) if a != b)
                if diffs == 1:
                    return True
        return False

    def scan(self):
        """Walk through the directory and scan relevant files."""
        for root, dirs, files in os.walk(self.target_dir):
            # Skip virtual environments and package directories
            if any(skip in root for skip in ['node_modules', '.venv', '__pycache__', '.git', 'venv']):
                continue

            for file in files:
                file_path = os.path.join(root, file)
                
                # Dependency files
                if file == 'package.json':
                    self.scan_package_json(file_path)
                elif file == 'package-lock.json':
                    self.scan_package_lock_json(file_path)
                elif file == 'requirements.txt':
                    self.scan_requirements_txt(file_path)
                elif file == 'pyproject.toml':
                    self.scan_pyproject_toml(file_path)
                
                # Source code files
                if file.endswith(('.py', '.js', '.ts', '.sh', '.bash', '.jsx', '.tsx')):
                    self.scan_source_file(file_path)

    def scan_package_json(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return

        # Check for suspicious scripts
        scripts = data.get('scripts', {})
        for script_name, script_cmd in scripts.items():
            if script_name in self.suspicious_scripts:
                self.findings.append(Finding(
                    "Suspicious Install Script", "HIGH", file_path, -1,
                    f"Found '{script_name}' script which runs automatically during installation.",
                    "remove suspicious install scripts"
                ))
            
            # Check for network downloads inside scripts
            if 'curl ' in script_cmd or 'wget ' in script_cmd:
                self.findings.append(Finding(
                    "Network Call in Script", "CRITICAL", file_path, -1,
                    f"Script '{script_name}' contains unauthorized network downloads (curl/wget).",
                    "review outbound network calls and remove unauthorized downloads"
                ))

        # Check dependencies for risky versions and URLs
        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        for dep, version in deps.items():
            self._check_dependency(dep, version, file_path)

    def scan_package_lock_json(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return
        
        # Basic check for suspicious registry URLs in lockfile
        deps = data.get('dependencies', {})
        for dep, info in deps.items():
            resolved = info.get('resolved', '')
            if resolved and not resolved.startswith('https://registry.npmjs.org'):
                self.findings.append(Finding(
                    "Suspicious Package Source", "MEDIUM", file_path, -1,
                    f"Dependency '{dep}' is resolved from a non-standard registry: {resolved}",
                    "rollback package-lock.json"
                ))

    def scan_requirements_txt(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            return

        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith(('http://', 'https://', 'git+', 'github.com')):
                self.findings.append(Finding(
                    "Remote Dependency Source", "HIGH", file_path, i + 1,
                    f"Dependency is installed directly from a URL: {line}",
                    "pin dependency versions"
                ))
            elif '==' not in line and '>=' not in line and '<=' not in line:
                self.findings.append(Finding(
                    "Loose Dependency Version", "LOW", file_path, i + 1,
                    f"Dependency '{line}' does not have a pinned version.",
                    "pin dependency versions"
                ))
            else:
                # Extract package name and check for typosquatting
                dep_name = re.split(r'[=><]+', line)[0].strip()
                if self.is_typosquatting(dep_name):
                    self.findings.append(Finding(
                        "Potential Typosquatting", "HIGH", file_path, i + 1,
                        f"Package '{dep_name}' looks suspiciously similar to a popular package.",
                        "quarantine suspicious dependency"
                    ))

    def scan_pyproject_toml(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            return
            
        for i, line in enumerate(lines):
            line = line.strip()
            if '="*"' in line.replace(' ', ''):
                self.findings.append(Finding(
                    "Wildcard Dependency Version", "MEDIUM", file_path, i + 1,
                    "Found '*' used as a dependency version specifier.",
                    "pin dependency versions"
                ))

    def _check_dependency(self, dep: str, version: str, file_path: str):
        """Helper method to check individual dependencies for Node/Python."""
        if version == '*' or version == 'latest':
            self.findings.append(Finding(
                "Loose Dependency Version", "MEDIUM", file_path, -1,
                f"Dependency '{dep}' uses a loose version specifier '{version}'.",
                "pin dependency versions"
            ))
        
        if any(url in version for url in ['http://', 'https://', 'git+', 'github']):
            self.findings.append(Finding(
                "Remote Dependency Source", "HIGH", file_path, -1,
                f"Dependency '{dep}' is installed from a raw URL or Git repository.",
                "pin dependency versions"
            ))

        if self.is_typosquatting(dep):
            self.findings.append(Finding(
                "Potential Typosquatting", "HIGH", file_path, -1,
                f"Package '{dep}' looks suspiciously similar to a popular package.",
                "quarantine suspicious dependency"
            ))

    def scan_source_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            return

        for i, line in enumerate(lines):
            for name, pattern in self.compiled_patterns.items():
                if pattern.search(line):
                    severity = "MEDIUM"
                    if name in ['eval', 'exec', 'os.system', 'subprocess']:
                        severity = "HIGH"
                    
                    self.findings.append(Finding(
                        "Suspicious Source Code Pattern", severity, file_path, i + 1,
                        f"Found potentially dangerous function call or network request: '{name}'",
                        "review outbound network calls and require human approval before changes"
                    ))

    def report(self):
        """Print a clear and beginner-readable security report."""
        print("=" * 60)
        print(" 🛡️  Supply Chain Guard Security Report")
        print("=" * 60)
        print()
        
        if not self.findings:
            print("✅ No supply chain vulnerabilities or suspicious patterns found.")
            print("   Your project dependencies and source files look clean!")
            print()
            return

        print(f"⚠️  Found {len(self.findings)} potential issues:\n")

        for f in self.findings:
            print(f"[{f.severity}] {f.finding_type}")
            line_info = f" (Line {f.line_number})" if f.line_number != -1 else ""
            print(f"  📍 File:        {f.file_path}{line_info}")
            print(f"  🔍 Explanation: {f.explanation}")
            print(f"  💡 Remediation: {f.remediation}")
            print("-" * 60)
        
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan project for supply chain vulnerabilities.")
    parser.add_argument("target_dir", help="Directory to scan (e.g., '.')")
    args = parser.parse_args()

    guard = SupplyChainGuard(args.target_dir)
    guard.scan()
    guard.report()
