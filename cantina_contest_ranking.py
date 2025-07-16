#!/usr/bin/env python3
"""
Cantina Contest Ranking Calculator
Generates automatic result/payout predictions for Cantina web3 audit competitions.

Examples
--------
python3 cantina_contest_ranking.py
python3 cantina_contest_ranking.py -p 150000 -i 677 10 203 -e
python3 cantina_contest_ranking.py --pot 200000 --no-early-bird
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

import requests
from tabulate import tabulate


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class Config:
    """Configuration settings for the Cantina ranking calculator."""

    # Repository and API settings
    # Change REPO_ID to the repo that you want to calculate the earnings
    REPO_ID = "5617fffa-4b67-42a7-a9f5-dad93627faa3"

    # Provide your cantina auth token of the account that has access to the competition findings.
    COOKIE = 'auth_token='

    # Change the Pot to the pot of the competition that is expected to be unlocked.

    DEFAULT_PRIZE_POT = 146_500
    DEFAULT_IGNORE_FINDING_NUMBERS: List[int] = []
    DEFAULT_ENABLE_EARLY_BIRD_BONUS = False
    EARLY_BIRD_BONUS_MULTIPLIER = 1.30  # 30 % bonus

    # API configuration
    API_URL_TEMPLATE = (
        "https://cantina.xyz/api/v0/repositories/{repo_id}/findings"
    )
    API_PARAMS = {
        "limit": 200,
        "with_events": "false",
        "with_files": "true",
        "duplicates": "true",
        "status": "confirmed,duplicate",
        "severity": "critical,high,medium",
    }

    # Use ONLY when severity‐override is supplied on the CLI
    API_PARAMS_OVERRIDE = {
        "limit": 200,
        "with_events": "false",
        "with_files": "true",
        "duplicates": "true",
        "status": "new,spam,duplicate,disputed,rejected,confirmed,acknowledged,fixed,withdrawn",
    }

    # Point system
    BASE_POINTS = {"critical":30, "high": 10, "medium": 3}

    # Request headers
    HEADERS = {
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/137.0.0.0 Safari/537.36"
        ),
    }


# --------------------------------------------------------------------------- #
# API Client
# --------------------------------------------------------------------------- #
class CantinaAPIClient:
    def __init__(
        self,
        repo_id: str,
        cookie: str,
        params: Optional[Dict[str, str]] = None,
    ) -> None:
        self.repo_id = repo_id
        self.headers = Config.HEADERS.copy()
        self.headers["Cookie"] = cookie
        # decide which params to use (fall back to normal)
        self.params = params or Config.API_PARAMS
        self.api_url = Config.API_URL_TEMPLATE.format(repo_id=repo_id)


    def fetch_findings(self) -> Optional[Dict[str, Any]]:
        """Fetch all findings with pagination support."""
        print(f"Fetching findings from {self.api_url} ...")

        findings: List[Dict[str, Any]] = []
        current_params = self.params.copy()

        while True:
            try:
                resp = requests.get(
                self.api_url,
                params=current_params,              # <- leave this line as-is
                headers=self.headers,
                timeout=60,
                )

                resp.raise_for_status()

                body = resp.json()
                page = body.get("findings", [])
                findings.extend(page)

                next_val = body.get("nextValue")
                if next_val:
                    current_params["next"] = next_val
                else:
                    break

            except (requests.RequestException, json.JSONDecodeError) as exc:
                print(f"[!] Error while contacting Cantina API: {exc}")
                return None

        print(f"✓ Retrieved {len(findings)} total finding objects.")
        return {"findings": findings}


class PayoutCalculator:
    """Calculates payouts based on findings data."""
    
    def __init__(self, prize_pot: float, ignore_numbers: List[int], early_bird_enabled: bool,
                 severity_overrides: Dict[int, str] = None, manual_dupes: Dict[int, List[int]] = None):
        self.prize_pot = prize_pot
        self.ignore_numbers = set(ignore_numbers)
        self.early_bird_enabled = early_bird_enabled
        self.severity_overrides = severity_overrides or {}
        self.manual_dupes = manual_dupes or {}
        
        # Data structures for processing
        self.confirmed_originals: Dict[str, Dict] = {}
        self.all_valid_submissions: Dict[str, List[Tuple]] = defaultdict(list)
        self.user_details: Dict[str, str] = {}
        self.user_findings: Dict[str, List[Dict]] = defaultdict(list)
        
        # Results
        self.user_points_no_bonus: Dict[str, float] = defaultdict(float)
        self.user_points_actual: Dict[str, float] = defaultdict(float)
        self.vulnerability_reports: Dict[str, List[Dict]] = defaultdict(list)
        
        # Tracking for manual overrides
        self.applied_severity_overrides: Dict[int, str] = {}
        self.applied_manual_dupes: Dict[int, List[int]] = {}
        self.findings_by_number: Dict[int, Dict] = {}  # Cache for quick lookup
    
    def process_findings(self, findings_data: List[Dict]) -> None:
        """Process findings data and calculate payouts."""
        print(f"\nProcessing {len(findings_data)} raw findings entries...")
        print(f"Early Bird Bonus: {'ENABLED' if self.early_bird_enabled else 'DISABLED'}")
        
        if self.ignore_numbers:
            print(f"Ignoring findings with numbers: {sorted(list(self.ignore_numbers))}")
        
        if self.severity_overrides:
            print(f"Severity overrides: {dict(self.severity_overrides)}")
            
        if self.manual_dupes:
            print(f"Manual duplicate groupings: {dict(self.manual_dupes)}")
        
        # Step 0: Build findings lookup and apply manual overrides
        self._build_findings_lookup(findings_data)
        self._apply_manual_overrides(findings_data)
        
        # Step 1: Identify confirmed originals
        self._identify_confirmed_originals(findings_data)
        
        if not self.confirmed_originals:
            print("No confirmed H/M findings found. Cannot process payouts.")
            return
        
        print(f"Found {len(self.confirmed_originals)} confirmed H/M findings.")
        
        # Step 2: Group valid submissions
        self._group_valid_submissions(findings_data)
        
        # Step 3: Calculate points
        self._calculate_points()
        
        # Step 4: Generate reports
        self._generate_reports()
    
    def _identify_confirmed_originals(self, findings_data: List[Dict]) -> None:
        """Identify confirmed original findings that aren't ignored."""
        ignored_uuids = set()
        
        for finding in findings_data:
            if not isinstance(finding, dict):
                continue
                
            finding_uuid = finding.get('id')
            finding_number = finding.get('number')
            
            if not finding_uuid:
                continue
            
            if (finding.get('status') == 'confirmed' and 
                finding_number is not None and finding_number in self.ignore_numbers):
                ignored_uuids.add(finding_uuid)
                continue
            
            if (finding.get('status') == 'confirmed' and 
                finding.get('severity') in Config.BASE_POINTS):
                self.confirmed_originals[finding_uuid] = finding
    
    def _group_valid_submissions(self, findings_data: List[Dict]) -> None:
        """Group all valid submissions by original vulnerability."""
        processed_ids = set()
        
        for finding in findings_data:
            if not isinstance(finding, dict):
                continue
                
            submission_uuid = finding.get('id')
            if not submission_uuid or submission_uuid in processed_ids:
                continue
            processed_ids.add(submission_uuid)
            
            # Extract user information
            created_by = finding.get('createdBy', {})
            if not isinstance(created_by, dict):
                continue
                
            user_id = created_by.get('userId')
            user_name = created_by.get('username', 'N/A')
            
            if not user_id:
                continue
                
            if user_id not in self.user_details:
                self.user_details[user_id] = user_name
            
            # Determine original vulnerability
            original_uuid, severity = self._get_original_reference(finding)
            
            if original_uuid and severity:
                submission_data = (
                    user_id, user_name, severity, submission_uuid, 
                    finding.get('number')
                )
                self.all_valid_submissions[original_uuid].append(submission_data)
                
                # Track user findings
                self.user_findings[user_id].append({
                    'original_uuid': original_uuid,
                    'original_number': self.confirmed_originals[original_uuid].get('number', 'N/A'),
                    'submission_title': finding.get('title', 'N/A'),
                    'submission_number': finding.get('number'),
                    'severity': severity
                })
    
    def _get_original_reference(self, finding: Dict) -> Tuple[Optional[str], Optional[str]]:
        """Get the original vulnerability reference and severity."""
        status = finding.get('status')
        
        if status == 'confirmed':
            uuid = finding.get('id')
            if uuid in self.confirmed_originals:
                return uuid, self.confirmed_originals[uuid].get('severity')
        
        elif status == 'duplicate':
            duplicate_of = finding.get('duplicateOf', {})
            if isinstance(duplicate_of, dict):
                original_uuid = duplicate_of.get('id')
                if original_uuid in self.confirmed_originals:
                    return original_uuid, self.confirmed_originals[original_uuid].get('severity')
        
        return None, None
    
    def _calculate_points(self) -> None:
        """Calculate points for each user."""
        print(f"\nCalculating points for {len(self.all_valid_submissions)} vulnerabilities...")
        
        for original_uuid, submissions in self.all_valid_submissions.items():
            if not submissions:
                continue
                
            severity = submissions[0][2]
            base_points = Config.BASE_POINTS.get(severity, 0)
            
            if not base_points:
                continue
            
            unique_users = set(s[0] for s in submissions)
            n_finders = len(unique_users)
            
            # Calculate total points for this vulnerability
            total_points = base_points * math.pow(0.9, n_finders - 1) if n_finders > 1 else base_points
            standard_share = total_points / n_finders if n_finders > 0 else 0
            
            # Add standard share to no-bonus calculation
            for user_id in unique_users:
                self.user_points_no_bonus[user_id] += standard_share
            
            # Calculate actual points (with early bird if applicable)
            if n_finders == 1:
                self.user_points_actual[list(unique_users)[0]] += total_points
            elif self.early_bird_enabled and n_finders > 1:
                early_bird_user = self._find_early_bird_user(submissions, unique_users)
                if early_bird_user:
                    self._distribute_early_bird_points(unique_users, early_bird_user, total_points, n_finders)
                else:
                    # Fallback to standard distribution
                    for user_id in unique_users:
                        self.user_points_actual[user_id] += standard_share
            else:
                # Standard distribution
                for user_id in unique_users:
                    self.user_points_actual[user_id] += standard_share
            
            # Record vulnerability details
            self._record_vulnerability_details(original_uuid, submissions, base_points, total_points, n_finders)
    
    def _find_early_bird_user(self, submissions: List[Tuple], unique_users: set) -> Optional[str]:
        """Find the user who submitted first (lowest submission number)."""
        user_min_numbers = {}
        
        for user_id in unique_users:
            user_submissions = [s for s in submissions if s[0] == user_id and s[4] is not None]
            if user_submissions:
                user_min_numbers[user_id] = min(s[4] for s in user_submissions)
        
        if user_min_numbers:
            return min(user_min_numbers, key=user_min_numbers.get)
        return None
    
    def _distribute_early_bird_points(self, unique_users: set, early_bird_user: str, total_points: float, n_finders: int) -> None:
        """Distribute points with early bird bonus."""
        # Calculate shares: early_bird_bonus * x + (n-1) * x = total_points
        # where x is the standard share for non-early-bird users
        other_share = total_points / (Config.EARLY_BIRD_BONUS_MULTIPLIER + (n_finders - 1))
        early_bird_share = Config.EARLY_BIRD_BONUS_MULTIPLIER * other_share
        
        for user_id in unique_users:
            if user_id == early_bird_user:
                self.user_points_actual[user_id] += early_bird_share
            else:
                self.user_points_actual[user_id] += other_share
    
    def _record_vulnerability_details(self, original_uuid: str, submissions: List[Tuple], 
                                    base_points: float, total_points: float, n_finders: int) -> None:
        """Record details about vulnerability for reporting."""
        original_details = self.confirmed_originals.get(original_uuid, {})
        
        report_entry = {
            'title': original_details.get('title', 'N/A'),
            'number': original_details.get('number', 'N/A'),
            'severity': submissions[0][2],
            'submitters_count': n_finders,
            'base_points': base_points,
            'total_points_for_vuln': total_points,
            'early_bird_info': "N/A (Bonus Disabled)"
        }
        
        if self.early_bird_enabled and n_finders > 1:
            early_bird_user = self._find_early_bird_user(submissions, set(s[0] for s in submissions))
            if early_bird_user:
                username = self.user_details.get(early_bird_user, early_bird_user)
                early_bird_submission = min(s[4] for s in submissions if s[0] == early_bird_user and s[4] is not None)
                report_entry['early_bird_info'] = f"Yes, to {username} (Submission #{early_bird_submission})"
            else:
                report_entry['early_bird_info'] = "Not applied (missing submission numbers)"
        
        self.vulnerability_reports[original_uuid].append(report_entry)
    
    def _build_findings_lookup(self, findings_data: List[Dict]) -> None:
        """Build a lookup dictionary for findings by their number."""
        for finding in findings_data:
            if isinstance(finding, dict) and finding.get('number') is not None:
                self.findings_by_number[finding['number']] = finding
    
    def _apply_manual_overrides(self, findings_data: List[Dict]) -> None:
        """Apply manual severity overrides and duplicate groupings."""
        # Apply severity overrides
        for finding_number, new_severity in self.severity_overrides.items():
            if finding_number in self.findings_by_number:
                finding = self.findings_by_number[finding_number]
                old_severity = finding.get('severity', 'unknown')
                
                # Override severity for the finding itself
                finding['severity'] = new_severity
                finding['status'] = 'confirmed'
                finding['_severity_overridden'] = True
                finding['_original_severity'] = old_severity
                
                self.applied_severity_overrides[finding_number] = new_severity
                
                # Also override severity for all its duplicates
                finding_uuid = finding.get('id')
                if finding_uuid:
                    for other_finding in findings_data:
                        if (isinstance(other_finding, dict) and 
                            other_finding.get('status') == 'duplicate'):
                            duplicate_of = other_finding.get('duplicateOf', {})
                            if (isinstance(duplicate_of, dict) and 
                                duplicate_of.get('id') == finding_uuid):
                                other_finding['severity'] = new_severity
                                other_finding['_severity_overridden'] = True
                                other_finding['_original_severity'] = other_finding.get('severity', 'unknown')
                
                print(f"Applied severity override: Finding #{finding_number} changed from {old_severity} to {new_severity}")
            else:
                print(f"Warning: Could not find finding #{finding_number} for severity override")
        
        # Apply manual duplicate groupings
        for original_number, dup_numbers in self.manual_dupes.items():
            if original_number not in self.findings_by_number:
                print(f"Warning: Original finding #{original_number} not found for manual duplication")
                continue
            
            original_finding = self.findings_by_number[original_number]
            original_uuid = original_finding.get('id')
            
            if not original_uuid:
                print(f"Warning: Original finding #{original_number} has no UUID")
                continue
            
            # Force the original to be confirmed if it isn't already
            if original_finding.get('status') != 'confirmed':
                original_finding['status'] = 'confirmed'
                original_finding['_status_overridden'] = True
                print(f"Forced finding #{original_number} to be confirmed for manual duplication")
            
            applied_dupes = []
            for dup_number in dup_numbers:
                if dup_number not in self.findings_by_number:
                    print(f"Warning: Duplicate finding #{dup_number} not found for manual duplication")
                    continue
                
                dup_finding = self.findings_by_number[dup_number]
                
                # Override the duplicate finding's status and reference
                dup_finding['status'] = 'duplicate'
                dup_finding['duplicateOf'] = {'id': original_uuid}
                dup_finding['_manually_duped'] = True
                
                # Also copy severity from original to duplicate
                if 'severity' in original_finding:
                    dup_finding['severity'] = original_finding['severity']
                
                applied_dupes.append(dup_number)
                print(f"Manually set finding #{dup_number} as duplicate of #{original_number}")
            
            if applied_dupes:
                self.applied_manual_dupes[original_number] = applied_dupes
    
    def _generate_reports(self) -> None:
        """Generate and print all reports."""
        self._print_manual_overrides_summary()
        self._print_vulnerability_summary()
        self._print_payout_table()
        self._print_top_participants()
    
    def _print_manual_overrides_summary(self) -> None:
        """Print summary of applied manual overrides."""
        if not self.applied_severity_overrides and not self.applied_manual_dupes:
            return
        
        print("\n" + "="*60)
        print("MANUAL OVERRIDES APPLIED")
        print("="*60)
        
        if self.applied_severity_overrides:
            print("\nSeverity Overrides:")
            for finding_num, new_severity in self.applied_severity_overrides.items():
                original_severity = "unknown"
                if finding_num in self.findings_by_number:
                    original_severity = self.findings_by_number[finding_num].get('_original_severity', 'unknown')
                print(f"  Finding #{finding_num}: {original_severity} → {new_severity}")
        
        if self.applied_manual_dupes:
            print("\nManual Duplicate Groupings:")
            for original_num, dup_nums in self.applied_manual_dupes.items():
                print(f"  Original #{original_num} ← Duplicates: {', '.join(f'#{num}' for num in dup_nums)}")
    
    def _print_vulnerability_summary(self) -> None:
        """Print summary of vulnerabilities and point calculations."""
        print("\n" + "="*60)
        print("VULNERABILITY SUMMARY")
        print("="*60)
        
        if not self.vulnerability_reports:
            print("No vulnerabilities qualified for point calculation.")
            return
        
        # Sort by vulnerability number
        sorted_vuln_uuids = sorted(
            self.vulnerability_reports.keys(),
            key=lambda uuid: (
                self.vulnerability_reports[uuid][0].get('number', float('inf')),
                self.vulnerability_reports[uuid][0]['title']
            )
        )
        
        for uuid in sorted_vuln_uuids:
            details = self.vulnerability_reports[uuid][0]
            print(f"\nVulnerability #{details['number']}: {details['title']}")
            print(f"  Severity: {details['severity'].upper()} | Base Points: {details['base_points']}")
            print(f"  Unique Finders: {details['submitters_count']} | Total Points: {details['total_points_for_vuln']:.4f}")
            
            if self.early_bird_enabled:
                print(f"  Early Bird: {details['early_bird_info']}")
    
    def _print_payout_table(self) -> None:
        """Print the main payout table."""
        print("\n" + "="*60)
        print("PAYOUT CALCULATIONS")
        print("="*60)
        
        total_points = sum(self.user_points_actual.values())
        
        if total_points <= 0:
            print("No points awarded. Cannot calculate payouts.")
            return
        
        payout_per_point = self.prize_pot / total_points
        
        print(f"Total Prize Pot: ${self.prize_pot:,.2f}")
        print(f"Total Points Awarded: {total_points:.4f}")
        print(f"Payout per Point: ${payout_per_point:.4f}")
        
        # Prepare table data
        table_data = []
        
        for user_id, username in self.user_details.items():
            points_nb = self.user_points_no_bonus.get(user_id, 0.0)
            points_actual = self.user_points_actual.get(user_id, 0.0)
            
            if points_actual > 1e-9:  # Only include users with points
                payout_nb = points_nb * payout_per_point
                payout_actual = points_actual * payout_per_point
                
                table_data.append([
                    username,
                    f"{points_nb:.4f}",
                    f"${payout_nb:,.2f}",
                    f"{points_actual:.4f}",
                    f"${payout_actual:,.2f}"
                ])
        
        # Sort by actual payout (descending)
        table_data.sort(key=lambda x: float(x[4].replace('$', '').replace(',', '')), reverse=True)
        
        # Add rank and percentile
        final_table = []
        for i, row in enumerate(table_data, 1):
            payout_value = float(row[4].replace('$', '').replace(',', ''))
            percentile = (i / len(table_data)) * 100 if len(table_data) > 0 else 0
            
            final_table.append([
                i,  # Rank
                row[0],  # Username
                row[1],  # Points (No Bonus)
                row[2],  # Payout (No Bonus)
                row[3],  # Points (Actual)
                row[4],  # Payout (Actual)
                f"{percentile:.1f}%"  # Percentile
            ])
        
        # Add totals row
        total_points_nb = sum(self.user_points_no_bonus.values())
        total_payout_nb = total_points_nb * payout_per_point
        total_payout_actual = sum(self.user_points_actual.values()) * payout_per_point
        
        final_table.extend([
            ['---'] * 7,
            ['', 'TOTALS', 
             f"{total_points_nb:.4f}", f"${total_payout_nb:,.2f}",
             f"{total_points:.4f}", f"${total_payout_actual:,.2f}",
             '']
        ])
        
        headers = ["Rank", "Username", "Points (No Bonus)", "Payout (No Bonus)", 
                  "Points (Actual)", "Payout (Actual)", "Top %"]
        
        print(f"\n{tabulate(final_table, headers=headers, tablefmt='grid')}")
    
    def _print_top_participants(self) -> None:
        """Print detailed findings for top 7 participants."""
        print("\n" + "="*60)
        print("TOP 7 PARTICIPANTS - DETAILED FINDINGS")
        print("="*60)
        
        # Get top 7 users by actual points
        top_users = sorted(
            [(user_id, points) for user_id, points in self.user_points_actual.items() if points > 1e-9],
            key=lambda x: x[1],
            reverse=True
        )[:7]
        
        if not top_users:
            print("No participants with payouts to display.")
            return
        
        for rank, (user_id, points) in enumerate(top_users, 1):
            username = self.user_details.get(user_id, f"ID:{user_id}")
            print(f"\n{rank}. {username}")
            print(f"   Total Points: {points:.4f}")
            print("   Findings:")
            
            if user_id in self.user_findings:
                # Sort findings by original number, then submission number
                findings = sorted(
                    self.user_findings[user_id],
                    key=lambda x: (
                        x['original_number'] if isinstance(x['original_number'], int) else float('inf'),
                        x['submission_number'] if isinstance(x['submission_number'], int) else float('inf')
                    )
                )
                
                seen_originals = set()
                for i, finding in enumerate(findings, 1):
                    original_num = finding['original_number']
                    title = finding['submission_title']
                    severity = finding['severity'].upper()
                    
                    dup_tag = " (Self Dup)" if original_num in seen_originals else ""
                    seen_originals.add(original_num)
                    
                    print(f"     {i}. #{original_num} - {title} ({severity}){dup_tag}")
            else:
                print("     No findings data available")


# --------------------------------------------------------------------------- #
# Helper-parsers for CLI overrides
# --------------------------------------------------------------------------- #
def parse_severity_overrides(
    overrides_list: Optional[List[str]],
) -> Dict[int, str]:
    """Convert `['123:high', '456:medium']` → {123: 'high', 456: 'medium'}."""
    if not overrides_list:
        return {}

    valid_sev = {"critical", "high", "medium", "low", "info"}
    result: Dict[int, str] = {}

    for item in overrides_list:
        if ":" not in item:
            print(f"Warning – bad format for severity override: '{item}'")
            continue
        num_str, sev = item.split(":", 1)
        try:
            num = int(num_str)
        except ValueError:
            print(f"Warning – '{num_str}' is not a number.")
            continue

        sev = sev.strip().lower()
        if sev not in valid_sev:
            print(f"Warning – invalid severity '{sev}'.")
            continue

        result[num] = sev

    return result


def parse_manual_dupes(
    dupes_list: Optional[List[str]],
) -> Dict[int, List[int]]:
    """
    Convert `['100:101,102', '200:201']`
    → {100: [101, 102], 200: [201]}
    """
    if not dupes_list:
        return {}

    dupes: Dict[int, List[int]] = {}

    for item in dupes_list:
        if ":" not in item:
            print(f"Warning – bad manual-dupe format: '{item}'")
            continue

        orig_str, dup_strs = item.split(":", 1)
        try:
            original = int(orig_str)
        except ValueError:
            print(f"Warning – '{orig_str}' is not a valid number.")
            continue

        dup_numbers: List[int] = []
        for part in dup_strs.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                dup_numbers.append(int(part))
            except ValueError:
                print(f"Warning – '{part}' is not a valid number.")

        if dup_numbers:
            dupes[original] = dup_numbers

    return dupes


# --------------------------------------------------------------------------- #
# Configuration sanity-check
# --------------------------------------------------------------------------- #
def validate_configuration() -> bool:
    """Ensure REPO_ID and COOKIE are set before running."""
    errors: List[str] = []

    if not Config.REPO_ID or "YOUR_REPOSITORY_ID_HERE" in Config.REPO_ID:
        errors.append("Config.REPO_ID is not set.")

    if not Config.COOKIE or Config.COOKIE.strip() == "auth_token=":
        errors.append("Config.COOKIE is missing your personal auth token.")

    if errors:
        print("Configuration errors:")
        for err in errors:
            print(f"  - {err}")
        return False

    return True


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #
def create_argument_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate payout predictions for Cantina web3 audit competitions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument(
        "-p",
        "--pot",
        type=float,
        metavar="AMOUNT",
        help=f"Override total prize pot (default {Config.DEFAULT_PRIZE_POT})",
    )
    p.add_argument(
        "-i",
        "--ignore-numbers",
        type=int,
        nargs="*",
        metavar="NUM",
        help="Finding numbers to ignore",
    )
    p.add_argument(
        "-s",
        "--severity-override",
        action="append",
        metavar="ID:SEVERITY",
        help="Manually override severity, e.g. 123:high (can repeat)",
    )
    p.add_argument(
        "-d",
        "--manual-dupe",
        action="append",
        metavar="ORIG:DUP1,DUP2,…",
        help="Force findings to be dupes, e.g. 100:101,102 (can repeat)",
    )

    eb = p.add_mutually_exclusive_group()
    eb.add_argument("-e", "--early-bird", action="store_true", help="Enable bonus")
    eb.add_argument(
        "-ne", "--no-early-bird", action="store_true", help="Disable bonus"
    )

    return p


# --------------------------------------------------------------------------- #
# Main entry-point
# --------------------------------------------------------------------------- #
def main() -> None:
    args = create_argument_parser().parse_args()

    if not validate_configuration():
        sys.exit(1)

    prize_pot = args.pot or Config.DEFAULT_PRIZE_POT
    ignore_nums = args.ignore_numbers or Config.DEFAULT_IGNORE_FINDING_NUMBERS
    early_bird = (
        True
        if args.early_bird
        else False
        if args.no_early_bird
        else Config.DEFAULT_ENABLE_EARLY_BIRD_BONUS
    )

    severity_overrides = parse_severity_overrides(args.severity_override)
    manual_dupes = parse_manual_dupes(args.manual_dupe)

    # Summary banner
    print("\nCantina Contest Ranking Calculator")
    print("=" * 50)
    print(f"Repository ID : {Config.REPO_ID}")
    print(f"Prize Pot     : ${prize_pot:,.2f}")
    print(f"Ignored #s    : {ignore_nums or 'None'}")
    print(f"Early-Bird    : {'ENABLED' if early_bird else 'DISABLED'}")
    if severity_overrides:
        print(f"Severity OVR  : {severity_overrides}")
    if manual_dupes:
        print(f"Manual Dupes  : {manual_dupes}")
    print("=" * 50)

    # pick API params based on presence of severity overrides
    api_params = (
        Config.API_PARAMS_OVERRIDE if severity_overrides else Config.API_PARAMS
    )

    client = CantinaAPIClient(Config.REPO_ID, Config.COOKIE, api_params)

    resp = client.fetch_findings()
    if resp is None:
        sys.exit("[!] Failed to fetch data; aborting.")

    # Compute payouts
    calc = PayoutCalculator(
        prize_pot, ignore_nums, early_bird, severity_overrides, manual_dupes
    )
    calc.process_findings(resp["findings"])

    print("\n✓ Script completed successfully.")


if __name__ == "__main__":
    main()