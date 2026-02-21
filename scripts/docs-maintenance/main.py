#!/usr/bin/env python3
"""FLEXT Auth Documentation Maintenance System - Main Orchestrator.

Comprehensive documentation maintenance framework orchestrator
for flext-auth project documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from content_optimizer import ContentOptimizer

# Import our maintenance modules
from docs_audit import DocumentationAuditor
from docs_sync import DocumentationSynchronizer, QualityAssuranceReporter
from flext_core import t
from link_validator import LinkValidator


class DocumentationMaintenanceSystem:
    """Main orchestrator for comprehensive documentation maintenance."""

    def __init__(self, project_root: Path) -> None:
        """Initialize documentation maintenance orchestrator with project root."""
        self.project_root = project_root
        self.auditor = DocumentationAuditor(project_root)
        self.link_validator = LinkValidator(project_root)
        self.content_optimizer = ContentOptimizer(project_root)
        self.synchronizer = DocumentationSynchronizer(project_root)
        self.qa_reporter = QualityAssuranceReporter(project_root)

        # Results storage
        self.audit_results: dict[str, t.GeneralValueType] | None = None
        self.link_results: dict[str, t.GeneralValueType] | None = None
        self.optimization_results: dict[str, t.GeneralValueType] | None = None
        self.sync_results: dict[str, t.GeneralValueType] | None = None

    def run_comprehensive_maintenance(self) -> dict[str, t.GeneralValueType]:
        """Run complete documentation maintenance cycle."""
        print("🚀 Starting comprehensive documentation maintenance...")
        print(f"📁 Project root: {self.project_root}")

        # Phase 1: Content Quality Audit
        print("\n📊 Phase 1: Content Quality Audit")
        self.audit_results = self.auditor.run_comprehensive_audit()

        # Phase 2: Link Validation
        print("\n🔗 Phase 2: Link Validation")
        self.link_results = self.link_validator.run_link_audit()

        # Phase 3: Content Optimization
        print("\n🔍 Phase 3: Content Optimization")
        self.optimization_results = self.content_optimizer.generate_report()

        # Phase 4: Synchronization Check
        print("\n🔄 Phase 4: Synchronization Analysis")
        self.sync_results = self.synchronizer.generate_sync_report()

        # Phase 5: Quality Assurance Report
        print("\n📋 Phase 5: Quality Assurance Report Generation")
        comprehensive_report = self.qa_reporter.generate_comprehensive_report(
            self.audit_results,
            self.link_results,
            self.optimization_results,
            self.sync_results,
        )

        # Save comprehensive report
        report_file = self.qa_reporter.save_comprehensive_report(comprehensive_report)

        print("\n✅ Comprehensive documentation maintenance complete!")
        print(f"📄 Full report saved to: {report_file}")

        return comprehensive_report

    def run_quick_audit(self) -> dict[str, t.GeneralValueType]:
        """Run quick audit for immediate feedback."""
        print("⚡ Running quick documentation audit...")

        # Quick audit - just run auditor
        self.audit_results = self.auditor.run_comprehensive_audit()

        # Generate basic report
        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "audit_type": "quick",
            "results": self.audit_results,
        }

        # Save quick report
        output_path = (
            self.project_root
            / f"docs_quick_audit_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
        )
        with Path(output_path).open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"📄 Quick audit report saved to: {output_path}")
        return report

    def generate_maintenance_report(self) -> dict[str, t.GeneralValueType]:
        """Generate maintenance status report."""
        if not all(
            [
                self.audit_results,
                self.link_results,
                self.optimization_results,
                self.sync_results,
            ]
        ):
            print(
                "❌ Cannot generate maintenance report - run comprehensive maintenance first"
            )
            return {}

        return self.qa_reporter.generate_comprehensive_report(
            self.audit_results,
            self.link_results,
            self.optimization_results,
            self.sync_results,
        )

    def print_maintenance_summary(self) -> None:
        """Print maintenance summary."""
        if not self.audit_results:
            print("❌ No audit results available. Run maintenance first.")
            return

        comprehensive_report = self.generate_maintenance_report()
        if comprehensive_report:
            self.qa_reporter.print_executive_summary(comprehensive_report)

    def apply_auto_fixes(self) -> tuple[int, list[str]]:
        """Apply auto-fixable issues."""
        if not self.optimization_results:
            print("❌ No optimization results available. Run maintenance first.")
            return 0, []

        fixes_applied = 0
        fix_log = []

        # Get auto-fixable suggestions
        suggestions_by_file = self.optimization_results.get("detailed_suggestions", {})

        for file_path, suggestions in suggestions_by_file.items():
            file_fixes = 0
            full_path = self.project_root / file_path

            try:
                content = full_path.read_text(encoding="utf-8")
                original_content = content

                for suggestion in suggestions:
                    if (
                        suggestion.get("auto_fixable", False)
                        and "trailing whitespace" in suggestion["issue"].lower()
                    ):
                        # Apply the fix (simplified - only handling trailing whitespace for now)
                        lines = content.split("\n")
                        fixed_lines = [line.rstrip() for line in lines]
                        content = "\n".join(fixed_lines)
                        file_fixes += 1
                        fix_log.append(f"Fixed trailing whitespace in {file_path}")

                # Save if changes were made
                if content != original_content:
                    full_path.write_text(content, encoding="utf-8")
                    fixes_applied += file_fixes

            except Exception as e:
                fix_log.append(f"Error processing {file_path}: {e!s}")

        return fixes_applied, fix_log

    def export_maintenance_config(self) -> Path:
        """Export maintenance configuration template."""
        config = {
            "maintenance_system": {
                "version": "1.0",
                "project": "flext-auth",
                "description": "Documentation maintenance configuration",
            },
            "audit_config": {
                "enabled": True,
                "frequency": "weekly",
                "quality_threshold": 80,
                "max_issues_per_file": 10,
            },
            "link_validation": {
                "enabled": True,
                "check_external_links": True,
                "check_internal_links": True,
                "timeout_seconds": 10,
                "max_retries": 3,
            },
            "content_optimization": {
                "enabled": True,
                "auto_fix_enabled": True,
                "readability_checks": True,
                "structure_validation": True,
            },
            "synchronization": {
                "enabled": True,
                "auto_commit": False,
                "remote_tracking": True,
                "conflict_resolution": "manual",
            },
            "reporting": {
                "enabled": True,
                "report_frequency": "weekly",
                "email_notifications": False,
                "dashboard_enabled": False,
            },
            "quality_gates": {
                "minimum_quality_score": 75,
                "maximum_broken_links": 5,
                "maximum_high_severity_issues": 3,
                "require_freshness_check": True,
            },
        }

        config_path = self.project_root / "docs_maintenance_config.json"
        with Path(config_path).open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        print(f"📄 Maintenance configuration template saved to: {config_path}")
        return config_path


def main() -> None:
    """Main entry point for documentation maintenance system."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth Documentation Maintenance System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run comprehensive maintenance
  python main.py comprehensive

  # Quick audit only
  python main.py quick

  # Apply auto-fixes
  python main.py fix

  # Export configuration template
  python main.py config

  # Show maintenance summary
  python main.py summary
        """,
    )

    parser.add_argument(
        "command",
        choices=["comprehensive", "quick", "fix", "summary", "config"],
        help="Maintenance command to run",
    )

    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )

    parser.add_argument("--output-dir", type=Path, help="Output directory for reports")

    args = parser.parse_args()

    # Initialize maintenance system
    system = DocumentationMaintenanceSystem(args.project_root)

    if args.command == "comprehensive":
        # Run full maintenance cycle
        system.run_comprehensive_maintenance()
        system.print_maintenance_summary()

    elif args.command == "quick":
        # Quick audit
        system.run_quick_audit()
        system.auditor.print_summary()

    elif args.command == "fix":
        # Apply auto-fixes
        if not system.optimization_results:
            print(
                "❌ No optimization results available. Run comprehensive maintenance first."
            )
            sys.exit(1)

        fixes_applied, fix_log = system.apply_auto_fixes()
        print(f"✅ Applied {fixes_applied} auto-fixes")
        for log_entry in fix_log:
            print(f"  {log_entry}")

    elif args.command == "summary":
        # Show maintenance summary
        system.print_maintenance_summary()

    elif args.command == "config":
        # Export configuration template
        system.export_maintenance_config()
        print("📋 Maintenance configuration template created")
        print("Edit the file to customize maintenance settings")


if __name__ == "__main__":
    main()
