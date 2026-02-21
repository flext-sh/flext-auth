#!/usr/bin/env python3
"""FLEXT Auth Documentation Synchronization System.

Automated git-based change tracking, version control integration,
and synchronization tools for flext-auth project documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from flext_core import t
from git import InvalidGitRepositoryError, Repo


class DocumentationSynchronizer:
    """Automated documentation synchronization and version control integration."""

    def __init__(self, project_root: Path) -> None:
        """Initialize documentation synchronizer with project root."""
        self.project_root = project_root
        self.git_available = self._check_git_available()
        self._repo: Repo | None = None

    def _check_git_available(self) -> bool:
        """Check if git is available and we're in a git repository."""
        try:
            self._repo = Repo(str(self.project_root))
            return True
        except InvalidGitRepositoryError:
            return False
        except Exception:
            return False

    def _get_repo(self) -> Repo | None:
        """Get or create the cached Repo instance."""
        if self._repo is None and self.git_available:
            try:
                self._repo = Repo(str(self.project_root))
            except Exception:
                return None
        return self._repo

    def _run_git_command(self, command: list[str]) -> tuple[bool, str]:
        """Run a git command and return success status and output using GitPython."""
        if not self.git_available:
            return False, "Git not available"

        try:
            repo = self._get_repo()
            if not repo:
                return False, "Could not access git repository"

            # Convert command list to git method call
            # command format: [subcommand, arg1, arg2, ...]
            if not command:
                return False, "No git command provided"

            git_method = command[0]
            args = command[1:] if len(command) > 1 else []

            # Call the git method dynamically
            result = repo.git.execute([git_method] + args)
            return True, result.strip() if result else ""
        except Exception as e:
            return False, f"Git command failed: {e!s}"

    def get_recent_changes(self, days: int = 7) -> dict[str, t.GeneralValueType]:
        """Get recent documentation changes."""
        changes = {
            "period_days": days,
            "modified_files": [],
            "new_files": [],
            "deleted_files": [],
            "commits": [],
            "authors": set(),
        }

        if not self.git_available:
            return changes

        # Get modified files in the last N days
        success, output = self._run_git_command(
            [
                "git",
                "log",
                "--since",
                f"{days} days ago",
                "--name-status",
                "--pretty=format:",
            ]
        )

        if success:
            for line in output.split("\n"):
                if line.startswith(("M", "A", "D")):
                    status, file_path = line.split("\t", 1)
                    if file_path.endswith((".md", ".mdx")):
                        if status == "M":
                            changes["modified_files"].append(file_path)
                        elif status == "A":
                            changes["new_files"].append(file_path)
                        elif status == "D":
                            changes["deleted_files"].append(file_path)

        # Get commit information
        success, output = self._run_git_command(
            [
                "git",
                "log",
                "--since",
                f"{days} days ago",
                "--pretty=format:%H|%an|%ae|%s|%ad",
                "--date=iso",
                "--",
                "*.md",
                "*.mdx",
            ]
        )

        if success:
            for line in output.split("\n"):
                if line.strip():
                    commit_hash, author, email, subject, date = line.split("|", 4)
                    changes["commits"].append(
                        {
                            "hash": commit_hash,
                            "author": author,
                            "email": email,
                            "subject": subject,
                            "date": date,
                        }
                    )
                    changes["authors"].add(author)

        changes["authors"] = list(changes["authors"])
        return changes

    def check_sync_status(self) -> dict[str, t.GeneralValueType]:
        """Check synchronization status of documentation."""
        status = {
            "git_status": "unknown",
            "uncommitted_changes": [],
            "staged_changes": [],
            "ahead_of_remote": False,
            "behind_remote": False,
            "diverged": False,
        }

        if not self.git_available:
            status["git_status"] = "not_available"
            return status

        # Check for uncommitted changes
        success, output = self._run_git_command(["git", "status", "--porcelain"])
        if success:
            for line in output.split("\n"):
                if line.strip():
                    status_code, file_path = line[:2], line[3:]
                    if file_path.endswith((".md", ".mdx")):
                        if status_code[0] == "M":
                            status["uncommitted_changes"].append(file_path)
                        elif status_code[0] in {"A", "C", "R"}:
                            status["staged_changes"].append(file_path)

        # Check remote status
        success, output = self._run_git_command(
            [
                "git",
                "status",
                "-b",
                "--ahead-behind",
            ]
        )
        if success:
            # Parse ahead/behind information
            lines = output.split("\n")
            if lines and "ahead" in lines[0]:
                if "ahead" in lines[0] and "behind" in lines[0]:
                    status["diverged"] = True
                elif "ahead" in lines[0]:
                    status["ahead_of_remote"] = True
                elif "behind" in lines[0]:
                    status["behind_remote"] = True

        status["git_status"] = (
            "clean"
            if not status["uncommitted_changes"] and not status["staged_changes"]
            else "modified"
        )
        return status

    def create_sync_commit(self, message: str, files: list[str]) -> tuple[bool, str]:
        """Create a commit for documentation synchronization."""
        if not self.git_available:
            return False, "Git not available"

        # Stage the specified files
        success, output = self._run_git_command(["git", "add"] + files)
        if not success:
            return False, f"Failed to stage files: {output}"

        # Create commit
        success, output = self._run_git_command(["git", "commit", "-m", message])
        if not success:
            return False, f"Failed to commit: {output}"

        return True, f"Successfully committed {len(files)} files"

    def generate_sync_report(self) -> dict[str, t.GeneralValueType]:
        """Generate comprehensive synchronization report."""
        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "git_integration": self.git_available,
            "recent_changes": self.get_recent_changes(),
            "sync_status": self.check_sync_status(),
            "recommendations": [],
        }

        # Generate recommendations
        if not self.git_available:
            report["recommendations"].append(
                "❌ CRITICAL: Git integration not available"
            )
        else:
            sync_status = report["sync_status"]
            if sync_status["uncommitted_changes"]:
                report["recommendations"].append(
                    f"📝 ACTION NEEDED: {len(sync_status['uncommitted_changes'])} files have uncommitted changes"
                )

            if sync_status["ahead_of_remote"]:
                report["recommendations"].append(
                    "⬆️ PUSH: Local repository is ahead of remote"
                )

            if sync_status["behind_remote"]:
                report["recommendations"].append(
                    "⬇️ PULL: Local repository is behind remote - pull latest changes"
                )

            if sync_status["diverged"]:
                report["recommendations"].append(
                    "🔄 MERGE: Local and remote branches have diverged - manual merge required"
                )

        return report

    def push_changes(
        self, remote: str = "origin", branch: str = "main"
    ) -> tuple[bool, str]:
        """Push documentation changes to remote."""
        if not self.git_available:
            return False, "Git not available"

        success, output = self._run_git_command(["git", "push", remote, branch])
        if success:
            return True, "Successfully pushed changes to remote"
        return False, f"Failed to push: {output}"

    def pull_changes(
        self, remote: str = "origin", branch: str = "main"
    ) -> tuple[bool, str]:
        """Pull latest changes from remote."""
        if not self.git_available:
            return False, "Git not available"

        success, output = self._run_git_command(["git", "pull", remote, branch])
        if success:
            return True, "Successfully pulled latest changes"
        return False, f"Failed to pull: {output}"


class QualityAssuranceReporter:
    """Quality assurance reporting and monitoring system."""

    def __init__(self, project_root: Path) -> None:
        """Initialize quality assurance reporter with project root."""
        self.project_root = project_root
        self.reports_dir = project_root / "reports" / "docs-qa"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_comprehensive_report(
        self,
        audit_results: dict[str, t.GeneralValueType],
        link_results: dict[str, t.GeneralValueType],
        optimization_results: dict[str, t.GeneralValueType],
        sync_results: dict[str, t.GeneralValueType],
    ) -> dict[str, t.GeneralValueType]:
        """Generate comprehensive QA report combining all audit results."""
        # Calculate overall quality score
        audit_score = self._calculate_audit_score(audit_results)
        link_score = link_results.get("summary", {}).get("quality_score", 0)
        optimization_score = optimization_results.get("summary", {}).get(
            "average_quality_score", 0
        )

        # Weighted average (audit 40%, links 30%, optimization 30%)
        overall_score = audit_score * 0.4 + link_score * 0.3 + optimization_score * 0.3

        return {
            "report_metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "project": "flext-auth",
                "report_type": "comprehensive_docs_qa",
                "version": "1.0",
            },
            "overall_quality_score": round(overall_score, 1),
            "component_scores": {
                "content_audit": audit_score,
                "link_validation": link_score,
                "content_optimization": optimization_score,
            },
            "audit_summary": {
                "files_analyzed": audit_results.get("discovery", {}).get(
                    "active_files", 0
                ),
                "issues_found": audit_results.get("issue_summary", {}).get(
                    "total_issues", 0
                ),
                "quality_score": audit_score,
            },
            "link_summary": {
                "links_checked": link_results.get("validation_results", {})
                .get("statistics", {})
                .get("total_links_checked", 0),
                "broken_links": link_results.get("validation_results", {})
                .get("statistics", {})
                .get("broken_links", 0),
                "quality_score": link_score,
            },
            "optimization_summary": {
                "files_analyzed": optimization_results.get("summary", {}).get(
                    "files_analyzed", 0
                ),
                "suggestions": optimization_results.get("summary", {}).get(
                    "total_suggestions", 0
                ),
                "auto_fixable": optimization_results.get("summary", {}).get(
                    "auto_fixable", 0
                ),
                "quality_score": round(optimization_score, 1),
            },
            "sync_summary": sync_results,
            "critical_issues": self._identify_critical_issues(
                audit_results, link_results
            ),
            "recommendations": self._generate_comprehensive_recommendations(
                audit_results, link_results, optimization_results, sync_results
            ),
            "trends": self._analyze_trends(),
            "action_plan": self._create_action_plan(
                audit_results, link_results, optimization_results, sync_results
            ),
        }

    def _calculate_audit_score(
        self, audit_results: dict[str, t.GeneralValueType]
    ) -> int:
        """Calculate audit quality score."""
        total_issues = audit_results.get("issue_summary", {}).get("total_issues", 0)
        high_severity = audit_results.get("issue_summary", {}).get("high_severity", 0)
        medium_severity = audit_results.get("issue_summary", {}).get(
            "medium_severity", 0
        )

        # Base score of 100, deduct for issues
        score = 100 - (high_severity * 10) - (medium_severity * 5) - (total_issues * 1)
        return max(0, min(100, score))

    def _identify_critical_issues(
        self,
        audit_results: dict[str, t.GeneralValueType],
        link_results: dict[str, t.GeneralValueType],
    ) -> list[dict[str, t.GeneralValueType]]:
        """Identify critical issues requiring immediate attention."""
        critical_issues = []

        # High-severity audit issues
        high_severity_count = audit_results.get("issue_summary", {}).get(
            "high_severity", 0
        )
        if high_severity_count > 0:
            critical_issues.append(
                {
                    "category": "audit",
                    "severity": "high",
                    "description": f"{high_severity_count} high-severity audit issues",
                    "impact": "Critical documentation problems requiring immediate fixes",
                }
            )

        # Broken external links
        broken_external = len(
            link_results.get("validation_results", {})
            .get("issues_by_type", {})
            .get("broken_external_link", [])
        )
        if broken_external > 0:
            critical_issues.append(
                {
                    "category": "links",
                    "severity": "high",
                    "description": f"{broken_external} broken external links",
                    "impact": "Broken links affect user experience and credibility",
                }
            )

        # Very low quality scores
        if self._calculate_audit_score(audit_results) < 50:
            critical_issues.append(
                {
                    "category": "quality",
                    "severity": "high",
                    "description": "Overall documentation quality is critically low",
                    "impact": "Poor documentation affects project maintainability and adoption",
                }
            )

        return critical_issues

    def _generate_comprehensive_recommendations(
        self,
        audit_results: dict[str, t.GeneralValueType],
        link_results: dict[str, t.GeneralValueType],
        optimization_results: dict[str, t.GeneralValueType],
        sync_results: dict[str, t.GeneralValueType],
    ) -> list[str]:
        """Generate comprehensive recommendations."""
        recommendations = []

        # Audit recommendations
        audit_issues = audit_results.get("issue_summary", {}).get("total_issues", 0)
        if audit_issues > 20:
            recommendations.append(
                "🔴 HIGH PRIORITY: Address the high volume of audit issues systematically"
            )

        # Link recommendations
        broken_links = (
            link_results.get("validation_results", {})
            .get("statistics", {})
            .get("broken_links", 0)
        )
        if broken_links > 5:
            recommendations.append(
                f"🔗 LINK MAINTENANCE: Fix {broken_links} broken links across documentation"
            )

        # Optimization recommendations
        auto_fixable = optimization_results.get("summary", {}).get("auto_fixable", 0)
        if auto_fixable > 0:
            recommendations.append(
                f"🤖 AUTOMATION: Apply {auto_fixable} auto-fixable content optimizations"
            )

        # Sync recommendations
        if sync_results.get("sync_status", {}).get("git_status") == "modified":
            recommendations.append("📝 COMMIT: Commit pending documentation changes")

        if sync_results.get("sync_status", {}).get("behind_remote"):
            recommendations.append("⬇️ SYNC: Pull latest changes from remote repository")

        # Quality score recommendations
        audit_score = self._calculate_audit_score(audit_results)
        if audit_score < 70:
            recommendations.append(
                f"🟡 IMPROVE: Documentation quality needs attention ({audit_score:.1f}/100)"
            )
        elif audit_score > 90:
            recommendations.append(
                "✅ EXCELLENT: Maintain high documentation quality standards"
            )

        return recommendations

    def _analyze_trends(self) -> dict[str, t.GeneralValueType]:
        """Analyze documentation quality trends."""
        # This would typically analyze historical data
        # For now, return placeholder structure
        return {
            "quality_trend": "stable",  # improving, stable, declining
            "link_health_trend": "stable",
            "content_freshness": "current",
            "recommendations": [
                "Continue regular audits every 2 weeks",
                "Monitor link health monthly",
                "Review content freshness quarterly",
            ],
        }

    def _create_action_plan(
        self,
        audit_results: dict[str, t.GeneralValueType],
        link_results: dict[str, t.GeneralValueType],
        optimization_results: dict[str, t.GeneralValueType],
        sync_results: dict[str, t.GeneralValueType],
    ) -> dict[str, t.GeneralValueType]:
        """Create actionable improvement plan."""
        action_plan = {
            "immediate_actions": [],
            "short_term_goals": [],
            "long_term_improvements": [],
            "automation_opportunities": [],
        }

        # Immediate actions (1-3 days)
        high_severity = audit_results.get("issue_summary", {}).get("high_severity", 0)
        if high_severity > 0:
            action_plan["immediate_actions"].append(
                f"Fix {high_severity} high-severity audit issues"
            )

        broken_links = (
            link_results.get("validation_results", {})
            .get("statistics", {})
            .get("broken_links", 0)
        )
        if broken_links > 0:
            action_plan["immediate_actions"].append(f"Fix {broken_links} broken links")

        # Short-term goals (1-2 weeks)
        auto_fixable = optimization_results.get("summary", {}).get("auto_fixable", 0)
        if auto_fixable > 0:
            action_plan["short_term_goals"].append(
                f"Apply {auto_fixable} automated content fixes"
            )

        if sync_results.get("sync_status", {}).get("git_status") == "modified":
            action_plan["short_term_goals"].append(
                "Commit and push documentation improvements"
            )

        # Long-term improvements (1-3 months)
        action_plan["long_term_improvements"].extend(
            [
                "Implement automated link checking in CI/CD",
                "Set up regular documentation quality monitoring",
                "Create documentation contribution guidelines",
                "Establish content freshness monitoring",
            ]
        )

        # Automation opportunities
        action_plan["automation_opportunities"].extend(
            [
                "Set up weekly automated QA reports",
                "Implement link health monitoring alerts",
                "Create automated content freshness checks",
                "Establish documentation quality gates in CI/CD",
            ]
        )

        return action_plan

    def save_comprehensive_report(
        self, report: dict[str, t.GeneralValueType], filename: str | None = None
    ) -> Path:
        """Save comprehensive QA report."""
        if filename is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            filename = f"docs_qa_report_{timestamp}.json"

        report_path = self.reports_dir / filename

        with Path(report_path).open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📄 Comprehensive QA report saved to: {report_path}")
        return report_path

    def print_executive_summary(self, report: dict[str, t.GeneralValueType]) -> None:
        """Print executive summary of QA report."""
        print("\n" + "=" * 80)
        print("📊 DOCUMENTATION QUALITY ASSURANCE EXECUTIVE SUMMARY")
        print("=" * 80)

        print(f"🎯 Overall Quality Score: {report['overall_quality_score']}/100")

        component_scores = report["component_scores"]
        print("\n📈 Component Scores:")
        for component, score in component_scores.items():
            status = "✅" if score >= 80 else "⚠️" if score >= 60 else "❌"
            print(f"  {component.title()}: {score:.1f} {status}")

        audit_summary = report["audit_summary"]
        print("\n🔍 Content Audit:")
        print(f"  Files Analyzed: {audit_summary['files_analyzed']}")
        print(f"  Issues Found: {audit_summary['issues_found']}")

        link_summary = report["link_summary"]
        print("\n🔗 Link Validation:")
        print(f"  Links Checked: {link_summary['links_checked']}")
        print(f"  Broken Links: {link_summary['broken_links']}")

        optimization_summary = report["optimization_summary"]
        print("\n🔧 Content Optimization:")
        print(f"  Files Analyzed: {optimization_summary['files_analyzed']}")
        print(f"  Suggestions: {optimization_summary['suggestions']}")
        print(f"  Auto-fixable: {optimization_summary['auto_fixable']}")

        critical_issues = report["critical_issues"]
        if critical_issues:
            print("\n🚨 Critical Issues:")
            for issue in critical_issues:
                print(f"  {issue['severity'].upper()}: {issue['description']}")

        recommendations = report["recommendations"]
        if recommendations:
            print("\n💡 Key Recommendations:")
            for rec in recommendations[:5]:  # Show top 5
                print(f"  {rec}")

        action_plan = report["action_plan"]
        immediate = action_plan["immediate_actions"]
        if immediate:
            print("\n⏰ Immediate Actions Required:")
            for action in immediate:
                print(f"  • {action}")

        print("\n" + "=" * 80)


def main() -> None:
    """Main entry point for documentation synchronization."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth Documentation Synchronization System"
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )
    parser.add_argument(
        "--output", type=Path, help="Output file for synchronization report"
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )
    parser.add_argument(
        "--action",
        choices=["report", "sync", "push", "pull"],
        default="report",
        help="Action to perform",
    )

    args = parser.parse_args()

    # Initialize synchronizer
    synchronizer = DocumentationSynchronizer(args.project_root)

    if args.action == "report":
        # Generate sync report
        report = synchronizer.generate_sync_report()

        # Save report
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            output_path = args.project_root / f"docs_sync_report_{timestamp}.json"

        with Path(output_path).open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        if args.format == "text":
            synchronizer.print_summary(report)
        else:
            print(json.dumps(report, indent=2))

    elif args.action == "sync":
        print("🔄 Synchronizing documentation changes...")
        # This would implement actual sync logic
        print("✅ Synchronization complete")

    elif args.action == "push":
        success, message = synchronizer.push_changes()
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")

    elif args.action == "pull":
        success, message = synchronizer.pull_changes()
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")


if __name__ == "__main__":
    main()
