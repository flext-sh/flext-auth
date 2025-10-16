#!/usr/bin/env python3
"""FLEXT Auth Documentation Audit System.

Comprehensive documentation quality assurance and maintenance system
for flext-auth project documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class DocumentationAuditor:
    """Comprehensive documentation audit and quality assurance system."""

    def __init__(self, project_root: Path) -> None:
        """Initialize documentation auditor with project root."""
        self.project_root = project_root
        self.docs_dir = project_root / "docs"
        self.results: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "project": "flext-auth",
            "audit_results": {},
            "quality_score": 0,
            "issues": [],
            "recommendations": [],
        }

    def discover_docs(self) -> list[Path]:
        """Discover all documentation files."""
        docs_files = []

        # Find all markdown files
        for pattern in ["*.md", "*.mdx"]:
            docs_files.extend(self.project_root.rglob(pattern))

        # Filter out archive files for separate analysis
        active_docs = []
        archive_docs = []

        for doc in docs_files:
            if "archive" in str(doc):
                archive_docs.append(doc)
            else:
                active_docs.append(doc)

        self.results["discovery"] = {
            "total_files": len(docs_files),
            "active_files": len(active_docs),
            "archive_files": len(archive_docs),
            "active_paths": [
                str(p.relative_to(self.project_root)) for p in active_docs
            ],
        }

        return active_docs

    def analyze_content_quality(self, docs_files: list[Path]) -> dict[str, object]:
        """Analyze content quality metrics."""
        quality_analysis = {
            "file_metrics": [],
            "content_freshness": [],
            "structure_analysis": [],
            "completeness_check": [],
        }

        for doc_file in docs_files:
            try:
                content = doc_file.read_text(encoding="utf-8")
                metrics = self._analyze_single_file(doc_file, content)
                quality_analysis["file_metrics"].append(metrics)

                # Check freshness
                mtime = datetime.fromtimestamp(doc_file.stat().st_mtime, tz=UTC)
                days_old = (datetime.now(UTC) - mtime).days
                quality_analysis["content_freshness"].append(
                    {
                        "file": str(doc_file.relative_to(self.project_root)),
                        "last_modified": mtime.isoformat(),
                        "days_old": days_old,
                        "freshness_score": self._calculate_freshness_score(days_old),
                    }
                )

                # Structure analysis
                structure = self._analyze_structure(content)
                quality_analysis["structure_analysis"].append(
                    {
                        "file": str(doc_file.relative_to(self.project_root)),
                        **structure,
                    }
                )

                # Completeness check
                completeness = self._check_completeness(content, doc_file.name)
                quality_analysis["completeness_check"].append(
                    {
                        "file": str(doc_file.relative_to(self.project_root)),
                        **completeness,
                    }
                )

            except Exception as e:
                self.results["issues"].append(
                    {
                        "type": "file_read_error",
                        "file": str(doc_file.relative_to(self.project_root)),
                        "error": str(e),
                        "severity": "high",
                    }
                )

        return quality_analysis

    def _analyze_single_file(self, file_path: Path, content: str) -> dict[str, object]:
        """Analyze a single documentation file."""
        lines = content.split("\n")
        word_count = len(re.findall(r"\b\w+\b", content))
        code_blocks = len(re.findall(r"```", content)) // 2
        links = len(re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content))
        images = len(re.findall(r"!\[([^\]]*)\]\(([^)]+)\)", content))
        headers = len(re.findall(r"^#{1,6}\s+", content, re.MULTILINE))
        lists = len(re.findall(r"^[\s]*[-*+]\s+", content, re.MULTILINE))
        tables = len(re.findall(r"^\|.*\|.*\|", content, re.MULTILINE))

        # Check for TODO/FIXME markers
        todo_markers = len(re.findall(r"(?i)(todo|fixme|hack|xxx)", content))

        return {
            "file": str(file_path.relative_to(self.project_root)),
            "lines": len(lines),
            "words": word_count,
            "code_blocks": code_blocks,
            "links": links,
            "images": images,
            "headers": headers,
            "lists": lists,
            "tables": tables,
            "todo_markers": todo_markers,
            "avg_words_per_line": round(word_count / max(len(lines), 1), 2),
        }

    def _calculate_freshness_score(self, days_old: int) -> str:
        """Calculate content freshness score."""
        if days_old <= 7:
            return "excellent"
        if days_old <= 30:
            return "good"
        if days_old <= 90:
            return "fair"
        if days_old <= 180:
            return "stale"
        return "outdated"

    def _analyze_structure(self, content: str) -> dict[str, object]:
        """Analyze document structure."""
        lines = content.split("\n")

        # Header hierarchy analysis
        headers = []
        for line in lines:
            if match := re.match(r"^(#{1,6})\s+(.+)", line):
                level = len(match.group(1))
                title = match.group(2).strip()
                headers.append({"level": level, "title": title})

        # Check header hierarchy
        hierarchy_issues = []
        prev_level = 0
        for header in headers:
            if header["level"] > prev_level + 1:
                hierarchy_issues.append(f"Skipped heading level: {header['title']}")
            prev_level = header["level"]

        # Check for required sections
        has_toc = bool(
            re.search(r"(table of contents|contents)", content, re.IGNORECASE)
        )
        has_examples = bool(re.findall(r"```", content))

        return {
            "total_headers": len(headers),
            "header_hierarchy": headers,
            "hierarchy_issues": hierarchy_issues,
            "has_table_of_contents": has_toc,
            "has_code_examples": has_examples,
            "structure_score": "good"
            if len(hierarchy_issues) == 0
            else "needs_attention",
        }

    def _check_completeness(self, content: str, filename: str) -> dict[str, object]:
        """Check documentation completeness."""
        checks = {
            "has_frontmatter": bool(re.search(r"^---\s*$", content, re.MULTILINE)),
            "has_version_info": bool(
                re.search(r"(version|updated)", content, re.IGNORECASE)
            ),
            "has_examples": bool(re.findall(r"```", content)),
            "has_links": bool(re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)),
            "has_status_indicators": bool(re.findall(r"(✅|❌|⚠️|🚧|📅)", content)),
            "has_todo_markers": bool(re.findall(r"(?i)(todo|fixme)", content)),
        }

        # File-specific checks
        if filename == "README.md":
            checks.update(
                {
                    "has_badges": bool(re.findall(r"!\[.*\]\(.*\)", content)),
                    "has_installation": bool(
                        re.search(r"(install|setup)", content, re.IGNORECASE)
                    ),
                    "has_usage": bool(
                        re.search(r"(usage|example)", content, re.IGNORECASE)
                    ),
                }
            )
        elif filename == "CLAUDE.md":
            checks.update(
                {
                    "has_commands": bool(r"make" in content),
                    "has_patterns": bool(
                        re.search(r"(pattern|architecture)", content, re.IGNORECASE)
                    ),
                }
            )

        completeness_score = sum(checks.values()) / len(checks)
        checks["completeness_score"] = round(completeness_score * 100, 1)

        return checks

    async def validate_links(self, docs_files: list[Path]) -> dict[str, object]:
        """Validate all links in documentation."""
        link_validation = {
            "internal_links": [],
            "external_links": [],
            "broken_links": [],
            "image_links": [],
        }

        for doc_file in docs_files:
            try:
                content = doc_file.read_text(encoding="utf-8")

                # Find all links
                link_pattern = r"\[([^\]]+)\]\(([^)]+)\)"
                for match in re.finditer(link_pattern, content):
                    link_text = match.group(1)
                    link_url = match.group(2)

                    if link_url.startswith("http"):
                        # External link
                        is_valid = await self._check_external_link(link_url)
                        link_validation["external_links"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "text": link_text,
                                "url": link_url,
                                "valid": is_valid,
                            }
                        )
                        if not is_valid:
                            link_validation["broken_links"].append(
                                {
                                    "file": str(
                                        doc_file.relative_to(self.project_root)
                                    ),
                                    "text": link_text,
                                    "url": link_url,
                                    "type": "external",
                                }
                            )
                    else:
                        # Internal link
                        is_valid = self._check_internal_link(doc_file, link_url)
                        link_validation["internal_links"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "text": link_text,
                                "url": link_url,
                                "valid": is_valid,
                            }
                        )
                        if not is_valid:
                            link_validation["broken_links"].append(
                                {
                                    "file": str(
                                        doc_file.relative_to(self.project_root)
                                    ),
                                    "text": link_text,
                                    "url": link_url,
                                    "type": "internal",
                                }
                            )

                # Check image links
                image_pattern = r"!\[([^\]]*)\]\(([^)]+)\)"
                for match in re.finditer(image_pattern, content):
                    alt_text = match.group(1)
                    image_url = match.group(2)

                    if image_url.startswith("http"):
                        # External image
                        is_valid = await self._check_external_link(image_url)
                        link_validation["image_links"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "alt_text": alt_text,
                                "url": image_url,
                                "valid": is_valid,
                            }
                        )
                    else:
                        # Local image
                        image_path = (doc_file.parent / image_url).resolve()
                        is_valid = image_path.exists()
                        link_validation["image_links"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "alt_text": alt_text,
                                "url": image_url,
                                "valid": is_valid,
                            }
                        )

            except Exception as e:
                self.results["issues"].append(
                    {
                        "type": "link_validation_error",
                        "file": str(doc_file.relative_to(self.project_root)),
                        "error": str(e),
                        "severity": "medium",
                    }
                )

        return link_validation

    async def _check_external_link(self, url: str) -> bool:
        """Check if an external link is accessible."""
        try:
            # Basic URL validation
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False

            # Security: Only allow HTTP/HTTPS schemes
            if parsed.scheme.lower() not in {"http", "https"}:
                return False

            # Try to access the URL (with timeout)
            if HAS_AIOHTTP:
                async with (
                    aiohttp.ClientSession() as session,
                    session.head(
                        url, timeout=aiohttp.ClientTimeout(total=10)
                    ) as response,
                ):
                    return response.status == 200
            else:
                # Fallback to thread-based blocking call
                def check_url() -> bool:
                    req = urlopen(url, timeout=10)  # noqa: S310
                    return req.status == 200

                return await asyncio.to_thread(check_url)
        except (TimeoutError, URLError, HTTPError, OSError, Exception):
            return False

    def _check_internal_link(self, from_file: Path, link_url: str) -> bool:
        """Check if an internal link is valid."""
        try:
            # Handle relative links
            if link_url.startswith("#"):
                # Anchor link - check if heading exists in same file
                content = from_file.read_text(encoding="utf-8")
                anchor = link_url[1:].lower().replace("-", " ")
                # Simple check for heading with similar text
                return bool(
                    re.search(
                        rf"^#{1, 6}.*{re.escape(anchor)}",
                        content,
                        re.MULTILINE | re.IGNORECASE,
                    )
                )
            if link_url.startswith(("./", "../")):
                # Relative file path
                target_path = (from_file.parent / link_url).resolve()
                return target_path.exists() and target_path.is_file()
            # Absolute path from project root
            target_path = (self.project_root / link_url).resolve()
            return target_path.exists() and target_path.is_file()
        except Exception:
            return False

    def check_style_consistency(self, docs_files: list[Path]) -> dict[str, object]:
        """Check style consistency across documentation."""
        style_issues = {
            "inconsistent_headers": [],
            "missing_alt_text": [],
            "inconsistent_lists": [],
            "code_block_issues": [],
            "formatting_issues": [],
        }

        for doc_file in docs_files:
            try:
                content = doc_file.read_text(encoding="utf-8")
                lines = content.split("\n")

                # Check header consistency
                header_pattern = re.compile(r"^(#{1,6})\s+(.+)")
                for i, line in enumerate(lines):
                    if match := header_pattern.match(line):
                        len(match.group(1))
                        title = match.group(2)

                        # Check for inconsistent capitalization
                        if title.isupper() or title.islower():
                            style_issues["inconsistent_headers"].append(
                                {
                                    "file": str(
                                        doc_file.relative_to(self.project_root)
                                    ),
                                    "line": i + 1,
                                    "header": title,
                                    "issue": "inconsistent capitalization",
                                }
                            )

                # Check for missing alt text on images
                image_pattern = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
                for match in image_pattern.finditer(content):
                    alt_text = match.group(1)
                    if not alt_text.strip():
                        style_issues["missing_alt_text"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "alt_text": alt_text,
                                "line": content[: match.start()].count("\n") + 1,
                            }
                        )

                # Check code block consistency
                code_blocks = re.findall(r"```(\w+)?", content)
                for i, lang in enumerate(code_blocks):
                    if not lang and i % 2 == 0:  # Opening code block without language
                        style_issues["code_block_issues"].append(
                            {
                                "file": str(doc_file.relative_to(self.project_root)),
                                "issue": "code block without language specification",
                            }
                        )

            except Exception as e:
                self.results["issues"].append(
                    {
                        "type": "style_check_error",
                        "file": str(doc_file.relative_to(self.project_root)),
                        "error": str(e),
                        "severity": "low",
                    }
                )

        return style_issues

    def generate_report(self) -> dict[str, object]:
        """Generate comprehensive audit report."""
        # Calculate quality score
        self.results["discovery"]["total_files"]
        issues = self.results["issues"]
        high_severity = len([i for i in issues if i.get("severity") == "high"])
        medium_severity = len([i for i in issues if i.get("severity") == "medium"])
        low_severity = len([i for i in issues if i.get("severity") == "low"])

        # Quality score calculation
        quality_score = max(
            0, 100 - (high_severity * 20 + medium_severity * 10 + low_severity * 2)
        )
        quality_score = min(quality_score, 100)

        self.results["quality_score"] = quality_score
        self.results["issue_summary"] = {
            "total_issues": len(issues),
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
        }

        # Generate recommendations
        recommendations = []
        if high_severity > 0:
            recommendations.append("🔴 CRITICAL: Fix high-severity issues immediately")
        if quality_score < 70:
            recommendations.append(
                "🟡 IMPROVE: Overall documentation quality needs attention"
            )
        if (
            not self.results["audit_results"]
            .get("link_validation", {})
            .get("broken_links")
        ):
            recommendations.append("✅ GOOD: No broken links detected")
        if quality_score > 85:
            recommendations.append(
                "✅ EXCELLENT: High-quality documentation standards maintained"
            )

        self.results["recommendations"] = recommendations

        return self.results

    def run_comprehensive_audit(self) -> dict[str, object]:
        """Run complete documentation audit."""
        print("🔍 Starting comprehensive documentation audit...")

        # Discover documentation files
        docs_files = self.discover_docs()
        print(f"📁 Found {len(docs_files)} active documentation files")

        # Content quality analysis
        print("📊 Analyzing content quality...")
        quality_results = self.analyze_content_quality(docs_files)
        self.results["audit_results"]["content_quality"] = quality_results

        # Link validation
        print("🔗 Validating links...")
        link_results = asyncio.run(self.validate_links(docs_files))
        self.results["audit_results"]["link_validation"] = link_results

        # Style consistency
        print("✨ Checking style consistency...")
        style_results = self.check_style_consistency(docs_files)
        self.results["audit_results"]["style_consistency"] = style_results

        # Generate final report
        print("📋 Generating audit report...")
        return self.generate_report()

    def save_report(self, output_path: Path | None = None) -> Path:
        """Save audit report to file."""
        if output_path is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            output_path = self.project_root / f"docs_audit_{timestamp}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with Path(output_path).open("w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"📄 Audit report saved to: {output_path}")
        return output_path

    def print_summary(self) -> None:
        """Print audit summary to console."""
        quality_score = self.results.get("quality_score", 0)
        issue_summary = self.results.get("issue_summary", {})

        print("\n" + "=" * 60)
        print("📊 DOCUMENTATION AUDIT SUMMARY")
        print("=" * 60)

        print(f"📈 Quality Score: {quality_score}/100")

        discovery = self.results.get("discovery", {})
        print(f"📁 Documentation Files: {discovery.get('active_files', 0)} active")

        issues = issue_summary.get("total_issues", 0)
        print(f"⚠️  Issues Found: {issues}")
        if issues > 0:
            print(f"  🔴 High: {issue_summary.get('high_severity', 0)}")
            print(f"  🟡 Medium: {issue_summary.get('medium_severity', 0)}")
            print(f"  🔵 Low: {issue_summary.get('low_severity', 0)}")

        recommendations = self.results.get("recommendations", [])
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  {rec}")

        print("\n" + "=" * 60)


def main() -> None:
    """Main entry point for documentation audit."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth Documentation Audit System"
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )
    parser.add_argument("--output", type=Path, help="Output file for audit report")
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )

    args = parser.parse_args()

    # Initialize auditor
    auditor = DocumentationAuditor(args.project_root)

    # Run comprehensive audit
    report = auditor.run_comprehensive_audit()

    # Save detailed report
    auditor.save_report(args.output)

    # Print summary
    if args.format == "text":
        auditor.print_summary()
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
