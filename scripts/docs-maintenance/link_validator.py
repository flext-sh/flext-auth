#!/usr/bin/env python3
"""FLEXT Auth Link Validation and Optimization System.

Automated link checking, reference validation, and optimization tools
for flext-auth project documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import asyncio
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import requests
except ImportError:
    requests = None


@dataclass
class LinkValidationResult:
    """Result of link validation."""

    url: str
    status: str
    response_time: float
    error_message: str | None = None
    redirect_url: str | None = None


@dataclass
class LinkIssue:
    """Represents a link-related issue."""

    file_path: Path
    line_number: int
    link_text: str
    url: str
    issue_type: str
    severity: str
    suggestion: str | None = None


class LinkValidator:
    """Comprehensive link validation and optimization system."""

    def __init__(
        self, project_root: Path, timeout: int = 10, max_retries: int = 3
    ) -> None:
        """Initialize link validator with project root and configuration."""
        self.project_root = project_root
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = "FLEXT-Docs-Link-Validator/1.0"
        self.results: dict[str, object] = {
            "timestamp": time.time(),
            "validation_results": {},
            "issues": [],
            "statistics": {},
        }

    async def validate_external_link(self, url: str) -> LinkValidationResult:
        """Validate an external link with retries."""
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                # Security check - only allow HTTP/HTTPS schemes
                parsed = urlparse(url)
                if parsed.scheme.lower() not in {"http", "https"}:
                    return LinkValidationResult(
                        url=url,
                        is_valid=False,
                        status_code=None,
                        error_message="Unsupported URL scheme",
                        response_time=0.0,
                        redirect_url=None,
                    )

                # Validate URL scheme for security
                parsed = urlparse(url)
                if parsed.scheme not in {"http", "https"}:
                    msg = f"Unsupported URL scheme: {parsed.scheme}"
                    raise ValueError(msg)

                def check_url() -> tuple[int, str | None]:
                    if requests is not None:
                        response = requests.get(
                            url,
                            headers={"User-Agent": self.user_agent},
                            timeout=self.timeout,
                            allow_redirects=True,
                        )
                        return response.status_code, response.url
                    # Fallback to urlopen with validation
                    parsed = urlparse(url)
                    if parsed.scheme not in {"http", "https"}:
                        msg = "Unsupported URL scheme"
                        raise ValueError(msg) from None
                    req = Request(url, headers={"User-Agent": self.user_agent})
                    with urlopen(req, timeout=self.timeout) as response:
                        return response.status, getattr(response, "url", None)

                _status_code, response_url = await asyncio.to_thread(check_url)
                response_time = time.time() - start_time

                # Check for redirects
                redirect_url = None
                if response_url and response_url != url:
                    redirect_url = response_url

                return LinkValidationResult(
                    url=url,
                    status="valid",
                    response_time=response_time,
                    redirect_url=redirect_url,
                )

            except HTTPError as e:
                response_time = time.time() - start_time
                if e.code == 404:
                    return LinkValidationResult(
                        url=url,
                        status="not_found",
                        response_time=response_time,
                        error_message=f"HTTP {e.code}: {e.reason}",
                    )
                if e.code >= 400:
                    return LinkValidationResult(
                        url=url,
                        status="error",
                        response_time=response_time,
                        error_message=f"HTTP {e.code}: {e.reason}",
                    )
                # For other HTTP errors, continue to retry

            except URLError as e:
                response_time = time.time() - start_time
                if attempt == self.max_retries - 1:
                    return LinkValidationResult(
                        url=url,
                        status="error",
                        response_time=response_time,
                        error_message=str(e.reason),
                    )

            except Exception as e:
                response_time = time.time() - start_time
                if attempt == self.max_retries - 1:
                    return LinkValidationResult(
                        url=url,
                        status="error",
                        response_time=response_time,
                        error_message=str(e),
                    )

            # Wait before retry
            if attempt < self.max_retries - 1:
                await asyncio.sleep(1 * (attempt + 1))

        # Should not reach here, but just in case
        return LinkValidationResult(
            url=url,
            status="error",
            response_time=time.time() - start_time,
            error_message="Max retries exceeded",
        )

    def validate_internal_link(
        self, from_file: Path, url: str
    ) -> tuple[bool, str | None]:
        """Validate an internal link or reference."""
        try:
            if url.startswith("#"):
                # Anchor link - check if heading exists in same file
                content = from_file.read_text(encoding="utf-8")
                anchor = url[1:].lower().replace("-", " ")

                # Look for heading with similar text
                headings = re.findall(
                    r"^#{1,6}\s+(.+)$", content, re.MULTILINE | re.IGNORECASE
                )
                for heading in headings:
                    if anchor in heading.lower():
                        return True, None

                return False, f"Anchor '{url}' not found in document"

            if url.startswith(("./", "../")):
                # Relative file path
                target_path = (from_file.parent / url).resolve()

                if target_path.exists() and target_path.is_file():
                    return True, None
                return False, f"File not found: {target_path}"

            # Absolute path from project root
            target_path = (self.project_root / url).resolve()

            if target_path.exists() and target_path.is_file():
                return True, None
            return False, f"File not found: {target_path}"

        except Exception as e:
            return False, f"Error checking link: {e!s}"

    def validate_image_link(self, from_file: Path, url: str) -> tuple[bool, str | None]:
        """Validate an image link."""
        try:
            if url.startswith("http"):
                # For external images, just check URL format
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    return True, None
                return False, "Invalid URL format"
            # Local image file
            if url.startswith(("./", "../")):
                image_path = (from_file.parent / url).resolve()
            else:
                image_path = (self.project_root / url).resolve()

            if image_path.exists() and image_path.is_file():
                # Check if it's actually an image
                valid_extensions = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
                if image_path.suffix.lower() in valid_extensions:
                    return True, None
                return (
                    False,
                    f"File exists but not a recognized image format: {image_path.suffix}",
                )
            return False, f"Image file not found: {image_path}"

        except Exception as e:
            return False, f"Error checking image: {e!s}"

    async def audit_document_links(self, doc_file: Path) -> list[LinkIssue]:
        """Audit all links in a single document."""
        issues: list[LinkIssue] = []

        try:
            content = await asyncio.to_thread(doc_file.read_text, encoding="utf-8")
            content.split("\n")

            # Find all markdown links
            link_pattern = r"\[([^\]]+)\]\(([^)]+)\)"
            for match in re.finditer(link_pattern, content):
                link_text = match.group(1)
                url = match.group(2)

                # Find line number
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_number = content[:line_start].count("\n") + 1

                if url.startswith("http"):
                    # External link - validate
                    result = await self.validate_external_link(url)

                    if result.status != "valid":
                        severity = "high" if result.status == "not_found" else "medium"
                        suggestion = None

                        if result.status == "not_found":
                            suggestion = (
                                "Check if URL is correct or update to new location"
                            )
                        elif result.redirect_url:
                            suggestion = (
                                f"Update to redirect URL: {result.redirect_url}"
                            )

                        issues.append(
                            LinkIssue(
                                file_path=doc_file,
                                line_number=line_number,
                                link_text=link_text,
                                url=url,
                                issue_type="broken_external_link",
                                severity=severity,
                                suggestion=suggestion,
                            )
                        )

                else:
                    # Internal link - validate
                    is_valid, error_msg = self.validate_internal_link(doc_file, url)

                    if not is_valid:
                        issues.append(
                            LinkIssue(
                                file_path=doc_file,
                                line_number=line_number,
                                link_text=link_text,
                                url=url,
                                issue_type="broken_internal_link",
                                severity="high",
                                suggestion=error_msg or "Check file path and anchor",
                            )
                        )

            # Find all image links
            image_pattern = r"!\[([^\]]*)\]\(([^)]+)\)"
            for match in re.finditer(image_pattern, content):
                alt_text = match.group(1)
                url = match.group(2)

                # Find line number
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_number = content[:line_start].count("\n") + 1

                is_valid, error_msg = self.validate_image_link(doc_file, url)

                if not is_valid:
                    issues.append(
                        LinkIssue(
                            file_path=doc_file,
                            line_number=line_number,
                            link_text=f"![{alt_text}]",
                            url=url,
                            issue_type="broken_image_link",
                            severity="medium",
                            suggestion=error_msg or "Check image path and format",
                        )
                    )

                # Check for missing alt text
                if not alt_text.strip():
                    issues.append(
                        LinkIssue(
                            file_path=doc_file,
                            line_number=line_number,
                            link_text=f"![{alt_text}]",
                            url=url,
                            issue_type="missing_alt_text",
                            severity="low",
                            suggestion="Add descriptive alt text for accessibility",
                        )
                    )

        except Exception as e:
            # Add a general file processing error
            issues.append(
                LinkIssue(
                    file_path=doc_file,
                    line_number=0,
                    link_text="",
                    url="",
                    issue_type="file_processing_error",
                    severity="high",
                    suggestion=f"Error processing file: {e!s}",
                )
            )

        return issues

    def discover_docs_files(self) -> list[Path]:
        """Discover all documentation files."""
        docs_files = []

        # Find all markdown files
        for pattern in ["*.md", "*.mdx"]:
            docs_files.extend(self.project_root.rglob(pattern))

        # Filter out archive files
        return [doc for doc in docs_files if "archive" not in str(doc)]

    async def run_link_audit(self) -> dict[str, object]:
        """Run comprehensive link audit."""
        print("🔗 Starting comprehensive link validation...")

        docs_files = self.discover_docs_files()
        print(f"📁 Found {len(docs_files)} documentation files to audit")

        all_issues: list[LinkIssue] = []

        # Process files concurrently with semaphore to avoid overwhelming servers
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        async def audit_with_semaphore(doc_file: Path) -> list[LinkIssue]:
            async with semaphore:
                return await self.audit_document_links(doc_file)

        # Create tasks for all files
        tasks = [audit_with_semaphore(doc_file) for doc_file in docs_files]

        # Process in batches to show progress
        batch_size = 5
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i : i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)

            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    print(f"❌ Error processing {docs_files[i + j]}: {result}")
                else:
                    all_issues.extend(result)

            processed = min(i + batch_size, len(docs_files))
            print(f"📊 Processed {processed}/{len(docs_files)} files...")

        # Organize results
        self.results["validation_results"] = {
            "total_files_audited": len(docs_files),
            "total_issues_found": len(all_issues),
            "issues_by_type": {},
            "issues_by_severity": {},
            "issues_by_file": {},
        }

        # Categorize issues
        for issue in all_issues:
            # By type
            issue_type = issue.issue_type
            if issue_type not in self.results["validation_results"]["issues_by_type"]:
                self.results["validation_results"]["issues_by_type"][issue_type] = []
            self.results["validation_results"]["issues_by_type"][issue_type].append({
                "file": str(issue.file_path.relative_to(self.project_root)),
                "line": issue.line_number,
                "text": issue.link_text,
                "url": issue.url,
                "severity": issue.severity,
                "suggestion": issue.suggestion,
            })

            # By severity
            severity = issue.severity
            if severity not in self.results["validation_results"]["issues_by_severity"]:
                self.results["validation_results"]["issues_by_severity"][severity] = 0
            self.results["validation_results"]["issues_by_severity"][severity] += 1

            # By file
            file_path = str(issue.file_path.relative_to(self.project_root))
            if file_path not in self.results["validation_results"]["issues_by_file"]:
                self.results["validation_results"]["issues_by_file"][file_path] = []
            self.results["validation_results"]["issues_by_file"][file_path].append({
                "line": issue.line_number,
                "text": issue.link_text,
                "url": issue.url,
                "type": issue.issue_type,
                "severity": issue.severity,
                "suggestion": issue.suggestion,
            })

        # Store raw issues for further processing
        self.results["issues"] = all_issues

        # Calculate statistics
        self._calculate_statistics()

        print(
            f"✅ Link audit complete! Found {len(all_issues)} issues across {len(docs_files)} files"
        )
        return self.results

    def _calculate_statistics(self) -> None:
        """Calculate validation statistics."""
        issues = self.results.get("issues", [])
        validation_results = self.results["validation_results"]

        # Response time statistics (for external links)
        response_times = [
            issue.response_time
            for issue in issues
            if hasattr(issue, "response_time") and issue.response_time
        ]

        validation_results["statistics"] = {
            "total_links_checked": sum(
                len(issues_list)
                for issues_list in validation_results["issues_by_type"].values()
            ),
            "broken_links": len(
                validation_results["issues_by_type"].get("broken_external_link", [])
            )
            + len(validation_results["issues_by_type"].get("broken_internal_link", [])),
            "broken_images": len(
                validation_results["issues_by_type"].get("broken_image_link", [])
            ),
            "accessibility_issues": len(
                validation_results["issues_by_type"].get("missing_alt_text", [])
            ),
            "avg_response_time": sum(response_times) / len(response_times)
            if response_times
            else 0,
            "files_with_issues": len(validation_results["issues_by_file"]),
        }

    def generate_report(self) -> dict[str, object]:
        """Generate comprehensive validation report."""
        return {
            "summary": {
                "timestamp": self.results["timestamp"],
                "total_files_audited": self.results["validation_results"][
                    "total_files_audited"
                ],
                "total_issues_found": self.results["validation_results"][
                    "total_issues_found"
                ],
                "quality_score": self._calculate_quality_score(),
            },
            "issues_by_severity": self.results["validation_results"][
                "issues_by_severity"
            ],
            "issues_by_type": {
                k: len(v)
                for k, v in self.results["validation_results"]["issues_by_type"].items()
            },
            "statistics": self.results["validation_results"]["statistics"],
            "recommendations": self._generate_recommendations(),
            "detailed_issues": self.results["validation_results"]["issues_by_file"],
        }

    def _calculate_quality_score(self) -> int:
        """Calculate overall link quality score."""
        stats = self.results["validation_results"]["statistics"]
        total_links = stats["total_links_checked"]

        if total_links == 0:
            return 100

        # Weight different issue types
        broken_weight = 20  # Most severe
        image_weight = 10  # Less severe but important
        accessibility_weight = 5  # Minor but good practice

        broken_penalty = (stats["broken_links"] / total_links) * broken_weight
        image_penalty = (stats["broken_images"] / total_links) * image_weight
        accessibility_penalty = (
            stats["accessibility_issues"] / total_links
        ) * accessibility_weight

        total_penalty = broken_penalty + image_penalty + accessibility_penalty
        score = max(0, 100 - total_penalty)

        return int(score)

    def _generate_recommendations(self) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []
        stats = self.results["validation_results"]["statistics"]

        if stats["broken_links"] > 0:
            recommendations.append(
                f"🔴 CRITICAL: Fix {stats['broken_links']} broken links immediately"
            )

        if stats["broken_images"] > 0:
            recommendations.append(
                f"🟡 IMPORTANT: Fix {stats['broken_images']} broken image links"
            )

        if stats["accessibility_issues"] > 0:
            recommendations.append(
                f"🔵 ACCESSIBILITY: Add alt text to {stats['accessibility_issues']} images"
            )

        if stats["files_with_issues"] > 5:
            recommendations.append(
                f"📊 CONSIDER: {stats['files_with_issues']} files have link issues - review systematically"
            )

        if self._calculate_quality_score() > 90:
            recommendations.append("✅ EXCELLENT: Link quality is very high")

        return recommendations

    def save_report(self, output_path: Path | None = None) -> Path:
        """Save validation report to file."""
        if output_path is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = self.project_root / f"link_audit_{timestamp}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate_report()
        with Path(output_path).open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📄 Link validation report saved to: {output_path}")
        return output_path

    def print_summary(self) -> None:
        """Print validation summary to console."""
        report = self.generate_report()

        print("\n" + "=" * 60)
        print("🔗 LINK VALIDATION SUMMARY")
        print("=" * 60)

        summary = report["summary"]
        print(f"📈 Quality Score: {summary['quality_score']}/100")
        print(f"📁 Files Audited: {summary['total_files_audited']}")
        print(f"🔍 Issues Found: {summary['total_issues_found']}")

        severity_breakdown = report["issues_by_severity"]
        if severity_breakdown:
            print("\n📊 Issues by Severity:")
            for severity, count in severity_breakdown.items():
                print(f"  {severity.capitalize()}: {count}")

        type_breakdown = report["issues_by_type"]
        if type_breakdown:
            print("\n📋 Issues by Type:")
            for issue_type, count in type_breakdown.items():
                print(f"  {issue_type.replace('_', ' ').title()}: {count}")

        stats = report["statistics"]
        print("\n📈 Statistics:")
        print(f"  Links Checked: {stats['total_links_checked']}")
        print(f"  Broken Links: {stats['broken_links']}")
        print(f"  Broken Images: {stats['broken_images']}")
        print(f"  Accessibility Issues: {stats['accessibility_issues']}")

        recommendations = report["recommendations"]
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  {rec}")

        print("\n" + "=" * 60)


def main() -> None:
    """Main entry point for link validation."""
    parser = argparse.ArgumentParser(description="FLEXT Auth Link Validation System")
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )
    parser.add_argument("--output", type=Path, help="Output file for validation report")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Timeout for external link checks"
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )

    args = parser.parse_args()

    # Initialize validator
    validator = LinkValidator(args.project_root, timeout=args.timeout)

    # Run comprehensive validation
    asyncio.run(validator.run_link_audit())

    # Save detailed report
    validator.save_report(args.output)

    # Print summary
    if args.format == "text":
        validator.print_summary()
    else:
        print(json.dumps(validator.generate_report(), indent=2))


if __name__ == "__main__":
    main()
