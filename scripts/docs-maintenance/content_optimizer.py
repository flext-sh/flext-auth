#!/usr/bin/env python3
"""FLEXT Auth Documentation Content Optimizer.

Automated content optimization, enhancement, and maintenance tools
for flext-auth project documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class OptimizationSuggestion:
    """Represents an optimization suggestion."""

    file_path: Path
    line_number: int
    content_type: str
    issue: str
    suggestion: str
    severity: str
    auto_fixable: bool = False
    fix_content: str | None = None


@dataclass
class ContentMetrics:
    """Content quality metrics."""

    readability_score: float
    structure_score: float
    completeness_score: float
    technical_accuracy: float
    overall_quality: float


class ContentOptimizer:
    """Comprehensive content optimization and enhancement system."""

    def __init__(self, project_root: Path) -> None:
        """Initialize content optimizer with project root."""
        self.project_root = project_root
        self.suggestions: list[OptimizationSuggestion] = []
        self.metrics: dict[str, ContentMetrics] = {}

    def analyze_document(self, doc_file: Path) -> list[OptimizationSuggestion]:
        """Analyze a single document for optimization opportunities."""
        suggestions: list[OptimizationSuggestion] = []

        try:
            content = doc_file.read_text(encoding="utf-8")
            lines = content.split("\n")

            # Analyze structure and formatting
            suggestions.extend(self._analyze_structure(content, doc_file))

            # Analyze content quality
            suggestions.extend(self._analyze_content_quality(content, doc_file))

            # Analyze technical content
            suggestions.extend(self._analyze_technical_content(content, doc_file))

            # Check for common issues
            suggestions.extend(self._check_common_issues(content, doc_file, lines))

            # Check for enhancement opportunities
            suggestions.extend(self._check_enhancement_opportunities(content, doc_file))

        except Exception as e:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,
                    content_type="file_error",
                    issue=f"Error analyzing file: {e!s}",
                    suggestion="Check file encoding and accessibility",
                    severity="high",
                )
            )

        return suggestions

    def _analyze_structure(
        self, content: str, doc_file: Path
    ) -> list[OptimizationSuggestion]:
        """Analyze document structure."""
        suggestions: list[OptimizationSuggestion] = []

        # Check for table of contents
        if not self._has_table_of_contents(content) and len(content) > 2000:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=1,
                    content_type="structure",
                    issue="Missing table of contents in long document",
                    suggestion="Add a table of contents for better navigation",
                    severity="medium",
                    auto_fixable=True,
                )
            )

        # Check heading hierarchy
        headings = re.findall(r"^(#{1,6})\s+(.+)$", content, re.MULTILINE)
        hierarchy_issues = self._check_heading_hierarchy(headings)

        for level, title in hierarchy_issues:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,  # Would need more complex line finding
                    content_type="structure",
                    issue=f"Inconsistent heading hierarchy at level {level}: '{title}'",
                    suggestion="Ensure proper heading hierarchy (h1 -> h2 -> h3, etc.)",
                    severity="low",
                )
            )

        # Check for missing frontmatter
        if not self._has_frontmatter(content):
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=1,
                    content_type="metadata",
                    issue="Missing frontmatter metadata",
                    suggestion="Add YAML frontmatter with title, date, and description",
                    severity="low",
                    auto_fixable=True,
                )
            )

        return suggestions

    def _analyze_content_quality(
        self, content: str, doc_file: Path
    ) -> list[OptimizationSuggestion]:
        """Analyze content quality."""
        suggestions: list[OptimizationSuggestion] = []

        # Check word count and readability
        words = re.findall(r"\b\w+\b", content)
        word_count = len(words)

        if word_count < 100:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,
                    content_type="content",
                    issue=f"Document is too short ({word_count} words)",
                    suggestion="Expand content with more detailed explanations and examples",
                    severity="medium",
                )
            )

        # Check for passive voice (simple heuristic)
        passive_indicators = ["is", "are", "was", "were", "be", "been", "being"]
        sentences = re.split(r"[.!?]+", content)
        passive_sentences = 0

        for sentence in sentences:
            words_in_sentence = sentence.lower().split()
            if any(indicator in words_in_sentence for indicator in passive_indicators):
                passive_sentences += 1

        passive_ratio = passive_sentences / max(len(sentences), 1)
        if passive_ratio > 0.3:  # More than 30% passive
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,
                    content_type="style",
                    issue="High use of passive voice detected",
                    suggestion="Consider using more active voice for clarity",
                    severity="low",
                )
            )

        # Check for long paragraphs
        paragraphs = re.split(r"\n\s*\n", content)
        long_paragraphs = [p for p in paragraphs if len(p.split()) > 150]

        # Limit to first 3 examples
        suggestions.extend(
            OptimizationSuggestion(
                file_path=doc_file,
                line_number=0,
                content_type="readability",
                issue="Very long paragraph detected",
                suggestion="Break long paragraphs into shorter, more readable sections",
                severity="low",
            )
            for para in long_paragraphs[:3]
        )

        return suggestions

    def _analyze_technical_content(
        self, content: str, doc_file: Path
    ) -> list[OptimizationSuggestion]:
        """Analyze technical content quality."""
        suggestions: list[OptimizationSuggestion] = []

        # Check for code examples without language specification
        code_blocks = re.findall(r"```(\w+)?\n(.*?)\n```", content, re.DOTALL)
        for lang, code in code_blocks:
            if not lang and len(code.strip()) > 50:  # Non-trivial code without language
                suggestions.append(
                    OptimizationSuggestion(
                        file_path=doc_file,
                        line_number=0,
                        content_type="technical",
                        issue="Code block without language specification",
                        suggestion="Specify programming language for syntax highlighting",
                        severity="low",
                    )
                )

        # Check for outdated version references
        version_patterns = [
            r"version\s*[\d\.]+\s*\(deprecated\)",
            r"v\d+\.\d+\.\d+\s*\(old\)",
            r"legacy.*version",
        ]

        suggestions.extend(
            OptimizationSuggestion(
                file_path=doc_file,
                line_number=0,
                content_type="technical",
                issue="Possible outdated version reference",
                suggestion="Verify version information is current",
                severity="medium",
            )
            for pattern in version_patterns
            if re.search(pattern, content, re.IGNORECASE)
        )

        # Check for TODO/FIXME markers
        todo_markers = re.findall(
            r"(?i)(todo|fixme|hack|xxx|note).*?:?\s*(.+)?", content
        )
        for marker, description in todo_markers:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,
                    content_type="maintenance",
                    issue=f"Unresolved {marker.upper()} marker: {description or 'No description'}",
                    suggestion="Address or remove TODO/FIXME markers",
                    severity="medium",
                )
            )

        return suggestions

    def _check_common_issues(
        self, _content: str, doc_file: Path, lines: list[str]
    ) -> list[OptimizationSuggestion]:
        """Check for common documentation issues."""
        suggestions: list[OptimizationSuggestion] = []

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check for trailing whitespace
            if line.rstrip() != line:
                suggestions.append(
                    OptimizationSuggestion(
                        file_path=doc_file,
                        line_number=line_num,
                        content_type="formatting",
                        issue="Trailing whitespace detected",
                        suggestion="Remove trailing whitespace",
                        severity="low",
                        auto_fixable=True,
                        fix_content=line.rstrip(),
                    )
                )

            # Check for inconsistent list formatting
            if re.match(r"^\s*[-*+]\s+", line):
                # Check if mixed with numbered lists nearby
                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 3)
                context = lines[context_start:context_end]

                has_numbered = any(
                    re.match(r"^\s*\d+\.", context_line) for context_line in context
                )
                if has_numbered:
                    suggestions.append(
                        OptimizationSuggestion(
                            file_path=doc_file,
                            line_number=line_num,
                            content_type="formatting",
                            issue="Mixed list types (bulleted and numbered) in close proximity",
                            suggestion="Use consistent list formatting",
                            severity="low",
                        )
                    )

            # Check for broken emphasis patterns
            emphasis_issues = re.findall(
                r"(\*{1,3}[^*]*\*{0,2}(?!\*))|(\*{0,2}[^*]*\*{1,3})", line
            )
            if emphasis_issues and not re.match(r"^\s*```", line):  # Not in code block
                suggestions.append(
                    OptimizationSuggestion(
                        file_path=doc_file,
                        line_number=line_num,
                        content_type="formatting",
                        issue="Possible broken emphasis formatting",
                        suggestion="Check markdown emphasis syntax (*italic*, **bold**, etc.)",
                        severity="low",
                    )
                )

        return suggestions

    def _check_enhancement_opportunities(
        self, content: str, doc_file: Path
    ) -> list[OptimizationSuggestion]:
        """Check for content enhancement opportunities."""
        suggestions: list[OptimizationSuggestion] = []

        # Check for missing examples in technical content
        if "function" in content.lower() or "class" in content.lower():
            code_blocks = len(re.findall(r"```", content))
            if code_blocks == 0:
                suggestions.append(
                    OptimizationSuggestion(
                        file_path=doc_file,
                        line_number=0,
                        content_type="enhancement",
                        issue="Technical content without code examples",
                        suggestion="Add practical code examples to illustrate concepts",
                        severity="medium",
                    )
                )

        # Check for missing links to related documentation
        internal_links = len(re.findall(r"\[([^\]]+)\]\((?!http)", content))
        if internal_links == 0 and len(content) > 1000:
            suggestions.append(
                OptimizationSuggestion(
                    file_path=doc_file,
                    line_number=0,
                    content_type="enhancement",
                    issue="No internal cross-references",
                    suggestion="Add links to related documentation sections",
                    severity="low",
                )
            )

        # Check for missing status indicators in technical docs
        if any(
            keyword in content.lower()
            for keyword in ["api", "implementation", "status", "version"]
        ):
            status_indicators = len(re.findall(r"(✅|❌|⚠️|🚧|📅)", content))
            if status_indicators == 0:
                suggestions.append(
                    OptimizationSuggestion(
                        file_path=doc_file,
                        line_number=0,
                        content_type="enhancement",
                        issue="Technical documentation without status indicators",
                        suggestion="Add status indicators (✅❌⚠️) for clarity",
                        severity="low",
                    )
                )

        return suggestions

    def _has_table_of_contents(self, content: str) -> bool:
        """Check if document has a table of contents."""
        toc_patterns = [
            r"(table of contents|contents|toc)",
            r"^\s*[-*+]\s*\[.*\]\(.*\)",  # Link lists
            r"^\d+\.\s*\[.*\]\(.*\)",  # Numbered link lists
        ]

        content_lower = content.lower()
        return any(
            re.search(pattern, content_lower, re.IGNORECASE | re.MULTILINE)
            for pattern in toc_patterns
        )

    def _check_heading_hierarchy(
        self, headings: list[tuple[str, str]]
    ) -> list[tuple[int, str]]:
        """Check heading hierarchy for consistency."""
        issues = []
        prev_level = 0

        for level_str, title in headings:
            level = len(level_str)
            if level > prev_level + 1 and prev_level > 0:
                issues.append((level, title))
            prev_level = level

        return issues

    def _has_frontmatter(self, content: str) -> bool:
        """Check if document has YAML frontmatter."""
        return content.startswith("---\n") and "---\n" in content[4:]

    def discover_docs_files(self) -> list[Path]:
        """Discover all documentation files."""
        docs_files = []

        # Find all markdown files
        for pattern in ["*.md", "*.mdx"]:
            docs_files.extend(self.project_root.rglob(pattern))

        # Filter out archive files
        return [doc for doc in docs_files if "archive" not in str(doc)]

    def run_optimization_audit(self) -> dict[str, object]:
        """Run comprehensive content optimization audit."""
        print("🔍 Starting content optimization audit...")

        docs_files = self.discover_docs_files()
        print(f"📁 Found {len(docs_files)} documentation files to analyze")

        all_suggestions: list[OptimizationSuggestion] = []

        for doc_file in docs_files:
            suggestions = self.analyze_document(doc_file)
            all_suggestions.extend(suggestions)

            # Calculate metrics for this file
            self.metrics[str(doc_file.relative_to(self.project_root))] = (
                self._calculate_metrics(suggestions)
            )

        # Organize results
        results = {
            "timestamp": datetime.now(UTC).isoformat(),
            "total_files_analyzed": len(docs_files),
            "total_suggestions": len(all_suggestions),
            "suggestions_by_severity": {},
            "suggestions_by_type": {},
            "suggestions_by_file": {},
            "quality_metrics": self.metrics,
            "auto_fixable_count": len([s for s in all_suggestions if s.auto_fixable]),
        }

        # Categorize suggestions
        for suggestion in all_suggestions:
            # By severity
            severity = suggestion.severity
            if severity not in results["suggestions_by_severity"]:
                results["suggestions_by_severity"][severity] = 0
            results["suggestions_by_severity"][severity] += 1

            # By type
            content_type = suggestion.content_type
            if content_type not in results["suggestions_by_type"]:
                results["suggestions_by_type"][content_type] = 0
            results["suggestions_by_type"][content_type] += 1

            # By file
            file_path = str(suggestion.file_path.relative_to(self.project_root))
            if file_path not in results["suggestions_by_file"]:
                results["suggestions_by_file"][file_path] = []
            results["suggestions_by_file"][file_path].append({
                "line": suggestion.line_number,
                "type": suggestion.content_type,
                "issue": suggestion.issue,
                "suggestion": suggestion.suggestion,
                "severity": suggestion.severity,
                "auto_fixable": suggestion.auto_fixable,
            })

        print(
            f"✅ Optimization audit complete! Found {len(all_suggestions)} suggestions across {len(docs_files)} files"
        )
        return results

    def _calculate_metrics(
        self, suggestions: list[OptimizationSuggestion]
    ) -> ContentMetrics:
        """Calculate content quality metrics for a file."""
        # Simple heuristic-based scoring
        structure_score = (
            100 - len([s for s in suggestions if s.content_type == "structure"]) * 10
        )
        readability_score = (
            100 - len([s for s in suggestions if s.content_type == "readability"]) * 5
        )
        completeness_score = (
            100 - len([s for s in suggestions if s.content_type == "content"]) * 15
        )
        technical_score = (
            100 - len([s for s in suggestions if s.content_type == "technical"]) * 10
        )

        overall_quality = (
            structure_score + readability_score + completeness_score + technical_score
        ) / 4

        return ContentMetrics(
            readability_score=max(0, min(100, readability_score)),
            structure_score=max(0, min(100, structure_score)),
            completeness_score=max(0, min(100, completeness_score)),
            technical_accuracy=max(0, min(100, technical_score)),
            overall_quality=max(0, min(100, overall_quality)),
        )

    def generate_report(self) -> dict[str, object]:
        """Generate comprehensive optimization report."""
        audit_results = self.run_optimization_audit()

        return {
            "summary": {
                "timestamp": audit_results["timestamp"],
                "files_analyzed": audit_results["total_files_analyzed"],
                "total_suggestions": audit_results["total_suggestions"],
                "auto_fixable": audit_results["auto_fixable_count"],
                "average_quality_score": sum(
                    m.overall_quality for m in audit_results["quality_metrics"].values()
                )
                / max(len(audit_results["quality_metrics"]), 1),
            },
            "severity_breakdown": audit_results["suggestions_by_severity"],
            "type_breakdown": audit_results["suggestions_by_type"],
            "recommendations": self._generate_recommendations(audit_results),
            "quality_metrics": {
                k: {
                    "overall_quality": v.overall_quality,
                    "readability": v.readability_score,
                    "structure": v.structure_score,
                    "completeness": v.completeness_score,
                    "technical_accuracy": v.technical_accuracy,
                }
                for k, v in audit_results["quality_metrics"].items()
            },
            "detailed_suggestions": audit_results["suggestions_by_file"],
        }

    def _generate_recommendations(self, audit_results: dict[str, object]) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []

        audit_results["total_suggestions"]
        auto_fixable = audit_results["auto_fixable_count"]
        avg_quality = audit_results.get("summary", {}).get("average_quality_score", 0)

        if auto_fixable > 0:
            recommendations.append(
                f"🤖 AUTOMATION: {auto_fixable} issues can be auto-fixed"
            )

        severity_breakdown = audit_results["suggestions_by_severity"]
        if severity_breakdown.get("high", 0) > 0:
            recommendations.append(
                f"🔴 PRIORITY: Address {severity_breakdown['high']} high-severity issues first"
            )

        if avg_quality < 70:
            recommendations.append(
                f"🟡 IMPROVE: Overall documentation quality needs attention ({avg_quality:.1f}/100)"
            )
        elif avg_quality > 90:
            recommendations.append(
                "✅ EXCELLENT: High content quality standards maintained"
            )

        type_breakdown = audit_results["suggestions_by_type"]
        if type_breakdown.get("structure", 0) > 5:
            recommendations.append(
                "🏗️ STRUCTURE: Multiple files need structural improvements"
            )

        if type_breakdown.get("technical", 0) > 3:
            recommendations.append("🔧 TECHNICAL: Review technical content accuracy")

        return recommendations

    def save_report(self, output_path: Path | None = None) -> Path:
        """Save optimization report to file."""
        if output_path is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            output_path = self.project_root / f"content_optimization_{timestamp}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = self.generate_report()
        with Path(output_path).open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"📄 Content optimization report saved to: {output_path}")
        return output_path

    def print_summary(self) -> None:
        """Print optimization summary to console."""
        report = self.generate_report()

        print("\n" + "=" * 60)
        print("🔍 CONTENT OPTIMIZATION SUMMARY")
        print("=" * 60)

        summary = report["summary"]
        print(f"📈 Quality Score: {summary['average_quality_score']:.1f}/100")
        print(f"📁 Files Analyzed: {summary['files_analyzed']}")
        print(f"💡 Suggestions: {summary['total_suggestions']}")
        print(f"🤖 Auto-fixable: {summary['auto_fixable']}")

        severity_breakdown = report["severity_breakdown"]
        if severity_breakdown:
            print("\n📊 Suggestions by Severity:")
            for severity, count in severity_breakdown.items():
                print(f"  {severity.capitalize()}: {count}")

        type_breakdown = report["type_breakdown"]
        if type_breakdown:
            print("\n📋 Suggestions by Type:")
            for issue_type, count in type_breakdown.items():
                print(f"  {issue_type.title()}: {count}")

        recommendations = report["recommendations"]
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  {rec}")

        print("\n" + "=" * 60)


def main() -> None:
    """Main entry point for content optimization."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth Content Optimization System"
    )
    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )
    parser.add_argument(
        "--output", type=Path, help="Output file for optimization report"
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )

    args = parser.parse_args()

    # Initialize optimizer
    optimizer = ContentOptimizer(args.project_root)

    # Generate report (this runs the audit)
    report = optimizer.generate_report()

    # Save detailed report
    optimizer.save_report(args.output)

    # Print summary
    if args.format == "text":
        optimizer.print_summary()
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
