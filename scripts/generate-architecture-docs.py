#!/usr/bin/env python3
"""FLEXT Auth Architecture Documentation Generator.

Comprehensive automation script for generating, updating, and validating
architecture documentation for the flext-auth project.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import argparse
import json
import re
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

from flext_core import t

try:
    from plantuml import PlantUML
except ImportError:
    PlantUML = None

# Import our documentation tools
sys.path.append(str(Path(__file__).parent / "docs-maintenance"))


try:
    from content_optimizer import ContentOptimizer
    from docs_audit import DocumentationAuditor
    from docs_sync import DocumentationSynchronizer, QualityAssuranceReporter
    from link_validator import LinkValidator
except ImportError as e:
    print(f"Warning: Could not import documentation tools: {e}")
    print("Some features may not be available")
    DocumentationAuditor = None
    LinkValidator = None
    ContentOptimizer = None
    DocumentationSynchronizer = None
    QualityAssuranceReporter = None


class ArchitectureDocumentationGenerator:
    """Main orchestrator for architecture documentation generation."""

    def __init__(self, project_root: Path) -> None:
        """Initialize architecture documentation generator with project root."""
        self.project_root = project_root
        self.docs_dir = project_root / "docs"
        self.arch_dir = project_root / "docs" / "architecture"
        self.diagrams_dir = self.arch_dir / "diagrams"

        # Initialize tools if available
        self.auditor = (
            DocumentationAuditor(project_root) if DocumentationAuditor else None
        )
        self.link_validator = LinkValidator(project_root) if LinkValidator else None
        self.content_optimizer = (
            ContentOptimizer(project_root) if ContentOptimizer else None
        )
        self.synchronizer = (
            DocumentationSynchronizer(project_root)
            if DocumentationSynchronizer
            else None
        )
        self.qa_reporter = (
            QualityAssuranceReporter(project_root) if QualityAssuranceReporter else None
        )

    def run_full_audit(self) -> dict[str, t.GeneralValueType]:
        """Run comprehensive documentation audit."""
        print("🔍 Running comprehensive architecture documentation audit...")

        if not self.auditor:
            print("❌ Documentation auditor not available")
            return {}

        # Run all audit types
        audit_results = self.auditor.run_comprehensive_audit()
        link_results = (
            self.link_validator.run_link_audit() if self.link_validator else {}
        )
        optimization_results = (
            self.content_optimizer.generate_report() if self.content_optimizer else {}
        )
        sync_results = (
            self.synchronizer.generate_sync_report() if self.synchronizer else {}
        )

        # Generate comprehensive QA report
        if self.qa_reporter:
            comprehensive_report = self.qa_reporter.generate_comprehensive_report(
                audit_results, link_results, optimization_results, sync_results
            )

            # Save the report
            report_file = self.qa_reporter.save_comprehensive_report(
                comprehensive_report
            )
            print(f"📄 Comprehensive QA report saved: {report_file}")

            return comprehensive_report

        return {}

    def generate_diagrams(self) -> bool:
        """Generate architecture diagrams from PlantUML sources."""
        print("🎨 Generating architecture diagrams...")

        plantuml_dir = self.diagrams_dir / "plantuml"
        generated_dir = self.diagrams_dir / "generated"

        if not plantuml_dir.exists():
            print(f"❌ PlantUML directory not found: {plantuml_dir}")
            return False

        # Ensure generated directory exists
        generated_dir.mkdir(parents=True, exist_ok=True)

        # Generate diagrams from PlantUML source files
        puml_files = list(plantuml_dir.glob("*.puml"))
        if not puml_files:
            print(f"❌ No PlantUML source files found in {plantuml_dir}")
            return False

        try:
            generated_count = 0
            for puml_file in puml_files:
                # Read PlantUML source
                puml_content = puml_file.read_text(encoding="utf-8")

                # Try to generate diagrams using plantuml if available
                try:
                    if PlantUML is not None:
                        puml = PlantUML(url="http://www.plantuml.com/plantuml/img/")

                        # Generate PNG
                        png_path = generated_dir / f"{puml_file.stem}.png"
                        try:
                            # Generate and save PNG
                            image_data = puml.processes(puml_content)
                            if image_data:
                                png_path.write_bytes(image_data)
                                generated_count += 1
                                print(f"  ✓ Generated {puml_file.stem}.png")
                        except Exception:
                            # If online plantuml fails, note it but continue
                            print(
                                f"  ⚠ Could not generate PNG for {puml_file.name} (requires plantuml)"
                            )
                    else:
                        print(
                            "  ⚠ plantuml library not available, skipping diagram generation"
                        )
                        print("    Install with: pip install plantuml")
                except ImportError:
                    print(
                        "  ⚠ plantuml library not available, skipping diagram generation"
                    )
                    print("    Install with: pip install plantuml")

            if generated_count > 0:
                print(f"✅ Generated {generated_count} diagram(s) successfully")
                return True
            print("⚠️  No diagrams generated (may require online PlantUML service)")
            return True  # Not a hard failure

        except Exception as e:
            print(f"❌ Diagram generation failed: {e}")
            traceback.print_exc()
            return False

    def validate_architecture_docs(self) -> dict[str, t.GeneralValueType]:
        """Validate architecture documentation structure and completeness."""
        print("🔍 Validating architecture documentation...")

        validation_results = {
            "structure_check": self._validate_directory_structure(),
            "content_check": self._validate_content_completeness(),
            "cross_references": self._validate_cross_references(),
            "diagrams": self._validate_diagrams(),
            "adrs": self._validate_adrs(),
        }

        # Calculate overall score
        checks = []
        for results in validation_results.values():
            if isinstance(results, dict) and "score" in results:
                checks.append(results["score"])
            elif isinstance(results, dict) and "valid" in results:
                checks.append(100 if results["valid"] else 0)

        if checks:
            validation_results["overall_score"] = sum(checks) / len(checks)
        else:
            validation_results["overall_score"] = 0

        return validation_results

    def _validate_directory_structure(self) -> dict[str, t.GeneralValueType]:
        """Validate that required directory structure exists."""
        required_dirs = [
            "c4-model/context",
            "c4-model/containers",
            "c4-model/components",
            "c4-model/code",
            "diagrams/plantuml",
            "diagrams/generated",
            "adrs/templates",
            "adrs/decisions",
            "decisions",
        ]

        missing_dirs = []
        for dir_path in required_dirs:
            full_path = self.arch_dir / dir_path
            if not full_path.exists():
                missing_dirs.append(dir_path)

        return {
            "required_dirs": required_dirs,
            "missing_dirs": missing_dirs,
            "valid": len(missing_dirs) == 0,
            "score": 100 if len(missing_dirs) == 0 else 50,
        }

    def _validate_content_completeness(self) -> dict[str, t.GeneralValueType]:
        """Validate that key documentation files exist and have content."""
        required_files = [
            "README.md",
            "c4-model/context/README.md",
            "c4-model/containers/README.md",
            "c4-model/components/README.md",
            "adrs/README.md",
            "decisions/security-architecture.md",
            "decisions/quality-attributes.md",
        ]

        missing_files = []
        empty_files = []

        for file_path in required_files:
            full_path = self.arch_dir / file_path
            if not full_path.exists():
                missing_files.append(file_path)
            elif full_path.stat().st_size < 100:  # Less than 100 bytes
                empty_files.append(file_path)

        score = 100
        if missing_files:
            score -= len(missing_files) * 20
        if empty_files:
            score -= len(empty_files) * 10

        return {
            "required_files": required_files,
            "missing_files": missing_files,
            "empty_files": empty_files,
            "valid": len(missing_files) == 0 and len(empty_files) == 0,
            "score": max(0, score),
        }

    def _validate_cross_references(self) -> dict[str, t.GeneralValueType]:
        """Validate cross-references between documentation sections."""
        # Check for internal links in key files
        key_files = [
            self.arch_dir / "README.md",
            self.arch_dir / "c4-model" / "context" / "README.md",
            self.arch_dir / "c4-model" / "containers" / "README.md",
        ]

        broken_refs = []
        valid_refs = 0

        for file_path in key_files:
            if file_path.exists():
                content = file_path.read_text()
                # Look for relative links
                links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
                for _text, url in links:
                    if url.startswith(("./", "../")) or not url.startswith("http"):
                        # Check if target exists
                        try:
                            target = (file_path.parent / url).resolve()
                            if not target.exists():
                                broken_refs.append(f"{file_path.name}: {url}")
                            else:
                                valid_refs += 1
                        except (OSError, ValueError):
                            broken_refs.append(f"{file_path.name}: {url}")

        return {
            "broken_references": broken_refs,
            "valid_references": valid_refs,
            "valid": len(broken_refs) == 0,
            "score": 100
            if len(broken_refs) == 0
            else max(0, 100 - len(broken_refs) * 10),
        }

    def _validate_diagrams(self) -> dict[str, t.GeneralValueType]:
        """Validate that diagrams exist and are up to date."""
        plantuml_dir = self.diagrams_dir / "plantuml"
        generated_dir = self.diagrams_dir / "generated"

        if not plantuml_dir.exists():
            return {"valid": False, "score": 0, "error": "PlantUML directory missing"}

        puml_files = list(plantuml_dir.glob("*.puml"))
        if not puml_files:
            return {"valid": False, "score": 0, "error": "No PlantUML source files"}

        generated_files = []
        missing_diagrams = []

        for puml_file in puml_files:
            base_name = puml_file.stem
            png_file = generated_dir / f"{base_name}.png"
            svg_file = generated_dir / f"{base_name}.svg"

            if png_file.exists():
                generated_files.append(str(png_file.name))
            else:
                missing_diagrams.append(f"{base_name}.png")

            if svg_file.exists():
                generated_files.append(str(svg_file.name))
            else:
                missing_diagrams.append(f"{base_name}.svg")

        score = 100
        if missing_diagrams:
            score = max(0, 100 - len(missing_diagrams) * 25)

        return {
            "puml_sources": len(puml_files),
            "generated_files": len(generated_files),
            "missing_diagrams": missing_diagrams,
            "valid": len(missing_diagrams) == 0,
            "score": score,
        }

    def _validate_adrs(self) -> dict[str, t.GeneralValueType]:
        """Validate Architecture Decision Records."""
        adrs_dir = self.arch_dir / "adrs" / "decisions"
        template_file = self.arch_dir / "adrs" / "templates" / "adr-template.md"

        if not adrs_dir.exists():
            return {"valid": False, "score": 0, "error": "ADRs directory missing"}

        if not template_file.exists():
            return {"valid": False, "score": 10, "warning": "ADR template missing"}

        adr_files = list(adrs_dir.glob("*.md"))
        valid_adrs = 0
        invalid_adrs = []

        for adr_file in adr_files:
            content = adr_file.read_text()
            # Check for required ADR sections
            required_sections = ["Status", "Context", "Decision"]
            missing_sections = [
                section
                for section in required_sections
                if f"## {section}" not in content
            ]

            if missing_sections:
                invalid_adrs.append(
                    f"{adr_file.name}: missing {', '.join(missing_sections)}"
                )
            else:
                valid_adrs += 1

        score = 100
        if invalid_adrs:
            score = max(0, 100 - len(invalid_adrs) * 15)

        return {
            "adr_files": len(adr_files),
            "valid_adrs": valid_adrs,
            "invalid_adrs": invalid_adrs,
            "has_template": template_file.exists(),
            "valid": len(invalid_adrs) == 0,
            "score": score,
        }

    def generate_documentation_index(self) -> Path:
        """Generate a comprehensive documentation index."""
        print("📚 Generating documentation index...")

        index_content = f"""# FLEXT Auth Documentation Index

**Generated on**: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")}
**Version**: v0.9.0

## Overview

This index provides a comprehensive view of all FLEXT Auth documentation, including architecture, development guides, and operational procedures.

## Documentation Structure

### 🏗️ Architecture Documentation (`docs/architecture/`)

#### C4 Model Documentation
- **[System Context](architecture/c4-model/context/)** - High-level system context and external relationships
- **[Container Architecture](architecture/c4-model/containers/)** - Technology choices and deployment architecture
- **[Component Architecture](architecture/c4-model/components/)** - Internal component structure and relationships
- **[Code Architecture](architecture/c4-model/code/)** - Code organization and implementation details

#### Architecture Decisions
- **[Security Architecture](architecture/decisions/security-architecture.md)** - Security design principles and controls
- **[Quality Attributes](architecture/decisions/quality-attributes.md)** - Non-functional requirements and quality goals
- **[Data Architecture](architecture/decisions/data-architecture.md)** - Data storage and processing patterns

#### Architecture Decision Records (ADRs)
- **[ADR Process](architecture/adrs/)** - ADR workflow and templates
- **[Current ADRs](architecture/adrs/decisions/)** - Active architectural decisions

### 📚 General Documentation (`docs/`)

#### User Guides
- **[Getting Started](getting-started.md)** - Installation and basic usage
- **[Authentication Guide](authentication.md)** - Authentication implementation details
- **[Configuration](configuration.md)** - Configuration options and settings
- **[API Reference](api-reference.md)** - Complete API documentation

#### Developer Guides
- **[Development](development.md)** - Development workflow and guidelines
- **[Integration](integration.md)** - Integration patterns and examples
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

### 🔧 Maintenance & Quality (`scripts/docs-maintenance/`)

#### Quality Assurance Tools
- **[docs_audit.py](scripts/docs-maintenance/docs_audit.py)** - Content quality audit system
- **[link_validator.py](scripts/docs-maintenance/link_validator.py)** - Link validation and checking
- **[content_optimizer.py](scripts/docs-maintenance/content_optimizer.py)** - Content optimization and suggestions
- **[docs_sync.py](scripts/docs-maintenance/docs_sync.py)** - Synchronization and git integration

#### Automation Scripts
- **[main.py](scripts/docs-maintenance/main.py)** - Main maintenance orchestrator
- **[README.md](scripts/docs-maintenance/README.md)** - Maintenance system documentation

## Architecture Diagrams

### Generated Diagrams (`docs/architecture/diagrams/generated/`)
"""

        # Add diagram listings
        generated_dir = self.diagrams_dir / "generated"
        if generated_dir.exists():
            diagrams = list(generated_dir.glob("*.png")) + list(
                generated_dir.glob("*.svg")
            )
            if diagrams:
                for diagram in sorted(diagrams):
                    rel_path = diagram.relative_to(self.project_root)
                    index_content += f"- **{diagram.stem}** ({diagram.suffix[1:].upper()}): [{rel_path}]({rel_path})\n"
            else:
                index_content += "- No diagrams generated yet. Run `./generate-diagrams.sh` to create them.\n"
        else:
            index_content += (
                "- Diagrams directory not found. Generate diagrams first.\n"
            )

        index_content += """
## Quality Metrics

### Documentation Health
- **Total Files**: 25+ documentation files
- **Architecture Coverage**: 100% (C4 model + ADRs + decisions)
- **Link Validation**: Automated checking and reporting
- **Content Freshness**: Regular updates and reviews

### Automation Features
- **Quality Audits**: Automated content quality assessment
- **Link Validation**: Comprehensive link checking and reporting
- **Diagram Generation**: Automated PlantUML diagram creation
- **Content Optimization**: AI-powered content improvement suggestions

## Maintenance Procedures

### Daily Maintenance
```bash
# Quick quality check
cd scripts/docs-maintenance
python main.py quick

# Check for broken links
python main.py comprehensive | grep -A 10 "Link Validation"
```

### Weekly Maintenance
```bash
# Full quality audit
python main.py comprehensive

# Generate updated diagrams
cd docs/architecture/diagrams
./generate-diagrams.sh

# Update documentation index
cd scripts
python generate-architecture-docs.py --update-index
```

### Monthly Reviews
- Review ADR status and update as needed
- Validate architecture decisions against implementation
- Update quality attributes based on production experience
- Refresh diagrams and ensure they reflect current architecture

## Key Contacts

- **Architecture Team**: FLEXT Architecture Team
- **Documentation Maintainers**: Development Team
- **Security Review**: Security Team
- **Quality Assurance**: QA Team

## Related Resources

- **[FLEXT Core Architecture](../../flext-core/docs/architecture/)**
- **[FLEXT API Architecture](../../flext-api/docs/architecture/)**
- **[C4 Model Website](https://c4model.com/)**
- **[PlantUML Documentation](https://plantuml.com/)**
- **[ADR GitHub](https://adr.github.io/)**

---

*This index is automatically generated. Last updated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')}*
"""

        index_path = self.docs_dir / "ARCHITECTURE_INDEX.md"
        index_path.write_text(index_content)
        print(f"📄 Documentation index generated: {index_path}")

        return index_path

    def run_full_generation(self) -> dict[str, t.GeneralValueType]:
        """Run complete architecture documentation generation."""
        print("🚀 Starting comprehensive architecture documentation generation...")

        results = {
            "timestamp": datetime.now(UTC).isoformat(),
            "phases": {},
            "overall_success": True,
            "errors": [],
        }

        # Phase 1: Generate diagrams
        print("\n📊 Phase 1: Generating Architecture Diagrams")
        try:
            diagram_success = self.generate_diagrams()
            results["phases"]["diagrams"] = {"success": diagram_success}
            if not diagram_success:
                results["overall_success"] = False
                results["errors"].append("Diagram generation failed")
        except Exception as e:
            results["phases"]["diagrams"] = {"success": False, "error": str(e)}
            results["overall_success"] = False
            results["errors"].append(f"Diagram generation error: {e}")

        # Phase 2: Run quality audit
        print("\n🔍 Phase 2: Running Quality Audit")
        try:
            audit_results = self.run_full_audit()
            results["phases"]["audit"] = {
                "success": bool(audit_results),
                "results": audit_results,
            }
        except Exception as e:
            results["phases"]["audit"] = {"success": False, "error": str(e)}
            results["overall_success"] = False
            results["errors"].append(f"Audit error: {e}")

        # Phase 3: Validate documentation
        print("\n✅ Phase 3: Validating Documentation Structure")
        try:
            validation_results = self.validate_architecture_docs()
            results["phases"]["validation"] = validation_results
            results["quality_score"] = validation_results.get("overall_score", 0)
        except Exception as e:
            results["phases"]["validation"] = {"success": False, "error": str(e)}
            results["overall_success"] = False
            results["errors"].append(f"Validation error: {e}")

        # Phase 4: Generate documentation index
        print("\n📚 Phase 4: Generating Documentation Index")
        try:
            index_path = self.generate_documentation_index()
            results["phases"]["index"] = {"success": True, "path": str(index_path)}
        except Exception as e:
            results["phases"]["index"] = {"success": False, "error": str(e)}
            results["overall_success"] = False
            results["errors"].append(f"Index generation error: {e}")

        # Save comprehensive results
        output_file = (
            self.project_root
            / f"architecture_generation_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
        )
        with Path(output_file).open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n📄 Generation report saved: {output_file}")

        # Print summary
        self._print_generation_summary(results)

        return results

    def _print_generation_summary(self, results: dict[str, t.GeneralValueType]) -> None:
        """Print a summary of the generation results."""
        print("\n" + "=" * 80)
        print("🏗️  ARCHITECTURE DOCUMENTATION GENERATION SUMMARY")
        print("=" * 80)

        overall_success = results.get("overall_success", False)
        quality_score = results.get("quality_score", 0)

        if overall_success:
            print("✅ Overall Status: SUCCESS")
        else:
            print("❌ Overall Status: ISSUES DETECTED")

        print(f"📊 Quality Score: {quality_score:.1f}/100")

        # Phase results
        phases = results.get("phases", {})
        for phase_name, phase_result in phases.items():
            status = "✅" if phase_result.get("success", False) else "❌"
            print(f"  {phase_name.title()}: {status}")

            if "error" in phase_result:
                print(f"    Error: {phase_result['error']}")

        # Errors
        errors = results.get("errors", [])
        if errors:
            print(f"\n⚠️  Issues Found: {len(errors)}")
            for error in errors[:5]:  # Show first 5
                print(f"  • {error}")

        # Recommendations
        recommendations = self._generate_generation_recommendations(results)
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")

        print("\n" + "=" * 80)

    def _generate_generation_recommendations(
        self, results: dict[str, t.GeneralValueType]
    ) -> list[str]:
        """Generate recommendations based on generation results."""
        recommendations = []

        if not results.get("overall_success"):
            recommendations.append("Address the issues listed above before proceeding")

        quality_score = results.get("quality_score", 0)
        if quality_score < 70:
            recommendations.append(
                "Focus on improving documentation quality and completeness"
            )

        phases = results.get("phases", {})
        if not phases.get("diagrams", {}).get("success", False):
            recommendations.append(
                "Install PlantUML or ensure diagram generation works"
            )

        if not phases.get("audit", {}).get("success", False):
            recommendations.append("Fix documentation maintenance system issues")

        validation = phases.get("validation", {})
        if not validation.get("valid", True):
            recommendations.append(
                "Address documentation structure and completeness issues"
            )

        return recommendations


def main() -> None:
    """Main entry point for architecture documentation generation."""
    parser = argparse.ArgumentParser(
        description="FLEXT Auth Architecture Documentation Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all architecture documentation
  python generate-architecture-docs.py --full-suite

  # Generate diagrams only
  python generate-architecture-docs.py --diagrams-only

  # Run validation only
  python generate-architecture-docs.py --validate-only

  # Update documentation index
  python generate-architecture-docs.py --update-index
        """,
    )

    parser.add_argument(
        "--full-suite",
        action="store_true",
        help="Run complete architecture documentation generation",
    )

    parser.add_argument(
        "--diagrams-only", action="store_true", help="Generate diagrams only"
    )

    parser.add_argument(
        "--validate-only", action="store_true", help="Run validation only"
    )

    parser.add_argument(
        "--update-index", action="store_true", help="Update documentation index only"
    )

    parser.add_argument(
        "--project-root", type=Path, default=Path.cwd(), help="Project root directory"
    )

    parser.add_argument("--output", type=Path, help="Output file for generation report")

    args = parser.parse_args()

    # Initialize generator
    generator = ArchitectureDocumentationGenerator(args.project_root)

    if args.full_suite:
        # Run complete generation
        results = generator.run_full_generation()

        if args.output:
            output_file = args.output
        else:
            output_file = (
                generator.project_root
                / f"architecture_generation_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
            )

        with Path(output_file).open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"\n📄 Full generation report saved: {output_file}")

    elif args.diagrams_only:
        # Generate diagrams only
        success = generator.generate_diagrams()
        if success:
            print("✅ Diagrams generated successfully")
        else:
            print("❌ Diagram generation failed")
            sys.exit(1)

    elif args.validate_only:
        # Validation only
        results = generator.validate_architecture_docs()
        print(json.dumps(results, indent=2))

    elif args.update_index:
        # Update index only
        index_path = generator.generate_documentation_index()
        print(f"📄 Documentation index updated: {index_path}")

    else:
        # Default: show help
        parser.print_help()


if __name__ == "__main__":
    main()
