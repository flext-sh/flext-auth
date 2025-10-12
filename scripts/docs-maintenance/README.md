# FLEXT Auth Documentation Maintenance System

Comprehensive automated documentation quality assurance, validation, optimization, and maintenance framework for the flext-auth project.

## Overview

This maintenance system provides automated tools for:

- **Content Quality Audit**: Comprehensive file analysis, freshness tracking, structure validation
- **Link Validation**: External and internal link checking with health monitoring
- **Content Optimization**: Automated suggestions for readability, structure, and technical accuracy improvements
- **Synchronization**: Git-based change tracking and version control integration
- **Quality Assurance**: Comprehensive reporting with prioritized recommendations and action plans

## Quick Start

### Prerequisites

```bash
# Python 3.13+ required
python --version  # Should show 3.13 or higher

# Install dependencies (if needed)
pip install requests beautifulsoup4 lxml  # For enhanced link checking
```

### Basic Usage

```bash
cd scripts/docs-maintenance

# Run comprehensive maintenance
python main.py comprehensive

# Quick audit only
python main.py quick

# Apply auto-fixes
python main.py fix

# Show summary
python main.py summary
```

## Architecture

### Core Components

```
docs-maintenance/
├── main.py              # Main orchestrator
├── docs_audit.py        # Content quality audit system
├── link_validator.py    # Link validation and checking
├── content_optimizer.py # Content optimization and suggestions
├── docs_sync.py         # Synchronization and git integration
└── README.md           # This documentation
```

### Data Flow

```
Documentation Files → Audit → Validation → Optimization → Sync → QA Report
                       ↓         ↓           ↓           ↓        ↓
                   Quality     Link       Content    Git       Action
                   Metrics     Health     Suggestions Status   Plan
```

## Detailed Usage

### 1. Content Quality Audit (`docs_audit.py`)

**Purpose**: Comprehensive analysis of documentation quality metrics.

**Features**:

- File discovery and categorization
- Content freshness analysis
- Structure validation (headings, TOC, frontmatter)
- Completeness checking
- Technical content analysis

**Usage**:

```bash
python docs_audit.py --project-root /path/to/flext-auth --output audit_report.json
```

**Sample Output**:

```json
{
  "discovery": {
    "total_files": 25,
    "active_files": 22,
    "archive_files": 3
  },
  "quality_score": 78,
  "issues": [
    {
      "type": "file_read_error",
      "severity": "high",
      "suggestion": "Check file encoding"
    }
  ]
}
```

### 2. Link Validation (`link_validator.py`)

**Purpose**: Automated link checking and reference validation.

**Features**:

- External link health monitoring
- Internal link validation
- Image reference checking
- Accessibility validation (alt text)
- Response time monitoring

**Usage**:

```bash
python link_validator.py --project-root /path/to/flext-auth --timeout 15
```

**Sample Output**:

```json
{
  "validation_results": {
    "total_issues_found": 12,
    "statistics": {
      "total_links_checked": 89,
      "broken_links": 3,
      "broken_images": 2,
      "accessibility_issues": 7
    }
  }
}
```

### 3. Content Optimization (`content_optimizer.py`)

**Purpose**: Automated content enhancement and improvement suggestions.

**Features**:

- Readability analysis
- Structure optimization suggestions
- Technical content validation
- Auto-fixable issue identification
- Enhancement recommendations

**Usage**:

```bash
python content_optimizer.py --project-root /path/to/flext-auth --format text
```

**Sample Output**:

```json
{
  "summary": {
    "files_analyzed": 22,
    "total_suggestions": 45,
    "auto_fixable": 12,
    "average_quality_score": 76.5
  },
  "suggestions_by_type": {
    "structure": 8,
    "content": 15,
    "technical": 12,
    "style": 10
  }
}
```

### 4. Synchronization (`docs_sync.py`)

**Purpose**: Git-based change tracking and version control integration.

**Features**:

- Recent change analysis
- Synchronization status monitoring
- Automated commit generation
- Remote repository integration
- Conflict resolution support

**Usage**:

```bash
# Generate sync report
python docs_sync.py report --output sync_status.json

# Push changes
python docs_sync.py push

# Pull latest changes
python docs_sync.py pull
```

### 5. Main Orchestrator (`main.py`)

**Purpose**: Unified interface for all maintenance operations.

**Commands**:

- `comprehensive`: Full maintenance cycle
- `quick`: Fast audit only
- `fix`: Apply auto-fixable issues
- `summary`: Show current status
- `config`: Export configuration template

**Usage**:

```bash
# Full maintenance cycle
python main.py comprehensive

# Quick check
python main.py quick

# Apply fixes
python main.py fix
```

## Configuration

### Configuration File

Create `docs_maintenance_config.json` in your project root:

```json
{
  "maintenance_system": {
    "version": "1.0",
    "project": "flext-auth"
  },
  "audit_config": {
    "enabled": true,
    "frequency": "weekly",
    "quality_threshold": 80
  },
  "link_validation": {
    "enabled": true,
    "check_external_links": true,
    "timeout_seconds": 10
  },
  "quality_gates": {
    "minimum_quality_score": 75,
    "maximum_broken_links": 5
  }
}
```

### Environment Variables

```bash
# Link validation settings
DOCS_LINK_TIMEOUT=15
DOCS_MAX_RETRIES=3

# Quality thresholds
DOCS_QUALITY_THRESHOLD=80
DOCS_MAX_BROKEN_LINKS=5

# Output settings
DOCS_OUTPUT_FORMAT=json
DOCS_REPORT_DIR=reports/docs-qa
```

## Quality Gates

### Automatic Quality Checks

| Metric               | Threshold | Action     |
| -------------------- | --------- | ---------- |
| Quality Score        | ≥75       | ✅ Pass    |
| Quality Score        | 60-74     | ⚠️ Warning |
| Quality Score        | <60       | ❌ Fail    |
| Broken Links         | ≤5        | ✅ Pass    |
| Broken Links         | 6-10      | ⚠️ Warning |
| Broken Links         | >10       | ❌ Fail    |
| High Severity Issues | ≤3        | ✅ Pass    |
| High Severity Issues | >3        | ❌ Fail    |

### Content Standards

- **Freshness**: Files older than 180 days get "stale" rating
- **Completeness**: Required sections (frontmatter, examples, links)
- **Structure**: Proper heading hierarchy and table of contents
- **Accessibility**: Alt text for images, descriptive link text
- **Technical**: Code examples with language specification

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Documentation QA
on:
  push:
    paths:
      - "docs/**"
      - "*.md"
  pull_request:
    paths:
      - "docs/**"
      - "*.md"
  schedule:
    - cron: "0 2 * * 1" # Weekly on Monday

jobs:
  docs-qa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.13"
      - name: Install dependencies
        run: |
          pip install requests beautifulsoup4 lxml
      - name: Run documentation QA
        run: |
          cd scripts/docs-maintenance
          python main.py comprehensive
      - name: Upload QA report
        uses: actions/upload-artifact@v3
        with:
          name: docs-qa-report
          path: reports/docs-qa/
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: docs-qa
        name: Documentation QA Check
        entry: python scripts/docs-maintenance/main.py
        args: [quick]
        pass_filenames: false
        files: \.(md|mdx)$
        language: system
```

## Troubleshooting

### Common Issues

**Import Errors**:

```bash
# Ensure you're in the scripts/docs-maintenance directory
cd scripts/docs-maintenance
PYTHONPATH=../.. python main.py comprehensive
```

**Permission Errors**:

```bash
# Check write permissions for reports directory
chmod -R 755 reports/
```

**Git Integration Issues**:

```bash
# Ensure git is available and repository is clean
git status
git remote -v
```

### Debug Mode

Enable detailed logging:

```bash
export DOCS_DEBUG=1
export DOCS_VERBOSE=1
python main.py comprehensive
```

## Best Practices

### Maintenance Schedule

- **Daily**: Quick audit during development
- **Weekly**: Comprehensive maintenance cycle
- **Monthly**: Quality trend analysis
- **Quarterly**: Major content reviews

### Quality Standards

1. **Consistency**: Use uniform formatting and style
2. **Completeness**: Ensure all features are documented
3. **Accuracy**: Keep technical information current
4. **Accessibility**: Follow web accessibility guidelines
5. **Freshness**: Regularly update content and examples

### Automation

1. **CI/CD Integration**: Run QA checks on every PR
2. **Scheduled Maintenance**: Weekly automated reports
3. **Alert System**: Notifications for critical issues
4. **Auto-fixes**: Apply safe automated corrections

## Contributing

### Adding New Checks

1. Extend the appropriate module (`docs_audit.py`, `link_validator.py`, etc.)
2. Add comprehensive tests
3. Update documentation
4. Submit PR with examples

### Configuration Changes

1. Update `docs_maintenance_config.json` template
2. Document new configuration options
3. Provide migration guide for existing configurations

## Support

- **Issues**: Report bugs in the flext-auth issue tracker
- **Discussions**: Join documentation maintenance discussions
- **Contributing**: See contribution guidelines in main project

---

**FLEXT Auth Documentation Maintenance System** - Ensuring documentation quality and consistency across the flext-auth project.
