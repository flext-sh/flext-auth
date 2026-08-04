#!/bin/bash
# FLEXT Auth Architecture Diagram Generation Script
#
# This script generates PNG and SVG diagrams from PlantUML source files
# Requires: PlantUML (java -jar plantuml.jar) or online PlantUML service

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
PLANTUML_DIR="${SCRIPT_DIR}/plantuml"
GENERATED_DIR="${SCRIPT_DIR}/generated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
	echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
	echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
	echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1"
}

# Check if PlantUML is available
check_plantuml() {
	if command -v plantuml >/dev/null 2>&1; then
		log_info "Found PlantUML CLI"
		PLANTUML_CMD=(plantuml)
		return 0
	elif java -jar /usr/local/bin/plantuml.jar --version >/dev/null 2>&1; then
		log_info "Found PlantUML JAR"
		PLANTUML_CMD=(java -jar /usr/local/bin/plantuml.jar)
		return 0
	else
		log_warning "PlantUML CLI/JAR not found locally"
		log_info "Will attempt to use online PlantUML service"
		return 1
	fi
}

# Generate diagram using local PlantUML
generate_local() {
	local input_file="$1"
	local output_file_png="${input_file%.puml}.png"
	local output_file_svg="${input_file%.puml}.svg"

	log_info "Generating diagrams for $(basename "${input_file}")"

	# Generate PNG
	if "${PLANTUML_CMD[@]}" -tpng "${input_file}" -o "${GENERATED_DIR}"; then
		log_success "Generated PNG: $(basename "${output_file_png}")"
	else
		log_error "Failed to generate PNG for $(basename "${input_file}")"
		return 1
	fi

	# Generate SVG
	if "${PLANTUML_CMD[@]}" -tsvg "${input_file}" -o "${GENERATED_DIR}"; then
		log_success "Generated SVG: $(basename "${output_file_svg}")"
	else
		log_error "Failed to generate SVG for $(basename "${input_file}")"
		return 1
	fi
}

# Generate diagram using online PlantUML service
generate_online() {
	local input_file="$1"
	local output_file_png="${input_file%.puml}.png"
	local output_file_svg="${input_file%.puml}.svg"

	log_info "Generating diagrams online for $(basename "${input_file}")"

	# Check if curl is available
	if ! command -v curl >/dev/null 2>&1; then
		log_error "curl not available for online generation"
		return 1
	fi

	# Encode PlantUML content in base64
	local content_b64
	content_b64=$(base64 -w 0 "${input_file}" 2>/dev/null || base64 "${input_file}")

	# Generate PNG
	if curl -s "http://www.plantuml.com/plantuml/png/~1${content_b64}" -o "${output_file_png}" 2>/dev/null; then
		log_success "Generated PNG: $(basename "${output_file_png}")"
	else
		log_error "Failed to generate PNG online for $(basename "${input_file}")"
		return 1
	fi

	# Generate SVG
	if curl -s "http://www.plantuml.com/plantuml/svg/~1${content_b64}" -o "${output_file_svg}" 2>/dev/null; then
		log_success "Generated SVG: $(basename "${output_file_svg}")"
	else
		log_error "Failed to generate SVG online for $(basename "${input_file}")"
		return 1
	fi
}

# Main generation function
generate_diagram() {
	local input_file="$1"
	local base_name
	base_name=$(basename "${input_file}" .puml)

	# Ensure output directory exists
	mkdir -p "${GENERATED_DIR}"

	# Determine output file paths
	local output_file_png="${GENERATED_DIR}/${base_name}.png"
	local output_file_svg="${GENERATED_DIR}/${base_name}.svg"

	if check_plantuml; then
		# Use local PlantUML
		if generate_local "${input_file}"; then
			return 0
		fi
		log_warning "Local generation failed, trying online..."
		generate_online "${input_file}"
		return $?
	else
		# Use online PlantUML
		generate_online "${input_file}"
		return $?
	fi
}

# Validate generated diagrams
validate_diagrams() {
	local generated_count=0
	local expected_count=0

	# Count expected diagrams (PlantUML files)
	local expected_files=()
	readarray -d '' expected_files < <(find "${PLANTUML_DIR}" -name "*.puml" -print0 || true)
	expected_count=${#expected_files[@]}

	# Count generated diagrams
	local generated_files=()
	if [ -d "${GENERATED_DIR}" ]; then
		readarray -d '' generated_files < <(find "${GENERATED_DIR}" \( -name "*.png" -o -name "*.svg" \) -print0 || true)
	fi
	generated_count=${#generated_files[@]}

	log_info "Validation: ${generated_count}/$((expected_count * 2)) diagrams generated (PNG+SVG per source)"

	if [ "${generated_count}" -eq "$((expected_count * 2))" ]; then
		log_success "All diagrams generated successfully"
		return 0
	else
		log_warning "Some diagrams may be missing"
		return 1
	fi
}

# Generate index file
generate_index() {
	local index_file="${GENERATED_DIR}/README.md"

	cat >"${index_file}" <<'EOF'
# Generated Architecture Diagrams

This directory contains automatically generated architecture diagrams for flext-auth.

## Available Diagrams

EOF

	# List all generated diagrams
	local diagram_files=()
	if [ -d "${GENERATED_DIR}" ]; then
		readarray -d '' diagram_files < <(find "${GENERATED_DIR}" \( -name "*.png" -o -name "*.svg" \) -print0 | sort -z || true)
	fi

	for diagram in "${diagram_files[@]}"; do
		local base_name
		base_name=$(basename "${diagram}")
		local diagram_name
		diagram_name=$(basename "${diagram}" | sed 's/\.[^.]*$//')
		local ext
		ext=$(basename "${diagram}" | sed 's/.*\.//')

		echo "- **${diagram_name}** (${ext}): [View](${base_name})" >>"${index_file}"
	done

	cat >>"${index_file}" <<'EOF'

## Generation

These diagrams are automatically generated from PlantUML source files located in `diagrams/plantuml/`.

To regenerate diagrams:
```bash
cd docs/architecture/diagrams
./generate-diagrams.sh
```

## PlantUML Sources

- [System Context](plantuml/system-context.puml)
- [Container Architecture](plantuml/container-architecture.puml)
- [Component Architecture](plantuml/component-architecture.puml)

---

*Generated on: $(date)*
EOF

	log_success "Generated diagram index: ${index_file}"
}

# Main execution
main() {
	log_info "Starting FLEXT Auth Architecture Diagram Generation"
	log_info "Project root: ${PROJECT_ROOT}"
	log_info "PlantUML sources: ${PLANTUML_DIR}"
	log_info "Generated diagrams: ${GENERATED_DIR}"

	# Check if PlantUML sources exist
	if [ ! -d "${PLANTUML_DIR}" ]; then
		log_error "PlantUML directory not found: ${PLANTUML_DIR}"
		exit 1
	fi

	local success_count=0
	local total_count=0
	local puml_total

	# Find and process all PlantUML files
	local puml_files=()
	readarray -d '' puml_files < <(find "${PLANTUML_DIR}" -name "*.puml" -print0 || true)
	puml_total=${#puml_files[@]}

	for puml_file in "${puml_files[@]}"; do
		total_count=$((total_count + 1))
		log_info "Processing ${total_count}/${puml_total}: ${puml_file##*/}"

		if generate_diagram "${puml_file}"; then
			success_count=$((success_count + 1))
		fi
	done

	# Generate index
	generate_index

	# Validate results
	validate_diagrams

	# Summary
	log_info "Generation complete: ${success_count}/${total_count} diagrams successfully generated"

	if [ "${success_count}" -eq "${total_count}" ]; then
		log_success "All architecture diagrams generated successfully!"
		exit 0
	else
		log_error "Some diagrams failed to generate"
		exit 1
	fi
}

# Run main function
main "$@"
