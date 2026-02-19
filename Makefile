# flext-auth - Authentication Framework
PROJECT_NAME := flext-auth
include ../base.mk

# === PROJECT-SPECIFIC TARGETS ===
.PHONY: test-unit test-integration build shell

.DEFAULT_GOAL := help
