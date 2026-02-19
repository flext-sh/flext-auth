# flext-auth - Authentication Framework
PROJECT_NAME := flext-auth
ifneq ("$(wildcard ../base.mk)", "")
include ../base.mk
else
include base.mk
endif

# === PROJECT-SPECIFIC TARGETS ===
.PHONY: test-unit test-integration build shell

.DEFAULT_GOAL := help
