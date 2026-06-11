# usque-a top-level Makefile
# Convenience wrapper around deps.sh and build.sh

.PHONY: all deps build test release clean status help

all: deps build test

deps:
	@./deps.sh all

build:
	@./build.sh build

test:
	@./build.sh test

release:
	@./build.sh release

clean:
	@./build.sh clean
	@./deps.sh clean

status:
	@./deps.sh status

help:
	@echo "usque-a build targets:"
	@echo ""
	@echo "  make all       - deps + build + test (full pipeline)"
	@echo "  make deps      - Fetch and build dependencies"
	@echo "  make build     - Build the project"
	@echo "  make test      - Run all tests"
	@echo "  make release   - Build + strip for deployment"
	@echo "  make clean     - Clean everything"
	@echo "  make status    - Show dependency status"
	@echo ""
	@echo "Quick start: make all"
