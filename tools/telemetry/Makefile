# Makefile for Telemetry Client
# SPDX-License-Identifier: BSD-3-Clause

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS =
LIBS =

# Target executable name
TARGET = mce_telemetry_client

# Source files
SRCS = telemetry.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(TARGET) $(OBJS)

# Install the executable to /usr/local/bin
install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/

# Uninstall from /usr/local/bin
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Run the program
run: $(TARGET)
	./$(TARGET)

# Debug build with extra warnings
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

# Release build with optimization
release: CFLAGS += -O3 -DNDEBUG
release: $(TARGET)

# Static analysis with clang
analyze: clean
	scan-build make

# Show help information
help:
	@echo "Telemetry Client Build System"
	@echo "============================="
	@echo "Available targets:"
	@echo "  all       - Build the program (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Uninstall from /usr/local/bin"
	@echo "  run       - Build and run the program"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build with optimization"
	@echo "  analyze   - Run static analysis"
	@echo "  help      - Show this help message"

.PHONY: all clean install uninstall run debug release analyze help
