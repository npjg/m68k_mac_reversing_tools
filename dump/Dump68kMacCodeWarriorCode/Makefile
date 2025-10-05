CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99 -fno-omit-frame-pointer -O0

TARGET = Appl68KStartup
SOURCE = Appl68KStartup.c

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

# Clean target
clean:
	rm -f $(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG
debug: $(TARGET)

# Release build with optimization
release: CFLAGS = -Wall -Wextra -std=c99 -O2 -DNDEBUG
release: $(TARGET)

# Phony targets
.PHONY: clean debug release all