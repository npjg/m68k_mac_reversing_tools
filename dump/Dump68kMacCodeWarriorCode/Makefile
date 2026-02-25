CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17 -fno-omit-frame-pointer -O0

TARGET = Dump68kMacCodeWarriorCode
SOURCE = Dump68kMacCodeWarriorCode.cpp

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

# Clean target
clean:
	rm -f $(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG
debug: $(TARGET)

# Release build with optimization
release: CXXFLAGS = -Wall -Wextra -std=c++17 -O2 -DNDEBUG
release: $(TARGET)

# Phony targets
.PHONY: clean debug release all