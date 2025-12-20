CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic -fopenmp
BUILD_DIR = ../build
BIN_DIR = ../bin
TARGET = $(BIN_DIR)/main
SRCS = main.cpp core/circuit.cpp core/circuit_compare.cpp io/bench_parser.cpp algorithm/matching.cpp
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET)
	rm -rf $(BUILD_DIR)
