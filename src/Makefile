CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic -fopenmp -march=native -I../extern
LDFLAGS ?= -lz3
BUILD_DIR = ../build
BIN_DIR = ../bin

PROG_SRCS := $(wildcard *.cpp script/*.cpp)
LIB_SRCS := $(wildcard core/*.cpp io/*.cpp algorithm/*.cpp)
PROG_OBJS := $(PROG_SRCS:%.cpp=$(BUILD_DIR)/%.o)
LIB_OBJS := $(LIB_SRCS:%.cpp=$(BUILD_DIR)/%.o)
TARGETS := $(PROG_SRCS:%.cpp=$(BIN_DIR)/%)

all: $(TARGETS)

$(BIN_DIR)/%: $(BUILD_DIR)/%.o $(LIB_OBJS)
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -rf $(BUILD_DIR)
