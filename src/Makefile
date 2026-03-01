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

# ── CUDA auto-detect ─────────────────────────────────────────────────────────
NVCC_CANDIDATES := nvcc \
  /usr/local/cuda/bin/nvcc \
  /usr/local/cuda-13.1/bin/nvcc \
  /usr/local/cuda-12/bin/nvcc
NVCC := $(shell for c in $(NVCC_CANDIDATES); do which $$c 2>/dev/null && break; done)

ifneq ($(NVCC),)
  USE_CUDA := 1
  CUDA_HOME ?= $(shell dirname $(shell dirname $(NVCC)))
  NVCCFLAGS := -std=c++17 -O2 --gpu-architecture=native \
               -Xcompiler "-fopenmp -O2 -march=native" \
               -I../extern -I$(CUDA_HOME)/include
  CXXFLAGS  += -DUSE_CUDA -I$(CUDA_HOME)/include
  LDFLAGS   += -lcudart -lcurand -L$(CUDA_HOME)/lib64
  CUDA_SRCS := $(wildcard core/*.cu algorithm/*.cu)
  CUDA_OBJS := $(CUDA_SRCS:%.cu=$(BUILD_DIR)/%.o)
  LIB_OBJS  += $(CUDA_OBJS)
  $(info CUDA detected: $(NVCC))
else
  $(info CUDA not found - CPU-only build)
endif
# ─────────────────────────────────────────────────────────────────────────────

all: $(TARGETS)

$(BIN_DIR)/%: $(BUILD_DIR)/%.o $(LIB_OBJS)
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.cu
	mkdir -p $(dir $@)
	$(NVCC) $(NVCCFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -rf $(BUILD_DIR)
