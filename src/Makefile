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

# Optional weighted set-cover MILP backend. Override HIGHS_ROOT for a
# non-standard installation. The local OR-Tools distribution used by this
# workspace also ships standalone HiGHS headers and libhighs.
HIGHS_ROOT ?= $(shell \
  for d in "$$HOME/.local/or-tools" /usr/local /usr; do \
    if test -f "$$d/include/highs/Highs.h" && \
       test -e "$$d/lib/libhighs.so"; then \
      printf '%s' "$$d"; \
      break; \
    fi; \
  done)

ifneq ($(strip $(HIGHS_ROOT)),)
  ifeq ($(wildcard $(HIGHS_ROOT)/include/highs/Highs.h),)
    $(error HIGHS_ROOT=$(HIGHS_ROOT) does not contain include/highs/Highs.h)
  endif
  ifeq ($(wildcard $(HIGHS_ROOT)/lib/libhighs.so),)
    $(error HIGHS_ROOT=$(HIGHS_ROOT) does not contain lib/libhighs.so)
  endif
  USE_HIGHS := 1
  CXXFLAGS += -DUSE_HIGHS -isystem $(HIGHS_ROOT)/include/highs
  LDFLAGS += -L$(HIGHS_ROOT)/lib \
             -Wl,-rpath,$(HIGHS_ROOT)/lib -lhighs
  $(info HiGHS detected: $(HIGHS_ROOT))
else
  $(info HiGHS not found - milp-cover backend unavailable)
endif

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
               -DUSE_CUDA -I../extern -I$(CUDA_HOME)/include
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
