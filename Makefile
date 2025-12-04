CC      = gcc
CFLAGS  = -Wall -Wextra -O0 -MMD -MP
LIBS    = -lelf -lcapstone -lreadline

BUILD   = build
INCLUDE = include

SRCS    = $(wildcard src/*.c)
OBJS    = $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
DEPS    = $(OBJS:.o=.d)

TARGET  = mdb.out

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

debug: CFLAGS += -ggdb3 -DDEBUG
debug: clean_build $(TARGET)

TEST        = tests
TEST_SRCS   = $(wildcard $(TEST)/*.c)
TEST_EXES   = $(patsubst $(TEST)/%.c,$(TEST)/%.out,$(TEST_SRCS))
TEST_CFLAGS = -no-pie

tests: $(TEST_EXES)

$(TEST)/%.out: $(TEST)/%.c
	$(CC) $(TEST_CFLAGS) $< -o $@

clean_tests:
	@rm -f $(TEST_EXES)

clean_build:
	@rm -rf $(BUILD)

clean:
	@rm -rf $(BUILD) $(TEST)

.PHONY: all debug tests clean clean_build clean_tests

-include $(DEPS)
