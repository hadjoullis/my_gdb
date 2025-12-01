CC      = gcc
CFLAGS  = -Wall -Werror -O0 -MMD -MP
LIBS    = -lelf -lcapstone

BUILD   = build
INCLUDE = include

SRCS    = $(wildcard src/*.c)
OBJS    = $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
DEPS    = $(OBJS:.o=.d)

TARGET  = mdb.out

-include $(DEPS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

debug: CFLAGS += -ggdb3 -DDEBUG
debug: clean $(TARGET)

TEST_DIR    = tests
TEST_SRCS   = $(wildcard $(TEST_DIR)/*.c)
TEST_CFLAGS = -no-pie
TEST_EXES   = $(patsubst $(TEST_DIR)/%.c,$(BUILD)/%.out,$(TEST_SRCS))

tests: $(TEST_EXES)

$(BUILD)/%.out: $(TEST_DIR)/%.c
	@mkdir -p $(BUILD)
	$(CC) $(TEST_CFLAGS) $< -o $@

clean:
	@rm -rf $(BUILD)

.PHONY: all debug tests clean
