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

# --- Primary Targets ---

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

# --- Utility Targets ---

debug: CFLAGS += -ggdb3 -DDEBUG
debug: clean $(TARGET)

clean:
	@rm -rf $(BUILD)

.PHONY: all debug clean
