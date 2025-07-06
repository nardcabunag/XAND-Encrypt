CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lcrypto
TARGET = xand_encrypt_example
SOURCES = xand_encrypt.c example.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = xand_encrypt.h

# Default target
all: $(TARGET)

# Build the example program
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Build library
libxand_encrypt.a: xand_encrypt.o
	ar rcs $@ $^

# Install library and headers (requires sudo)
install: libxand_encrypt.a
	sudo cp libxand_encrypt.a /usr/local/lib/
	sudo cp xand_encrypt.h /usr/local/include/
	sudo ldconfig

# Uninstall library and headers
uninstall:
	sudo rm -f /usr/local/lib/libxand_encrypt.a
	sudo rm -f /usr/local/include/xand_encrypt.h
	sudo ldconfig

# Run the example
run: $(TARGET)
	./$(TARGET)

# Clean build files
clean:
	rm -f $(OBJECTS) $(TARGET) libxand_encrypt.a

# Check for memory leaks with valgrind
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)

# Run with address sanitizer
asan: CFLAGS += -fsanitize=address -g
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG
release: $(TARGET)

.PHONY: all install uninstall run clean valgrind asan debug release 