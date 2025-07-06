CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lcrypto
TARGET = xand_encrypt_example
SOURCES = xand_encrypt.c example.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = xand_encrypt.h


all: $(TARGET)


$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)


%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@


libxand_encrypt.a: xand_encrypt.o
	ar rcs $@ $^


install: libxand_encrypt.a
	sudo cp libxand_encrypt.a /usr/local/lib/
	sudo cp xand_encrypt.h /usr/local/include/
	sudo ldconfig


uninstall:
	sudo rm -f /usr/local/lib/libxand_encrypt.a
	sudo rm -f /usr/local/include/xand_encrypt.h
	sudo ldconfig


run: $(TARGET)
	./$(TARGET)


clean:
	rm -f $(OBJECTS) $(TARGET) libxand_encrypt.a


valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)


asan: CFLAGS += -fsanitize=address -g
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)


debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)


release: CFLAGS += -DNDEBUG
release: $(TARGET)

.PHONY: all install uninstall run clean valgrind asan debug release 