CC = g++
CFLAGS  = -g -Werror
TARGET = ipk-sniffer

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp

clean:
	$(RM) $(TARGET)