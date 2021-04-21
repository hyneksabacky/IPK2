CC = g++
CFLAGS  = -g -Werror
TARGET  = ipk-sniffer

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) -lpcap

debug: 
	$(CC) $(CFLAGS) -DDEBUG $(TARGET).cpp -o debug -lpcap

clean:
	$(RM) $(TARGET) debug