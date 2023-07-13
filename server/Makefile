SRC ?= aesdsocket.c 
TARGET ?= aesdsocket
OBJS ?= $(SRC:.c=.o)
LDFLAGS ?= -pthread -lrt
CFLAGS ?= -g -Wall -Werror

CROSS_COMPILE?= aarch64-none-linux-gnu
CC?= $(CROSS_COMPILE)gcc


all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS) $(CFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
