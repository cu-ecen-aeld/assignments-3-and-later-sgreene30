SRC := aesdsocket.c 
TARGET = aesdsocket
OBJS := $(SRC:.c=.o)
CFLAGS = -g -Wall -Werror -pthread -lrt


CROSS_COMPILE:=
CC:= $(CROSS_COMPILE)gcc


all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS) $(CFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
