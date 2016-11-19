
CC=g++
CFLAGS=-c -Wall

SOURCES= des.cpp main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=des

all: $(SOURCES) $(EXECUTABLE) clean

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o
