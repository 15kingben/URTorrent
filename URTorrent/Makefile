CC = g++
CPPFLAGS = -Wall -g3
OBJS = *.o 
MAIN = URTorrent
LIBS = -lcrypto -lcurl -lpthread

all: $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CPPFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

clean:
	$(RM) *.o *~ $(MAIN)

# DO NOT DELETE THIS LINE -- make depend needs it
