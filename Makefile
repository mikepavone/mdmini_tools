.SUFFIXES:

.PHONY: clean all

all: mecd_decode psb m2decrypt

clean: 
	rm -rf *.o mecd_decode psb m2decrypt

LIBS:=opus libzstd
INC:=`pkg-config $(LIBS) --cflags`
LINK:=`pkg-config $(LIBS) --libs`

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

mecd_decode: mecd_decode.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(LINK)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
