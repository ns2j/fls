CC = g++

PROGRAM = fls
HEADERS = lazypcscfelicalite.h felica_keys.h
OBJS = fls.o
WS_PROGRAM = fls_ws
WS_OBJS = fls_ws.o mongoose.o
PAM_PROGRAM = pam_fls.so
PAM_SOURCES = pam_fls.cpp

# Linux
PCSC_CFLAGS := $(shell pkg-config --cflags libpcsclite) $(shell pkg-config --cflags mbedtls)
LDFLAGS := $(shell pkg-config --libs libpcsclite) $(shell pkg-config --libs mbedtls) $(shell pkg-config -libs mbedcrypto)

# Mac OS X
#PCSC_CFLAGS := -framework PCSC

CFLAGS += $(PCSC_CFLAGS)
CPPFLAGS += $(PCSC_CFLAGS)

.SUFFIXES: .c .cpp .o

all: $(PROGRAM) $(WS_PROGRAM) $(PAM_PROGRAM)


$(PROGRAM): $(OBJS)
	$(CC) -o $(PROGRAM) $^ $(LDFLAGS)

$(WS_PROGRAM): $(WS_OBJS)
	$(CC) -o $(WS_PROGRAM) $^ $(LDFLAGS) -pthread

$(PAM_PROGRAM): $(PAM_SOURCES) lazypcscfelicalite.h felica_keys.h
	$(CC) -fPIC -shared $< -o $@ $(PCSC_CFLAGS) -lpam $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $<
.cpp.o:
	$(CC) $(CPPFLAGS) -c $<

$(OBJS): fls.cpp $(HEADERS)
$(WS_OBJS): fls_ws.cpp  mongoose.c mongoose.h $(HEADERS)
#mongoose.o: 

.PHONY: clean
clean:
	$(RM) $(PROGRAM) $(OBJS) $(WS_PROGRAM) $(WS_OBJS) $(PAM_PROGRAM) 
