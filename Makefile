CXX = g++
CXXFLAGS = -std=c++14 -Wall `pkg-config --cflags libndn-cxx`
LIBS = `pkg-config --libs libndn-cxx`
DESTDIR ?= /usr/local
SOURCE_OBJS = server-daemon.o nd-client.o nd-server.o
PROGRAMS = nd-client nd-server

all: $(PROGRAMS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(LIBS)

%: $(SOURCE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(PROGRAMS)

install: all
	cp $(PROGRAMS) $(DESTDIR)/bin/

uninstall:
	cd $(DESTDIR)/bin && rm -f $(PROGRAMS)
