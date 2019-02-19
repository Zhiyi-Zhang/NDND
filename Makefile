CXX = g++
CXXFLAGS = -std=c++11 -Wall -Werror `pkg-config --cflags libndn-cxx`
LIBS = `pkg-config --libs libndn-cxx`
DESTDIR ?= /usr/local

PROGRAMS = nd-client nd-server

all: $(PROGRAMS)

%: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(PROGRAMS)

install: all
	cp $(PROGRAMS) $(DESTDIR)/bin/

uninstall:
	cd $(DESTDIR)/bin && rm -f $(PROGRAMS)
