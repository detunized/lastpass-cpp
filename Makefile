# Copyright (C) 2014 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

.PHONY: all
all: build/Makefile
	cd build && make
	build/test

build/Makefile: CMakeLists.txt
	rm -rf build
	mkdir build
	cd build && cmake ..

.PHONY: all
clean:
	rm -rf build

.PHONY: example
example: all
	build/example
