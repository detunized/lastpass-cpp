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
