default: build/Makefile
	cd build && make
	build/test

build/Makefile: CMakeLists.txt
	rm -rf build
	mkdir build
	cd build && cmake ..

clean:
	rm -rf build
