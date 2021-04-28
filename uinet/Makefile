all:
	if [ ! -d lib/machine_include/machine ];then cp -rf lib/machine_include/machine_x64 lib/machine_include/machine ;fi
	make -C lib
	make -C example

clean:
	make -C lib clean
	make -C example clean