all:
	$(MAKE) -C cpl0/
	if [ -f cpl0/svsm.bin ]; then cp cpl0/svsm.bin .; fi
clean:
	if [ -f svsm.bin ]; then rm svsm.bin ; fi
	$(MAKE) -C cpl0/ clean
