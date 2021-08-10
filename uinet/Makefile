ifeq ($(V),1)
	Q :=
else
	Q := -s
endif

export MAKE := $(MAKE) $(Q)

all:
	@echo "make uinet at:"`date`
	@$(MAKE) -C lib
	@$(MAKE) -C example
	@$(MAKE) -C tools

clean:
	@echo "make clean at:"`date`
	@$(MAKE) -C lib clean
	@$(MAKE) -C example clean
	@$(MAKE) -C tools clean