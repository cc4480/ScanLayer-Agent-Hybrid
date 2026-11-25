# Host (Linux stand-in):  make
# QNX 8.0 target:         source ~/qnx800/qnxsdp-env.sh && make CC="qcc -Vgcc_ntox86_64" OUT=qnx-runner.x86_64
CC ?= cc
OUT ?= qnx-runner
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Werror
$(OUT): qnx-runner.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f qnx-runner qnx-runner.x86_64
.PHONY: clean
