obj-m   := test_char.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

build: t
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order *.mod test

t: test.c
	gcc test.c -o test

test: build
	rmmod test_char || :
	insmod ./test_char.ko
	./test

