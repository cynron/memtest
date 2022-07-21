#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>

int main() {
	char *f = "/dev/test_char";
	long test = 0x1122334455667788;
	long addr = (long)&test;
	printf("virtual addr: 0x%lx\n", addr); 
	printf("before: 0x%lx\n", test);
	int fd = open(f, O_RDWR);
	write(fd, &addr, sizeof(long));
	printf("after: 0x%lx\n", test);
	close(fd);
	return 0;
}


