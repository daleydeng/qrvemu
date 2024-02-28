#include <stdio.h>

int main(int argc, char **argv)
{
	if (argc == 1)
		return -1;

	int count = 16;
	int c, p = 0;
	printf("static const unsigned char %s[] = {\n", argv[1]);
	while ((c = getchar()) != EOF)
		printf("0x%02x,%c", c,
		       (((p++) % count) == count - 1) ? '\n' : ' ');
	printf("};");
	return 0;
}
