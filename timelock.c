#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define WASHERCNT 8
#define CHARSPERWASHER 5

static char *arg0;

_Noreturn void usage(FILE *f, int ex)
{
	fprintf(f, "usage: %s <washer1> .. <washer%d>\n", arg0, (int)WASHERCNT);
	fprintf(f, "washers in any order - each one has %d numbers/letters\n", (int)CHARSPERWASHER);
	fprintf(f, "washers will be sorted like works in a dictionary\n");
	fprintf(f, "(numbers before letters)\n");
	exit(ex);
}

static void upperfy(char *s)
{
	char *orig = s;

	for (;;) {
		if (*s >= 'a' && *s <= 'z') *s += 'A'-'a';

		if (!strchr("ACDEFGHJKLNPQRTUX234679", *s)) {
			fprintf(stderr, "character '%c' in %s is not valid\n", *s, orig);
			usage(stderr, 1);
		}
		if (!*++s) break;
	}
}

int lexicosort(const void *a, const void *b)
{
	return strcmp(a, b);
}

int main(int argc, char **argv)
{
	int i;
	arg0 = *argv++;

	if (--argc != WASHERCNT) usage(stderr, 1);
	for (i = 0; i < WASHERCNT; i++) {
		if (strlen(argv[i]) != CHARSPERWASHER) usage(stderr, 1);
		upperfy(argv[i]);
	}

	qsort(argv, WASHERCNT, sizeof(*argv), lexicosort);
}
