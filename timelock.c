#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "btc/sha2.h"

#define WASHERCNT 8
#define CHARSPERWASHER 5

/* 570000 happened on Nov 12, 2024 */
#define BASEHEIGHT 570000
#define BASEYEAR   (2024 + (11.0/30.0+10.0)/12.0)

#define BLOCKSINCR  5000
#define YEARININCR (0.09512937595129375)

static char *arg0;

_Noreturn void usage(FILE *f, int ex)
{
	fprintf(f, "usage: %s <washer1> .. <washer%d>\n", arg0, (int)WASHERCNT);
	fprintf(f, "  washers in any order - each one has %d numbers/letters\n", (int)CHARSPERWASHER);
	fprintf(f, "  washers will be sorted like works in a dictionary (numbers\n");
	fprintf(f, "  before letters)\n");
	fprintf(f, "\n");
	fprintf(f, "usage: %s times\n", arg0);
	fprintf(f, "  shows times at which coins can be locked (approximate)\n");
	exit(ex);
}

static void upperfy(char *s)
{
	char *orig = s;

	for (; *s; s++) {
		if (*s >= 'a' && *s <= 'z') *s += 'A'-'a';

		if (!strchr("ACDEFGHJKLNPQRTUX234679", *s)) {
			fprintf(stderr, "character '%c' in %s is not valid\n", *s, orig);
			usage(stderr, 1);
		}
	}
}

int lexicocmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

static void checksum(char **argv)
{
	SHA256_CTX context;
	int i;
	uint8_t hashout[SHA256_DIGEST_LENGTH];

	sha256_Init(&context);
	for (i = 0; i < WASHERCNT; i++)
		sha256_Update(&context, (uint8_t *)argv[i], strlen(argv[i]));
	sha256_Final(&context, hashout);
	printf("checksum: %02x%02x\n", 0xff & hashout[0], 0xff & hashout[1]);
}

static _Noreturn void times(int argc, char **argv)
{
	int i;
	double yr;

	if (argc) usage(stderr, 1);
	printf("BLOCKHEIGHT YEAR MONTH\n");
	for (i = 0; i < 100; i++) {
		printf("%11d ", BASEHEIGHT + i*BLOCKSINCR);
		yr = BASEYEAR + YEARININCR * i;
		printf("%4d ", (int) yr);
		yr -= floor(yr);
		printf("%2d\n", (int)(yr * 12) + 1);
	}
	exit(0);
}

int main(int argc, char **argv)
{
	int i;
	arg0 = *argv++;
	argc--;

	if (argc == 1 && !strcmp("-h", *argv))		usage(stdout, 0);
	if (argc >= 1 && !strcmp("times", *argv))	times(argc-1, argv+1);

	if (argc != WASHERCNT) usage(stderr, 1);
	for (i = 0; i < WASHERCNT; i++) {
		if (strlen(argv[i]) != CHARSPERWASHER) usage(stderr, 1);
		upperfy(argv[i]);
	}

	qsort(argv, WASHERCNT, sizeof(*argv), lexicocmp);

	checksum(argv);
}
