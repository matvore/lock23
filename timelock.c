#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "btc/chainparams.h"
#include "btc/ecc_key.h"
#include "btc/sha2.h"

#define WASHERCNT 8
#define CHARSPERWASHER 5

/* 870000 happened on Nov 12, 2024 */
#define BASEHEIGHT 870000
#define BASEYEAR   (2024 + (11.0/30.0+10.0)/12.0)

#define BLOCKSINCR  5000
#define YEARININCR (0.09512937595129375)

static char *arg0;

_Noreturn void usage(FILE *f, int ex)
{
	fprintf(f, "usage: %s <washer1> .. <washer%d> <command> <commandargs>\n", arg0, (int)WASHERCNT);
	fprintf(f, "  washers in any order - each one has %d numbers/letters\n", (int)CHARSPERWASHER);
	fprintf(f, "  washers will be sorted like works in a dictionary (numbers\n");
	fprintf(f, "  before letters)\n");
	fprintf(f, "  Omit <command> ... to just verify the CHECKSUM environment variable\n");
	fprintf(f, "  COMMANDS:\n");
	fprintf(f, "  fortime <blockheight>\n");
	fprintf(f, "    shows keys, address, redeem script, for locking at this blockheight\n");
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
	const char *as = *(const char **)a;
	const char *bs = *(const char **)b;
	return strcmp(as, bs);
}

static void feedkeyinfo(char **washers, long blockheight, const char *flags, uint8_t *hashout)
{
	char buf[256];
	int showbrainwallet = !!strchr(flags, 'b');
	SHA256_CTX ctx;
	int i;

	sha256_Init(&ctx);
	if (showbrainwallet) printf("brainwallet phrase: \"");
	for (i = 0; i < WASHERCNT; i++) {
		sha256_Update(&ctx, (uint8_t*)washers[i], strlen(washers[i]));
		if (showbrainwallet) { putchar(washers[i][0]); printf("____"); }
	}
	if (blockheight >= 0) {
		sprintf(buf, "%ld", blockheight);
		sha256_Update(&ctx, buf, strlen(buf));
		if (showbrainwallet) printf("%ld", blockheight);
	}
	if (showbrainwallet) printf("\"\n");
	sha256_Final(&ctx, hashout);
}

static void checksum(char **ws)
{
	int i;
	uint8_t hashout[SHA256_DIGEST_LENGTH];
	char hex[5];
	const char *hexenv = getenv("CHECKSUM");

	feedkeyinfo(ws, -1, "b", hashout);
	sprintf(hex, "%02x%02x", 0xff & hashout[0], 0xff & hashout[1]);
	if (!hexenv || strcmp(hex,hexenv)) {
		fprintf(stderr, "you set CHECKSUM to %s\n", hexenv ? hexenv : "<nothing>");
		fprintf(stderr, "does not match the checksum of the washers: %s\n", hex);
		fprintf(stderr, "if it is correct, run: export CHECKSUM=%s\n", hex);
		fprintf(stderr, "and retry the command\n");
		exit(1);
	}
}

#define TIMESHEADER "BLOCKHEIGHT YEAR MONTH\n"
static void timeinfo(int incrs)
{
	double yr = BASEYEAR + YEARININCR * incrs;
	printf("%11d ", BASEHEIGHT + incrs*BLOCKSINCR);
	printf("%4d ", (int) yr);
	yr -= floor(yr);
	printf("%2d\n", (int)(yr * 12) + 1);
}

static _Noreturn void times(int argc, char **argv)
{
	int i;
	double yr;

	if (argc) usage(stderr, 1);
	printf(TIMESHEADER);
	for (i = 0; i < 100; i++) timeinfo(i);
	exit(0);
}

static int issecure(void)
{
	static int res;
	const char *e;

	if (res) return res > 0;

	e = getenv("ISSECURE");
	if (!e || !*e) {
		fprintf(stderr, "hiding sensitive info, run and retry to show: ");
		fprintf(stderr, "export ISSECURE=1\n");
		res = -1;
	} else {
		res = 1;
	}
	return res > 0;
}

static _Noreturn void fortime(char **washers, char *heightstr)
{
	long height = atol(heightstr);
	uint8_t hashout[SHA256_DIGEST_LENGTH];
	char privkey_wif[512];
	size_t wif_sz = sizeof privkey_wif;

	if (height < BASEHEIGHT) {
		fprintf(stderr, "invalid height: %s\n", heightstr);
		exit(1);
	}

	if ((height - BASEHEIGHT) % BLOCKSINCR) {
		fprintf(stderr, "must <height> minus %d be a multiple of %d\n",
			BASEHEIGHT, BLOCKSINCR);
		exit(1);
	}

	printf(TIMESHEADER);
	timeinfo((height - BASEHEIGHT) / BLOCKSINCR);

	feedkeyinfo(washers, height, "b", hashout);

	if (sizeof(btc_key) != sizeof(hashout)) {
		fprintf(stderr, "PANIC key size should be %zu, but it's %zu?\n",
			sizeof hashout, sizeof(btc_key));
		exit(1);
	}
	btc_privkey_encode_wif((void*)hashout, &btc_chainparams_main, privkey_wif, &wif_sz);
	printf("private key: %s\n", issecure() ? privkey_wif : "<hidden>");

	exit(0);
}

int main(int argc, char **argv)
{
	char **washers;
	int i;
	arg0 = *argv++;
	argc--;

	if (argc == 1 && !strcmp("-h", *argv))		usage(stdout, 0);
	if (argc >= 1 && !strcmp("times", *argv))	times(argc-1, argv+1);

	if (argc < WASHERCNT) usage(stderr, 1);
	washers = argv;
	argv += WASHERCNT;
	argc -= WASHERCNT;
	for (i = 0; i < WASHERCNT; i++) {
		if (strlen(washers[i]) != CHARSPERWASHER) usage(stderr, 1);
		upperfy(washers[i]);
	}

	qsort(washers, WASHERCNT, sizeof(*washers), lexicocmp);

	checksum(washers);

	if (!argc) exit(0);

	if (argc == 2 && !strcmp(argv[0], "fortime")) fortime(washers, argv[1]);

	usage(stderr, 1);
}
