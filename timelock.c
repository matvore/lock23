#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "btc/chainparams.h"
#include "btc/ecc_key.h"
#include "btc/sha2.h"
#include "btc/cstr.h"
#include "btc/base58.h"
#include "btc/script.h"
#include "btc/ripemd160.h"
#include "btc/ecc.h"

#define WASHERCNT 8
#define CHARSPERWASHER 5

/* 870000 happened on Nov 12, 2024 */
#define BASEHEIGHT 870000
#define BASEYEAR   (2024 + (11.0/30.0+10.0)/12.0)

#define BLOCKSINCR  5000
#define YEARININCR (0.09512937595129375)

#define PANIC(...) do {					\
	fprintf(stderr, "PANIC: " __VA_ARGS__);		\
	fprintf(stderr, "\n");				\
	abort();					\
} while (0);

static char *arg0;

_Noreturn void usage(FILE *f, int ex)
{
	fprintf(f,
"usage: %s <washer1> .. <washer%d> <command> <commandargs>\n",
	arg0, (int)WASHERCNT); fprintf(f,
"  washers in any order - each one has %d numbers/letters\n",
	(int)CHARSPERWASHER); fprintf(f,
"  washers will be sorted like works in a dictionary (numbers\n"
"  before letters)\n"
"  Omit <command> ... to just verify the CHECKSUM environment variable\n"
"  COMMANDS:\n"
"  fortime <blockheight>\n"
"    shows keys, address, redeem script, for locking at this blockheight\n"
"  bals\n"
"    similar to running 'times', but includes addresses and balances\n"
"\n"
"usage: %s times\n", arg0); fprintf(f,
"  shows times at which coins can be locked (approximate)\n");
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
	if (showbrainwallet)
		printf("%s: \"", blockheight >= 0	? "brainwallet phrase"
							: "base washer code");
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
		fprintf(stderr,
"you set CHECKSUM to %s\n", hexenv ? hexenv : "<nothing>"); fprintf(stderr,
"does not match the checksum of the washers: %s\n", hex); fprintf(stderr,
"if it is correct, run: export CHECKSUM=%s\n", hex); fprintf(stderr,
"and retry the command\n");
		exit(1);
	}
}

#define TIMESHEADER "BLOCKHEIGHT YEAR MONTH"
static void timeinfo(int incrs)
{
	double yr = BASEYEAR + YEARININCR * incrs;
	printf("%11d ", BASEHEIGHT + incrs*BLOCKSINCR);
	printf("%4d ", (int) yr);
	yr -= floor(yr);
	printf("%5d", (int)(yr * 12) + 1);
}

static _Noreturn void times(int argc, char **argv)
{
	int i;
	double yr;

	if (argc) usage(stderr, 1);
	printf(TIMESHEADER "\n");
	for (i = 0; i < 100; i++) { timeinfo(i); putchar('\n'); }
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

static void append_byte(cstring *out, int b)
{
	uint8_t by = b;
	cstr_append_buf(out, &by, 1);
}

static void append_push_height(cstring *out, long height)
{
	int hsz;

	if (height >= 500000000)
		PANIC("this blockheight is not valid: %ld", height);
	if (height > 0x7fffff) {
		fprintf(stderr, "WARNING!! "
			"This height is very far in the future!! %ld\n",
			height);
		hsz = 4;
	}
	else if (height > 0x7fff) hsz = 3;
	else PANIC("shouldn't be so low: %ld", height);

	append_byte(out, hsz);
	for (; hsz; hsz--) {
		append_byte(out, height);
		height >>= 8;
	}
}

static void printbalance(const char *addr)
{
	char cmd[1024];
	static char *server;
	const char *servenv;

	if (!server) {
		/*	To use official public server:
			export BEXSERVER=https://bitcoinexplorer.org */
		servenv = getenv("BEXSERVER");
		server = strdup(servenv ? servenv : "http://10.0.0.111:3002");
	}
	snprintf(
		cmd, sizeof cmd,
		"curl -s %s/api/address/%s | "
		"sed '/.*\"balanceSat\":\\([^,]*\\).*/!d; s//\\1/'",
		server, addr);
	system(cmd);
}

static void timelockinfo(char **washers, long height, const char *flags)
{
	uint8_t privhash[SHA256_DIGEST_LENGTH];
	char privkey_wif[512];
	size_t wif_sz = sizeof privkey_wif;
	btc_pubkey pubk;
	cstring *scri;
	int i;
	uint8_t scrhash1[32];
	uint8_t scrhash2[20];
	char addr[64];
	int fullout = !!strchr(flags, 'F');

	if (height < BASEHEIGHT) {
		fprintf(stderr, "invalid height: %ld\n", height);
		exit(1);
	}

	if ((height - BASEHEIGHT) % BLOCKSINCR) {
		fprintf(stderr, "must <height> minus %d be a multiple of %d\n",
			BASEHEIGHT, BLOCKSINCR);
		exit(1);
	}

	if (fullout) {
		printf(TIMESHEADER "\n");
		timeinfo((height - BASEHEIGHT) / BLOCKSINCR);
		putchar('\n');
	}

	feedkeyinfo(washers, height, fullout ? "b" : "", privhash);

	if (sizeof(btc_key) != sizeof(privhash))
		PANIC("key size should be %zu, but it's %zu?",
			sizeof privhash, sizeof(btc_key));
	if (fullout) {
		btc_privkey_encode_wif(
			(void*)privhash, &btc_chainparams_main,
			privkey_wif, &wif_sz);
		printf(	"private key: %s\n",
			issecure() ? privkey_wif : "<hidden>");
		memset(privkey_wif, 0, sizeof(privkey_wif));
	}

	btc_pubkey_from_key((void*)privhash, &pubk);
	memset(privhash, 0, sizeof(privhash));
	if (!pubk.compressed) PANIC("expected a compressed key");

	scri = cstr_new("");
	append_push_height(scri, height);
	append_byte(scri, OP_CHECKLOCKTIMEVERIFY);
	append_byte(scri, OP_DROP);

	if (33 != btc_pubkey_get_length(pubk.pubkey[0]))
		PANIC("wrong pubkey length");
	append_byte(scri, 33);
	cstr_append_buf(scri, pubk.pubkey, 33);
	append_byte(scri, OP_CHECKSIG);

	if (fullout) {
		printf("redeem script: ");
		for (i = 0; i < scri->len; i++)
			printf("%02x", scri->str[i] & 0xff);
		putchar('\n');
	}
	sha256_Raw(scri->str, scri->len, scrhash1);
	cstr_free(scri, 1);
	btc_ripemd160(scrhash1, sizeof(scrhash1), scrhash2);

	if (!btc_p2sh_addr_from_hash160(
			scrhash2, &btc_chainparams_main, addr, sizeof(addr)))
		PANIC("could not encode p2sh address");
	if (fullout) printf("addr: ");
	printf("%s", addr);
	if (fullout) printf("\nsat balance:");
	putchar(' ');
	fflush(stdout);
	printbalance(addr);

	putchar('\n');
}

static _Noreturn void fortime(char **washers, char *heightstr)
{
	long h = atol(heightstr);
	if (strcmp(heightstr, "0") && !h) {
		fprintf(stderr, "invalid height arg: %s\n", heightstr);
		exit(1);
	}
	timelockinfo(washers, h, "F");
	exit(0);
}

static _Noreturn void bals(char **washers)
{
	int i;
	printf(TIMESHEADER "%35s BALANCE\n", "ADDR");
	for (i = 0; i < 100; i++) {
		timeinfo(i);
		putchar(' ');
		timelockinfo(washers, BASEHEIGHT + BLOCKSINCR * (long)i, "");
	}
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
	if (!btc_ecc_start()) PANIC("could not init ecc engine");
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
	if (argc == 1 && !strcmp(argv[0], "bals")) bals(washers);

	usage(stderr, 1);
}
