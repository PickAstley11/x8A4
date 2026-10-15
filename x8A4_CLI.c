// x8A4 read-only command line interface.

#include <x8A4/x8A4.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static const struct option x8A4_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"verbose", no_argument, NULL, 'v'},
    {"print-all", no_argument, NULL, 'a'},
    {"get-cryptex-seed", no_argument, NULL, 'x'},
    {"get-cryptex-nonce", no_argument, NULL, 't'},
    {"get-apnonce-generator", no_argument, NULL, 'g'},
    {"get-apnonce", no_argument, NULL, 'n'},
    {"get-accel-key", required_argument, NULL, 'k'},
    {"get-accel-keys", no_argument, NULL, 'l'},
    {"get-nonce-seeds", no_argument, NULL, 'd'},
    {NULL, 0, NULL, 0}
};

static void x8A4_help(const char *cmd) {
  if (!cmd) {
    cmd = "x8A4";
  }
  printf("%s: Read-only firmware nonce and seed inspection tool\n", x8A4_version());
  printf("Usage: %s [OPTIONS]\n\n", cmd);
  printf("  -h, --help                  Show this help message\n");
  printf("  -v, --verbose               Enable verbose logging\n");
  printf("  -a, --print-all             Print all supported values\n");
  printf("  -x, --get-cryptex-seed      Read the current Cryptex1 seed\n");
  printf("  -t, --get-cryptex-nonce     Calculate the current Cryptex1 nonce\n");
  printf("  -g, --get-apnonce-generator Read the current APNonce generator\n");
  printf("  -n, --get-apnonce           Calculate the current APNonce\n");
  printf("  -k, --get-accel-key ID      Read one IOAESAccelerator key by ID\n");
  printf("  -l, --get-accel-keys        Read all IOAESAccelerator keys\n");
  printf("  -d, --get-nonce-seeds       Read nonce seed domains/slots\n");
}

static int initialize(void) {
  if (x8A4_init()) {
    fprintf(stderr, "Read-only inspection initialization failed.\n");
    return -1;
  }
  return 0;
}

static void print_all(void) {
  if (initialize()) return;
  x8A4_cli_get_cryptex_seed();
  x8A4_cli_get_cryptex_nonce();
  x8A4_cli_get_apnonce_generator();
  x8A4_cli_get_apnonce();
  x8A4_cli_get_accel_keys(0);
  x8A4_cli_get_nonce_seeds();
}

int main(int argc, char **argv) {
  int option;
  int option_index = 0;
  while ((option = getopt_long(argc, argv, "hvaxtgnk:ld", x8A4_options,
                               &option_index)) != -1) {
    switch (option) {
      case 'h':
        x8A4_help(argv[0]);
        break;
      case 'v':
        x8A4_cli_enable_verbose();
        break;
      case 'a':
        print_all();
        break;
      case 'x':
        if (!initialize()) x8A4_cli_get_cryptex_seed();
        break;
      case 't':
        if (!initialize()) x8A4_cli_get_cryptex_nonce();
        break;
      case 'g':
        if (!initialize()) x8A4_cli_get_apnonce_generator();
        break;
      case 'n':
        if (!initialize()) x8A4_cli_get_apnonce();
        break;
      case 'k':
        if (!initialize()) x8A4_cli_get_accel_keys((uint32_t)strtoul(optarg, NULL, 0));
        break;
      case 'l':
        if (!initialize()) x8A4_cli_get_accel_keys(0);
        break;
      case 'd':
        if (!initialize()) x8A4_cli_get_nonce_seeds();
        break;
      default:
        x8A4_help(argv[0]);
        return 2;
    }
  }
  if (argc == 1) {
    x8A4_help(argv[0]);
  }
  return 0;
}
