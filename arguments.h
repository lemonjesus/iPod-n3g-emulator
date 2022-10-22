#ifndef _ARGUMENTS_H_
#define _ARGUMENTS_H_

#include <stdint.h>
#include <argp.h>

typedef struct {
    int log_level;  // log level to use. default: debug
    uint32_t breakpoints[256];
    uint32_t breakpoint_count;
} Arguments;

static struct argp_option options[] = {
    {"breakpoint", 'b', "0xADDRESS", 0, "Sets a breakpoint at a specified hexidecimal address"},
    {"loglevel", 'l', "LOGLEVEL", 0, "Sets the logging verbosity (trace, debug, info, warn, error, fatal) - use the first letter of each for shorthand"},
    {0}
};

error_t parse_opt(int key, char *arg, struct argp_state *state);
static char doc[] = "Emulates a 3rd Generation iPod Nano";

#endif