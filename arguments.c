#include "arguments.h"
#include "log.h"

error_t parse_opt(int key, char *arg, struct argp_state *state) {
    Arguments* args = state->input;

    switch (key) {
        case 'b':
            sscanf(arg, "0x%x", &args->breakpoints[args->breakpoint_count]);
            log_debug("Breakpoint %d Set at 0x%08X", args->breakpoint_count, args->breakpoints[args->breakpoint_count]);
            args->breakpoint_count++;
            break;
        case 'l':
            switch (arg[0]) {
                case 't':
                    args->log_level = LOG_TRACE;
                    break;
                case 'd':
                    args->log_level = LOG_DEBUG;
                    break;
                case 'i':
                    args->log_level = LOG_INFO;
                    break;
                case 'w':
                    args->log_level = LOG_WARN;
                    break;
                case 'e':
                    args->log_level = LOG_ERROR;
                    break;
                case 'f':
                    args->log_level = LOG_FATAL;
                    break;
                default:
                    args->log_level = LOG_INFO;
                    break;
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
        }
    return 0;
}