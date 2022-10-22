#include "arguments.h"
#include "log.h"

error_t parse_opt(int key, char *arg, struct argp_state *state) {
    Arguments* arguments = state->input;

    switch (key) {
        case 'l':
            switch (arg[0]) {
                case 't':
                    arguments->log_level = LOG_TRACE;
                    break;
                case 'd':
                    arguments->log_level = LOG_DEBUG;
                    break;
                case 'i':
                    arguments->log_level = LOG_INFO;
                    break;
                case 'w':
                    arguments->log_level = LOG_WARN;
                    break;
                case 'e':
                    arguments->log_level = LOG_ERROR;
                    break;
                case 'f':
                    arguments->log_level = LOG_FATAL;
                    break;
                default:
                    arguments->log_level = LOG_INFO;
                    break;
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
        }
    return 0;
}