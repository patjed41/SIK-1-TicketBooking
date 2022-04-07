#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>

#define DEFAULT_PORT 2022
#define MIN_PORT 0
#define MAX_PORT 65535

#define DEFAULT_TIMEOUT 5
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 86400

// Prints [message] and exits program with code 1.
void fatal(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

// Checks if value of uint32_t represented by [str] is between [min_value]
// and [max_value].
bool check_uint(const char *str, uint32_t min_value, uint32_t max_value) {
    errno = 0;

    char *end_ptr;
    uint32_t value = strtoul(str, &end_ptr, 10);

    return *end_ptr == '\0' && errno == 0 && value >= min_value && value <= max_value;
}

void read_port(const char *port_str, uint16_t *port_ptr) {
    if (!check_uint(port_str, MIN_PORT, MAX_PORT)) {
        fatal("Incorrect port.");
    }

    *port_ptr = atoi(port_str);
}

void read_timeout(const char *timeout_str, uint32_t *timeout_ptr) {
    if (!check_uint(timeout_str, MIN_TIMEOUT, MAX_TIMEOUT)) {
        fatal("Incorrect timeout.");
    }

    *timeout_ptr = atoi(timeout_str);
}

// Function responsible for reading and checking comand line parameters.
void read_parameters(int argc, char *argv[], char **file_name_ptr,
                     uint16_t *port_ptr, uint32_t *timeout_ptr) {
    if (argc != 3 && argc != 5 && argc != 7) {
        fatal("Wrong number of command line parameters.");
    }

    if (strcmp(argv[1], "-f") != 0) {
        fatal("First parameter should be \'-f\'.");
    }
    if (strcmp(argv[2], "-f") == 0) {
        fatal("File name \'-f\' is prohibited.");
    }
    strcpy(*file_name_ptr, argv[2]);

    // only port
    if (argc == 5 && strcmp(argv[3], "-p") == 0) {
        read_port(argv[4], port_ptr);
    }
    // only timeout
    else if (argc == 5 && strcmp(argv[3], "-t") == 0) {
        read_timeout(argv[4], timeout_ptr);
    }
    // port and timout
    else if (argc == 7 && strcmp(argv[3], "-p") == 0 && strcmp(argv[5], "-t") == 0) {
        read_port(argv[4], port_ptr);
        read_timeout(argv[6], timeout_ptr);
    }
    // second or third parameter is incorrect
    else if (argc > 3) {
        fatal("Second or third parameter is incorrect.");
    }
}

int main(int argc, char *argv[]) {
    char *file_name;
    uint16_t port = DEFAULT_PORT;
    uint32_t timeout = DEFAULT_TIMEOUT;

    read_parameters(argc, argv, &file_name, &port, &timeout);

    printf("%s\n%d\n%d", file_name, port, timeout);
}