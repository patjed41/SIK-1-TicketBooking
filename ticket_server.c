// Needed to make getline work.
#define _GNU_SOURCE

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

#define DESCRIPTION_SIZE 80
#define MIN_NUMBER_OF_TICKETS 0
#define MAX_NUMBER_OF_TICKETS 65535

typedef struct Event {
    char description[DESCRIPTION_SIZE + 1];
    uint16_t tickets;
} Event;

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
void read_parameters(int argc, char *argv[], char **file_ptr,
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

    if ((*file_ptr = (char *) malloc(strlen(argv[2]) + 1)) == NULL) {
        fatal("malloc on file_ptr failed.");
    }
    strcpy(*file_ptr, argv[2]);

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

// Function responsible for reading information about events from file.
// Returns number of events read.
size_t read_events(const char *file, Event **events) {
    FILE *events_file = fopen(file, "r");
    if (events_file == NULL) {
        fatal("Could not open file.");
    }

    char *line_buffer = NULL;
    size_t line_buffer_size = 0;
    ssize_t line_size = 0;
    size_t events_read = 0;
    size_t events_size = 0;

    while ((line_size = getline(&line_buffer, &line_buffer_size, events_file)) != -1) {
        if (events_read == events_size) {
            events_size = (events_size + 1) * 2;
            if ((*events = (Event *) realloc(*events, events_size * sizeof(Event))) == NULL) {
                fatal("realloc on events failed.");
            }
        }

        strcpy((*events)[events_read].description, line_buffer);
        (*events)[events_read].description[line_size - 1] = '\0';

        if ((line_size = getline(&line_buffer, &line_buffer_size, events_file)) == -1) {
            break;
        }

        check_uint(line_buffer, MIN_NUMBER_OF_TICKETS, MAX_NUMBER_OF_TICKETS);
        (*events)[events_read].tickets = atoi(line_buffer);

        events_read++;

        errno = 0;
    }

    // Checking if last getline call succeeded.
    if (errno != 0) {
        fatal("Getline failed.");
    }

    if (fclose(events_file) != 0) {
        fatal("Could not close file.");
    }

    free(line_buffer);

    return events_read;
}

int main(int argc, char *argv[]) {
    char *file;
    uint16_t port = DEFAULT_PORT;
    uint32_t timeout = DEFAULT_TIMEOUT;

    read_parameters(argc, argv, &file, &port, &timeout);

    Event *events = NULL;
    size_t number_of_events = read_events(file, &events);
    for (size_t i = 0; i < number_of_events; i++) {
        printf("%s\n%d\n\n", events[i].description, events[i].tickets);
    }

    free(file);
    free(events);

    return 0;
}