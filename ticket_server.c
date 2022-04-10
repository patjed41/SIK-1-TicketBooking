// Needed to make getline work.
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#define DEFAULT_PORT 2022
#define MIN_PORT 0
#define MAX_PORT 65535

#define DEFAULT_TIMEOUT 5
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 86400

#define DESCRIPTION_SIZE 80
#define MIN_NUMBER_OF_TICKETS 0
#define MAX_NUMBER_OF_TICKETS 65535

#define OCTET_SIZE 8

#define GET_EVENTS_ID 1
#define EVENTS_ID 2
#define GET_RESERVETION_ID 3
#define RESERVATION_ID 4
#define GET_TICKETS_ID 5
#define TICKETS_ID 6
#define BAD_REQUEST_ID 255

#define DATAGRAM_LIMIT 65507

#define RESERVATION_OFFSET 1000000

#define TICKET_SIZE 7
#define TICKETS_LIMIT 9357 // (DATAGRAM_LIMIT - 7) / TICKET_SIZE
#define TICKET_ID_BASE 36
#define MIN_TICKET_ID 1
#define MAX_TICKET_ID 78364164095 // TICKET_ID_BASE^TICKET_SIZE - 1

#define COOKIE_SIZE 48
#define MIN_COOKIE_CHAR 33
#define MAX_COOKIE_CHAR 126

// Evaluate `x`: if non-zero, describe it as a standard error code and exit with an error.
#define CHECK(x)                                                          \
    do {                                                                  \
        int err = (x);                                                    \
        if (err != 0) {                                                   \
            fprintf(stderr, "Error: %s returned %d in %s at %s:%d\n%s\n", \
                #x, err, __func__, __FILE__, __LINE__, strerror(err));    \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Evaluate `x`: if false, print an error message and exit with an error.
#define ENSURE(x)                                                         \
    do {                                                                  \
        bool result = (x);                                                \
        if (!result) {                                                    \
            fprintf(stderr, "Error: %s was false in %s at %s:%d\n",       \
                #x, __func__, __FILE__, __LINE__);                        \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Check if errno is non-zero, and if so, print an error message and exit with an error.
#define PRINT_ERRNO()                                                  \
    do {                                                               \
        if (errno != 0) {                                              \
            fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n",    \
              errno, __func__, __FILE__, __LINE__, strerror(errno));   \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)


// Set `errno` to 0 and evaluate `x`. If `errno` changed, describe it and exit.
#define CHECK_ERRNO(x)                                                             \
    do {                                                                           \
        errno = 0;                                                                 \
        (void) (x);                                                                \
        PRINT_ERRNO();                                                             \
    } while (0)

// Note: the while loop above wraps the statements so that the macro can be used with a semicolon
// for example: if (a) CHECK(x); else CHECK(y);

// Print an error message and exit with an error.
void fatal(const char *fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

typedef struct Event {
    char description[DESCRIPTION_SIZE];
    uint8_t description_length;
    uint16_t tickets;
} Event;

struct __attribute__((__packed__)) ReservationRequest {
    uint32_t event_id;
    uint16_t ticket_count;
};

typedef struct ReservationRequest ReservationRequest;

struct __attribute__((__packed__)) Reservation {
    uint32_t reservation_id;
    uint32_t event_id;
    uint16_t ticket_count;
    char cookie[COOKIE_SIZE];
    time_t expiration_time;
};

typedef struct Reservation Reservation;

struct __attribute__((__packed__)) TicketsRequest {
    uint32_t reservation_id;
    char cookie[COOKIE_SIZE];
};

typedef struct TicketsRequest TicketsRequest;

// Checks if value of uint32_t represented by [str] is between [min_value]
// and [max_value].
bool check_uint(const char *str, uint32_t min_value, uint32_t max_value) {
    errno = 0;

    char *end_ptr;
    uint32_t value = strtoul(str, &end_ptr, 10);

    return *end_ptr == '\0' && errno == 0 && value >= min_value && value <= max_value;
}

void read_file_name(const char *file_str, char **file_ptr) {
    if (strcmp(file_str, "-f") == 0) {
        fatal("Illegal file name \'-f\'.");
    }

    if ((*file_ptr = (char *) malloc(strlen(file_str) + 1)) == NULL) {
        fatal("malloc on file_ptr failed.");
    }
    strcpy(*file_ptr, file_str);
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
    if (argc % 2 == 0) {
        fatal("Wrong number of command line parameters.");
    }

    for (int i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "-f") == 0) {
            read_file_name(argv[i + 1], file_ptr);
        }
        else if (strcmp(argv[i], "-p") == 0) {
            read_port(argv[i + 1], port_ptr);
        }
        else if (strcmp(argv[i], "-t") == 0) {
            read_timeout(argv[i + 1], timeout_ptr);
        }
        else {
            fatal("Illegal parameter ", argv[i], ".");
        }
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

        (*events)[events_read].description_length = line_size - 1;
        strncpy((*events)[events_read].description, line_buffer, line_size - 1);

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

int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket
    ENSURE(socket_fd > 0);
    // after socket() call; we should close(sock) on any execution path;

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
    server_address.sin_port = htons(port);

    // bind the socket to a concrete address
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                        (socklen_t) sizeof(server_address)));

    return socket_fd;
}

size_t read_message(int socket_fd, struct sockaddr_in *client_address, char *buffer, size_t max_length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0; // we do not request anything special
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (len < 0) {
        PRINT_ERRNO();
    }
    return (size_t) len;
}

void send_message(int socket_fd, const struct sockaddr_in *client_address, const char *message, size_t length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address, address_length);
    ENSURE(sent_length == (ssize_t) length);
}

uint8_t get_message_id(const char buffer[], size_t read_length) {
    if (read_length < 1) {
        return 0;
    }

    uint8_t *id_ptr = (uint8_t *) buffer;

    if (*id_ptr != GET_EVENTS_ID && *id_ptr != GET_RESERVETION_ID && *id_ptr != GET_TICKETS_ID) {
        return 0;
    }

    return *id_ptr;
}

void put_into_buffer(char buffer[], const void *source, size_t size, size_t *next_byte_ptr) {
    memcpy(buffer + *next_byte_ptr, source, size);
    *next_byte_ptr += size;
}

void put_message_id_into_buffer(char buffer[], uint8_t message_id) {
    memcpy(buffer, &message_id, 1);
}

// Returns length.
size_t build_events_message(char buffer[], Event *events, size_t number_of_events) {
    uint32_t next_event = 0;
    size_t next_byte = 1;
    size_t next_event_size = 0;

    put_message_id_into_buffer(buffer, EVENTS_ID);
    
    while (next_event < number_of_events) {
        next_event_size = 7 + events[next_event].description_length;
        if (next_event_size + next_byte > DATAGRAM_LIMIT) {
            break;
        }

        uint32_t net_order_next_event = htonl(next_event);
        uint16_t net_order_tickets = htons(events[next_event].tickets);
        put_into_buffer(buffer, &net_order_next_event, 4, &next_byte);
        put_into_buffer(buffer, &net_order_tickets, 2, &next_byte);
        put_into_buffer(buffer, &events[next_event].description_length, 1, &next_byte);
        put_into_buffer(buffer, events[next_event].description, events[next_event].description_length, &next_byte);

        next_event++;
    }

    return next_byte;
}

void get_reservetion_request(const char buffer[], ReservationRequest *request) {
    memcpy(request, buffer, sizeof(ReservationRequest));
    request->event_id = ntohl(request->event_id);
    request->ticket_count = ntohs(request->ticket_count);
}

bool is_reservation_possible(const ReservationRequest *request, const Event *events, size_t number_of_events) {
    return request->event_id < number_of_events &&
           request->ticket_count > 0 &&
           request->ticket_count <= TICKETS_LIMIT &&
           events[request->event_id].tickets >= request->ticket_count;
}

char random_char(char min_char, char max_char) {
    return rand() % (max_char - min_char + 1) + min_char;
}

void fill_cookie(uint32_t reservation_id, char cookie[]) {
    static const char MID_COOKIE_CHAR = (MAX_COOKIE_CHAR + MIN_COOKIE_CHAR) / 2;

    for (size_t i = 0; i < sizeof(uint32_t) * OCTET_SIZE; i++) {
        if (reservation_id & (1 << i)) {
            cookie[i] = random_char(MIN_COOKIE_CHAR, MID_COOKIE_CHAR);
        }
        else {
            cookie[i] = random_char(MID_COOKIE_CHAR + 1, MAX_COOKIE_CHAR);
        }
    }

    for (size_t i = sizeof(uint32_t) * OCTET_SIZE; i < COOKIE_SIZE; i++) {
        cookie[i] = random_char(MID_COOKIE_CHAR, MAX_COOKIE_CHAR);
    }
}

void create_reservation(const ReservationRequest *request, Reservation **reservations, uint64_t **first_tickets,
                        size_t *number_of_reservations, size_t *reservations_size, uint32_t timeout) {
    if (*number_of_reservations == *reservations_size) {
        *reservations_size = (*reservations_size + 1) * 2;
        if ((*reservations = (Reservation *) realloc(*reservations, *reservations_size * sizeof(Reservation))) == NULL) {
            fatal("realloc on reservations failed.");
        }
        if ((*first_tickets = (uint64_t *) realloc(*first_tickets, *reservations_size * sizeof(uint64_t))) == NULL) {
            fatal("realloc on reservations failed.");
        }
    }

    (*reservations)[*number_of_reservations].reservation_id = htonl(*number_of_reservations + RESERVATION_OFFSET);
    (*reservations)[*number_of_reservations].event_id = htonl(request->event_id);
    (*reservations)[*number_of_reservations].ticket_count = htons(request->ticket_count);
    fill_cookie((*reservations)[*number_of_reservations].reservation_id, (*reservations)[*number_of_reservations].cookie);
    (*reservations)[*number_of_reservations].expiration_time = htobe64(time(NULL) + (time_t) timeout);

    (*first_tickets)[*number_of_reservations] = 0;
    (*number_of_reservations)++;
}

void build_reservation_message(char buffer[], Reservation *reservations, size_t number_of_reservations) {
    put_message_id_into_buffer(buffer, RESERVATION_ID);

    memcpy(buffer + 1, reservations + (number_of_reservations - 1), sizeof(Reservation));
}

void update_reservations(const Reservation *reservations, const uint64_t *first_tickets, size_t number_of_reservations,
                         size_t *next_reservation_to_update, Event *events) {
    while (*next_reservation_to_update < number_of_reservations &&
           time(NULL) > (time_t) be64toh(reservations[*next_reservation_to_update].expiration_time)) {
        if (first_tickets[*next_reservation_to_update] == 0) {
            events[ntohl(reservations[*next_reservation_to_update].event_id)].tickets += ntohs(reservations[*next_reservation_to_update].ticket_count);
        }

        (*next_reservation_to_update)++;
    }
}

void get_tickets_request(const char buffer[], TicketsRequest *request) {
    memcpy(request, buffer, sizeof(TicketsRequest));
    request->reservation_id = ntohl(request->reservation_id);
}

bool is_sending_tickets_possible(const TicketsRequest *request, const Reservation *reservations,
                                 const uint64_t *first_tickets, size_t number_of_reservations) {
    size_t reservation_index = request->reservation_id - RESERVATION_OFFSET;

    return request->reservation_id >= RESERVATION_OFFSET &&
           reservation_index < number_of_reservations &&
           strcmp(reservations[reservation_index].cookie, request->cookie) == 0 &&
           ((time_t) be64toh(reservations[reservation_index].expiration_time) >= time(NULL) ||
            first_tickets[reservation_index] != 0);
}

// [value] should be less than 36
char get_symbol_in_base36(uint64_t value) {
    ENSURE(value < TICKET_ID_BASE);
    if (value < 10) {
        return '0' + value;
    }
    else {
        return 'A' + value - 10;
    }
}

// [buffer] size shuld be at least equal to TICKET_SIZE
void ticket_to_base36(char buffer[], uint64_t ticket_id) {
    ENSURE(ticket_id < MAX_TICKET_ID);
    memset(buffer, '0', TICKET_SIZE);

    size_t next_letter = 0;
    while (ticket_id > 0) {
        buffer[next_letter] = get_symbol_in_base36(ticket_id % TICKET_ID_BASE);
        ticket_id /= TICKET_ID_BASE;
        next_letter++;
    }
}

// Returns length.
size_t build_tickets_message(char buffer[], const TicketsRequest *request,
                             const Reservation *reservations, uint64_t first_ticket) {
    put_message_id_into_buffer(buffer, TICKETS_ID);

    size_t next_byte = 1;
    const Reservation *reservation = reservations + (request->reservation_id - RESERVATION_OFFSET);

    put_into_buffer(buffer, &(reservation->reservation_id), sizeof(uint32_t), &next_byte);
    put_into_buffer(buffer, &(reservation->ticket_count), sizeof(uint16_t), &next_byte);

    char ticket_buffer[TICKET_SIZE];
    for (size_t i = 0; i < ntohs(reservation->ticket_count); i++) {
        ticket_to_base36(ticket_buffer, first_ticket++);
        put_into_buffer(buffer, ticket_buffer, TICKET_SIZE, &next_byte);
    }

    return next_byte;
}

void build_bad_request_message(char buffer[], uint32_t id) {
    put_message_id_into_buffer(buffer, BAD_REQUEST_ID);

    uint32_t net_order_id = htonl(id);
    memcpy(buffer + 1, &net_order_id, sizeof(uint32_t));
}

int main(int argc, char *argv[]) {
    char *file;
    uint16_t port = DEFAULT_PORT;
    uint32_t timeout = DEFAULT_TIMEOUT;

    read_parameters(argc, argv, &file, &port, &timeout);

    Event *events = NULL;
    size_t number_of_events = read_events(file, &events);

    Reservation *reservations = NULL;
    size_t number_of_reservations = 0;
    size_t reservations_size = 0;
    size_t next_reservation_to_update = 0;
    uint64_t *first_tickets = NULL;
    uint64_t next_ticket = MIN_TICKET_ID;

    char buffer[DATAGRAM_LIMIT];
    memset(buffer, 0, sizeof(buffer));

    int socket_fd = bind_socket(port);

    struct sockaddr_in client_address;
    size_t read_length;
    for (;;) {
        read_length = read_message(socket_fd, &client_address, buffer, sizeof(buffer));
        uint8_t message_id = get_message_id(buffer, read_length);

        update_reservations(reservations, first_tickets, number_of_reservations,
                            &next_reservation_to_update, events);

        switch (message_id) {
            case GET_EVENTS_ID:
                if (read_length == 1) {
                    size_t send_length = build_events_message(buffer, events, number_of_events);
                    send_message(socket_fd, &client_address, buffer, send_length);
                }
                break;
            case GET_RESERVETION_ID:
                if (read_length == sizeof(ReservationRequest) + 1) {
                    ReservationRequest request;
                    get_reservetion_request(buffer + 1, &request);
                    if (is_reservation_possible(&request, events, number_of_events)) {
                        create_reservation(&request, &reservations, &first_tickets, &number_of_reservations, &reservations_size, timeout);
                        events[request.event_id].tickets -= request.ticket_count;
                        build_reservation_message(buffer, reservations, number_of_reservations);
                        send_message(socket_fd, &client_address, buffer, sizeof(Reservation) + 1);
                    }
                    else {
                        build_bad_request_message(buffer, request.event_id);
                        send_message(socket_fd, &client_address, buffer, sizeof(uint32_t) + 1);
                    }
                }
                break;
            case GET_TICKETS_ID:
                if (read_length == sizeof(TicketsRequest) + 1) {
                    TicketsRequest request;
                    get_tickets_request(buffer + 1, &request);
                    if (is_sending_tickets_possible(&request, reservations, first_tickets, number_of_reservations)) {
                        size_t reservation_index = request.reservation_id - RESERVATION_OFFSET;
                        if (first_tickets[reservation_index] == 0) {
                            first_tickets[reservation_index] = next_ticket;
                            next_ticket += ntohs(reservations[reservation_index].ticket_count);
                        }
                        size_t send_length = build_tickets_message(buffer, &request,
                            reservations, first_tickets[reservation_index]);
                        send_message(socket_fd, &client_address, buffer, send_length);
                    }
                    else {
                        build_bad_request_message(buffer, request.reservation_id);
                        send_message(socket_fd, &client_address, buffer, sizeof(uint32_t) + 1);
                    }
                }
                break;
        }
    }

    CHECK_ERRNO(close(socket_fd));

    free(file);
    free(events);
    free(reservations);
    free(first_tickets);

    return 0;
}