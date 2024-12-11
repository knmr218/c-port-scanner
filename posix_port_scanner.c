#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_THREADS 100
#define MAX_PORTS 65535

typedef struct {
    const char *ip_address;
    int port;
    int is_udp;
    int *open_ports;
    int *open_ports_count;
} ScanArgs;

const char *get_service_name(int port, int is_udp) {
    static char service_name[64];
    FILE *services = fopen("/etc/services", "r");
    if (!services) {
        perror("Could not open /etc/services");
        return "unknown";
    }

    char line[256];
    char protocol[4];
    snprintf(protocol, sizeof(protocol), "%s", is_udp ? "udp" : "tcp");

    while (fgets(line, sizeof(line), services)) {
        char name[64];
        int port_num;
        char proto[4];
        if (sscanf(line, "%63s %d/%3s", name, &port_num, proto) == 3) {
            if (port_num == port && strcmp(proto, protocol) == 0) {
                fclose(services);
                snprintf(service_name, sizeof(service_name), "%s", name);
                return service_name;
            }
        }
    }

    fclose(services);
    return "unknown";
}

void *scan_port(void *args) {
    ScanArgs *scan_args = (ScanArgs *)args;
    int sock;
    struct sockaddr_in server;

    if (scan_args->is_udp) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        sock = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (sock == -1) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    server.sin_family = AF_INET;
    server.sin_port = htons(scan_args->port);
    inet_pton(AF_INET, scan_args->ip_address, &server.sin_addr);

    if (scan_args->is_udp) {
        char message[] = "Hello";
        sendto(sock, message, sizeof(message), 0, (struct sockaddr*)&server, sizeof(server));
        char buffer[10];
        socklen_t len = sizeof(server);
        if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server, &len) >= 0) {
            scan_args->open_ports[(*scan_args->open_ports_count)++] = scan_args->port;
        }
    } else {
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            scan_args->open_ports[(*scan_args->open_ports_count)++] = scan_args->port;
        }
    }

    close(sock);
    pthread_exit(NULL);
}

void start_scan(const char *ip_address, const int *ports, int port_count, int is_udp) {
    pthread_t threads[MAX_THREADS];
    ScanArgs args[MAX_THREADS];
    int thread_count = 0;

    int open_ports[MAX_PORTS];
    int open_ports_count = 0;

    for (int i = 0; i < port_count; i++) {
        args[thread_count].ip_address = ip_address;
        args[thread_count].port = ports[i];
        args[thread_count].is_udp = is_udp;
        args[thread_count].open_ports = open_ports;
        args[thread_count].open_ports_count = &open_ports_count;

        pthread_create(&threads[thread_count], NULL, scan_port, &args[thread_count]);
        thread_count++;

        if (thread_count == MAX_THREADS || i == port_count - 1) {
            for (int j = 0; j < thread_count; j++) {
                pthread_join(threads[j], NULL);
            }
            thread_count = 0;
        }
    }

    if (open_ports_count > 0) {
        // 最大桁数を計算
        int max_digits = 0;
        for (int i = 0; i < open_ports_count; i++) {
            int temp = open_ports[i];
            int digits = 0;
            while (temp > 0) {
                temp /= 10;
                digits++;
            }
            if (digits > max_digits) {
                max_digits = digits;
            }
        }

        printf("\n%-*sSTATE  SERVICE\n", max_digits + 5, "PORT");
        for (int i = 0; i < open_ports_count; i++) {
            // 数字と文字列を結合
            char combined[50];  // 結合用の文字列バッファ
            sprintf(combined, "%d/%s", open_ports[i], is_udp ? "udp" : "tcp");

            const char *service = get_service_name(open_ports[i], is_udp);
            printf("%-*s open  %-20s\n", max_digits + 5, combined, service);
        }
    } else {
        printf("No open ports found for %s\n", is_udp ? "UDP" : "TCP");
    }
}

int is_valid_ip(const char *ip_address) {
    if (strcmp(ip_address, "192.168.1.3") == 0 || strcmp(ip_address, "127.0.0.1") == 0) {
        struct sockaddr_in sa;
        return inet_pton(AF_INET, ip_address, &(sa.sin_addr)) == 1;
    } else {
        return 0;
    }
}

int parse_ports(const char *port_arg, int *ports, int max_ports) {
    int count = 0;
    char *port_str = strdup(port_arg);
    char *token = strtok(port_str, ",");

    while (token != NULL && count < max_ports) {
        if (strchr(token, '-') != NULL) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2 && start > 0 && end > 0 && start <= 65535 && end <= 65535 && start <= end) {
                for (int i = start; i <= end && count < max_ports; i++) {
                    ports[count++] = i;
                }
            } else {
                fprintf(stderr, "Invalid range: %s\n", token);
                free(port_str);
                return -1;
            }
        } else {
            int port = atoi(token);
            if (port > 0 && port <= 65535) {
                ports[count++] = port;
            } else {
                fprintf(stderr, "Invalid port: %s\n", token);
                free(port_str);
                return -1;
            }
        }
        token = strtok(NULL, ",");
    }

    free(port_str);
    return count;
}

int main(int argc, char *argv[]) {
    const char *ip_address = NULL;
    int ports[MAX_PORTS];
    int port_count = 0;
    int mode = 0; // 0 = tcp, 1 = udp, 2 = both

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s <IP Address> [<Port List>] [tcp|udp|both]\n", argv[0]);
            return 1;
        } else if (is_valid_ip(argv[i])) {
            ip_address = argv[i];
        } else if (strchr(argv[i], ',') != NULL || strchr(argv[i], '-') != NULL || atoi(argv[i]) > 0) {
            int temp_ports[MAX_PORTS];
            int temp_count = parse_ports(argv[i], temp_ports, MAX_PORTS);
            if (temp_count < 0) {
                return 1;
            }
            memcpy(&ports[port_count], temp_ports, temp_count * sizeof(int));
            port_count += temp_count;
        } else if (strcmp(argv[i], "udp") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "both") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "tcp") == 0) {
            mode = 0;
        } else {
            fprintf(stderr, "Invalid argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!ip_address) {
        printf("Enter a valid IP address.\n");
        return 1;
    }

    if (port_count == 0) {
        for (int i = 1; i <= 1024; i++) {
            ports[port_count++] = i;
        }
    }

    printf("Scanning IP: %s\n", ip_address);

    if (mode == 0 || mode == 2) {
        printf("\nStarting TCP scan...\n");
        start_scan(ip_address, ports, port_count, 0);
    }
    if (mode == 1 || mode == 2) {
        printf("\nStarting UDP scan...\n");
        start_scan(ip_address, ports, port_count, 1);
    }

    printf("\nScan completed\n");

    return 0;
}
