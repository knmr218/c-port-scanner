#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREADS 100

typedef struct {
    const char* ip_address;
    int port;
    int is_udp;
} ScanArgs;

DWORD WINAPI scan_port(LPVOID args) {
    ScanArgs* scan_args = (ScanArgs*)args;
    SOCKET sock;
    struct sockaddr_in server;

    if (scan_args->is_udp) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    else {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %ld\n", WSAGetLastError());
        return 1;
    }

    // Set socket timeout
    DWORD timeout = 1000; // 1 second
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // Configure server address
    server.sin_family = AF_INET;
    server.sin_port = htons(scan_args->port);
    inet_pton(AF_INET, scan_args->ip_address, &server.sin_addr);

    if (scan_args->is_udp) {
        // UDP scan
        char message[] = "Hello";
        sendto(sock, message, sizeof(message), 0, (struct sockaddr*)&server, sizeof(server));
        char buffer[10];
        int len = sizeof(server);
        if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server, &len) != SOCKET_ERROR) {
            printf("UDP Port %d: OPEN\n", scan_args->port);
        }
    }
    else {
        // TCP scan
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            printf("TCP Port %d: OPEN\n", scan_args->port);
        }
    }

    closesocket(sock);
    return 0;
}

void start_scan(const char* ip_address, int start_port, int end_port, int is_udp) {
    HANDLE threads[MAX_THREADS];
    ScanArgs args[MAX_THREADS];
    int thread_count = 0;

    for (int port = start_port; port <= end_port; port++) {
        args[thread_count].ip_address = ip_address;
        args[thread_count].port = port;
        args[thread_count].is_udp = is_udp;

        threads[thread_count] = CreateThread(NULL, 0, scan_port, &args[thread_count], 0, NULL);
        thread_count++;

        if (thread_count == MAX_THREADS || port == end_port) {
            for (int i = 0; i < thread_count; i++) {
                WaitForSingleObject(threads[i], INFINITE);
                CloseHandle(threads[i]);
            }
            thread_count = 0;
        }
    }
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <IP Address> [<Start Port>-<End Port>] [tcp|udp|both]\n", argv[0]);
        WSACleanup();
        return 1;
    }

    const char* ip_address = argv[1];
    int start_port = 1, end_port = 1024;
    int mode = 0; // 0 = tcp, 1 = udp, 2 = both

    // Process port range and scan type
    if (argc >= 3 && strchr(argv[2], '-') != NULL) {
        // Port range specified
        sscanf_s(argv[2], "%d-%d", &start_port, &end_port);
        if (argc >= 4) {
            // Scan type specified
            if (strcmp(argv[3], "udp") == 0) mode = 1;
            else if (strcmp(argv[3], "both") == 0) mode = 2;
            else if (strcmp(argv[3], "tcp") == 0) mode = 0;
        }
    }
    else if (argc >= 3) {
        // Only scan type specified
        if (strcmp(argv[2], "udp") == 0) mode = 1;
        else if (strcmp(argv[2], "both") == 0) mode = 2;
        else if (strcmp(argv[2], "tcp") == 0) mode = 0;
        if (argc >= 4) {
            // Port range specified
            sscanf_s(argv[2], "%d-%d", &start_port, &end_port);
        }
    }

    if (mode == 0 || mode == 2) {
        printf("Starting TCP scan...\n");
        start_scan(ip_address, start_port, end_port, 0);
    }
    if (mode == 1 || mode == 2) {
        if (mode == 2) { printf("\n"); }
        printf("Starting UDP scan...\n");
        start_scan(ip_address, start_port, end_port, 1);
    }

    printf("\nScan completed\n");

    WSACleanup();
    return 0;
}
