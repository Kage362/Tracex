#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#define BUF_SIZE 1024
#define MAX_HOPS 30
#define TIMEOUT_SEC 1
#define PROBES_PER_HOP 3

// Colores ANSI
#define RESET   "\033[0m"
#define CYAN    "\033[1;36m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define RED     "\033[1;31m"
#define GRAY    "\033[1;30m"
#define WHITE   "\033[1;37m"
#define BLUE    "\033[1;34m"

unsigned short calculate_checksum(unsigned short *b, int len) {
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *b++;
    if (len == 1) sum += *(unsigned char *)b;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char *argv[]) {
    char target_input[256] = "";
    int disable_dns = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0) {
            disable_dns = 1;
        } else {
            strncpy(target_input, argv[i], sizeof(target_input));
        }
    }

    if (strlen(target_input) == 0) {
        printf(CYAN "\n[?] Ingresa el host, dominio o IP a rastrear: " RESET);
        if (fgets(target_input, sizeof(target_input), stdin) == NULL) {
            printf(RED "[-] Error leyendo la entrada.\n" RESET);
            return 1;
        }
        target_input[strcspn(target_input, "\n")] = 0;
    }

    if (strlen(target_input) == 0) {
        printf(RED "[-] Error: No ingresaste ningún objetivo válido.\n" RESET);
        return 1;
    }

    struct hostent *host = gethostbyname(target_input);
    if (!host) {
        printf(RED "[-] Error: No se pudo resolver el host '%s'\n" RESET, target_input);
        return 1;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr = *((struct in_addr *)host->h_addr);
    char *target_ip = inet_ntoa(target_addr.sin_addr);

    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_sock < 0 || recv_sock < 0) {
        printf(RED "[-] Error: Se requieren privilegios de administrador. Ejecuta con sudo.\n" RESET);
        return 1;
    }

    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT_SEC;
    tv_out.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out));

    printf("\n" CYAN "==========================================================================" RESET "\n");
    printf(GREEN " TRACEX v3.1 PRO -> Rastreando ruta avanzada hacia %s (%s)" RESET "\n", target_input, target_ip);
    if (disable_dns) printf(YELLOW " [*] Modo sin DNS (-n) activado: Mostrando sólo IPs." RESET "\n");
    printf(CYAN "==========================================================================" RESET "\n\n");

    // Variables estadísticas mejoradas
    double total_sum_ms = 0;
    int total_probes_success = 0;
    double min_lat = 999999.0;
    double max_hop_avg = 0.0;
    int slowest_hop_num = 0;
    char slowest_hop_ip[INET_ADDRSTRLEN] = "N/A";
    int destination_reached = 0;

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        printf(WHITE " [Salto %2d]" RESET, ttl);
        int success_in_this_hop = 0;
        char last_responder_ip[INET_ADDRSTRLEN] = "";
        
        double hop_sum_ms = 0;
        int hop_success_count = 0;

        for (int p = 0; p < PROBES_PER_HOP; p++) {
            struct icmp icmphdr;
            memset(&icmphdr, 0, sizeof(icmphdr));
            icmphdr.icmp_type = ICMP_ECHO;
            icmphdr.icmp_code = 0;
            icmphdr.icmp_id = htons((getpid() + p) & 0xFFFF);
            icmphdr.icmp_seq = htons(ttl * 10 + p);
            icmphdr.icmp_cksum = calculate_checksum((unsigned short *)&icmphdr, sizeof(icmphdr));

            struct timeval start_time, end_time;
            gettimeofday(&start_time, NULL);

            if (sendto(send_sock, &icmphdr, sizeof(icmphdr), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) <= 0) {
                continue;
            }

            char buffer[BUF_SIZE];
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);

            int bytes_received = recvfrom(recv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
            gettimeofday(&end_time, NULL);

            if (bytes_received < 0) {
                printf(GRAY "   *   " RESET);
            } else {
                double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                                    (end_time.tv_usec - start_time.tv_usec) / 1000.0;

                char *color = GREEN;
                if (elapsed_ms > 100) color = RED;
                else if (elapsed_ms > 50) color = YELLOW;

                printf(" %s%.1f ms" RESET, color, elapsed_ms);

                strcpy(last_responder_ip, inet_ntoa(recv_addr.sin_addr));
                success_in_this_hop = 1;

                hop_sum_ms += elapsed_ms;
                hop_success_count++;

                total_sum_ms += elapsed_ms;
                total_probes_success++;
                if (elapsed_ms < min_lat) min_lat = elapsed_ms;

                if (recv_addr.sin_addr.s_addr == target_addr.sin_addr.s_addr) {
                    destination_reached = 1;
                }
            }
        }

        // Evaluar el promedio de este salto para detectar el verdadero cuello de botella
        if (hop_success_count > 0) {
            double hop_avg = hop_sum_ms / hop_success_count;
            if (hop_avg > max_hop_avg) {
                max_hop_avg = hop_avg;
                slowest_hop_num = ttl;
                strcpy(slowest_hop_ip, last_responder_ip);
            }
        }

        if (success_in_this_hop) {
            printf("  " CYAN "%-15s" RESET, last_responder_ip);

            if (!disable_dns) {
                struct sockaddr_in node_addr;
                memset(&node_addr, 0, sizeof(node_addr));
                node_addr.sin_family = AF_INET;
                inet_pton(AF_INET, last_responder_ip, &node_addr.sin_addr);

                char host_name[NI_MAXHOST];
                int has_hostname = getnameinfo((struct sockaddr *)&node_addr, sizeof(node_addr),
                                               host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);
                if (has_hostname == 0) {
                    printf("  " BLUE "[%s]" RESET, host_name);
                } else {
                    printf("  " GRAY "[IP directa]" RESET);
                }
            }
        } else {
            printf("  " RED "* * * (Nodo silencioso / Firewall)" RESET);
        }

        printf("\n");

        if (destination_reached) {
            printf("\n" GREEN "[✔] ¡Objetivo alcanzado con éxito en el salto #%d!" RESET "\n", ttl);
            break;
        }
    }

    // Reporte Estadístico Ajustado y Real
    printf("\n" CYAN "==========================================================================" RESET "\n");
    printf(GREEN " ESTADÍSTICAS DE RED DE TRACEX (REALES):" RESET "\n");
    printf(CYAN "==========================================================================" RESET "\n");
    if (total_probes_success > 0) {
        printf(" • Paquetes respondidos exitosamente: %d\n", total_probes_success);
        printf(" • Latencia promedio en ruta:         %.2f ms\n", total_sum_ms / total_probes_success);
        printf(" • Nodo más rápido (Mejor latencia):  %.2f ms\n", min_lat);
        printf(" • Cuello de botella real (Salto #%d - %s): %.2f ms prom.\n", slowest_hop_num, slowest_hop_ip, max_hop_avg);
    } else {
        printf(" • No se pudieron recopilar estadísticas (Demasiados timeouts).\n");
    }
    printf(CYAN "==========================================================================" RESET "\n\n");

    close(send_sock);
    close(recv_sock);
    return 0;
}
