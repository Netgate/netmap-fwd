#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>

#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "cli.h"
#include "event.h"
#include "inet.h"
#include "ribsync.h"

union rtsocket_msg {
    char buf[1024];
    struct rt_msghdr rtm;
    struct if_msghdr ifm;
    struct ifa_msghdr ifam;
    struct if_announcemsghdr ifann;
};

static int
ribsync_cli_stats(struct cli *cli, struct cli_args *args)
{
    const char *p;

    if (1 == args->args) {
        p = "RIBSYNC STATISTICS\n";
        if (cli_obuf_append(cli, p, strlen(p)) == -1)
            return (-1);
    }

    return (0);
}

int
ribsync_init(void)
{
    /* Register the ribsync cli command. */
    cli_cmd_add("ribsync", "ribsync - monitors kernel routing table\n", ribsync_cli_stats, NULL);
    
    // cleanup_add(ribsync_cleanup, NULL);
    return 0;
}

void
dump_sockaddr_in(struct sockaddr_in *addr)
{
    printf("  sin_family: %d \n",addr->sin_family);
    printf("  sin_addr: %s\n",inet_ntoa(addr->sin_addr));
}

struct sockaddr_route {
    struct sockaddr_in route_dst;
    struct sockaddr_in route_mask;
    struct sockaddr_in route_gw;
    int route_flasgs;
};

static struct sockaddr_route
parse_rt_addr(const union rtsocket_msg *msg_data, size_t len, int addrs_mask, size_t ppos)
{
    size_t i=0;
    int maskvec[] = {RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK, RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD};

    struct sockaddr_route rt_addr;
    while (ppos < len && i < sizeof(maskvec)/sizeof(maskvec[0])) {
        
        if (addrs_mask & maskvec[i]) {
            const struct sockaddr *sa = (const struct sockaddr *)((const char *)msg_data + ppos);
            
            if ( maskvec[i] == RTA_DST) {
                rt_addr.route_dst = *(const struct sockaddr_in*)sa;
                
            }else if ( maskvec[i] == RTA_GATEWAY) {
                rt_addr.route_gw = *(const struct sockaddr_in*)sa;
                
            }else if ( maskvec[i] == RTA_NETMASK) {
                rt_addr.route_mask = *(const struct sockaddr_in*)sa;
            }
            
            // jump to next socketaddr struct
            size_t diff = sa->sa_len;
            if (!diff) {
                diff = sizeof(long);
            }
            ppos += diff;
            if (diff & (sizeof(long) - 1)) {
                ppos += sizeof(long) - (diff & (sizeof(long) - 1));
            }
        }
        i++;
    }
    
    printf("%s", inet_ntoa(rt_addr.route_dst.sin_addr));
    printf("/%s", inet_ntoa(rt_addr.route_mask.sin_addr));
    printf(" -> %s", inet_ntoa(rt_addr.route_gw.sin_addr));
        
    return rt_addr;
}

static void
ribsync_ev_data(evutil_socket_t socket, short event, void *data)
{
    union rtsocket_msg recv_data;
    struct sockaddr_route rt_addr;
    
    recv_data.rtm.rtm_msglen = 4;
    
    int r1 = recv(socket, &recv_data, sizeof(recv_data), 0);
    if (-1 == r1) {
        printf("[EE] pf_socket recv error");
        return;
    }
    
    if (r1 < 4 || r1 < recv_data.rtm.rtm_msglen) {
        printf("SHORT READ (have %d want %hu), SKIPPING.\n", r1, recv_data.rtm.rtm_msglen);
        return;
    }
    
    if ( 0 != recv_data.rtm.rtm_errno ) {
        printf("Route message contains errors(%d), SKIPPING.\n", recv_data.rtm.rtm_errno);
        return;
    }
    
    /*printf("Received %d bytes. Version %d, Type %#x, Len %d\n", r1,
        recv_data.rtm.rtm_version,
        recv_data.rtm.rtm_type,
        recv_data.rtm.rtm_msglen
    );*/

    int rt_status=0;
    switch (recv_data.rtm.rtm_type) {
        case RTM_ADD:
            printf("Add route: ");
            rt_addr = parse_rt_addr(&recv_data, r1,recv_data.rtm.rtm_addrs, sizeof(struct rt_msghdr));
            rt_status = inet_route_add_ipv4(rt_addr.route_dst, rt_addr.route_mask, rt_addr.route_gw, recv_data.rtm.rtm_flags);
            break;
        case RTM_DELETE:
            printf("Del route: ");
            rt_addr = parse_rt_addr(&recv_data, r1,recv_data.rtm.rtm_addrs, sizeof(struct rt_msghdr));
            rt_status = inet_route_del_ipv4(rt_addr.route_dst, rt_addr.route_mask, rt_addr.route_gw, recv_data.rtm.rtm_flags);
            
            break;
        // case RTM_CHANGE:
        // case RTM_NEWADDR:
        // case RTM_DELADDR:
        // case RTM_IFINFO:
        // case RTM_IFANNOUNCE:
        }
    if( -1 == rt_status) {
        printf("[DBG] Route dst\n");
        dump_sockaddr_in(&rt_addr.route_dst);

        printf("[DBG] Route netmask\n");
        dump_sockaddr_in(&rt_addr.route_mask);

        printf("[DBG] Route gateway\n");
        dump_sockaddr_in(&rt_addr.route_gw);
        printf("\n");
    }
    fflush(stdout);
}

int ribsync_open(void)
{
    int rt_socket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (-1 == rt_socket) {
        return -1;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(rt_socket, &fds);
  
    // Setup the event for pf_route socket.
    struct event *ev;
    ev = event_new(ev_get_base(), rt_socket, EV_READ | EV_PERSIST, ribsync_ev_data, NULL);
    event_add(ev, NULL);
    
    return 0;
}
