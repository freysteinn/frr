#ifndef _ZEBRA_NEIGHSNOOP_PROBE_H
#define _ZEBRA_NEIGHSNOOP_PROBE_H

#include "if.h"

#include "zebra/interface.h"
#include "zebra/zebra_neigh.h"


void zebra_send_neighbor_solicitation(int probe_fd, struct interface *src_ifp,
				      struct ipaddr *dst,
				      struct ethaddr *dst_mac,
				      struct ipaddr *src);

void zebra_send_arp_request(int probe_fd, struct interface *src_ifp,
			    struct ipaddr *dst, struct ethaddr *dst_mac,
			    struct ipaddr *src);

int zebra_get_next_probe_time_ms(struct interface *ifp,
				  struct zebra_neigh_ent *n,
				  double *msec);


#endif // _ZEBRA_NEIGHSNOOP_PROBE_H
