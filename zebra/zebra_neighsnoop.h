#ifndef _ZEBRA_NEIGHSNOOP_H
#define _ZEBRA_NEIGHSNOOP_H

#include "zebra/zebra_neighsnoop.bpf.skel.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_neighsnoop_cache.h"

struct zebra_neighsnoop_bridge {
	struct bpf_tc_hook tc_hook;
	struct bpf_tc_opts tc_opts;
	unsigned long int replies_handled;
	unsigned long int replies_ignored;
};

struct zebra_if_neighsnoop_probe {
	int refcount;
	int probes_sent;
};

extern void zebra_neighsnoop_neighbor_add(struct zebra_neigh_ent *n);
extern void zebra_neighsnoop_neighbor_del(struct zebra_neigh_ent *n);

extern void zebra_neighsnoop_bridge_add(struct interface *ifp);
extern void zebra_neighsnoop_bridge_del(struct interface *ifp);

extern void zebra_neighsnoop_init(void);
extern void zebra_neighsnoop_terminate(void);

#endif // _ZEBRA_NEIGHSNOOP_H
