// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _ZEBRA_NEIGHSNOOP_CACHE_H
#define _ZEBRA_NEIGHSNOOP_CACHE_H

#include "prefix.h"
#include "typesafe.h"
#include "vxlan.h"

struct zebra_snoop_cache_vni;

/*
 * Neighbor cache used for sending probes
 */
PREDECL_RBTREE_UNIQ(zebra_snoop_neigh_ent);
struct zebra_snoop_neigh_ent {
	struct ipaddr dst_ip;
	struct ethaddr mac;

	long last_probe_time_ms;
	long next_probe_time_ms;
	int probes_sent;
	struct event *probe_timer;

	struct zebra_snoop_cache_vni *zsc_vni;
	struct zebra_snoop_neigh_ent_item entry;
};

extern int zebra_snoop_neigh_ent_cmp(const struct zebra_snoop_neigh_ent *a,
				     const struct zebra_snoop_neigh_ent *b);

DECLARE_RBTREE_UNIQ(zebra_snoop_neigh_ent,
		    struct zebra_snoop_neigh_ent,
		    entry,
		    zebra_snoop_neigh_ent_cmp);

PREDECL_SORTLIST_NONUNIQ(zebra_snoop_cache_if);
struct zebra_snoop_cache_if {
	struct interface *ifp; /* MACVLAN or SVI */
	struct ipaddr ip;      /* IP address on the interface */

	/*
	 * priority for source selection
	 * A higher number gives higher priority.
	 */
	int priority;

	struct zebra_snoop_cache_if_item entry;
};

extern int zebra_snoop_cache_if_cmp(const struct zebra_snoop_cache_if *a,
				const struct zebra_snoop_cache_if *b);

DECLARE_SORTLIST_NONUNIQ(zebra_snoop_cache_if,
			 struct zebra_snoop_cache_if,
			 entry,
			 zebra_snoop_cache_if_cmp);

struct zebra_snoop_cache_iflist {
	struct prefix network; 

	struct zebra_snoop_cache_if_head iflist;
};

/*
 * Per-address-family tables of connected prefixes,
 * indexed for longest-prefix match.
 */
struct zebra_snoop_cache_table {
	struct route_table *ipv4;
	struct route_table *ipv6;
};

/*
 * VNI-scoped container of all L3-connected prefixes
 */
PREDECL_RBTREE_UNIQ(zebra_snoop_cache_vni);
struct zebra_snoop_cache_vni {
	vni_t vni;

	struct zebra_snoop_neigh_ent_head neighsnoop_ent_head;

	struct zebra_snoop_cache_table table;

	struct zebra_snoop_cache_vni_item entry;
};

/* RB-tree comparator */
extern int zebra_snoop_cache_vni_cmp(const struct zebra_snoop_cache_vni *a,
				 const struct zebra_snoop_cache_vni *b);

DECLARE_RBTREE_UNIQ(zebra_snoop_cache_vni,
		     struct zebra_snoop_cache_vni,
		     entry,
		     zebra_snoop_cache_vni_cmp);

struct zebra_snoop_cache {
	struct zebra_snoop_cache_vni_head vni_head;
};

struct zebra_snoop_neigh_ent *zvebra_snoop_neigh_ent_get_by_ip(
	struct zebra_snoop_neigh_ent_head *head, struct ipaddr *dst_ip);

struct zebra_snoop_neigh_ent *zebra_snoop_neigh_ent_cache_add(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni, struct ipaddr *dst_ip, struct ethaddr *mac);


void zebra_snoop_neigh_ent_cache_del(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni, struct ipaddr *dst_ip);

struct zebra_evpn* zebra_is_connected_to_active_svi(struct interface *ifp);
struct zebra_evpn* zebra_is_active_svi(struct interface *ifp);

void zebra_snoop_cache_init(struct zebra_snoop_cache *zsc_cache);

struct zebra_snoop_cache_vni *zebra_snoop_cache_get_by_vni(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni);

void zebra_snoop_cache_add_if(
	struct zebra_snoop_cache *zsc_cache,
	struct interface *ifp);

struct interface * zebra_snoop_cache_lookup(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni,
	const struct ipaddr *dst_ip_in,
	struct ipaddr *src_ip_out);

void zebra_snoop_cache_dump_iflist(struct vty *vty,
				   struct zebra_snoop_cache_iflist *iflist);

void zebra_snoop_cache_dump_table(struct vty *vty,
				  struct route_table *table,
				  uint8_t family);

void zebra_snoop_cache_dump(struct vty *vty,
			    struct zebra_snoop_cache *zsc_cache);

void zebra_snoop_cache_neigh_ent_dump(struct vty *vty,
				struct zebra_snoop_neigh_ent *ent);

void zebra_snoop_cache_neigh_ent_head_dump(struct vty *vty,
				     struct zebra_snoop_neigh_ent_head *head);

void zebra_snoop_cache_neigh_dump(struct vty *vty,
		      struct zebra_snoop_cache *zsc_cache);

#endif // _ZEBRA_NEIGHSNOOP_CACHE_H
