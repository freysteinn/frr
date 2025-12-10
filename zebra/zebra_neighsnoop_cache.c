// SPDX-License-Identifier: GPL-2.0-or-later

#include "zebra_neighsnoop_cache.h"

#include "if.h"
#include "prefix.h"

#include "lib/typesafe.h"
#include "lib/table.h"

#include "zebra/interface.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn.h"
#include "zebra_neighsnoop.h"

DEFINE_MTYPE(ZEBRA, ZEBRA_SNOOP_NEIGH_ENT, "Zebra snoop neighbor entry");
DEFINE_MTYPE(ZEBRA, ZEBRA_SNOOP_INTERFACE_LIST, "Zebra snoop interface list");
DEFINE_MTYPE(ZEBRA, ZEBRA_SNOOP_ZVL3_TABLE, "Zebra VNI L3-connected table");

int zebra_snoop_neigh_ent_cmp(const struct zebra_snoop_neigh_ent *ap,
			      const struct zebra_snoop_neigh_ent *bp)
{
	const struct ipaddr *a = &ap->dst_ip;
	const struct ipaddr *b = &bp->dst_ip;
	
	if (a->ipa_type != b->ipa_type)
		return a->ipa_type < b->ipa_type ? -1 : 1;

	if (a->ipa_type == AF_INET)
		return memcmp(&a->ip._v4_addr,
			      &b->ip._v4_addr,
			      sizeof(struct in_addr));

	if (a->ipa_type == AF_INET6)
		return memcmp(&a->ip._v6_addr,
			      &b->ip._v6_addr,
			      sizeof(struct in6_addr));

	/* Should never happen */
	return 0;	
}


int zebra_snoop_cache_if_cmp(const struct zebra_snoop_cache_if *a,
			 const struct zebra_snoop_cache_if *b)
{
	if (a->priority > b->priority)
		return -1;
	else if (a->priority < b->priority)
		return 1;
	else
		return 0;
}

struct zebra_snoop_neigh_ent *zvebra_snoop_neigh_ent_get_by_ip(
	struct zebra_snoop_neigh_ent_head *head, struct ipaddr *dst_ip)
{
	struct zebra_snoop_neigh_ent key = { .dst_ip = *dst_ip };

	return zebra_snoop_neigh_ent_find(head, &key);
}
		

struct zebra_snoop_neigh_ent *zebra_snoop_neigh_ent_cache_add(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni, struct ipaddr *dst_ip, struct ethaddr *mac)
{
	struct zebra_snoop_cache_vni *zsc_vni;
	struct zebra_snoop_neigh_ent *ent;

	zsc_vni = zebra_snoop_cache_get_by_vni(zsc_cache, vni);
	if (!zsc_vni)
		return NULL;

	ent = zvebra_snoop_neigh_ent_get_by_ip(&zsc_vni->neighsnoop_ent_head, dst_ip);
	if (!ent) {
		ent = XCALLOC(MTYPE_ZEBRA_SNOOP_NEIGH_ENT, sizeof(*ent));
		ent->dst_ip = *dst_ip;
		memcpy(&ent->mac, mac, sizeof(*mac));
		ent->zsc_vni = zsc_vni;
		zebra_snoop_neigh_ent_add(&zsc_vni->neighsnoop_ent_head, ent);
	} else {
		memcpy(&ent->mac, mac, sizeof(*mac));
	}
	return ent;
}	
		
void zebra_snoop_neigh_ent_cache_del(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni, struct ipaddr *dst_ip)
{
	struct zebra_snoop_cache_vni *zsc_vni;
	struct zebra_snoop_neigh_ent *ent;

	zsc_vni = zebra_snoop_cache_get_by_vni(zsc_cache, vni);
	if (!zsc_vni)
		return;

	ent = zvebra_snoop_neigh_ent_get_by_ip(&zsc_vni->neighsnoop_ent_head,
					       dst_ip);
	if (ent) {
		event_cancel(&ent->probe_timer);
		zebra_snoop_neigh_ent_del(&zsc_vni->neighsnoop_ent_head, ent);
		XFREE(MTYPE_ZEBRA_SNOOP_NEIGH_ENT, ent);
	}
}

int zebra_snoop_cache_vni_cmp(const struct zebra_snoop_cache_vni *a,
			      const struct zebra_snoop_cache_vni *b)
{
	if (a->vni < b->vni)
		return -1;
	else if (a->vni > b->vni)
		return 1;
	else
		return 0;
}

struct zebra_evpn* zebra_is_active_svi(struct interface *ifp)
{
	struct interface *br_ifp;
	struct zebra_if *zif;
	struct zebra_evpn *zevpn = NULL;

	if (!ifp)
		goto out;

	zif = ifp->info;
	if (!zif)
		goto out;

	/* VLAN-aware SVI */
	if (IS_ZEBRA_IF_VLAN(ifp)) {
		if (!zif->link)
			goto out;

		if (!IS_ZEBRA_IF_BRIDGE(zif->link))
			goto out;

		br_ifp = zif->link;
	}
	/* VLAN-unaware SVI */
	else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		br_ifp = ifp;
	}
	else {
		goto out;
	}

	zevpn = zebra_evpn_from_svi(ifp, br_ifp);
out:
	return zevpn;
}

struct zebra_evpn* zebra_is_connected_to_active_svi(struct interface *ifp)
{
	struct zebra_evpn *zevpn = NULL;
	if (!ifp)
		goto out;

	if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		struct zebra_if *zif = ifp->info;
		if (!zif || !zif->link)
			goto out;

		zevpn = zebra_is_active_svi(zif->link);
	} else {
		zevpn = zebra_is_active_svi(ifp);
	}

out:
	return zevpn;
}

static void zebra_snoop_neigh_ent_cache_init(void)
{
	struct zebra_neigh_ent *n;

	RB_FOREACH (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree)
		zebra_neighsnoop_neighbor_add(n);
}

void zebra_snoop_cache_init(
	struct zebra_snoop_cache *zsc_cache)
{
	struct vrf *vrf;
	struct interface *ifp;

	zebra_snoop_cache_vni_init(&zsc_cache->vni_head);

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			zebra_snoop_cache_add_if(zsc_cache, ifp);
		}
	}

	zebra_snoop_neigh_ent_cache_init();
}

struct zebra_snoop_cache_vni *zebra_snoop_cache_get_by_vni(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni)
{
	struct zebra_snoop_cache_vni key = { key.vni = vni };

	return zebra_snoop_cache_vni_find(&zsc_cache->vni_head, &key);
}

static struct route_table *ipaddr_to_table(
	struct zebra_snoop_cache_vni *zsc_vni,
	const struct ipaddr *ip)
{
	switch (ipaddr_family(ip)) {
	case AF_INET:
		return zsc_vni->table.ipv4;
	case AF_INET6:
		return zsc_vni->table.ipv6;
	default:
		return NULL;
	}
}

static struct route_table *snoop_cache_vni_get_table(
	struct zebra_snoop_cache_vni *zsc_vni,
	uint8_t family)
{
	switch (family) {
	case AF_INET:
		return zsc_vni->table.ipv4;
	case AF_INET6:
		return zsc_vni->table.ipv6;
	default:
		return NULL;
	}
}

static void prefix_to_ipaddr(const struct prefix *p_in, struct ipaddr *ip_out)
{
	switch (p_in->family) {
	case AF_INET:
		ip_out->ipa_type = AF_INET;
		ip_out->ipaddr_v4 = p_in->u.prefix4;
		break;
	case AF_INET6:
		ip_out->ipa_type = AF_INET6;
		ip_out->ipaddr_v6 = p_in->u.prefix6;
		break;
	}
}

static void zebra_snoop_cache_vni_add_if(
	struct zebra_snoop_cache *zsc_cache,
	struct zebra_evpn *zevpn,
	const struct prefix *prefix,
	struct interface *ifp)
{
	struct zebra_snoop_cache_vni *zsc_vni;
	struct route_table *table;
	struct route_node *rn;
	struct prefix network = {0};
	struct zebra_snoop_cache_iflist *zsc_iflist;
	struct zebra_snoop_cache_if *zsc_if;
	struct ipaddr ip;

	zsc_vni = zebra_snoop_cache_get_by_vni(zsc_cache, zevpn->vni);
	if (!zsc_vni) {
		zsc_vni = XCALLOC(MTYPE_ZEBRA_SNOOP_ZVL3_TABLE,
				  sizeof(*zsc_vni));
		zsc_vni->vni = zevpn->vni;
		zsc_vni->table.ipv4 = route_table_init();
		zsc_vni->table.ipv6 = route_table_init();
		zebra_snoop_cache_vni_add(&zsc_cache->vni_head, zsc_vni);
	}
	
	table = snoop_cache_vni_get_table(zsc_vni, prefix->family);
	if (!table)
		return;

	network = *prefix;
	apply_mask(&network);

	rn = route_node_get(table, &network);

	route_lock_node(rn);

	if (!rn->info) {
		zsc_iflist = XCALLOC(MTYPE_ZEBRA_SNOOP_INTERFACE_LIST,
				  sizeof(*zsc_iflist));
		zebra_snoop_cache_if_init(&zsc_iflist->iflist);

		zsc_iflist->network = network;

		rn->info = zsc_iflist;
	} else {
		zsc_iflist = rn->info;
	}

	prefix_to_ipaddr(prefix, &ip);

	frr_each (zebra_snoop_cache_if , &zsc_iflist->iflist, zsc_if) {
		if (zsc_if->ifp != ifp)
			continue;

		if (!ipaddr_is_same(&zsc_if->ip, &ip))
			continue;
		break;
	}

	if (!zsc_if) {
		zsc_if = XCALLOC(MTYPE_ZEBRA_SNOOP_INTERFACE_LIST,
				sizeof(*zsc_if));

		zsc_if->ip = ip;
		zsc_if->ifp = ifp;
		zebra_snoop_cache_if_add(&zsc_iflist->iflist, zsc_if);
	}

	route_unlock_node(rn);
}

void zebra_snoop_cache_add_if(
	struct zebra_snoop_cache *zsc_cache,
	struct interface *ifp)
{
	struct connected *c;
	struct zebra_evpn *zevpn;
	struct zebra_if *zif = ifp->info;
	struct interface *svi_ifp;

	if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		if (!zif || !zif->link)
			return;

		svi_ifp = zif->link;
	} else {
		svi_ifp = ifp;
	}

	zevpn = zebra_is_active_svi(svi_ifp);
	if (!zevpn)
		return;


	if (ifp == svi_ifp) {
		/* Create default targets for SVIs
		 * 0.0.0.0/0 and ::/0
		 */
		struct prefix pv4 = {0};
		struct prefix pv6 = {0};
		pv4.family = AF_INET;
		pv6.family = AF_INET6;
		zebra_snoop_cache_vni_add_if(zsc_cache, zevpn, &pv4, ifp);
		zebra_snoop_cache_vni_add_if(zsc_cache, zevpn, &pv6, ifp);
	}

	frr_each (if_connected, ifp->connected, c) {
		zebra_snoop_cache_vni_add_if(zsc_cache, zevpn, c->address, ifp);
	}
}

static void ipaddr_to_prefix(const struct ipaddr *ip_in, struct prefix *p_out)
{
	switch (ipaddr_family(ip_in)) {
	case AF_INET:
		p_out->family = AF_INET;
		p_out->prefixlen = 32;
		p_out->u.prefix4 = ip_in->ipaddr_v4;
		break;
	case AF_INET6:
		p_out->family = AF_INET6;
		p_out->prefixlen = 128;
		p_out->u.prefix6 = ip_in->ipaddr_v6;
		break;
	}
}

struct interface * zebra_snoop_cache_lookup(
	struct zebra_snoop_cache *zsc_cache,
	vni_t vni,
	const struct ipaddr *dst_ip_in,
	struct ipaddr *src_ip_out)
{
	struct zebra_snoop_cache_vni *zsc_vni;
	struct route_table *table;
	struct route_node *rn;
	struct zebra_snoop_cache_iflist *iflist;
	struct zebra_snoop_cache_if *zsc_if;
	struct prefix network = {0};

	zsc_vni = zebra_snoop_cache_get_by_vni(zsc_cache, vni);
	if (!zsc_vni)
		return NULL;

	table = ipaddr_to_table(zsc_vni, dst_ip_in);

	ipaddr_to_prefix(dst_ip_in, &network);

	rn = route_node_match(table, &network);
	if (!rn)
		return NULL;

	iflist = rn->info;

	route_unlock_node(rn);

	if (!iflist)
		return NULL;

	zsc_if = zebra_snoop_cache_if_first(&iflist->iflist);
	if (!zsc_if)
		return NULL;

	if (src_ip_out)
		*src_ip_out = zsc_if->ip;

	return zsc_if->ifp;
}

void zebra_snoop_cache_dump_iflist(struct vty *vty,
				   struct zebra_snoop_cache_iflist *zsc_iflist)
{
	struct zebra_snoop_cache_if *zsc_if;

	frr_each (zebra_snoop_cache_if, &zsc_iflist->iflist, zsc_if) {
		if (ipaddr_is_zero(&zsc_if->ip))
			vty_out(vty, "                %s(%d)\n",
				zsc_if->ifp->name,
				zsc_if->ifp->ifindex);
		else
			vty_out(vty, "                %s(%d) IP: %pIA\n",
				zsc_if->ifp->name, zsc_if->ifp->ifindex,
				&zsc_if->ip);
	}
}

void zebra_snoop_cache_dump_table(struct vty *vty,
				  struct route_table *table,
				  uint8_t family)
{
	struct route_node *rn;

	vty_out(vty, "        Address family: %s\n", family == AF_INET ?
		"IPv4" : "IPv6");

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		struct zebra_snoop_cache_iflist *iflist;

		if (!rn->info)
			continue;

		iflist = rn->info;

		vty_out(vty, "            Network: %pFX\n", &iflist->network);

		zebra_snoop_cache_dump_iflist(vty, iflist);
	}
}

void zebra_snoop_cache_dump(struct vty *vty,
			    struct zebra_snoop_cache *zsc_cache)
{
	struct zebra_snoop_cache_vni *zsc_vni;

	vty_out(vty, "Neighbor target lookup cache:\n");

	frr_each (zebra_snoop_cache_vni, &zsc_cache->vni_head, zsc_vni) {
		vty_out(vty, "    VNI: %u\n", zsc_vni->vni);
		zebra_snoop_cache_dump_table(vty, zsc_vni->table.ipv4, AF_INET);
		zebra_snoop_cache_dump_table(vty, zsc_vni->table.ipv6, AF_INET6);
	}
	vty_out(vty, "\n");
}

void zebra_snoop_cache_neigh_ent_dump(struct vty *vty, struct zebra_snoop_neigh_ent *ent)
{
	char ipbuf[INET6_ADDRSTRLEN];
	char macbuf[ETHER_ADDR_STRLEN];

	ipaddr2str(&ent->dst_ip, ipbuf, sizeof(ipbuf));
	prefix_mac2str(&ent->mac, macbuf, sizeof(macbuf));

	vty_out(vty, "        IP: %s MAC:%s\n", ipbuf, macbuf);
}

void zebra_snoop_cache_neigh_ent_head_dump(struct vty *vty, struct zebra_snoop_neigh_ent_head *head)
{
	struct zebra_snoop_neigh_ent *ent;

	frr_each (zebra_snoop_neigh_ent, head, ent)
		zebra_snoop_cache_neigh_ent_dump(vty, ent);
}

void zebra_snoop_cache_neigh_dump(struct vty *vty,
			    struct zebra_snoop_cache *zsc_cache)
{
	struct zebra_snoop_cache_vni *zsc_vni;

	vty_out(vty, "Neighsnoop cache dump:\n");
	frr_each (zebra_snoop_cache_vni, &zsc_cache->vni_head, zsc_vni) {
		vty_out(vty, "    VNI: %u\n", zsc_vni->vni);
		zebra_snoop_cache_neigh_ent_head_dump(vty,
						&zsc_vni->neighsnoop_ent_head);
	}
}
