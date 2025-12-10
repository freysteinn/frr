// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>
#include <errno.h>

#include "command.h"
#include "if.h"
#include "vrf.h"
#include "vty.h"
#include "privs.h"
#include "ipaddr.h"
#include "hash.h"
#include "prefix.h"

#include <linux/if_packet.h>
#include <linux/filter.h>

#include <net/if_arp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

#include "lib/typesafe.h"
#include "lib/frr_pthread.h"

#include "zebra_neighsnoop.h"
#include "zebra_neighsnoop_shared.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_router.h"
#include "zebra/rt.h"
//#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_neighsnoop.h"
#include "zebra/zebra_neighsnoop_cache.h"
#include "zebra/zebra_neighsnoop_probe.h"
#include "zebra_vrf.h"

#include <net/if_arp.h>           // for ARPHRD_VETH

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "zebra/zebra_neighsnoop_clippy.c"

extern struct zebra_privs_t zserv_privs;

static struct zebra_neighsnoop_globals {

	/* pthread */
	struct frr_pthread *pthread;

	/* Event-delivery context 'master' for the module */
	struct event_loop *master;

	bool enabled;

	/* Probe target cache */
	struct zebra_snoop_cache zsc_cache;

	/* BPF program */
	struct zebra_neighsnoop_bpf *skel;
	struct ring_buffer *ringbuf;
	int ringbuf_fd;

	int ipv4_probe_fd;
	int ipv6_probe_fd;
} zn_info;

static inline int is_neighsnoop_enabled(void)
{
	return zn_info.enabled;
}

static void zebra_send_probe(struct event *t)
{
	struct zebra_snoop_neigh_ent *sn = EVENT_ARG(t);
	struct interface *ifp;
	struct ipaddr src_ip;

	ifp = zebra_snoop_cache_lookup(&zn_info.zsc_cache, sn->zsc_vni->vni,
					&sn->dst_ip, &src_ip);
		
	if (!ifp) {
		zlog_warn("Failed to find interface for probe to IP: %pIA",
			 &sn->dst_ip);
		return;
	}

	if (IS_IPADDR_V4(&sn->dst_ip)) {
		zebra_send_arp_request(zn_info.ipv4_probe_fd, ifp,
				       &sn->dst_ip, &sn->mac, &src_ip);
	} else if (sn->dst_ip.ipa_type == AF_INET6) {
		zebra_send_neighbor_solicitation(zn_info.ipv6_probe_fd, ifp,
					    &sn->dst_ip, &sn->mac, &src_ip);
	}
}

void zebra_neighsnoop_neighbor_add(struct zebra_neigh_ent *n)
{
	struct interface *neigh_ifp;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_snoop_neigh_ent *sn;
	double msec;

	if (!is_evpn_enabled() || !is_neighsnoop_enabled())
		return;

	if (n->ifindex == 0)
		return;

	neigh_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					      n->ifindex);
	if (!neigh_ifp)
		return;

	zevpn = zebra_is_connected_to_active_svi(neigh_ifp);
	if (!zevpn)
		return;

	sn = zebra_snoop_neigh_ent_cache_add(&zn_info.zsc_cache, zevpn->vni,
					     &n->ip, &n->mac);
	if (!sn)
		return;

	if (sn->probe_timer)
		event_cancel(&sn->probe_timer);

	if (zebra_get_next_probe_time_ms(neigh_ifp, n, &msec) < 0)
		return;
	
	// TODO: Add debug
	zlog_debug("%s: Next probe time for %s(%d):%pIA(%pEA) is %f msec",
		 __func__, neigh_ifp->name, neigh_ifp->ifindex, &n->ip,
		   &n->mac, msec);

	event_add_timer_msec(zn_info.master, zebra_send_probe, sn,
			msec, &sn->probe_timer);
}

void zebra_neighsnoop_neighbor_del(struct zebra_neigh_ent *n)
{
	struct interface *neigh_ifp;
	struct zebra_evpn *zevpn = NULL;

	if (!is_evpn_enabled() || !is_neighsnoop_enabled())
		return;

	if (n->ifindex == 0)
		return;

	neigh_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					      n->ifindex);
	if (!neigh_ifp) 
		return;

	zevpn = zebra_is_connected_to_active_svi(neigh_ifp);
	if (!zevpn)
		return;

	zebra_snoop_neigh_ent_cache_del(&zn_info.zsc_cache, zevpn->vni, &n->ip);
}

static int handle_neighbor_reply_cb(void *ctx, void *data, size_t data_sz)
{
	struct neighbor_reply *reply = data;
	struct interface *svi_ifp = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct interface *src_ifp = NULL;
	struct ipaddr dst_ip = {0};
	struct zebra_neigh_ent *n;

	if (data_sz < sizeof(*reply))
		return -1;

	if (reply->in_family != AF_INET && reply->in_family != AF_INET6)
		return -1;

	svi_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					reply->ingress_ifindex);
	if (!svi_ifp)
		return -1;

	if (reply->vlan_id != 0) {
		zevpn = zebra_evpn_lookup_bridge_vlan(svi_ifp, reply->vlan_id);
	} else {
		zevpn = zebra_is_active_svi(svi_ifp);
	}
	if (!zevpn)
		return -1;

	dst_ip.ipa_type = reply->in_family;
	if (dst_ip.ipa_type == AF_INET) {
		memcpy(&dst_ip.ipaddr_v4, &reply->ip._v4_addr,
		       sizeof(dst_ip.ipaddr_v4));
	} else if (dst_ip.ipa_type == AF_INET6) {
		memcpy(&dst_ip.ipaddr_v6, &reply->ip._v6_addr,
		       sizeof(dst_ip.ipaddr_v6));
	}

	src_ifp = zebra_snoop_cache_lookup(&zn_info.zsc_cache, zevpn->vni,
					   &dst_ip, NULL);

	if (!src_ifp)
		src_ifp = svi_ifp;

	kernel_neigh_update(true, src_ifp->ifindex,
			    (void *) &reply->ip,
			    (void *) &reply->mac, ETH_ALEN,
			    NS_DEFAULT, reply->in_family,
			    false, true);

	n = zebra_neigh_find(src_ifp->ifindex, &dst_ip);
	if (n)
		zebra_neighsnoop_neighbor_add(n);

	// TODO: Add debug
	zlog_debug("%s: Processed neighbor reply for IP %pIA on SVI %s(%d), src_ifp %s(%d)",
		   __func__, &dst_ip, svi_ifp->name, svi_ifp->ifindex, src_ifp->name,
		   src_ifp->ifindex);

	return 0;
}

/*
 * Event loop, process the incoming message queue.
 */
static void process_neighsnoop_reply_cb(struct event *event)
{
	int err;

	/* Consume all items in the ring buffer */
	err = ring_buffer__consume(zn_info.ringbuf);
	if (err < 0) {
		zlog_err("%s: Failed to consume neighsnoop reply: %s",
			 __func__, strerror(-err));
	}

	event_add_read(zn_info.master, process_neighsnoop_reply_cb, NULL,
		       zn_info.ringbuf_fd, NULL);
}

DEFPY (show_frey_init,
       show_frey_init_cmd,
       "show frey_init",
       SHOW_STR
       "frey\n")
{
	zebra_snoop_cache_dump(vty, &zn_info.zsc_cache);
		
	zebra_snoop_cache_neigh_dump(vty, &zn_info.zsc_cache);

	return CMD_SUCCESS;
}

static void neighsnoop_print_iface(struct interface *ifp, void *arg)
{
	struct vty *vty = arg;

	struct zebra_if *zebra_if = ifp->info;
	struct zebra_l2info_brslave *br_slave;
	struct zebra_if *br_if;

	if (!IS_ZEBRA_IF_VXLAN(ifp))
		return;

	vty_out(vty, "VXLAN: %s \n", ifp->name);

	if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp)) {
		vty_out(vty, "  Not a bridge slave interface\n");
		return;
	}

	br_slave = &zebra_if->brslave_info;
	br_if = br_slave->br_if->info;
	if (br_slave->bridge_ifindex != IFINDEX_INTERNAL) {
		if (br_if && !br_if->neighsnoop_br)
			return;
		if (br_slave->br_if) {
			vty_out(vty, "    SVI: %s(%u): Replies handled: %lu\n",
				br_slave->br_if->name,
				br_slave->br_if->ifindex,
				br_if->neighsnoop_br ?
				br_if->neighsnoop_br->replies_handled : 0);
		} else {
			vty_out(vty, "  Master ifindex: %u\n",
				br_slave->bridge_ifindex);
		}
	}
}

static void neighsnoop_print_topology_vrf(struct vrf *vrf, void *arg)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		neighsnoop_print_iface(ifp, arg);
}

DEFPY(show_evpn_neighsnoop,
      show_evpn_neighsnoop_cmd,
      "show evpn neighsnoop [detail$detail]",
      SHOW_STR
      "EVPN\n"
      "Show neighbor snooping topology\n"
      "Detailed output\n")
{
	struct vrf *vrf;

	vty_out(vty, "Zebra Neighsnoop Topology:\n");

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		neighsnoop_print_topology_vrf(vrf, vty);
	}

	return CMD_SUCCESS;
}

void zebra_neighsnoop_bridge_add(struct interface *br_ifp)
{
	int err;
	struct zebra_if *zif = br_ifp->info;

	if (zif->neighsnoop_br)
		return;

	// TC OPTS
	LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		    .ifindex = br_ifp->ifindex,
		    .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		    .handle = 1,
		    .priority = 1,
		    .prog_fd = bpf_program__fd(
			    zn_info.skel->progs.handle_neighbor_reply_tc),
		    .flags = BPF_TC_F_REPLACE);

	frr_with_privs(&zserv_privs) {
		err = bpf_tc_hook_create(&tc_hook);
	}
	if (err && err != -EEXIST) {
		zlog_err("%s: Failed to create neighsnoop TC hook on interface %s: %s",
			 __func__, br_ifp->name, strerror(-err));
		return;
	}

	frr_with_privs(&zserv_privs) {
		err = bpf_tc_attach(&tc_hook, &tc_opts);
	}
	if (err) {
		zlog_err("%s: Failed to attach neighsnoop TC program to interface %s: %s",
			 __func__, br_ifp->name, strerror(-err));
		bpf_tc_hook_destroy(&tc_hook);
		return;
	}

	zif->neighsnoop_br = calloc(1, sizeof(struct zebra_neighsnoop_bridge));
	zif->neighsnoop_probe = calloc(1, sizeof(struct zebra_if_neighsnoop_probe));

	zif->neighsnoop_br->tc_hook = tc_hook;
	zif->neighsnoop_br->tc_opts = tc_opts;
}

void zebra_neighsnoop_bridge_del(struct interface *ifp)
{
	int err;
	struct zebra_if *zebra_if = ifp->info;

	if (!zebra_if->neighsnoop_br)
		return;

	zebra_if->neighsnoop_br->tc_opts.flags = 0;
	zebra_if->neighsnoop_br->tc_opts.prog_id = 0;
	zebra_if->neighsnoop_br->tc_opts.prog_fd = 0;

	frr_with_privs(&zserv_privs) {
		err = bpf_tc_detach(&zebra_if->neighsnoop_br->tc_hook,
				    &zebra_if->neighsnoop_br->tc_opts);
	}
	if (err && err != -ENOENT) {
		zlog_err("%s: Failed to detach neighsnoop TC program from interface %s: %s",
			 __func__, zebra_if->ifp->name, strerror(-err));
	}

	frr_with_privs(&zserv_privs) {
		err = bpf_tc_hook_destroy(&zebra_if->neighsnoop_br->tc_hook);
	}
	if (err) {
		zlog_err("%s: Failed to destroy neighsnoop TC hook from interface %s: %s",
			 __func__, zebra_if->ifp->name, strerror(-err));
	}

	free(zebra_if->neighsnoop_br);
	free(zebra_if->neighsnoop_probe);
	zebra_if->neighsnoop_br = NULL;

	// TODO: Add debug
	zlog_debug("Removed neighsnoop from bridge interface %s",
		 ifp->name);
}

static void zebra_neighsnoop_bridge_walk_all(bool add)
{
	struct interface *ifp;
	struct zebra_if *zebra_if;
	struct zebra_l2info_brslave *br_slave;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf, ifp) {
		if (!IS_ZEBRA_IF_VXLAN(ifp))
			continue;

		if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
			continue;

		zebra_if = ifp->info;
		br_slave = &zebra_if->brslave_info;
		if (br_slave->bridge_ifindex == IFINDEX_INTERNAL)
			continue;

		if (add)
			zebra_neighsnoop_bridge_add(br_slave->br_if);
		else
			zebra_neighsnoop_bridge_del(br_slave->br_if);
	}
}

static void zebra_neighsnoop_bridge_add_all(void)
{
    zebra_neighsnoop_bridge_walk_all(true);
}

static void zebra_neighsnoop_bridge_del_all(void)
{
    zebra_neighsnoop_bridge_walk_all(false);
}

static int neighsnoop_ebpf_init(struct vty *vty)
{
	struct bpf_map *ringbuf_map;
	struct ring_buffer *ringbuf;
	int ringbuf_fd;
	int err = 0;

	zn_info.skel = zebra_neighsnoop_bpf__open();
	if (!zn_info.skel) {
		zlog_err("%s: Failed to open zebra_neighsnoop eBPF program",
			 __func__);
		goto err1;
	}

	frr_with_privs(&zserv_privs) {
		err = zebra_neighsnoop_bpf__load(zn_info.skel);
		if (err) {
			zlog_err("%s: Failed to load zebra_neighsnoop eBPF program: %s",
				 __func__, strerror(-err));
			err = 1;
		}
	}

	if (err)
		goto err2;

	// Parse Neighbor replies
	ringbuf_map = bpf_object__find_map_by_name(
		zn_info.skel->obj, "neighbor_ringbuf");

	if (!ringbuf_map) {
		zlog_err("%s: Failed to find Zebra Neighsnoop ring buffer map",
			 __func__);
		goto err2;
	}

	ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map),
				   handle_neighbor_reply_cb, NULL, NULL);
	if (!ringbuf) {
		zlog_err("%s: Failed to create Zebra Neighsnoop ring buffer",
			 __func__);
		goto err2;
	}


	ringbuf_fd = bpf_map__fd(ringbuf_map);
	if (ringbuf_fd < 0) {
		zlog_err("%s: Failed to get Zebra Neighsnoop ring buffer map fd: %s",
			 __func__, strerror(-ringbuf_fd));
		goto err3;
	}

	zn_info.ringbuf_fd = ringbuf_fd;
	zn_info.ringbuf = ringbuf;

	return CMD_SUCCESS;
err3:
	ring_buffer__free(ringbuf);
err2:
	zebra_neighsnoop_bpf__destroy(zn_info.skel);
	zn_info.skel = NULL;
err1:
	return CMD_WARNING;
}

static void attach_drop_all_filter(int fd)
{
	struct sock_filter code[] = {
		BPF_STMT(BPF_RET | BPF_K, 0),
	};

	struct sock_fprog prog = {
		.len = 1,
		.filter = code,
	};

	setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
}

static int zebra_evpn_neighsnoop_init(struct vty *vty)
{
	int ret;

	zlog_info("Starting EVPN Neighsnoop");

	zn_info.master = zrouter.master;

	ret = neighsnoop_ebpf_init(vty);
	if (ret < 0) {
		zlog_err("%s: Failed to initialize neighsnoop eBPF program: %s",
			 __func__, strerror(-ret));
		vty_out(vty, "Failed to initialize neighsnoop eBPF program\n");
		return CMD_WARNING;
	}

	/* Enqueue an initial ringbuffer read event */
	event_add_read(zn_info.master, process_neighsnoop_reply_cb, NULL,
		       zn_info.ringbuf_fd, NULL);

	zebra_neighsnoop_bridge_add_all();

	frr_with_privs(&zserv_privs) {
		zn_info.ipv4_probe_fd = socket(AF_PACKET, SOCK_RAW,
					       htons(ETH_P_ARP));
	}
	if (zn_info.ipv4_probe_fd < 0) {
		zlog_err("%s: Failed to create IPv4 probe socket: %s",
			 __func__, safe_strerror(errno));
		return CMD_WARNING;
	}
	attach_drop_all_filter(zn_info.ipv4_probe_fd);

	frr_with_privs(&zserv_privs) {
		zn_info.ipv6_probe_fd = socket(AF_PACKET, SOCK_RAW,
					       htons(ETH_P_IPV6));
	}
	if (zn_info.ipv6_probe_fd < 0) {
		zlog_err("%s: Failed to create IPv6 probe socket: %s",
			 __func__, safe_strerror(errno));
		close(zn_info.ipv4_probe_fd);
		zn_info.ipv4_probe_fd = -1;
		return CMD_WARNING;
	}
	attach_drop_all_filter(zn_info.ipv6_probe_fd);

	zebra_snoop_cache_init(&zn_info.zsc_cache);

	zn_info.enabled = true;

	return CMD_SUCCESS;
}

static void zebra_evpn_neighsnoop_cleanup(void)
{
	zebra_neighsnoop_bridge_del_all();

	if (zn_info.ringbuf_fd >= 0) {
		close(zn_info.ringbuf_fd);
		zn_info.ringbuf_fd = -1;
		zlog_info("Closed neighsnoop ring buffer fd");
	}

	if (zn_info.skel) {
		zebra_neighsnoop_bpf__destroy(zn_info.skel);
		zn_info.skel = NULL;
		zlog_info("Destroyed neighsnoop eBPF program");
	}

	if (zn_info.ringbuf) {
		ring_buffer__free(zn_info.ringbuf);
		zn_info.ringbuf = NULL;
		zlog_info("Freed neighsnoop ring buffer");
	}

	if (zn_info.ipv4_probe_fd >= 0) {
		close(zn_info.ipv4_probe_fd);
		zn_info.ipv4_probe_fd = -1;
		zlog_info("Closed IPv4 neighsnoop probe socket");
	}

	if (zn_info.ipv6_probe_fd >= 0) {
		close(zn_info.ipv6_probe_fd);
		zn_info.ipv6_probe_fd = -1;
		zlog_info("Closed IPv6 neighsnoop probe socket");
	}

	zlog_info("Completed EVPN Neighsnoop cleanup");
}

static int zebra_evpn_neighsnoop_fini(struct vty *vty)
{
	zlog_info("Stopping EVPN neighsnoop");
	zebra_evpn_neighsnoop_cleanup();

	return CMD_SUCCESS;
}

DEFPY(zebra_evpn_neighsnoop,
       zebra_evpn_neighsnoop_cmd,
       "[no$no] evpn neighsnoop",
       NO_STR
       "EVPN\n"
       "Neighsnoop monitor ARP and ND replies for correct registration\n")
{
	int ret = CMD_SUCCESS;
	if (!no) {
		ret = zebra_evpn_neighsnoop_init(vty);
		if (ret < 0) {
			zlog_err("Failed to initialize neighsnoop");
			vty_out(vty, "Failed to initialize neighsnoop\n");
		}
	} else {
		ret = zebra_evpn_neighsnoop_fini(vty);
		if (ret < 0) {
			zlog_err("Failed to finalize neighsnoop: %s",
				 strerror(-ret));
			vty_out(vty, "Failed to finalize neighsnoop\n");
		}
	}
	return ret;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	char buf[1024];
	int len;

	len = vsnprintf(buf, sizeof(buf), format, args);
	buf[sizeof(buf) - 1] = '\0';

	if (level == LIBBPF_DEBUG)
		zlog_debug("libbpf: %s", buf);
	else if (level == LIBBPF_INFO)
		zlog_info("libbpf: %s", buf);
	else if (level == LIBBPF_WARN)
		zlog_warn("libbpf: %s", buf);

	return len;
}

void zebra_neighsnoop_init(void)
{
	libbpf_set_print(libbpf_print_fn);

	install_element(VIEW_NODE, &show_evpn_neighsnoop_cmd);
	install_element(VIEW_NODE, &show_frey_init_cmd);
	install_element(CONFIG_NODE, &zebra_evpn_neighsnoop_cmd);
	zn_info.ringbuf_fd = -1;
	zn_info.enabled = false;
}

void zebra_neighsnoop_terminate(void)
{
	uninstall_element(VIEW_NODE, &show_evpn_neighsnoop_cmd);
	uninstall_element(VIEW_NODE, &show_frey_init_cmd);
	uninstall_element(CONFIG_NODE, &zebra_evpn_neighsnoop_cmd);
	zebra_evpn_neighsnoop_cleanup();
}
