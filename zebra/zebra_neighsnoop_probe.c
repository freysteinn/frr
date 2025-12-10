#include "zebra_neighsnoop_probe.h"

#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <linux/ipv6.h>
#include <netinet/icmp6.h>

// Function to calculate the checksum for an IPv6 pseudo-header and payload
static uint16_t checksum(const void *data, int len)
{
    uint32_t sum = 0;
    const uint16_t *ptr = data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/* Build ff02::1:ffXX:XXXX from the last 24 bits of target */
static void ipv6_solicited_node_multicast(struct in6_addr *out,
					  const struct in6_addr *target)
{
	memset(out, 0, sizeof(*out));
	out->s6_addr[0]  = 0xff;
	out->s6_addr[1]  = 0x02;
	out->s6_addr[11] = 0x01;
	out->s6_addr[12] = 0xff;
	out->s6_addr[13] = target->s6_addr[13];
	out->s6_addr[14] = target->s6_addr[14];
	out->s6_addr[15] = target->s6_addr[15];
}

/* Build 33:33:ff:XX:XX:XX from the last 24 bits of target */
static void ipv6_multicast_mac_from_target(uint8_t mac[ETH_ALEN],
					   const struct in6_addr *target)
{
	mac[0] = 0x33;
	mac[1] = 0x33;
	mac[2] = 0xff;
	mac[3] = target->s6_addr[13];
	mac[4] = target->s6_addr[14];
	mac[5] = target->s6_addr[15];
}

void zebra_send_neighbor_solicitation(int probe_fd, struct interface *src_ifp,
				      struct ipaddr *dst,
				      struct ethaddr *dst_mac,
				      struct ipaddr *src)
{
	const struct in6_addr src_ip = src->ip._v6_addr;
	const struct in6_addr tgt_ip = dst->ip._v6_addr;

	/* DAD/Probe mode: no IPv6 source address configured */
	const bool dad_mode = IN6_IS_ADDR_UNSPECIFIED(&src_ip);

	/*
	 * In DAD mode (src == ::), RFC 4861/4862 require:
	 *  - IPv6 src = ::
	 *  - Destination = solicited-node multicast of target
	 *  - MUST NOT include Source Link-Layer Address option
	 */
	const size_t opt_len = dad_mode ? 0 : 8;

	/* ---- Packet layout offsets ---- */
	const size_t off_eth = 0;
	const size_t off_ip6 = ETH_HLEN;
	const size_t off_ns  = off_ip6 + sizeof(struct ipv6hdr);
	const size_t off_opt = off_ns  + sizeof(struct nd_neighbor_solicit);

	const size_t icmp_len = sizeof(struct nd_neighbor_solicit) + opt_len;
	const size_t pkt_len  = ETH_HLEN + sizeof(struct ipv6hdr) + icmp_len;

	uint8_t buffer[pkt_len];
	memset(buffer, 0, sizeof(buffer));

	/* Compute destination IPv6 + destination MAC */
	struct in6_addr dst_ip = tgt_ip;
	uint8_t eth_dst[ETH_ALEN];

	if (dad_mode) {
		ipv6_solicited_node_multicast(&dst_ip, &tgt_ip);
		ipv6_multicast_mac_from_target(eth_dst, &tgt_ip);
	} else {
		/* Caller-provided destination MAC is used for normal NS */
		memcpy(eth_dst, dst_mac, ETH_ALEN);
	}

	/* ============================================================
	 * Ethernet header (build locally -> memcpy)
	 * ============================================================ */
	struct ethhdr eth;
	memset(&eth, 0, sizeof(eth));

	memcpy(eth.h_dest,   eth_dst, ETH_ALEN);
	memcpy(eth.h_source, src_ifp->hw_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_IPV6);

	memcpy(buffer + off_eth, &eth, sizeof(eth));

	/* ============================================================
	 * IPv6 header (build locally -> memcpy)
	 * ============================================================ */
	struct ipv6hdr ip6;
	memset(&ip6, 0, sizeof(ip6));

	ip6.version     = 6;
	ip6.priority    = 0;
	ip6.payload_len = htons((uint16_t)icmp_len);
	ip6.nexthdr     = IPPROTO_ICMPV6;
	ip6.hop_limit   = 255; /* required for NS */

	memcpy(&ip6.saddr, &src_ip, sizeof(ip6.saddr));
	memcpy(&ip6.daddr, &dst_ip, sizeof(ip6.daddr));

	memcpy(buffer + off_ip6, &ip6, sizeof(ip6));

	/* ============================================================
	 * Neighbor Solicitation (LOCAL STRUCT — NO BUFFER CASTS)
	 * ============================================================ */
	struct nd_neighbor_solicit ns;
	memset(&ns, 0, sizeof(ns));

	ns.nd_ns_type     = ND_NEIGHBOR_SOLICIT;
	ns.nd_ns_code     = 0;
	ns.nd_ns_cksum    = 0; /* filled later */
	ns.nd_ns_reserved = 0;

	/* Target = the address we are probing/resolving */
	memcpy(&ns.nd_ns_target, &tgt_ip, sizeof(struct in6_addr));

	memcpy(buffer + off_ns, &ns, sizeof(ns));

	/* ============================================================
	 * ICMPv6 option: Source Link-Layer Address (ONLY if not DAD)
	 * ============================================================ */
	if (!dad_mode) {
		uint8_t opt[8] = {0};

		opt[0] = 1; /* type: Source Link-Layer Address */
		opt[1] = 1; /* length (units of 8 octets) */
		memcpy(opt + 2, src_ifp->hw_addr, ETH_ALEN);

		memcpy(buffer + off_opt, opt, sizeof(opt));
	}

	/* ============================================================
	 * Pseudo-header for checksum
	 * ============================================================ */
	struct {
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t length;
		uint8_t zeros[3];
		uint8_t next_header;
	} pseudo_header;

	memset(&pseudo_header, 0, sizeof(pseudo_header));

	pseudo_header.src = ip6.saddr;
	pseudo_header.dst = ip6.daddr;
	pseudo_header.length = htonl((uint32_t)icmp_len);
	pseudo_header.next_header = IPPROTO_ICMPV6;

	uint8_t pseudo_buffer[sizeof(pseudo_header) + icmp_len];

	memcpy(pseudo_buffer, &pseudo_header, sizeof(pseudo_header));
	memcpy(pseudo_buffer + sizeof(pseudo_header),
	       buffer + off_ns,
	       icmp_len);

	uint16_t csum = checksum(pseudo_buffer, (int)sizeof(pseudo_buffer));

	/* Write checksum WITHOUT misaligned struct access */
	memcpy(buffer + off_ns + 2, &csum, sizeof(csum));

	/* ============================================================
	 * Send packet
	 * ============================================================ */
	struct sockaddr_ll dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));

	dest_addr.sll_family   = AF_PACKET;
	dest_addr.sll_protocol = htons(ETH_P_IPV6);
	dest_addr.sll_halen    = ETH_ALEN;
	dest_addr.sll_ifindex  = src_ifp->ifindex;
	memcpy(dest_addr.sll_addr, eth_dst, ETH_ALEN);

	if (sendto(probe_fd, buffer, sizeof(buffer), 0,
		   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
		zlog_err("%s: Neighbor Solicitation send failed: %s",
			 __func__, safe_strerror(errno));
	}
}

void zebra_send_arp_request(int probe_fd, struct interface *src_ifp,
			    struct ipaddr *dst, struct ethaddr *dst_mac,
			    struct ipaddr *src)
{
	unsigned char buffer[ETH_HLEN + sizeof(struct ether_arp)];

	struct in_addr src_ip = src->ip._v4_addr;
	struct in_addr dst_ip = dst->ip._v4_addr;

	// Zero out the buffer
	memset(buffer, 0, sizeof(buffer));

	// Ethernet header
	struct ethhdr *eth = (struct ethhdr *)buffer;
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);            // Target MAC address
	memcpy(eth->h_source, src_ifp->hw_addr, ETH_ALEN); // Source MAC address
	eth->h_proto = htons(ETH_P_ARP);                   // ARP protocol

	// ARP header
	struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HLEN);
	arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);    // Hardware type (Ethernet)
	arp->ea_hdr.ar_pro = htons(ETH_P_IP);        // Protocol type (IPv4)
	arp->ea_hdr.ar_hln = ETH_ALEN;               // Hardware address length
	arp->ea_hdr.ar_pln = sizeof(struct in_addr); // Protocol address length
	arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);    // ARP operation (request)

	// Fill ARP request details
	memcpy(arp->arp_sha, src_ifp->hw_addr, ETH_ALEN); // Sender MAC address
	memcpy(arp->arp_spa, &src_ip, sizeof(src_ip)); // Sender IP address
	memset(arp->arp_tha, 0, ETH_ALEN);             // Target MAC address
	memcpy(arp->arp_tpa, &dst_ip, sizeof(dst_ip)); // Target IP address

	// Set up the destination address for sending
	struct sockaddr_ll dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sll_family = AF_PACKET;
	dest_addr.sll_protocol = htons(ETH_P_ARP);
	dest_addr.sll_halen = ETH_ALEN;
	memcpy(dest_addr.sll_addr, src_ifp->hw_addr, ETH_ALEN);
	dest_addr.sll_ifindex = src_ifp->ifindex;

	// Send the ARP
	if (sendto(probe_fd, buffer, sizeof(buffer), 0,
		   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
		zlog_err("%s: ARP probe send failed: %s",
			 __func__, safe_strerror(errno));
	}
}

/* TODO: We should replace this with RTM_GETNEIGHTBL. There is no reason to
   constantly read these values using the filesystem */
#define IPV4_BASE_REACHABLE_TIME_MS /proc/sys/net/ipv4/neigh/default/base_reachable_time_ms
#define IPV6_BASE_REACHABLE_TIME_MS /proc/sys/net/ipv6/neigh/default/base_reachable_time_ms

int zebra_get_next_probe_time_ms(struct interface *ifp,
				  struct zebra_neigh_ent *n,
				  double *msec)
{
	int ret = -1;
	double base_reachable_time;
	char path[PATH_MAX];
	FILE *fp;
	bool is_ipv4;

	if (n->ip.ipa_type != AF_INET && n->ip.ipa_type != AF_INET6)
		goto out0;

	is_ipv4 = (n->ip.ipa_type == AF_INET);

	snprintf(path, sizeof(path),
		 "/proc/sys/net/%s/neigh/%s/base_reachable_time_ms",
	     is_ipv4 ? "ipv4" : "ipv6",
	     ifp->name);

	fp = fopen(path, "r");
	if (!fp) {
		zlog_err("%s: Failed to open %s: %s", __func__, path,
			 safe_strerror(errno));
		goto out0;
	}

	if (fscanf(fp, "%lf", &base_reachable_time) != 1) {
		zlog_err("%s: Failed to read base_reachable_time from %s",
			 __func__, path);
		goto out1;
	}

	/* Our primary aim is to send gratuitous neighbor requests before the
	 * kernel changes the nud state to STALE. Therefore, we will change the
	 * time to one-fourth of the base_reachable_time and add a random time of
	 * up to two seconds to prevent too many gratuitous requests from happening
	 * simultaneously. This is an arbitrary choice for the time. */
	*msec = base_reachable_time / 4.0 + (rand() % 2000);
	ret = 0;

out1:
	fclose(fp);
out0:
	return ret;
}

