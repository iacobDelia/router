#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

// binary search to get the route entry
int route_table_binary_search(int left, int right, uint32_t ip_dest, struct route_table_entry *rtable){
	int middle = (left + right) / 2;

	if(rtable[middle].prefix == (ip_dest & rtable[middle].mask))
	{

		// find the match with the biggest mask
		while(rtable[middle].prefix == (ip_dest & rtable[middle].mask))
			middle++;
		middle--;
		return middle;
	}
		
	if(left > right)
		return -1;
	
	if(htonl(rtable[middle].prefix) > htonl((ip_dest & rtable[middle].mask)))
		return route_table_binary_search(left, middle - 1, ip_dest, rtable);
	else
		return route_table_binary_search(middle + 1, right, ip_dest, rtable);

	return -2;
}
// finds the route table entry corresponding to an ip
struct route_table_entry *get_route_entry(uint32_t ip_dest, int rtable_length, struct route_table_entry *rtable)
{
	int rez = route_table_binary_search(0, rtable_length, ip_dest, rtable);
	
	// in either of these situations something has gone wrong
	if(rez == -1 || rez == -2)
		return NULL;
	
	return &rtable[rez];

}
// finds the arp entry corresponding to an ip
struct arp_table_entry *get_arp_entry(uint32_t ip, int arptable_length, struct arp_table_entry *arptable)
{
	for (int i = 0; i < arptable_length; i++)
	{
		if (arptable[i].ip == ip)
			return &arptable[i];
	}
	return NULL;
}
// sets the default functionalities for an ip header
void set_ip_functionalities(struct iphdr *ip_hdr)
{
	ip_hdr->frag_off = 0;
	ip_hdr->tos = 0;
	ip_hdr->id = htons(1);
	ip_hdr->ttl = 64;
	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	// only the icmp protocol
	ip_hdr->protocol = 1;
}

// creates a new packet containing an icmp header
void new_icmp_packet(char *new_packet, uint8_t type, uint8_t code, char *original_packet, int interface, size_t size)
{

	// get the headers
	struct ether_header *eth_hdr_original = (struct ether_header *)original_packet;
	struct iphdr *ip_hdr_original = (struct iphdr *)(original_packet + sizeof(struct ether_header));

	struct ether_header *eth_hdr_new_packet = (struct ether_header *)new_packet;
	struct iphdr *ip_hdr_new_packet = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr_new_packet = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// set mac addresses
	// we're sending back a message so the source from the initial message becomes the destination
	memcpy(eth_hdr_new_packet->ether_dhost, eth_hdr_original->ether_shost, 6);

	// set the source
	memcpy(eth_hdr_new_packet->ether_shost, eth_hdr_original->ether_dhost, 6);

	// set the ipv4 type
	eth_hdr_new_packet->ether_type = 0x0008;
	// set up the new ip header
	set_ip_functionalities(ip_hdr_new_packet);
	ip_hdr_new_packet->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr_new_packet->daddr = ip_hdr_original->saddr;
	ip_hdr_new_packet->tot_len = htons(size);

	ip_hdr_new_packet->check = 0;
	ip_hdr_new_packet->check = htons(checksum((uint16_t *)ip_hdr_new_packet, sizeof(struct iphdr)));
	// set up the icmp message
	icmp_hdr_new_packet->type = type;
	icmp_hdr_new_packet->code = code;
	// checksum icmp
	icmp_hdr_new_packet->checksum = 0;
	icmp_hdr_new_packet->checksum = htons(checksum((uint16_t *)icmp_hdr_new_packet, sizeof(struct icmphdr)));
}

// sends an icmp error packet
void send_error_icmp_packet(uint8_t type, uint8_t code, char *original_packet, int interface)
{
	// make the new packet
	char new_packet[MAX_PACKET_LEN];

	// couldn't find the offsets by using sizeof
	// so I had to resort to primitive methods such as "counting"
	size_t packet_size = 126 - sizeof(struct ether_header);
	new_icmp_packet(new_packet, type, code, original_packet, interface, packet_size);

	// copy ip header (original) + 64 bytes after the icmp header ends
	// on the hw page it says "64 bits" but that doesnt seem right?
	memcpy(new_packet + 42, original_packet + sizeof(struct ether_header), 86);

	// calculate new checksum
	struct icmphdr *icmp_hdr = (struct icmphdr *)(original_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, 92));

	// save travels
	send_to_link(interface, new_packet, packet_size + sizeof(struct ether_header));
}

// sends an echo reply
void send_echo_reply_icmp_packet(char *original_packet, int interface)
{
	struct iphdr *ip_hdr_original = (struct iphdr *)(original_packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr_original = (struct icmphdr *)(original_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// make the new packet
	char new_packet[MAX_PACKET_LEN];
	// same size as the one we received
	size_t packet_size = ntohs(ip_hdr_original->tot_len);
	new_icmp_packet(new_packet, 0, 0, original_packet, interface, packet_size);

	// set the echo datagram
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->un.echo = icmp_hdr_original->un.echo;

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// set the original data
	size_t data_size = packet_size - sizeof(struct iphdr) - sizeof(struct icmphdr);
	size_t header_size = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);
	memcpy(new_packet + header_size, original_packet + header_size, data_size);

	// calculate new checksum
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + data_size));
	// send the packet
	send_to_link(interface, new_packet, packet_size + sizeof(struct ether_header));
}
// sends a packet to a next hop
void send_next_hop(char *packet, struct arp_table_entry *arp_destination, size_t len, int next_hop_interface)
{
	struct ether_header *ethdr = (struct ether_header *)packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// new ttl new checksum
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// change source and destination for ethernet header
	uint8_t new_mac[6];

	// new source
	get_interface_mac(next_hop_interface, new_mac);
	memcpy(ethdr->ether_shost, new_mac, 6);

	// new destination
	memcpy(ethdr->ether_dhost, arp_destination->mac, 6);

	// arrivederci goodbye sayonara
	send_to_link(next_hop_interface, packet, len);
}

// makes a basic arp packet
void make_arp_packet(char *new_packet, int interface, uint16_t op_code)
{
	struct ether_header *ethdr_new = (struct ether_header *)(new_packet);

	// set the ether type and MAC addresses
	ethdr_new->ether_type = htons(0x0806);

	uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);
	memcpy(ethdr_new->ether_shost, router_mac, 6);

	// set the other parametres
	struct arp_header *arphdr_new = (struct arp_header *)(new_packet + sizeof(struct ether_header));

	arphdr_new->htype = htons(1);
	arphdr_new->ptype = htons(0x0800);
	arphdr_new->hlen = 6;
	arphdr_new->plen = 4;
	arphdr_new->op = htons(op_code);

	// set the source mac for the arp header
	memcpy(arphdr_new->sha, router_mac, 6);

	// set the source ip for the arp header
	arphdr_new->spa = inet_addr(get_interface_ip(interface));
}
// sends an arp reply packet
void send_arp_reply(char *initial_packet, int interface)
{
	char new_arp_packet[MAX_PACKET_LEN];

	// op code for reply is 2
	make_arp_packet(new_arp_packet, interface, 2);
	struct ether_header *ethdr_new = (struct ether_header *)(new_arp_packet);
	struct ether_header *ethdr_initial = (struct ether_header *)(initial_packet);
	struct arp_header *arphdr_new = (struct arp_header *)(new_arp_packet + sizeof(struct ether_header));
	struct arp_header *arphdr_initial = (struct arp_header *)(initial_packet + sizeof(struct ether_header));

	// set the mac and ip destination
	memcpy(ethdr_new->ether_dhost, ethdr_initial->ether_shost, 6);
	memcpy(arphdr_new->tha, arphdr_initial->sha, 6);
	arphdr_new->tpa = arphdr_initial->spa;

	// reply back
	send_to_link(interface, new_arp_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}
// sends an arp request for an ip_addr
void send_arp_request(uint32_t ip_addr, int interface)
{
	char new_arp_packet[MAX_PACKET_LEN];
	// op code for request is 1
	make_arp_packet(new_arp_packet, interface, 1);

	struct arp_header *arphdr_new = (struct arp_header *)(new_arp_packet + sizeof(struct ether_header));
	struct ether_header *ethdr_new = (struct ether_header *)(new_arp_packet);

	// set the destination macs
	for (int i = 0; i < 6; i++)
	{
		arphdr_new->tha[i] = 0x00;
		ethdr_new->ether_dhost[i] = 0xff;
	}

	// set the ip
	arphdr_new->tpa = ip_addr;
	send_to_link(interface, new_arp_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}
// checks the queue and sends any packets that match arp_entry
int check_queue_send(queue *q, int queue_length, struct arp_table_entry *arp_entry, struct route_table_entry *rtable, int rtable_length)
{
	int initial_length = queue_length;
	while (initial_length)
	{
		// take the current element of the queue
		char *packet;
		packet = queue_deq(*q);
		struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

		// find its corresponding route table entry
		struct route_table_entry *next_hop = get_route_entry(ip_hdr->daddr, rtable_length, rtable);
		// if we have a match, send it away
		if (next_hop->next_hop == arp_entry->ip && next_hop != NULL)
		{
			send_next_hop(packet, arp_entry, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len), next_hop->interface);
			free(packet);
			queue_length--;
		}
		// add it back to the queue
		else
		{
			queue_enq((*q), packet);
		}
		initial_length--;
	}
	return queue_length;
}
// returns 1 if a mac address is broadcast
int is_broadcast(uint8_t mac[6])
{
	for (int i = 0; i < 6; i++)
		if (mac[i] != 0xff)
			return 0;
	return 1;
}
// qsort compare function
int compare_route_table(const void *a, const void *b){
	struct route_table_entry* a_entry = (struct route_table_entry*)a;
	struct route_table_entry* b_entry = (struct route_table_entry*)b;

	if(ntohl(a_entry->prefix) == ntohl(b_entry->prefix))
		return (int)(ntohl(a_entry->mask) - ntohl(b_entry -> mask));
	return (int)(ntohl(a_entry->prefix) - ntohl(b_entry->prefix));
}
// searches the rtable and removes incorrect entries from the table; returns the new length
int remove_bad_entries(struct route_table_entry* old_rtable, struct route_table_entry* new_rtable, int rtable_length){
	int new_length = 0;
	for(int i = 0; i < rtable_length; i++){
		if(old_rtable[i].prefix == (old_rtable[i].prefix & old_rtable[i].mask)){
			new_rtable[new_length++] = old_rtable[i];
		}
	}
	return new_length;
}
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	struct route_table_entry temp_rtable[80000];
	// read the route table
	struct route_table_entry rtable[80000];
	int rtable_length;
	rtable_length = read_rtable(argv[1], temp_rtable);
	// remove incorrect entries from the route table and sort it
	rtable_length = remove_bad_entries(temp_rtable, rtable, rtable_length);
	qsort(rtable, rtable_length, sizeof(struct route_table_entry), compare_route_table);

	// initialize the arp table
	struct arp_table_entry arptable[8000];
	int arptable_length = 0;

	// initialize the queue
	queue q = queue_create();
	int queue_length = 0;

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// get the headers
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint8_t mac[6];
		get_interface_mac(interface, mac);
		
		// check if we received an arp packet
		if (ntohs(eth_hdr->ether_type) == 0x0806)
		{
			struct arp_header *arphdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			// if it's a request, send a reply
			if (ntohs(arphdr->op) == 1)
			{
				send_arp_reply(buf, interface);
			}
			// if it's a reply, add it to our table
			if (ntohs(arphdr->op) == 2)
			{
				arptable[arptable_length].ip = arphdr->spa;
				memcpy(arptable[arptable_length].mac, arphdr->sha, 6);
				// check the queue to send away any packets that may match
				queue_length = check_queue_send(&q, queue_length, &(arptable[arptable_length]),
												rtable, rtable_length);

				arptable_length++;
			}
		}
		// if it isn't arp, it's ip
		// check checksum and whether the destination mac address matches the router's
		else if (!checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) &&
				(memcmp(eth_hdr->ether_dhost, mac, 6) == 0 || is_broadcast(eth_hdr->ether_dhost)))
		{
			ip_hdr->ttl = (ip_hdr->ttl) - 1;
			// check TTL
			if (ip_hdr->ttl >= 1)
			{
				// if it's not arp it's icmp, check where to go next
				// welcome home
				if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr)
				{
					// check if it's icmp
					if (ip_hdr->protocol == 1)
					{
						struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
						// check if it's echo request
						if (icmp_hdr->type == 8 && icmp_hdr->code == 0)
						{
							// send back a response
							send_echo_reply_icmp_packet(buf, interface);
						}
					}
				}
				// the router is not the destination
				else
				{
					// find or check if we found a new destination
					struct route_table_entry *next_hop = get_route_entry(ip_hdr->daddr, rtable_length, rtable);

					// we found the next destination
					if (next_hop != NULL)
					{
						struct arp_table_entry *arp_destination = get_arp_entry(next_hop->next_hop, arptable_length, arptable);
						// found an entry in the arp table, send it away
						if (arp_destination != NULL)
						{
							send_next_hop(buf, arp_destination, len, next_hop->interface);
						}
						// didn't find an entry
						else
						{
							
							// buf will get overwritten, so we need new space
							char* new_pointer = malloc(MAX_PACKET_LEN);
							memcpy(new_pointer, buf, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
							// time to wait in the queue
							queue_enq(q, new_pointer);
							queue_length++;
							// somebody please tell me who this guy is
							send_arp_request(next_hop->next_hop, next_hop->interface);
						}
					}
					// couldn't find where to send it next
					else
					{
						send_error_icmp_packet(3, 0, buf, interface);
					}
				}
			}
			// TTL is zero
			else
			{
				send_error_icmp_packet(11, 0, buf, interface);
			}
		}
	}
}