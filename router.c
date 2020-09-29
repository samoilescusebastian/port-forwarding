#include <stdio.h>
#include "include/skel.h"
#include "include/trie.h"
#include "include/parse.h"
#include <string.h>
#include "queue.h"

uint16_t checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}



void swap_macs(uint8_t *mac_A, uint8_t* mac_B, uint8_t len) {
	uint8_t mac_aux[len];
	memcpy(mac_aux, mac_A, len);
	memcpy(mac_A, mac_B, len);
	memcpy(mac_B, mac_aux, len);
}
void send_icmp(packet* m, u_int8_t type, uint8_t code) {
	
	struct ether_header *eth_hdr = (struct ether_header *)m -> payload;
	struct iphdr* ip_hdr = (struct iphdr*)(m -> payload + sizeof(struct ether_header));
	struct icmphdr* icmp_hdr = (struct icmphdr*)(m -> payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	m -> len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	swap_macs(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));


	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	
	uint32_t ip_aux;
	ip_aux = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip_aux;


	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
	send_packet(m->interface, m);

}
void forward_packet(packet *m,  struct node* trie, struct arp_entry* arp_table, int arp_table_length) {
			struct ether_header *eth_hdr = (struct ether_header *)m -> payload;
			struct iphdr* ip_hdr = (struct iphdr*)(m -> payload + sizeof(struct ether_header));
			struct r_table_entry* best_entry = get_entry(trie, ip_hdr -> daddr);


			if (ip_hdr -> ttl <= 1) {
				send_icmp(m, 11, 0);
				return;
			}
		
			uint8_t router_mac[6];
			get_interface_mac(best_entry->interface, router_mac);

			uint32_t router_ip;
			inet_pton(AF_INET, get_interface_ip(best_entry->interface), &router_ip);
			
			if (!memcmp(router_mac, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost))) {
				send_icmp(m, 0, 0);
				return;
			}
			__u16 old_check = ip_hdr -> check;
			ip_hdr -> check = 0;
			if (checksum(ip_hdr, sizeof(struct iphdr)) != old_check) {
				fprintf(stderr, "Corrupted package!\n");
				return;
			}

			ip_hdr->ttl--;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

			struct arp_entry* arp_entry = get_arp_entry(arp_table, arp_table_length, best_entry->next_hp);
			memcpy(eth_hdr->ether_shost, router_mac, sizeof(eth_hdr->ether_dhost));
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));
			send_packet(best_entry->interface, m);
}
int main(int argc, char *argv[])
{
	packet m;
	int rc;

	char* buffer = malloc(64);
	init();
	
	struct r_table_entry *r_table;
	struct arp_entry *arp_table = malloc(10 * sizeof(struct arp_entry));
	queue packets = queue_create();
	int r_table_length;
	int arp_table_length = 0;
	if(!parse_route_table(&r_table, &r_table_length)) {
		fprintf(stderr, "ERROR!!n");
		exit(-1);
	}

	struct node *trie = get_new_node();
	build_trie(trie, r_table, r_table_length);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr;
		struct my_arphdr* arp_hdr; 
		if (ntohs(eth_hdr->ether_type) == 0x0806) {
			arp_hdr = (struct my_arphdr*)(m.payload + sizeof(struct ether_header));
			int ip_adr = (*(int32_t*)(arp_hdr->__ar_tip));
			if (ntohs(arp_hdr->ar_op) == 1) {
				struct r_table_entry *best_entry = get_entry(trie, ip_adr);
				if (best_entry == NULL) {
					fprintf(stderr, "NO SUCH ENTRY!");
					continue;
				} else {
					uint8_t mac[6];
					get_interface_mac(best_entry->interface, mac);

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
					memcpy(eth_hdr->ether_shost, mac, sizeof(eth_hdr->ether_shost));
					arp_hdr->ar_op = htons(2);
					memcpy(arp_hdr->__ar_tip, arp_hdr->__ar_sip, sizeof(arp_hdr->__ar_tip));
					memcpy(arp_hdr->__ar_sip, &ip_adr, sizeof(arp_hdr->__ar_sip));
					memcpy(arp_hdr->__ar_tha, arp_hdr->__ar_sha, sizeof(arp_hdr->__ar_tha));
					memcpy(arp_hdr->__ar_sha, mac, sizeof(arp_hdr->__ar_sha));
					send_packet(best_entry->interface, &m);
				}
			} else {
		
				memcpy(&arp_table[arp_table_length].ip, arp_hdr->__ar_sip, sizeof(arp_hdr->__ar_sip));
				memcpy(&arp_table[arp_table_length].mac, arp_hdr->__ar_sha, sizeof(arp_hdr->__ar_sha));
				arp_table_length++;
				while(!queue_empty(packets)) {
					forward_packet(queue_deq(packets), trie, arp_table, arp_table_length);
				}
				
			}
			
		} else {
			ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ether_header));
			arp_hdr = (struct my_arphdr*)(m.payload + sizeof(struct ether_header));
			uint32_t ip_dest = ip_hdr->daddr;
			struct r_table_entry *best_entry = get_entry(trie, ip_dest);

			if (best_entry == NULL) {
					fprintf(stderr, "NO SUCH ENTRY*\n!");
					send_icmp(&m, 3, 0);
					continue;
			}
			struct arp_entry* arp_entry = get_arp_entry(arp_table, arp_table_length, best_entry->next_hp);
			if (arp_entry == NULL) {
					packet *new_packet = malloc(sizeof(m));
					*new_packet = m;
					queue_enq(packets, new_packet);
					packet arp_request;
					struct ether_header* eth_hdr_req = (struct ether_header *)arp_request.payload;
					struct my_arphdr* arp_hdr_req = (struct my_arphdr*)(arp_request.payload + sizeof(struct ether_header));
					eth_hdr_req->ether_type = htons(0x0806);
					memset(eth_hdr_req->ether_dhost, 255, sizeof(eth_hdr_req->ether_dhost));
					get_interface_mac(best_entry->interface, eth_hdr_req->ether_shost);

					arp_hdr_req->ar_hln = 6;
					arp_hdr_req->ar_pln = 4;
					arp_hdr_req->ar_pro = htons(0x0800);
					arp_hdr_req->ar_hrd = htons(1);
					arp_hdr_req->ar_op = htons(1);
					
					uint32_t router_ip;
					inet_pton(AF_INET, get_interface_ip(best_entry->interface), &router_ip);

					
					memcpy(arp_hdr_req->__ar_tip, &ip_dest, sizeof(arp_hdr_req->__ar_tip));
					memset(arp_hdr_req->__ar_tha, 0, sizeof(arp_hdr_req->__ar_tha));
					memcpy(arp_hdr_req->__ar_sip, &router_ip, sizeof(arp_hdr_req->__ar_sip));
					get_interface_mac(best_entry->interface, arp_hdr_req->__ar_sha);
					arp_request.len = 42;
					send_packet(best_entry->interface, &arp_request);
			} else {
			
					forward_packet(&m, trie, arp_table, arp_table_length);

			}
		}
		/* Students will write code here */
	}
		
	free(r_table);
	free(buffer);
	free(arp_table);
}
