#include "trie.h"


struct node* get_new_node() {
	struct node* new_node = malloc(sizeof(struct node)); 
	new_node -> nodes[0] = new_node -> nodes[1] = NULL;
	new_node -> entry = NULL;
	return new_node;
}

void build_trie(struct node* trie, struct r_table_entry* r_table, int r_table_length) {
	int32_t value;
	for (int i = 0; i < r_table_length; i++) {
		value = r_table[i].prefix & r_table[i].mask;
		add_in_trie(trie, value, &r_table[i], __builtin_popcount(r_table[i].mask));
	}
}
// faptul ca informatia e stocata in format little endian
// ajuta sa introducem adresa in ordinea corecta.
// Cu toate acestea, trebuie sa introducem bitii de la cel mai
// semnificativ la cel mai semnificativ
void add_in_trie(struct node* trie, int32_t address, struct r_table_entry* entry, int level) {
	int i = 7;
	int j = 4;
	int mask = 1 << i;

	while(j > 0) {
		short bit = (address & mask) ? 1 : 0;
		if (trie -> nodes[bit] == NULL) {
			trie -> nodes[bit] = get_new_node();
		}
		if(level == 0) {
			break;
		}
		level--;
		trie = trie -> nodes[bit];
		if (i == 0) {
			j--;
			i = 7;
			mask <<= 15;
			continue;
		}
		mask >>= 1;
		i--;
	}
	trie -> entry = entry;
}

struct r_table_entry* get_entry(struct node* trie, int32_t address) {
	int i = 7;
	int j = 4;
	int mask = 1 << i;
	struct r_table_entry* entry = NULL;
	while(j > 0) {
		short bit = (address & mask) ? 1 : 0;
		if (trie -> entry != NULL) {
			entry = trie -> entry;
		}
		if (trie -> nodes[bit] == NULL) {
			return entry;
		}
		trie = trie -> nodes[bit];
		if (i == 0) {
			j--;
			i = 7;
			mask <<= 15;
			continue;
		}
		mask >>= 1;
		i--;
	}
	if (trie -> entry) {
		entry = trie -> entry;
	}
	return entry;
}
struct arp_entry *get_arp_entry(struct arp_entry *arp_table, int arp_table_len, u_int32_t ip) {
    for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
    return NULL;
}
