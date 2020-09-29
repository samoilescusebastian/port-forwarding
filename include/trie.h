#ifndef __TRIE_H__
#define __TRIE_H__

#include <stdlib.h>
#include <string.h>
#include "structs.h"



void build_trie(struct node* trie, struct r_table_entry* r_table, int);
void add_in_trie(struct node* trie, int32_t address, struct r_table_entry* entry, int level);
struct r_table_entry* get_entry(struct node* trie, int32_t address) ;
struct node* get_new_node();
struct arp_entry *get_arp_entry(struct arp_entry*, int , __uint32_t);
#endif 