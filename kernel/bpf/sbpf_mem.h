#ifndef __SBPF_MEM_H__
#define __SBPF_MEM_H__

#include <linux/types.h>

#define TRI_SIZE 512

struct trie_node {
	union {
		struct trie_node *trie_node[TRI_SIZE];
		void *data[TRI_SIZE];
	};
};

extern const struct bpf_func_proto bpf_set_page_table_proto;
void trie_init(struct trie_node **node);
int trie_remove(struct trie_node *root, const void *caddr);
int trie_insert(struct trie_node *root, const void *caddr, void *data);
void *trie_search(struct trie_node *root, const void *caddr);
void **trie_search_node(struct trie_node *root, const void *caddr);
int trie_free(struct trie_node *root);

#endif