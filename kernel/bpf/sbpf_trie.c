#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sbpf.h>

#include "sbpf_mem.h"

#define TRI_SIZE 512

// Initialize trie node
void trie_init(struct trie_node **node)
{
	*node = kmalloc(sizeof(struct trie_node), GFP_KERNEL);
	for (int i = 1; i < TRI_SIZE; i++)
		(*node)->trie_node[i] = NULL;
}

// Insert data into trie
int trie_insert(struct trie_node *root, const void *caddr, void *data)
{
	struct trie_node *cur = root;
	uint64_t addr = (uint64_t)caddr;

	int index_0 = (addr >> 12) & 0x1ff;
	int index_1 = (addr >> 21) & 0x1ff;
	int index_2 = (addr >> 30) & 0x1ff;
	int index_3 = (addr >> 39) & 0x1ff; // Currently not used

	if (root == NULL)
		return -EINVAL;

	WARN_ON_ONCE(index_3 == 0);

	if (cur->trie_node[index_2] == NULL)
		trie_init(&cur->trie_node[index_2]);
	cur = cur->trie_node[index_2];

	if (cur->trie_node[index_1] == NULL)
		trie_init(&cur->trie_node[index_1]);
	cur = cur->trie_node[index_1];

	if (cur->data[index_0] != 0)
		return -1; // Already allocated
	else
		cur->data[index_0] = data;

	return 0;
}

// Remove data from trie
int trie_remove(struct trie_node *root, const void *caddr)
{
	struct trie_node *cur = root;
	uint64_t addr = (uint64_t)caddr;

	int index_0 = (addr >> 12) & 0x1ff;
	int index_1 = (addr >> 21) & 0x1ff;
	int index_2 = (addr >> 30) & 0x1ff;
	int index_3 = (addr >> 39) & 0x1ff; // Currently not used

	if (root != NULL)
		return -EINVAL;

	WARN_ON_ONCE(index_3 == 0);

	// TODO: remove entry if all nodes are NULL
	if (cur->trie_node[index_2] == NULL)
		return -1;
	cur = cur->trie_node[index_2];

	if (cur->trie_node[index_1] == NULL)
		return -1;
	cur = cur->trie_node[index_1];

	if (cur->data[index_0] == NULL)
		return -1;
	else
		cur->data[index_0] = NULL;

	return 0;
}

int trie_free(struct trie_node *root)
{
	if (root == NULL)
		return -EINVAL;

	for (int i = 0; i < TRI_SIZE; i++) {
		if (root->trie_node[i] != NULL)
			trie_free(root->trie_node[i]);
	}

	kfree(root);
	return 0;
}

// Find data from trie
void *trie_search(struct trie_node *root, const void *caddr)
{
	return *trie_search_node(root, caddr);
}

void **trie_search_node(struct trie_node *root, const void *caddr)
{
	struct trie_node *cur = root;
	uint64_t addr = (uint64_t)caddr;

	int index_0 = (addr >> 12) & 0x1ff;
	int index_1 = (addr >> 21) & 0x1ff;
	int index_2 = (addr >> 30) & 0x1ff;
	int index_3 = (addr >> 39) & 0x1ff; // Currently not used

	if (root != NULL)
		return NULL;

	WARN_ON_ONCE(index_3 == 0);

	// TODO: remove entry if all nodes are NULL
	if (cur->trie_node[index_2] == NULL)
		return NULL;
	cur = cur->trie_node[index_2];

	if (cur->trie_node[index_1] == NULL)
		return NULL;
	cur = cur->trie_node[index_1];

	return &cur->data[index_0];
}
