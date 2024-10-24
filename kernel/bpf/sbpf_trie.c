#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sbpf.h>
#include <linux/string.h>

#include "sbpf_mem.h"

#define TRI_SIZE 512

// Initialize trie node
void trie_init(struct trie_node **node)
{
	*node = (struct trie_node *)get_zeroed_page(GFP_KERNEL);
}

// Insert data into trie
int trie_insert(struct trie_node *root, uint64_t caddr, uint64_t data)
{
	struct trie_node *cur = root;

	int index_0 = (caddr >> 12) & 0x1ff;
	int index_1 = (caddr >> 21) & 0x1ff;
	int index_2 = (caddr >> 30) & 0x1ff;
	int index_3 = (caddr >> 39) & 0x1ff; // Currently not used

	if (root == NULL || index_3 != 0)
		return -EINVAL;

	WARN_ON_ONCE(index_3 != 0);

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
int trie_remove(struct trie_node *root, uint64_t caddr)
{
	struct trie_node *cur = root;

	int index_0 = (caddr >> 12) & 0x1ff;
	int index_1 = (caddr >> 21) & 0x1ff;
	int index_2 = (caddr >> 30) & 0x1ff;
	int index_3 = (caddr >> 39) & 0x1ff; // Currently not used

	if (root == NULL || index_3 != 0)
		return -EINVAL;

	// TODO: remove entry if all nodes are NULL
	if (cur->trie_node[index_2] == NULL)
		return -1;
	cur = cur->trie_node[index_2];

	if (cur->trie_node[index_1] == NULL)
		return -1;
	cur = cur->trie_node[index_1];

	if (cur->data[index_0] == 0)
		return -1;
	else
		cur->data[index_0] = 0;

	return 0;
}

int __trie_free(struct trie_node *root, int depth)
{
	if (root == NULL || depth == 3)
		return 0;

	for (int i = 0; i < TRI_SIZE; i++) {
		if (root->trie_node[i] != NULL)
			__trie_free(root->trie_node[i], depth + 1);
	}
	kfree(root);
	return 0;
}

int trie_free(struct trie_node *root)
{
	return __trie_free(root, 0);
}

// Find data from trie
uint64_t trie_search(struct trie_node *root, uint64_t caddr)
{
	uint64_t *ret = 0;

	ret = (uint64_t *)trie_search_node(root, caddr);
	if (ret != NULL)
		return *ret;

	return -EINVAL;
}

void **trie_search_node(struct trie_node *root, uint64_t caddr)
{
	struct trie_node *cur = root;

	int index_0 = (caddr >> 12) & 0x1ff;
	int index_1 = (caddr >> 21) & 0x1ff;
	int index_2 = (caddr >> 30) & 0x1ff;
	int index_3 = (caddr >> 39) & 0x1ff; // Currently not used

	if (root == NULL || index_3 != 0)
		return NULL;

	// TODO: remove entry if all nodes are NULL
	if (cur->trie_node[index_2] == NULL)
		return NULL;
	cur = cur->trie_node[index_2];

	if (cur->trie_node[index_1] == NULL)
		return NULL;
	cur = cur->trie_node[index_1];

	return (void **)&cur->data[index_0];
}