/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * B-trees
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/errno.h>

#include "btree.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

/* Reasonable limit to avoid overflow of ssize_t */
#define BTREE_MAX_ORDER (1 << 20)

struct key_val {
        uint32_t key;
        void *   val;
};

/* Node in btree of order k. */
struct btnode {
        size_t           k;
        size_t           used;

        bool             leaf;

        struct key_val * keyvals;

        struct btnode ** children;
};

struct btree {
        struct btnode * root;
        size_t          k;
};

/* Binary search for arr[i].key <= key. */
static size_t search_key(const struct key_val * arr,
                         size_t                 len,
                         uint32_t               key)
{
        ssize_t lft = -1;
        ssize_t rgt = len;
        ssize_t mid;

        while (lft + 1 < rgt) {
                mid = (lft + rgt) / 2;
                if (arr[mid].key == key)
                        return mid;
                else if (arr[mid].key < key)
                        lft = mid;
                else
                        rgt = mid;
        }

        return rgt;
}

static struct btnode * btnode_create(size_t k)
{
        struct btnode * node;
        size_t i = 0;

        node = malloc(sizeof(*node));
        if (node == NULL)
                return NULL;

        node->keyvals = malloc(sizeof(*node->keyvals) * k);
        if (node->keyvals == NULL) {
                free(node);
                return NULL;
        }

        node->children = malloc(sizeof(*node->children) * (k + 1));
        if (node->children == NULL) {
                free(node->keyvals);
                free(node);
                return NULL;
        }

        for (i = 0; i < k; ++i) {
                node->children[i] = NULL;
                node->keyvals[i].key = 0;
                node->keyvals[i].val = NULL;
        }

        node->k    = k;
        node->used = 0;
        node->leaf = true;

        return node;
}

static void btnode_destroy(struct btnode * node)
{
        assert(node);

        free(node->children);
        free(node->keyvals);
        free(node);
}

static void btnode_destroy_subtree(struct btnode * node)
{
        size_t i;

        for (i = 0; !node->leaf && i <= node->used; ++i)
                btnode_destroy_subtree(node->children[i]);

        btnode_destroy(node);
}

static int btnode_insert(struct btnode *  node,
                         struct key_val   kv,
                         struct key_val * med,
                         struct btnode ** split)
{
        size_t p;

        assert(node);
        assert(split);
        assert(kv.val);

        p = search_key(node->keyvals, node->used, kv.key);

        if (p < node->used && node->keyvals[p].key == kv.key)
                return -EPERM;

        assert(p < node->k);

        if (node->leaf) {
                memmove(&node->keyvals[p + 1],
                        &node->keyvals[p],
                        sizeof(*node->keyvals) * (node->used - p));
                node->keyvals[p] = kv;
                node->used++;
        } else {
                struct btnode * rgt_s = NULL;
                struct key_val m;

                if (btnode_insert(node->children[p], kv, &m, &rgt_s))
                        return -1;
                if (rgt_s != NULL) {
                        memmove(&node->keyvals[p + 1],
                                &node->keyvals[p],
                                sizeof(*node->keyvals) * (node->used - p));
                        node->keyvals[p] = m;
                        memmove(&node->children[p + 2],
                                &node->children[p + 1],
                                sizeof(*node->children)
                                * (node->used - p));
                        node->children[p + 1] = rgt_s;
                        node->used++;
                }
        }

        if (node->used == node->k) {
                size_t mid = node->used / 2;
                *med = node->keyvals[mid];
                *split = btnode_create(node->k);
                if (*split == NULL)
                        return -ENOMEM;

                (*split)->used = node->used - mid - 1;
                (*split)->leaf = node->leaf;

                memmove((*split)->keyvals,
                        &node->keyvals[mid + 1],
                        sizeof(*node->keyvals) * (*split)->used);
                if (!node->leaf)
                        memmove((*split)->children,
                                &node->children[mid + 1],
                                sizeof(*node->children) * ((*split)->used + 1));

                node->used = mid;
        }

        return 0;
}

/* Merge child i with child i + 1 */
void merge(struct btnode * node,
           size_t          i)
{
        struct btnode * chld = node->children[i];
        struct btnode * next = node->children[i + 1];

        chld->keyvals[node->k / 2 - 1] = node->keyvals[i];

        memmove(&chld->keyvals[node->k / 2],
                &next->keyvals[0],
                sizeof(*next->keyvals) * next->used);

        if (!chld->leaf)
                memmove(&chld->children[node->k / 2],
                        &next->children[0],
                        sizeof(*next->children) * (next->used + 1));

        memmove(&node->keyvals[i],
                &node->keyvals[i + 1],
                sizeof(*node->keyvals) * (node->used - i - 1));

        memmove(&node->children[i + 1],
                &node->children[i + 2],
                sizeof(*node->children) * (node->used - i));

        chld->used += next->used + 1;
        node->used--;

        btnode_destroy(next);
}

/* Handle starving child at index i. */
static void fill(struct btnode * node,
                 size_t          i)
{
        struct btnode * chld = node->children[i];

        /* Feed from previous sibling. */
        if (i != 0 && node->children[i - 1]->used >= node->k / 2) {
                struct btnode * prev = node->children[i - 1];

                memmove(&chld->keyvals[1],
                        &chld->keyvals[0],
                        sizeof(*chld->keyvals) * chld->used);

                chld->keyvals[0] = node->keyvals[i - 1];

                if (!chld->leaf)
                        memmove(&chld->children[1],
                                &chld->children[0],
                                sizeof(*chld->children) * (chld->used + 1));

                if (!node->leaf)
                        chld->children[0] = prev->children[prev->used];

                node->keyvals[i - 1] = prev->keyvals[prev->used - 1];

                ++chld->used;
                --prev->used;

                return;
        }

        /* Feed from next sibling. */
        if (i != node->used && node->children[i + 1]->used >= node->k / 2) {
                struct btnode * next = node->children[i + 1];

                chld->keyvals[chld->used] = node->keyvals[i];

                if (!chld->leaf)
                        chld->children[chld->used + 1] = next->children[0];

                node->keyvals[i] = next->keyvals[0];

                memmove(&next->keyvals[0],
                        &next->keyvals[1],
                        sizeof(*next->keyvals) * next->used);

                if (!next->leaf)
                        memmove(&next->children[0],
                                &next->children[1],
                                sizeof(*next->children) * next->used);

                ++chld->used;
                --next->used;

                return;
        }

        /* Cannibalize sibling. */
        if (i != node->used)
                merge(node, i);
        else
                merge(node, i - 1);
}

static struct key_val btnode_pred(struct btnode * node,
                                  size_t          i)
{
        struct btnode * pred = node->children[i];
        while (!pred->leaf)
                pred = pred->children[pred->used];

        return pred->keyvals[pred->used - 1];
}

static struct key_val btnode_succ(struct btnode * node,
                                  size_t          i)
{
        struct btnode * succ = node->children[i + 1];
        while (!succ->leaf)
                succ = succ->children[0];
        return succ->keyvals[0];
}

static int btnode_delete(struct btnode * node,
                         uint32_t        key)
{
        size_t i;
        int ret = 0;

        assert(node);

        i = search_key(node->keyvals, node->used, key);

        if (i < node->used && node->keyvals[i].key == key) {
                if (node->leaf) {
                        memmove(&node->keyvals[i],
                                &node->keyvals[i + 1],
                                sizeof(*node->keyvals) * (node->used - i - 1));

                        --node->used;
                } else {
                        if (node->children[i]->used >= node->k / 2) {
                                node->keyvals[i] = btnode_pred(node, i);
                                ret = btnode_delete(node->children[i],
                                                    node->keyvals[i].key);
                        } else if (node->children[i + 1]->used >= node->k / 2) {
                                node->keyvals[i] = btnode_succ(node, i);
                                ret = btnode_delete(node->children[i + 1],
                                                    node->keyvals[i].key);
                        } else {
                                merge(node, i);
                                ret = btnode_delete(node, key);
                        }
                }
        } else {
                if (node->leaf) {
                        return -1; /* value not in tree */
                } else {
                        bool flag = (i == node->used ? true : false);
                        if (node->children[i]->used < node->children[i]->k / 2)
                                fill(node, i);
                        if (flag && i > node->used)
                                ret = btnode_delete(node->children[i - 1], key);
                        else
                                ret = btnode_delete(node->children[i], key);
                }
        }

        return ret;
}

struct btree * btree_create(size_t k)
{
        struct btree * tree = malloc(sizeof(*tree));
        if (tree == NULL)
                return NULL;

        if (k > BTREE_MAX_ORDER)
                return NULL;

        tree->k = k;
        tree->root = NULL;

        return tree;
}

void btree_destroy(struct btree * tree)
{
        if (tree == NULL)
                return;

        if (tree->root != NULL)
                btnode_destroy_subtree(tree->root);

        free(tree);
}

int btree_insert(struct btree * tree,
                 uint32_t       key,
                 void *         val)
{
        struct btnode * rgt = NULL;
        struct key_val kv;
        struct key_val med;

        kv.key = key;
        kv.val = val;

        if (tree == NULL || val == NULL)
                return -EINVAL;

        if (tree->root == NULL)
                tree->root = btnode_create(tree->k);

        if (tree->root == NULL)
                return -ENOMEM;

        if (btnode_insert(tree->root, kv, &med, &rgt))
                return -1;

        if (rgt != NULL) {
                struct btnode * lft = btnode_create(tree->root->k);
                if (lft == NULL)
                        return -ENOMEM;

                lft->used = tree->root->used;
                lft->leaf = tree->root->leaf;

                memmove(lft->keyvals,
                        tree->root->keyvals,
                        sizeof(*tree->root->keyvals) * tree->root->used);
                memmove(lft->children,
                        tree->root->children,
                        sizeof(*tree->root->children) * (tree->root->used + 1));

                tree->root->used = 1;
                tree->root->leaf = false;
                tree->root->keyvals[0] = med;
                tree->root->children[0] = lft;

                tree->root->children[1] = rgt;
        }

        return 0;
}

int btree_remove(struct btree * tree,
                 uint32_t       key)
{
        struct btnode * prev_root;

        if (tree == NULL)
                return -EINVAL;

        if (tree->root == NULL)
                return 0;

        if (btnode_delete(tree->root, key))
                return -1;

        if (tree->root->used == 0) {
                if (tree->root->leaf) {
                        btnode_destroy(tree->root);
                        tree->root = NULL;
                } else {
                        prev_root = tree->root;
                        tree->root = tree->root->children[0];
                        btnode_destroy(prev_root);
                }
        }

        return 0;
}

static void * btnode_search(struct btnode * node,
                            uint32_t        key)
{
        size_t i;

        assert(node);

        i = search_key(node->keyvals, node->used, key);

        if (node->keyvals[i].key == key)
                return node->keyvals[i].val;

        if (node->children[i])
                return btnode_search(node->children[i], key);

        return NULL;
}

void * btree_search(struct btree * tree,
                    uint32_t       key)
{

        if (tree == NULL || tree->root == NULL)
                return NULL;

        return btnode_search(tree->root, key);
}
