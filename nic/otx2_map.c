#include <linux/netdevice.h>
#include <linux/filter.h>
#include "otx2_common.h"
#include "otx2_xdp_debug.h"
#include "otx2_map.h"

static bool
otx2_map_key_match(struct bpf_map *map, struct otx2_map_entry *e, void *key)
{
	return e->key && !memcmp(key, e->key, map->key_size);
}

static int otx2_map_key_find(struct bpf_offloaded_map *offmap, void *key)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(otx2->entry); i++)
		if (otx2_map_key_match(&offmap->map, &otx2->entry[i], key))
			return i;

	return -ENOENT;
}

static int
otx2_map_alloc_elem(struct bpf_offloaded_map *offmap, unsigned int idx)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;

	otx2->entry[idx].key = kmalloc(offmap->map.key_size, GFP_USER);
	if (!otx2->entry[idx].key)
		return -ENOMEM;
	otx2->entry[idx].value = kmalloc(offmap->map.value_size, GFP_USER);
	if (!otx2->entry[idx].value) {
		kfree(otx2->entry[idx].key);
		otx2->entry[idx].key = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int
otx2_map_get_next_key(struct bpf_offloaded_map *offmap,
		      void *key, void *next_key)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	int idx = -ENOENT;

	mutex_lock(&otx2->mutex);

	if (key)
		idx = otx2_map_key_find(offmap, key);
	if (idx == -ENOENT)
		idx = 0;
	else
		idx++;

	for (; idx < ARRAY_SIZE(otx2->entry); idx++) {
		if (otx2->entry[idx].key) {
			memcpy(next_key, otx2->entry[idx].key,
			       offmap->map.key_size);
			break;
		}
	}

	mutex_unlock(&otx2->mutex);

	if (idx == ARRAY_SIZE(otx2->entry))
		return -ENOENT;
	return 0;
}

static int
otx2_map_lookup_elem(struct bpf_offloaded_map *offmap, void *key, void *value)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	int idx;

	mutex_lock(&otx2->mutex);

	idx = otx2_map_key_find(offmap, key);
	if (idx >= 0)
		memcpy(value, otx2->entry[idx].value, offmap->map.value_size);

	mutex_unlock(&otx2->mutex);

	return idx < 0 ? idx : 0;
}

static int
otx2_map_update_elem(struct bpf_offloaded_map *offmap,
		     void *key, void *value, u64 flags)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	int idx, err = 0;

	mutex_lock(&otx2->mutex);

	idx = otx2_map_key_find(offmap, key);
	if (idx < 0 && flags == BPF_EXIST) {
		err = idx;
		goto exit_unlock;
	}
	if (idx >= 0 && flags == BPF_NOEXIST) {
		err = -EEXIST;
		goto exit_unlock;
	}

	if (idx < 0) {
		for (idx = 0; idx < ARRAY_SIZE(otx2->entry); idx++)
			if (!otx2->entry[idx].key)
				break;
		if (idx == ARRAY_SIZE(otx2->entry)) {
			err = -E2BIG;
			goto exit_unlock;
		}

		err = otx2_map_alloc_elem(offmap, idx);
		if (err)
			goto exit_unlock;
	}

	memcpy(otx2->entry[idx].key, key, offmap->map.key_size);
	memcpy(otx2->entry[idx].value, value, offmap->map.value_size);
exit_unlock:
	mutex_unlock(&otx2->mutex);

	return err;
}

static int otx2_map_delete_elem(struct bpf_offloaded_map *offmap, void *key)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	int idx;

	if (offmap->map.map_type == BPF_MAP_TYPE_ARRAY)
		return -EINVAL;

	mutex_lock(&otx2->mutex);

	idx = otx2_map_key_find(offmap, key);
	if (idx >= 0) {
		kfree(otx2->entry[idx].key);
		kfree(otx2->entry[idx].value);
		memset(&otx2->entry[idx], 0, sizeof(otx2->entry[idx]));
	}

	mutex_unlock(&otx2->mutex);

	return idx < 0 ? idx : 0;
}

static const struct bpf_map_dev_ops otx2_bpf_map_ops = {
	.map_get_next_key	= otx2_map_get_next_key,
	.map_lookup_elem	= otx2_map_lookup_elem,
	.map_update_elem	= otx2_map_update_elem,
	.map_delete_elem	= otx2_map_delete_elem,
};

int
otx2_bpf_map_alloc(struct net_device *netdev, struct bpf_offloaded_map *offmap)
{
	struct otx2_bpf_bound_map *otx2_map;
	struct otx2_nic *pf = netdev_priv(netdev);
	int i, err;

	if (WARN_ON(offmap->map.map_type != BPF_MAP_TYPE_ARRAY &&
		    offmap->map.map_type != BPF_MAP_TYPE_HASH))
		return -EINVAL;
	if (offmap->map.max_entries > OTX2_BPF_MAX_KEYS)
		return -ENOMEM;
	if (offmap->map.map_flags)
		return -EINVAL;

	otx2_map = kzalloc(sizeof(*otx2_map), GFP_USER);
	if (!otx2_map)
		return -ENOMEM;

	offmap->dev_priv = otx2_map;
	otx2_map->map = offmap;
	mutex_init(&otx2_map->mutex);

	INIT_LIST_HEAD(&otx2_map->l);

	if (offmap->map.map_type == BPF_MAP_TYPE_ARRAY) {
		for (i = 0; i < ARRAY_SIZE(otx2_map->entry); i++) {
			u32 *key;

			err = otx2_map_alloc_elem(offmap, i);

			if (err)
				goto err_free;
			key = otx2_map->entry[i].key;
			*key = i;
			memset(otx2_map->entry[i].value, 0, offmap->map.value_size);
		}
	}

	offmap->dev_ops = &otx2_bpf_map_ops;
	list_add_tail(&otx2_map->l, &pf->xdp_hw.lmaps);

	return 0;

err_free:
	while (--i >= 0) {
		kfree(otx2_map->entry[i].key);
		kfree(otx2_map->entry[i].value);
	}

	kfree(otx2_map);
	return err;
}

void otx2_bpf_map_free(struct bpf_offloaded_map *offmap)
{
	struct otx2_bpf_bound_map *otx2 = offmap->dev_priv;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(otx2->entry); i++) {
		kfree(otx2->entry[i].key);
		kfree(otx2->entry[i].value);
	}
	list_del_init(&otx2->l);
	mutex_destroy(&otx2->mutex);
	kfree(otx2);
}
