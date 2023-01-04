#ifndef OTX2_MAP_H
#define OTX2_MAP_H

#define OTX2_BPF_MAX_KEYS		2

struct otx2_bpf_bound_map {
	struct bpf_offloaded_map *map;
	struct mutex mutex;
	struct otx2_map_entry {
		void *key;
		void *value;
	} entry[OTX2_BPF_MAX_KEYS];
	struct list_head l;
};

int otx2_bpf_map_alloc(struct net_device *dev, struct bpf_offloaded_map *offmap);
void otx2_bpf_map_free(struct bpf_offloaded_map *offmap);

#endif /*  OTX2_MAP_H */
