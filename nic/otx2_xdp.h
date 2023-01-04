

#ifndef OTX2_XDP_H_
#define OTX2_XDP_H_

int otx2_setup_hw_xdp(struct net_device *dev, struct netdev_bpf *xdp);

void otx2_xdp_proc_create(void);

void otx2_xdp_offload_dev_unregister(struct net_device *dev);
int otx2_xdp_offload_dev_register(struct net_device *dev);

#endif /* OTX2_XDP_H_ */
