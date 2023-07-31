# firewall-lkm

This is an unfinished LKM firewall using netfilter hooks. The idea behind this was to create an stateful firewall with application filters. Since we switched to a XDP/eBPF solution, the idea was scrapped and not finished. Some may find this useful, but do take into account that this is not an implementation for a production environment.