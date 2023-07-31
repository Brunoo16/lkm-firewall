#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/if_arp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_bridge.h>
#include <linux/ioctl.h>
#include <linux/unistd.h>
#include <linux/fcntl.h>
#include <linux/timer.h>
#include <net/ip.h>

// Declarations
#define MAX_APPLICATION_FILTERS 20
#define MAX_FIREWALL_RULES 20

#define NONE 0
#define SYN_RECEIVED 1
#define SYN_SENT 2
#define AWAITING_ACK 3
#define STABILISHED 4

#define FILTER_NONE 0
#define FILTER_SSH_SERVICE 1
#define FILTER_TCP_SYMMETRIC 2

// Structures
typedef struct serverRules
{
    unsigned long sourceIp;
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned short protocol;
    int accept;
} serverRules;

typedef struct applicationFilters
{
    unsigned short destinationPort;
    unsigned int filterType; // 0 - None | 1 - SSH Service | 2 - TCP SYMMETRIC 
} applicationFilters;

typedef struct activeLink 
{
    unsigned long sourceIp;
    unsigned long destinationIp;
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned short protocol;
    unsigned int currentState;
    unsigned char linkLifeTime;
    struct activeLink *next;
} activeLink;

typedef struct ipInfo
{
    unsigned long serverIp;
    struct serverRules ipRules[MAX_FIREWALL_RULES];
    struct applicationFilters ipFilters[MAX_APPLICATION_FILTERS];
    activeLink *activeLinkList;
    activeLink *activeLinkListTail;
    struct ipInfo *next;
} ipInfo;

// Variables
static ipInfo *ipInfoList, *ipInfoListTail;
static struct nf_hook_ops incomingPacketsHook;
static struct nf_hook_ops outgoingPacketsHook;
struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct ethhdr *mac_header;
char *data;

int g_time_interval = 1000;
//static struct timer_list linkLifeTimer;

// Function prototypes
int addServerToFirewall(const ipInfo *list);
int removeServerFromFirewall(const unsigned long targetServerIp);
ipInfo *findServerOnFirewall(const unsigned long targetServerIp);

int addActiveLink(ipInfo *list, const activeLink *activeLinkInstance);
int removeActiveLink(ipInfo *list, const activeLink *activeLinkInstance);
activeLink *findActiveLink(ipInfo *list, const activeLink *activeLinkInstance);
int compareActiveLink(const activeLink *linkInstanceA, const activeLink *linkInstanceB);
unsigned int inet_addr(char *str);

// Function declarations
/*void linkLifeTimerCallback( unsigned long data )
{
    mod_timer( &linkLifeTimer, jiffies + msecs_to_jiffies(g_time_interval));
    printk( "timer called (%ld).\n", jiffies );
}*/

int addServerToFirewall(const ipInfo *list)
{
    ipInfo *newIP = (ipInfo*)kmalloc(sizeof(ipInfo), 0);

    if(!newIP)
    {
        return 0;
    }

    if(ipInfoListTail)
    {
        ipInfoList->next = newIP;
    }
    else
    {
        ipInfoListTail = newIP;
    }

    ipInfoList = newIP;

    ipInfoList->serverIp = list->serverIp;

    int i;

    for(i = 0; i < MAX_FIREWALL_RULES; ++i)
    {
        ipInfoList->ipFilters[i].destinationPort = list->ipFilters[i].destinationPort;
        ipInfoList->ipFilters[i].filterType = list->ipFilters[i].filterType;

        ipInfoList->ipRules[i].sourceIp = list->ipRules[i].sourceIp;
        ipInfoList->ipRules[i].sourcePort = list->ipRules[i].sourcePort;
        ipInfoList->ipRules[i].destinationPort = list->ipRules[i].destinationPort;
        ipInfoList->ipRules[i].protocol = list->ipRules[i].protocol; // None
        ipInfoList->ipRules[i].accept = list->ipRules[i].accept;
    }

    ipInfoList->next = NULL;
    ipInfoList->activeLinkList = NULL;
    ipInfoList->activeLinkListTail = NULL;

    return 1;
}

int removeServerFromFirewall(const unsigned long targetServerIp)
{
    if(!ipInfoListTail)
    {
        return 0;
    }

    ipInfo *node = ipInfoListTail;
    ipInfo *previousNode = ipInfoListTail;

    while(node)
    {
        if (node->serverIp == targetServerIp)
        {
            if(node->next)
            {
                previousNode->next = node->next;
            }

            if(node->activeLinkListTail)
            {
                activeLink *previousLinkNode = node->activeLinkListTail;
                activeLink *linkNode = node->activeLinkListTail;

                while(linkNode)
                {
                    previousLinkNode = linkNode;

                    if(linkNode->next)
                    {
                        linkNode = linkNode->next;
                    }

                    kfree(previousLinkNode);
                    previousLinkNode = NULL;
                }
            }

            kfree(node);
            node = NULL;
            return 1;
        }

        previousNode = node;
        node = node->next;
    }

    return 0;
}

ipInfo *findServerOnFirewall(const unsigned long targetServerIp)
{
    if(!ipInfoListTail)
    {
        return 0;
    }

    ipInfo *node = ipInfoListTail;

    while(node)
    {
        if (node->serverIp == targetServerIp)
        { 
            return node;
        }
        node = node->next;
    }
    return 0;
}

int addActiveLink(ipInfo *list, const activeLink *activeLinkInstance)
{
    if(!list)
    {
        return 0;
    }

    if(!activeLinkInstance)
    {
        return 0;
    }

    activeLink *newList = (activeLink*)kmalloc(sizeof(activeLink), 0);

    if(!newList)
    {
        return 0;
    }

    if(list->activeLinkListTail)
    {
        list->activeLinkList->next = newList;
    }
    else
    {
        list->activeLinkListTail = newList;
    }

    list->activeLinkList = newList;

    newList->sourceIp = activeLinkInstance->sourceIp;
    newList->destinationIp = activeLinkInstance->destinationIp;
    newList->sourcePort = activeLinkInstance->sourcePort;
    newList->destinationPort = activeLinkInstance->destinationPort;
    newList->protocol = activeLinkInstance->protocol;
    newList->currentState = activeLinkInstance->currentState;
    newList->next = NULL;

    if(newList->protocol == IPPROTO_TCP)
    {
        newList->linkLifeTime = 60;
    }
    else
    {
        newList->linkLifeTime = 20;
    }

    return 1;
}

int removeActiveLink(ipInfo *list, const activeLink *activeLinkInstance)
{
    if(!list)
    {
        return 0;
    }

    if(!activeLinkInstance)
    {
        return 0;
    }

    if(!list->activeLinkListTail)
    {
        return 0;
    }

    activeLink *node = list->activeLinkListTail;
    activeLink *previousNode = list->activeLinkListTail;

    while(node)
    {
        if (node->sourceIp == activeLinkInstance->sourceIp && 
        node->sourcePort == activeLinkInstance->sourcePort && 
        node->destinationPort == activeLinkInstance->destinationPort &&
        node->protocol == activeLinkInstance->protocol && node->destinationIp == activeLinkInstance->destinationIp)
        {
            if(node->next)
            {
                previousNode->next = node->next;
            }

            kfree(node);
            node = NULL;
            return 1;
        }

        previousNode = node;
        node = node->next;
    }
    return 0;
}

activeLink *findActiveLink(ipInfo *list, const activeLink *activeLinkInstance)
{
    if(!list)
    {
        return 0;
    }

    if(!activeLinkInstance)
    {
        return 0;
    }

    activeLink *node = list->activeLinkListTail;

    while(node)
    {
        if (node->sourceIp == activeLinkInstance->sourceIp && 
        node->sourcePort == activeLinkInstance->sourcePort && 
        node->destinationPort == activeLinkInstance->destinationPort &&
        node->protocol == activeLinkInstance->protocol && node->destinationIp == activeLinkInstance->destinationIp)
        {
            return node;
        }

        node = node->next;
    }
    return 0;
}

int compareActiveLink(const activeLink *linkInstanceA, const activeLink *linkInstanceB)
{
    if(!linkInstanceA)
    {
        return 0;
    }

    if(!linkInstanceB)
    {
        return 0;
    }

    if (linkInstanceA->sourceIp == linkInstanceB->sourceIp && 
    linkInstanceA->sourcePort == linkInstanceB->sourcePort && 
    linkInstanceA->destinationPort == linkInstanceB->destinationPort &&
    linkInstanceA->protocol == linkInstanceB->protocol && linkInstanceA->destinationIp == linkInstanceB->destinationIp)
    {
        return 1;
    }
    return 0;
}

unsigned int inet_addr(char *str)
{
    int a,b,c,d;
    char arr[4];
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int*)arr;
}

MODULE_DESCRIPTION("Firewall Kernel module");
MODULE_AUTHOR("Brunoo");
MODULE_LICENSE("GPL");

unsigned int incomingPackets(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    sock_buff = skb;
    ip_header = (struct iphdr*)skb_network_header(sock_buff);
    mac_header = (struct ethhdr*)skb_mac_header(sock_buff);

    struct tcphdr* tcph;
    struct udphdr* udph;

    udph = (struct udphdr*)((unsigned char*)ip_header + (ip_header->ihl << 2));
    tcph = (struct tcphdr*)((unsigned char*)ip_header + (ip_header->ihl << 2));

    if(!sock_buff)
    { 
        return NF_DROP;
    }

    unsigned int defaultPolicy = NF_DROP;

    if(ip_header)
    {
        ipInfo* ipFound = findServerOnFirewall(ip_header->daddr);
        ipInfo* srcConfirmation = findServerOnFirewall(ip_header->saddr);

        if (srcConfirmation)
        {
            defaultPolicy = NF_ACCEPT;
        }

        if (ipFound)
        {
            int rule;

            for (rule = 0; rule < MAX_FIREWALL_RULES; ++rule)
            {
                if (ipFound->ipRules[rule].protocol == ip_header->protocol)
                {
                    if (ipFound->ipRules[rule].sourceIp == 0 || ntohl(ipFound->ipRules[rule].sourceIp) == ip_header->saddr)
                    {
                        if (ip_header->protocol == IPPROTO_UDP)
                        {
                            if (udph)
                            {
                                if (ipFound->ipRules[rule].sourcePort == 0 || ipFound->ipRules[rule].sourcePort == ntohs(udph->source))
                                {
                                    if (ipFound->ipRules[rule].destinationPort == ntohs(udph->dest))
                                    {
                                        if (ipFound->ipRules[rule].accept == 0)
                                        {
                                            defaultPolicy = NF_DROP;
                                        }
                                        else
                                        {
                                            defaultPolicy = NF_ACCEPT;
                                        }
                                    }
                                }
                            }
                        }
                        else if (ip_header->protocol == IPPROTO_TCP)
                        {
                            if (tcph)
                            {
                                if (ipFound->ipRules[rule].sourcePort == 0 || ipFound->ipRules[rule].sourcePort == ntohs(tcph->source))
                                {
                                    if (ipFound->ipRules[rule].destinationPort == ntohs(tcph->dest))
                                    {
                                        if (ipFound->ipRules[rule].accept == 0)
                                        {
                                            defaultPolicy = NF_DROP;
                                        }
                                        else
                                        {
                                            defaultPolicy = NF_ACCEPT;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            activeLink placeHolder;

            placeHolder.protocol = ip_header->protocol;
            placeHolder.sourceIp = ip_header->saddr;
            placeHolder.destinationIp = ip_header->daddr;

            if (ip_header->protocol == IPPROTO_TCP)
            {
                placeHolder.linkLifeTime = 60;
                placeHolder.destinationPort = ntohs(tcph->dest);
                placeHolder.sourcePort = ntohs(tcph->source);
            }
            else if (ip_header->protocol == IPPROTO_UDP)
            {
                placeHolder.linkLifeTime = 20;
                placeHolder.destinationPort = ntohs(udph->dest);
                placeHolder.sourcePort = ntohs(udph->source);
            }

            activeLink* linkFound = findActiveLink(ipFound, &placeHolder);

            if(linkFound != 0) defaultPolicy = NF_ACCEPT;

            if (defaultPolicy == NF_ACCEPT)
            {
                activeLink placeHolder;

                placeHolder.protocol = ip_header->protocol;
                placeHolder.sourceIp = ip_header->saddr;
                placeHolder.destinationIp = ip_header->daddr;

                if (ip_header->protocol == IPPROTO_TCP)
                {
                    placeHolder.linkLifeTime = 60;
                    placeHolder.destinationPort = ntohs(tcph->dest);
                    placeHolder.sourcePort = ntohs(tcph->source);
                }
                else if (ip_header->protocol == IPPROTO_UDP)
                {
                    placeHolder.linkLifeTime = 20;
                    placeHolder.destinationPort = ntohs(udph->dest);
                    placeHolder.sourcePort = ntohs(udph->source);
                }

                if (linkFound != 0)
                {
                    if (placeHolder.protocol == IPPROTO_TCP)
                    {
                        if(linkFound->currentState == SYN_RECEIVED)
                        {
                            defaultPolicy = NF_DROP;
                            removeActiveLink(ipFound, linkFound);
                        }
                        else if(linkFound->currentState == SYN_SENT)
                        {
                            if (tcph->syn == true && tcph->ack == true)
                            {
                                linkFound->currentState = AWAITING_ACK;
                                linkFound->linkLifeTime = placeHolder.linkLifeTime;
                            }
                            else
                            {
                                defaultPolicy = NF_DROP;
                                removeActiveLink(ipFound, linkFound);
                            }
                        }
                        else if(linkFound->currentState == AWAITING_ACK)
                        {
                            if (tcph->ack == true)
                            {
                                linkFound->currentState = STABILISHED;
                                linkFound->linkLifeTime = placeHolder.linkLifeTime;
                            }
                            else
                            {
                                defaultPolicy = NF_DROP;
                                removeActiveLink(ipFound, linkFound);
                            }
                        }
                        else if(linkFound->currentState == STABILISHED)
                        {
                            if (tcph->fin == true || tcph->rst == true)
                            {
                                removeActiveLink(ipFound, linkFound);
                            }
                            else
                            {
                                linkFound->linkLifeTime = placeHolder.linkLifeTime;
                            }
                        }
                    }
                    else if (ip_header->protocol == IPPROTO_UDP)
                    {
                        linkFound->linkLifeTime = placeHolder.linkLifeTime;
                    }
                }
                else
                {
                    if (placeHolder.protocol == IPPROTO_TCP)
                    {
                        if (tcph->syn == true)
                        {
                            placeHolder.currentState = SYN_RECEIVED;
                            addActiveLink(ipFound, &placeHolder);
                        }
                        else
                        {
                            defaultPolicy = NF_DROP;
                        }
                    }
                    else if (ip_header->protocol == IPPROTO_UDP)
                    {
                        placeHolder.currentState = NONE;
                        addActiveLink(ipFound, &placeHolder);
                    }
                }
            }

        }
    }
    return defaultPolicy;
}

unsigned int outgoingPackets(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    sock_buff = skb;
    ip_header = (struct iphdr*)skb_network_header(sock_buff);
    mac_header = (struct ethhdr*)skb_mac_header(sock_buff);

    struct tcphdr* tcph;
    struct udphdr* udph;

    udph = (struct udphdr*)((unsigned char*)ip_header + (ip_header->ihl << 2));
    tcph = (struct tcphdr*)((unsigned char*)ip_header + (ip_header->ihl << 2));

    if(!sock_buff)
    { 
        return NF_DROP;
    }

    if(ip_header)
    {
        ipInfo* ipFound = findServerOnFirewall(ip_header->saddr);

        if (ipFound)
        {   
            activeLink placeHolder;

            placeHolder.protocol = ip_header->protocol;
            placeHolder.sourceIp = ip_header->daddr;
            placeHolder.destinationIp = ip_header->saddr;

            if (ip_header->protocol == IPPROTO_TCP)
            {
                placeHolder.linkLifeTime = 60;
                placeHolder.destinationPort = ntohs(tcph->source);
                placeHolder.sourcePort = ntohs(tcph->dest);
            }
            else if (ip_header->protocol == IPPROTO_UDP)
            {
                placeHolder.linkLifeTime = 20;
                placeHolder.destinationPort = ntohs(udph->source);
                placeHolder.sourcePort = ntohs(udph->dest);
            }

            activeLink* linkFound = findActiveLink(ipFound, &placeHolder);

            if (linkFound != 0)
            {
                if (placeHolder.protocol == IPPROTO_TCP)
                {
                    if(linkFound->currentState == SYN_SENT)
                    {
                        removeActiveLink(ipFound, linkFound);
                    }
                    else if(linkFound->currentState == SYN_RECEIVED)
                    {
                        if (tcph->syn == true && tcph->ack == true)
                        {
                            linkFound->currentState = AWAITING_ACK;
                            linkFound->linkLifeTime = placeHolder.linkLifeTime;
                        }
                        else
                        {
                            removeActiveLink(ipFound, linkFound);
                        }
                    }
                    else if(linkFound->currentState == AWAITING_ACK)
                    {
                        if (tcph->ack)
                        {
                            linkFound->currentState = STABILISHED;
                            linkFound->linkLifeTime = placeHolder.linkLifeTime;
                        }
                        else
                        {
                            removeActiveLink(ipFound, linkFound);
                        }
                    }
                    else if(linkFound->currentState == STABILISHED)
                    {
                        if (tcph->fin == true || tcph->rst == true)
                        {
                            removeActiveLink(ipFound, linkFound);
                        }
                        else
                        {
                            linkFound->linkLifeTime = placeHolder.linkLifeTime;
                        }
                    }
                }
                if (ip_header->protocol == IPPROTO_UDP)
                {
                    linkFound->linkLifeTime = placeHolder.linkLifeTime;
                }
            }
            else
            {
                if (placeHolder.protocol == IPPROTO_TCP)
                {
                    if (tcph->syn == true)
                    {
                        placeHolder.currentState = SYN_SENT;
                        addActiveLink(ipFound, &placeHolder);
                    }
                }
                if (ip_header->protocol == IPPROTO_UDP)
                {
                    placeHolder.currentState = NONE;
                    addActiveLink(ipFound, &placeHolder);
                }
            }
        }
    }

    return NF_ACCEPT;
}
 
int init_module()
{
    incomingPacketsHook.hook = incomingPackets;
    incomingPacketsHook.hooknum = NF_BR_PRE_ROUTING; // NF_IP_PRE_ROUTING
    incomingPacketsHook.pf = PF_BRIDGE;
    incomingPacketsHook.priority = NF_BR_PRI_FIRST;

    outgoingPacketsHook.hook = outgoingPackets;
    outgoingPacketsHook.hooknum = NF_BR_POST_ROUTING; // NF_IP_POST_ROUTING
    outgoingPacketsHook.pf = PF_BRIDGE;
    outgoingPacketsHook.priority = NF_BR_PRI_FIRST;

    nf_register_net_hook(&init_net, &incomingPacketsHook);
    nf_register_net_hook(&init_net, &outgoingPacketsHook);

    ipInfo serverToAdd;

    int i;

    for(i = 0; i < MAX_FIREWALL_RULES; ++i)
    {
        serverToAdd.ipFilters[i].destinationPort = 0;
        serverToAdd.ipFilters[i].filterType = 0;

        serverToAdd.ipRules[i].sourceIp = 0;
        serverToAdd.ipRules[i].sourcePort = 0;
        serverToAdd.ipRules[i].destinationPort = 0;
        serverToAdd.ipRules[i].protocol = 0xFF; // None
        serverToAdd.ipRules[i].accept = 1;
    }

    serverToAdd.serverIp = inet_addr("test ip"); // Example

    serverToAdd.ipFilters[0].destinationPort = 22;
    serverToAdd.ipFilters[0].filterType = FILTER_SSH_SERVICE;
    
    serverToAdd.ipFilters[1].destinationPort = 80;
    serverToAdd.ipFilters[1].filterType = FILTER_TCP_SYMMETRIC;

    serverToAdd.ipRules[0].sourceIp = 0;
    serverToAdd.ipRules[0].sourcePort = 0;
    serverToAdd.ipRules[0].destinationPort = 22;
    serverToAdd.ipRules[0].protocol = IPPROTO_TCP;
    serverToAdd.ipRules[0].accept = 1;

    serverToAdd.ipRules[1].sourceIp = 0;
    serverToAdd.ipRules[1].sourcePort = 0;
    serverToAdd.ipRules[1].destinationPort = 80;
    serverToAdd.ipRules[1].protocol = IPPROTO_TCP;
    serverToAdd.ipRules[1].accept = 1;

    addServerToFirewall(&serverToAdd);

    //timer_setup(&linkLifeTimer, linkLifeTimerCallback, 0);
    //mod_timer(&linkLifeTimer, jiffies + msecs_to_jiffies(g_time_interval));

    printk(KERN_INFO "---------------------------------------\n");
    printk(KERN_INFO "Loading Firewall kernel module...\n");
    return 0;
}
 
void cleanup_module()
{
    printk(KERN_INFO "Cleaning up Firewall kernel module.\n");
    nf_unregister_net_hook(&init_net, &incomingPacketsHook);
    nf_unregister_net_hook(&init_net, &outgoingPacketsHook);
    //del_timer(&linkLifeTimer);
}