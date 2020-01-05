#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <unistd.h>
#include <iostream>

#include "DevSniffer.h"
#include "util.h"

std::ostream &operator<<(std::ostream &os, tpacket2_hdr &v)
{
    os << "TPacket2Hdr:status[" << v.tp_status
       << "] len[" << v.tp_len
       << "] snaplen[" << v.tp_snaplen
       << "] sec[" << v.tp_sec
       << "] nsec[" << v.tp_nsec
       << "] mac[" << v.tp_mac
       << "] net[" << v.tp_net
       << "]";
    return os;
}

std::ostream &operator<<(std::ostream &os, const sockaddr_ll &v)
{
    os << "Sockaddr_ll:family[" << v.sll_family
       << "] protocol[" << v.sll_protocol
       << "] index[" << v.sll_ifindex
       << "]";
    return os;
}

std::ostream &operator<<(std::ostream &os, const ether_header &v)
{
    os << "Ether:type[" << v.ether_type
       << "] dst[" << hex((const char *)v.ether_dhost, sizeof v.ether_dhost)
       << "] src[" << hex((const char *)v.ether_shost, sizeof v.ether_shost)
       << "]";
    return os;
}
std::ostream &operator<<(std::ostream &os, const iphdr &v)
{
    struct in_addr saddr, daddr;
    saddr.s_addr = v.saddr;
    daddr.s_addr = v.daddr;
    os << "Ip:header_len[" << v.ihl * 4
       << "] src[" << inet_ntoa(saddr)
       << "] dst[" << inet_ntoa(daddr)
       << "] tot_len[" << htons(v.tot_len)
       << "]";
    return os;
}

DevSniffer::~DevSniffer()
{
    close(fd_);
}

bool DevSniffer::CreateRawSocket()
{
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ == -1)
    {
        std::cerr << "create raw socket" << std::endl;
        exit(-1);
    }

    int val = TPACKET_V2;
    int ret = setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
    if (ret == -1)
    {
        std::cerr << "set packet version failed" << std::endl;
        exit(-2);
    }

    unsigned int dev_idx = if_nametoindex(dev_name_.c_str());
    if (dev_idx == 0)
    {
        std::cerr << "unable to find dev index of " << dev_name_ << std::endl;
        exit(-2);
    }

    struct sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = dev_idx;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd_, (sockaddr *)&addr, sizeof addr) < 0)
    {
        std::cerr << "bind error: " << dev_name_ << std::endl;
        exit(-3);
    }

    struct tpacket_req req;
    req.tp_frame_size = 2048;
    req.tp_frame_nr = 2 * 256;
    req.tp_block_size = 4096;
    req.tp_block_nr = 256;

    if (setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) == -1)
    {
        std::cerr << "crate rx ring failed" << std::endl;
        exit(-3);
    }

    size_t rx_size = req.tp_block_nr * req.tp_block_size;
    rx_ring_ = (char *)mmap(0, rx_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (rx_ring_ == NULL)
    {
        std::cerr << "mmap failed" << std::endl;
        exit(-4);
    }

    frame_nr_ = req.tp_frame_nr;
    frame_size_ = req.tp_frame_size;

    return true;
}

void DevSniffer::OnData()
{
    while (HasFrame())
    {
        StreamKey sk;
        if (CurrentKey(sk))
        {
            auto fnit = stream_fn_map_.find(sk);
            if (fnit != stream_fn_map_.end())
            {
                std::cout << sk << std::endl;
                fnit->second((const char *)l2(), hdr()->tp_snaplen);
            }
        }

        std::cout << "=========" << std::endl;
        std::cout << "  " << *hdr() << std::endl;
        std::cout << "  " << *addr() << std::endl;
        std::cout << "  " << *l2() << std::endl;
        std::cout << "  " << *l3() << std::endl;
        Next();
    }
}

void DevSniffer::RegisterStream(StreamKey &k, StreamCallbackFn fn)
{
    stream_fn_map_[k] = fn;
}

bool DevSniffer::CurrentKey(StreamKey &sk)
{
    switch (l3()->protocol)
    {
    case IPPROTO_TCP:
    {
        sk.protocol_ = IPPROTO_TCP;
        auto tcp = (const tcphdr *)l4();
        sk.port_dst_ = tcp->dest;
        sk.port_src_ = tcp->source;
        break;
    }
    case IPPROTO_UDP:
    {
        sk.protocol_ = IPPROTO_UDP;
        auto udp = (const udphdr *)l4();
        sk.port_dst_ = udp->dest;
        sk.port_src_ = udp->source;
        break;
    }
    default:
        return false;
    }

    memcpy(sk.mac_dst_, l2()->ether_dhost, sizeof(sk.mac_dst_));
    memcpy(sk.mac_src_, l2()->ether_shost, sizeof(sk.mac_src_));
    sk.ip_dst_ = l3()->daddr;
    sk.ip_src_ = l3()->saddr;

    return true;
}
