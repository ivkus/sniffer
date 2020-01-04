#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>

#include "DevSniffer.h"

char *hex(const char *in, int size)
{
    static char buf[1024];
    int l = 0;
    for (int i = 0; i < size; ++i)
    {
        l += snprintf(buf + l, sizeof buf - l,
                      "%02hhx-", in[i]);
    }
    buf[l] = '\000';
    return buf;
}

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

std::ostream &operator<<(std::ostream &os, sockaddr_ll &v)
{
    os << "Sockaddr_ll:family[" << v.sll_family
       << "] protocol[" << v.sll_protocol
       << "] index[" << v.sll_ifindex
       << "]";
    return os;
}

std::ostream &operator<<(std::ostream &os, ether_header &v)
{
    os << "Ether:type[" << v.ether_type
       << "] dst[" << hex((const char *)v.ether_dhost, sizeof v.ether_dhost)
       << "] src[" << hex((const char *)v.ether_shost, sizeof v.ether_shost)
       << "]";
    return os;
}
std::ostream &operator<<(std::ostream &os, iphdr &v)
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
        // TODO: handle frame
        std::cout << "=========" << std::endl;
        std::cout << "  " << *hdr() << std::endl;
        std::cout << "  " << *addr() << std::endl;
        std::cout << "  " << *l2() << std::endl;
        std::cout << "  " << *l3() << std::endl;
        Next();
    }
}
