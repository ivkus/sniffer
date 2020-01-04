#ifndef _DEV_SNIFFER_H_
#define _DEV_SNIFFER_H_

#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <string>

class DevSniffer
{
public:
    DevSniffer(std::string dev_name)
        : dev_name_(dev_name),
          fd_(-1),
          rx_ring_(nullptr),
          idx_(0)
    {
    }

    ~DevSniffer();
    bool CreateRawSocket();
    void OnData();
    int fd() { return fd_; }

private:
    char *frame() { return rx_ring_ + idx_ * frame_size_; }
    tpacket2_hdr *hdr() { return (tpacket2_hdr *)frame(); }
    sockaddr_ll *addr() { return (struct sockaddr_ll *)(frame() + TPACKET_HDRLEN - sizeof(struct sockaddr_ll)); }
    ether_header *l2() { return (ether_header *)(frame() + hdr()->tp_mac); }
    iphdr *l3() { return (iphdr *)(frame() + hdr()->tp_net); }

    void Next()
    {
        hdr()->tp_status &= TP_STATUS_KERNEL;
        idx_ = ++idx_ % frame_nr_;
    }
    bool HasFrame() { return hdr()->tp_status & TP_STATUS_USER; }

private:
    std::string dev_name_;
    int fd_;
    char *rx_ring_;

    int frame_nr_;
    int frame_size_;
    int idx_;
};

#endif
