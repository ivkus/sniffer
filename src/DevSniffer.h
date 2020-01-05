#ifndef _DEV_SNIFFER_H_
#define _DEV_SNIFFER_H_

#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <string>
#include <map>
#include <functional>

#include "Stream.h"

using StreamCallbackFn = std::function<void(const char *, size_t)>;

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
    void RegisterStream(StreamKey &k, StreamCallbackFn fn);
    int fd() { return fd_; }

private:
    char *frame() { return rx_ring_ + idx_ * frame_size_; }
    tpacket2_hdr *hdr() { return (tpacket2_hdr *)frame(); }

    // read only accessor
    const sockaddr_ll *addr() { return (struct sockaddr_ll *)(frame() + TPACKET_HDRLEN - sizeof(struct sockaddr_ll)); }
    const ether_header *l2() { return (ether_header *)(frame() + hdr()->tp_mac); }
    const iphdr *l3() { return (iphdr *)(frame() + hdr()->tp_net); }
    const char *l4() { return (const char *)l3() + l3()->ihl * 4; }

    bool HasFrame() { return hdr()->tp_status & TP_STATUS_USER; }

    void Next()
    {
        hdr()->tp_status = TP_STATUS_KERNEL;
        idx_ = ++idx_ % frame_nr_;
    }

    bool CurrentKey(StreamKey &);

private:
    std::string dev_name_;
    int fd_;
    char *rx_ring_;

    int frame_nr_;
    int frame_size_;
    int idx_;

    // dispatch logic
    std::map<StreamKey, StreamCallbackFn> stream_fn_map_;
};

#endif
