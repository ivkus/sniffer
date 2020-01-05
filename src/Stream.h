#ifndef STREAM_H
#define STREAM_H

#include <net/ethernet.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include "util.h"

struct StreamKey
{
    uint8_t mac_src_[ETH_ALEN];
    uint8_t mac_dst_[ETH_ALEN];
    uint32_t ip_src_;
    uint32_t ip_dst_;
    uint16_t port_src_;
    uint16_t port_dst_;
    uint16_t protocol_;
    bool operator<(const StreamKey &o) const
    {
        return memcmp(this, &o, sizeof(StreamKey));
    }
};

std::ostream &operator<<(std::ostream &os, const StreamKey &v);

#endif
