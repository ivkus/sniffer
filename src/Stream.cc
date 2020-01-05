#include "Stream.h"

std::ostream &operator<<(std::ostream &os, const StreamKey &v)
{
    os << "StreamKey smac[" << hex((const char *)v.mac_src_, sizeof v.mac_src_)
       << "] dmac[" << hex((const char *)v.mac_dst_, sizeof v.mac_dst_)
       << "] sip[" << hex((const char *)v.mac_dst_, sizeof v.mac_dst_)
       << "]";
    return os;
}