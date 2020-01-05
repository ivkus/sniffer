#include "util.h"

char *hex(const char *in, int size)
{
    static char buf[1024];
    int l = 0;
    for (int i = 0; i < size; ++i)
    {
        l += snprintf(buf + l, sizeof buf - l,
                      "%02hhx-", in[i]);
    }
    buf[l - 1] = '\000';
    return buf;
}
