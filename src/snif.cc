#include <iostream>
#include <vector>
#include <string>
#include <memory>

#include <net/if.h>

#include "DevSniffer.h"
#include "Sniffer.h"

int main(int argc, char **argv)
{
    std::string dev_name("wlp3s0");
    auto ds = std::make_shared<DevSniffer>(dev_name);
    Sniffer sniffer;
    sniffer.AddDevSniffer(ds);
    sniffer.Start();
    return 0;
}
