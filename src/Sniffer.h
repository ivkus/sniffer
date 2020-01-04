#ifndef _SNIFFER_H
#define _SNIFFER_H

#include <vector>
#include <memory>
#include "DevSniffer.h"

class Sniffer
{
public:
    Sniffer() {}
    void AddDevSniffer(std::shared_ptr<DevSniffer> dev);
    void Start();

private:
    std::vector<std::shared_ptr<DevSniffer>> devs_;
};

#endif
