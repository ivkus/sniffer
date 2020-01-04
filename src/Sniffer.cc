#include <algorithm>
#include <poll.h>
#include "Sniffer.h"

void Sniffer::AddDevSniffer(std::shared_ptr<DevSniffer> dev)
{
    devs_.push_back(dev);
    dev->CreateRawSocket();
}

void Sniffer::Start()
{
    std::vector<pollfd> fds;
    std::transform(devs_.begin(), devs_.end(),
                   std::back_inserter(fds),
                   [](std::shared_ptr<DevSniffer> dev) { return pollfd{dev->fd(), POLLIN, 0}; });

    while (true)
    {
        int ret = poll(fds.data(), fds.size(), -1);
        if (ret == -1)
        {
            perror("poll");
            exit(-100);
        }

        for (size_t i  = 0; i < fds.size(); ++i)
        {
            if (fds[i].revents & POLLIN)
                devs_[i]->OnData();
        }
    }
}
