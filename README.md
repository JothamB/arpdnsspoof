# ARPDNSSPOOF

ARPspoof and DNSSpoof in one aplication. It poisons the ARP table of the victim and modifies DNS responses to the victim. ARPDNSSPOOF does not modify the ARP table of the gateway switch.

### Install Requirements

```gem install packetfu```
```gem install hex_string```
```gem install colorize```

### How it works

ARPDNSSPOOF poisons the victim's ARP table to conduct a partial Man in the Middle attack.

The victim's ARP table is modified to route through the attacker's machine network traffic that is intended to the gateway.
ARPDNSSPOOF tests each packet. If the packet is a DNS query that has to be spoofed, according to arpdnsspoof.conf, a cooked DNS response is sent to the victim. In any other case, the packet is naturally routed to the gateway.

By poisoning only the victim's ARP table ARPDNSSPOOF avoids issues that may raise while attempting to poison modern switchs' ARP table.

In order for ARPDNSSPOOF to work, ipv4 forwarding must be set off.

### Usage

```./arpdnsspoof.rb VictimIpAddress```

### Author

JothamB (C) 2018

### Licence

GPL. See COPYING for licensing details.
