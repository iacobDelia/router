# Router forwarding
router.c implements the process of forwarding,
and the ARP and ICMP protocols

## The process of forwarding:
 - the router receives a packet, and it checks whether the protocol
 is ARP or IP
 - if it's IP, check the checksum, TTL and whether or not it's
 meant for the router by checking if the MAC address matches its own
 - look in the route table to find the next hop
 - also look in the ARP table to find the MAC of the next destination
 - if there are any entries in the ARP table matching the packet,
 send the packet on its way after changing its MAC addresses
 - if not, add it to the queue and send an ARP request

## Efficient algorithm for searching the route table:
 - when reading the route table for the first time, qsort it in
 ascending order based on the prefix and the mask; also filter it
 so that the table doesn't have any invalid entries
 - the searching function is binary search
 - once the algorithm finds an entry, we traverse the array until
 the mask applied on the ip address isn't equal to the current prefix;
 this is done to find the entry with the biggest mask

## The ARP protocol:
 - if the router receives an ARP packet, it checks whether it's a reply or request
 - if it's a request, the router sends back an ARP reply packet
 - if it's a reply, the router adds the new entry to its ARP table
 and checks its queue to see if there are any packets in the
 waiting matching the new ARP entry

## The ICMP protocol:
 - if the router receives an echo request, it sends back an echo
 reply ICMP packet
 - if the TTL expires or the router can't find an entry in the 
 route table, send an error ICMP packet matching either of these situations
