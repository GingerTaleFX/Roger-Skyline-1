#!/bin/sh
#
#
# Script is for stoping Portscan and smurf attack

### first flush all the iptables Rules
iptables -F


# INPUT iptables Rules

# Accept loopback input
iptables -A INPUT -i lo -p all -j ACCEPT

# Accept 192.168.56.2 connection for updates
iptables -I INPUT 1 -p all -s 192.168.56.2 -j ACCEPT
iptables -I OUTPUT 1 -p all -s 192.168.56.2 -j ACCEPT
iptables -I FORWARD 1 -p all -s 192.168.56.2 -j ACCEPT

#Few groups for packs

#iptables -N bad_tcp_packets
#iptables -N allowed
#iptables -N tcp_packets

# bad_tcp_packets chain

iptables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "New not syn:"
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

# allowed chain

iptables -A allowed -p TCP --syn -j ACCEPT
iptables -A allowed -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A allowed -p TCP -j DROP

# TCP rules

iptables -A tcp_packets -p TCP -s 0/0 --dport 443 -j allowed
iptables -A tcp_packets -p TCP -s 0/0 --dport 2222 -j allowed
iptables -A tcp_packets -p TCP -s 0/0 --dport 80 -j allowed

#iptables -A tcp_packets -p TCP -s 0/0 --dport 113 -j allowed

# Bad TCP packets we don't want.

iptables -A INPUT -p tcp -j bad_tcp_packets

# Log weird packets that don't match the above.

iptables -A INPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level debug --log-prefix "IPT INPUT packet died: "

# Bad TCP packets we don't want

iptables -A FORWARD -p tcp -j bad_tcp_packets

# Log weird packets that don't match the above.

iptables -A FORWARD -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level debug --log-prefix "IPT FORWARD packet died: "

# Bad TCP packets we don't want.

iptables -A OUTPUT -p tcp -j bad_tcp_packets

# Log weird packets that don't match the above.

iptables -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level debug --log-prefix "IPT OUTPUT packet died: "

# allow 3 way handshake
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

### DROPspoofing packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

#for SMURF attack protection
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT

# Droping all invalid packets

iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Protecting portscans
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Remove attacking IP after 24 hours
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

# Allow the following ports through from outside
iptables -A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT

# Allow ping means ICMP port is open (If you do not want ping replace ACCEPT with REJECT)
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Lastly reject All INPUT traffic
iptables -A INPUT -j REJECT


################# Below are for OUTPUT iptables rules #############################################

## Allow loopback OUTPUT 
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow the following ports through from outside 
# SMTP = 25
# DNS =53
# HTTP = 80
# HTTPS = 443
# SSH = 22
### You can also add or remove port no. as per your requirement

iptables -A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 2222 -j ACCEPT

# Allow pings
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Lastly Reject all Output traffic
iptables -A OUTPUT -j REJECT

## Reject Forwarding  traffic
iptables -A FORWARD -j REJECT
