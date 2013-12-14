#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import sys
import socket
import argparse
from collections import defaultdict

import pcap
import dpkt

re_args = re.compile('\*\d+')
re_lens = re.compile('\$\d+')

def sniff(interface, port=6379, src_ip=None, dst_ip=None):
    """Sniff Redis queries and responses

    *interface* is network interface name or raw packets file record with
    tcpdump::

        tcpdump -i <interface> -s 65535 tcp port <port> -w <redis.pcap>

    *port* is port of the redis server
    """

    pc = pcap.pcap(interface)
    _filter = 'tcp port %s' % port
    if src_ip:
        _filter += ' and src %s' % src_ip
    if dst_ip:
        _filter += ' and dst %s' % dst_ip
    pc.setfilter(_filter)

    receiving = False
    receiving_partials = {}
    request_sizes = defaultdict(int)
    sessions = {}
    for ptime, pdata in pc:
        ether_pkt = dpkt.ethernet.Ethernet(pdata)
        ip_pkt = ether_pkt.data
        tcp_pkt = ip_pkt.data
        tcp_data = tcp_pkt.data

        if len(tcp_data) == 0:
            continue

        src = socket.inet_ntoa(ip_pkt.src)
        sport = tcp_pkt.sport
        dst = socket.inet_ntoa(ip_pkt.dst)
        dport = tcp_pkt.dport
        src_addr = '%s:%s' % (src, sport)
        dst_addr = '%s:%s' % (dst, dport)
        if sport == port:
            receiving = False
            client = dst_addr
        else:
            receiving = True
            client = src_addr

        if receiving:
            # request
            if not tcp_data:
                continue
            _parts = tcp_data.splitlines()
            _receiving_partial = receiving_partials.get(client, [])
            _parts = _receiving_partial + _parts
            request_sizes[client] += len(pdata)
            request_size = request_sizes[client]
            n_parts = len(_parts)
            n_args = int(_parts[0][1:])
            if (n_args * 2 + 1) == n_parts and int(_parts[-2][1:]) == len(_parts[-1]):
                # Complete normal command
                command = ' '.join([c for (i, c) in enumerate(_parts[1:]) if i % 2 == 1])
                receiving_partials.pop(client, None)
                request_sizes.pop(client, None)
            else:
                if _parts[2] == 'MULTI':
                    if _parts[-1] == 'EXEC':
                        # Complete MULTI command
                        _multi_parts = _parts[2:]
                        _partial = []
                        _n_args = 1
                        for _part in _multi_parts:
                            if re_args.match(_part):
                                _n_args = int(_part[1:])
                                continue
                            if re_lens.match(_part):
                                continue
                            if _n_args > 0:
                                _partial.append(_part)
                                _n_args -= 1
                                if _n_args == 0 and _part != 'EXEC':
                                    _partial.append('/')
                                continue
                        command = ' '.join(_partial)
                        receiving_partials.pop(client, None)
                        request_sizes.pop(client, None)
                    else:
                        # Partial MULTI command
                        receiving_partials[client] = _parts
                        continue
                else:
                    # Partial normal command
                    receiving_partials[client] = _parts
                    continue

            stat = sessions.pop(client, None)
            if stat:
                _request_size = stat.get('request_size', 0)
                _response_size = stat.get('response_size', 0)
                _command = stat['command']
                yield ptime, client, _request_size, _response_size, _command

            sessions[client] = {'command': command, 'request_size': request_size}
        else:
            session = sessions.get(client)
            if not session:
                # request not captured, drop its response
                continue
            if session.get('response_size'):
                session['response_size'] += len(pdata)
            else:
                session['response_size'] = len(pdata)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface')
    parser.add_argument('-p', '--port', type=int)
    args = parser.parse_args()

    fmt = '%.6f %-21s %8d %8d %s\n'
    for session in sniff(args.interface, args.port):
        ptime, client, req_size, resp_size, command = session
        sys.stdout.write(fmt % (ptime, client, req_size, resp_size, command))
        sys.stdout.flush()

if __name__ == '__main__':
    main()
