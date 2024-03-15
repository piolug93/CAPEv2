#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import errno
import grp
import json
import logging.handlers
import os
import re
import signal
import socket
import stat
import subprocess
import sys

if sys.version_info[:2] < (3, 8):
    sys.exit("You are running an incompatible version of Python, please use >= 3.8")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.exceptions import CuckooNetworkError
from lib.cuckoo.common.path_utils import path_delete, path_exists

username = False
log = logging.getLogger("cuckoo-rooter")
formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
log.addHandler(ch)
log.setLevel(logging.INFO)


class s:
    iptables = None
    iptables_save = None
    iptables_restore = None
    ip = None
    nft = None


def run(*args):
    """Wrapper to Popen."""
    log.debug("Running command: %s", " ".join(args))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    return stdout, stderr


def check_tuntap(vm_name, main_iface):
    """Create tuntap device for qemu vms"""
    try:
        run([s.ip, "tuntap", "add", "dev", f"tap_{vm_name}", "mode", "tap", "user", username])
        run([s.ip, "link", "set", "tap_{vm_name}", "master", main_iface])
        run([s.ip, "link", "set", "dev", "tap_{vm_name}", "up"])
        run([s.ip, "link", "set", "dev", main_iface, "up"])
        return True
    except subprocess.CalledProcessError:
        return False


def run_iptables(*args):
    iptables_args = [s.iptables]
    iptables_args.extend(list(args))
    iptables_args.extend(["-m", "comment", "--comment", "CAPE-rooter"])
    return run(*iptables_args)


def run_nft(*args):
    nft_args = [s.nft]
    nft_args.extend(["-ea"])
    nft_args.extend(list(args))
    return run(*nft_args)


def cleanup_rooter():
    """Filter out all CAPE rooter entries from iptables-save and
    restore the resulting ruleset."""
    if(s.iptables):
        _cleanup_rooter_ipt()
    else:
        _cleanup_rooter_nft()
        

def _cleanup_rooter_nft():
    run_nft("flush", "table", "cape_filter")
    run_nft("delete", "table", "cape_filter")
    chain, err = run_nft("list", "chain", "ip", "filter", "FORWARD")
    handlers = re.findall(r".*meta mark 0x00000f00 accept comment \"cape_filter\" # handle ([0-9]+)", chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "filter", "FORWARD", handle)
    run_nft("add", "table", "ip", "cape_filter")
    run_nft("add", "chain", "ip", "cape_filter", "forward", "{type filter hook forward priority 0;}")
    run_nft("add", "chain", "ip", "cape_filter", "input", "{type filter hook input priority 0;}")
    run_nft("add", "chain", "ip", "cape_filter", "postrouting", "{type nat hook postrouting priority 100;}")
    run_nft("add", "chain", "ip", "cape_filter", "prerouting", "{type nat hook prerouting priority -100;}")
    run_nft("add", "chain", "ip", "cape_filter", "output", "{type filter hook output priority 0;}")
    

def _cleanup_rooter_ipt():
    stdout = False
    try:
        stdout, _ = run(s.iptables_save)
    except OSError as e:
        log.error("Failed to clean CAPE rooter rules. Is iptables-save available? %s", e)
        return

    if not stdout:
        return

    cleaned = [line for line in stdout.split("\n") if line and "CAPE-rooter" not in line]

    p = subprocess.Popen([s.iptables_restore], stdin=subprocess.PIPE, universal_newlines=True)
    p.communicate(input="\n".join(cleaned))


def nic_available(interface):
    """Check if specified network interface is available."""
    try:
        subprocess.check_call(
            [settings.ip, "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call(
            [settings.ip, "route", "list", "table", rt_table],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def interface_with_network(srcip):
    """Check what interface in natwork same as ip."""
    try:
        output = subprocess.check_output([settings.ip, "route", "get", srcip])
        interface = re.search('(?<=(dev ))(\S+)', output.decode())[0]
        return interface
    except Exception:
        return False


def vpn_status(name):
    """Gets current VPN status."""
    ret = {}
    for line in run(settings.systemctl, "status", "openvpn@{}.service".format(name))[0].split("\n"):
        if "running" in line:
            ret[name] = "running"
            break

    return ret


def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    if(s.iptables):
        _forward_drop_ipt()
    else:
        _forward_drop_nft()
        
    
def _forward_drop_nft():
    run_nft("add", "chain", "ip", "cape_filter", "forward", "{type filter hook forward priority 0; policy drop;}")
    run_nft("insert", "rule", "ip", "filter", "FORWARD", "meta mark == 0x00000f00", "accept", "comment cape_filter") # need for pass LIBVIRT rules.

def _forward_drop_ipt():
    run_iptables("-P", "FORWARD", "DROP")


def state_enable():
    """Enable stateful connection tracking."""
    if(s.iptables):
        _state_enable_ipt()
    else:
        _state_enable_nft()
    

def _state_enable_nft():
    run_nft("add", "rule", "ip", "cape_filter", "input", "ct state", "established,related", "accept")


def _state_enable_ipt():
    run_iptables("-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")


def state_disable():
    """Disable stateful connection tracking."""
    if(s.iptables):
        _state_disable_ipt()
    else:
        _state_disable_nft()


def _state_disable_nft():
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "input")
    handlers = re.findall(r".*ct state established,related accept # handle ([0-9]+)", chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "input", handle)


def _state_disable_ipt():
    while True:
        _, err = run_iptables("-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        if err:
            break


def enable_nat(interface):
    """Enable NAT on this interface."""
    if(s.iptables):
        _enable_nat_ipt(**locals())
    else:
        _enable_nat_nft(**locals())
        

def _enable_nat_nft(interface):
    run_nft("add", "rule", "ip", "cape_filter", "postrouting", "oifname", interface, "masquerade")


def _enable_nat_ipt(interface):
    run_iptables("-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def disable_nat(interface):
    """Disable NAT on this interface."""
    if(s.iptables):
        _disable_nat_ipt(**locals())
    else:
        _disable_nat_nft(**locals())


def _disable_nat_nft(interface):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "postrouting")
    handlers = re.findall(r".*oifname \"{interface}\" masquerade # handle ([0-9]+)".format(interface=interface), chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "input", handle)


def _disable_nat_ipt(interface):
    run_iptables("-t", "nat", "-D", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ("local", "main", "default"):
        return

    stdout, _ = run(settings.ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(settings.ip, *args)


def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ("local", "main", "default"):
        return

    run(settings.ip, "route", "flush", "table", rt_table)


def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    if(s.iptables):
        _forward_enable_ipt(**locals())
    else:
        _forward_enable_nft(**locals())


def _forward_enable_nft(src, dst, ipaddr, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "forward")
    handlers = re.findall(r".*iifname \"{interface}\" reject # handle ([0-9]+)".format(interface=src), chain)
    handlers.extend(re.findall(r".*oifname \"{interface}\" reject # handle ([0-9]+)".format(interface=src), chain))
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "forward", handle)
    run_nft("add", "rule", "ip", "cape_filter", "forward", "ip saddr", ipaddr, "iifname", src, "oifname", dst, "meta mark set 0x00000f00", "accept")
    run_nft("add", "rule", "ip", "cape_filter", "forward", "ip daddr", ipaddr, "iifname", dst, "oifname", src, "meta mark set 0x00000f00", "accept")


def _forward_enable_ipt(src, dst, ipaddr, **kwargs):
    # Delete libvirt's default FORWARD REJECT rules. e.g.:
    # -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
    # -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
    run_iptables("-D", "FORWARD", "-i", src, "-j", "REJECT")
    run_iptables("-D", "FORWARD", "-o", src, "-j", "REJECT")
    run_iptables("-I", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "-j", "ACCEPT")
    run_iptables("-I", "FORWARD", "-i", dst, "-o", src, "--destination", ipaddr, "-j", "ACCEPT")


def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    if(s.iptables):
        _forward_disable_ipt(**locals())
    else:
        _forward_disable_nft(**locals())
        

def _forward_disable_nft(src, dst, ipaddr, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "forward")
    if not err:
        handlers = re.findall(r".*ip saddr {ipaddr} iifname \"{src}\" oifname \"{dst}\" meta mark 0x00000f00 accept # handle ([0-9]+)".format(ipaddr=ipaddr, src=src, dst=dst), chain)
        handlers.extend(re.findall(r".*ip daddr {ipaddr} iifname \"{dst}\" oifname \"{src}\" meta mark 0x00000f00 accept # handle ([0-9]+)".format(ipaddr=ipaddr, src=src, dst=dst), chain))
        for handle in handlers:
            run_nft("delete", "rule", "ip", "cape_filter", "forward", handle)


def _forward_disable_ipt(src, dst, ipaddr, **kwargs):
    run_iptables("-D", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "-j", "ACCEPT")
    run_iptables("-D", "FORWARD", "-i", dst, "-o", src, "--destination", ipaddr, "-j", "ACCEPT")


def forward_reject_enable(src, dst, ipaddr, reject_segments):
    """Enable forwarding a specific IP address from one interface into another
    but reject some targets network segments."""
    if(s.iptables):
        _forward_reject_enable_ipt(**locals())
    else:
        _forward_reject_enable_nft(**locals())
        
    
def _forward_reject_enable_nft(src, dst, ipaddr, reject_segments, **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "forward", "ip saddr", ipaddr, "ip daddr", reject_segments, "iifname", src, "oifname", dst, "reject")


def _forward_reject_enable_ipt(src, dst, ipaddr, reject_segments, **kwargs):
    run_iptables("-I", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "--destination", reject_segments, "-j", "REJECT")


def forward_reject_disable(src, dst, ipaddr, reject_segments):
    """Disable forwarding a specific IP address from one interface into another
    but reject some targets network segments."""
    if(s.iptables):
        _forward_reject_disable_ipt(**locals())
    else:
        _forward_reject_disable_nft(**locals())
        

def _forward_reject_disable_nft(src, dst, ipaddr, reject_segments, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "forward")
    handlers = re.findall(r".*ip saddr {ipaddr} ip daddr {reject_segments} iifname \"{src}\" oifname \"{dst}\" reject # handle ([0-9]+)".format(ipaddr=ipaddr, reject_segments=reject_segments, src=src, dst=dst), chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "forward", handle)


def _forward_reject_disable_ipt(src, dst, ipaddr, reject_segments, **kwargs):
    run_iptables("-D", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "--destination", reject_segments, "-j", "REJECT")


def hostports_reject_enable(src, ipaddr, reject_hostports):
    """Enable drop a specific IP address from one interface to host ports."""
    if(s.iptables):
        _hostports_reject_enable_ipt(**locals())
    else:
        _hostports_reject_enable_nft(**locals())
        
    
def _hostports_reject_enable_nft(src, ipaddr, reject_hostports, **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "input", "ip saddr", ipaddr, "tcp dport {", reject_hostports, "} iifname", src, "reject")
    run_nft("add", "rule", "ip", "cape_filter", "input", "ip saddr", ipaddr, "udp dport {", reject_hostports, "} iifname", src, "reject")


def _hostports_reject_enable_ipt(src, ipaddr, reject_hostports, **kwargs):
    run_iptables(
        "-A", "INPUT", "-i", src, "--source", ipaddr, "-p", "tcp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )
    run_iptables(
        "-A", "INPUT", "-i", src, "--source", ipaddr, "-p", "udp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )


def hostports_reject_disable(src, ipaddr, reject_hostports):
    """Disable drop a specific IP address from one interface to host ports."""
    if(s.iptables):
        _hostports_reject_disable_ipt(**locals())
    else:
        _hostports_reject_disable_nft(**locals())
        

def _hostports_reject_disable_nft(src, ipaddr, reject_hostports, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "input")
    handlers = re.findall(r".*ip saddr {ipaddr} (?:tcp|udp) dport {reject_hostports} iifname \"{src}\" reject # handle ([0-9]+)".format(ipaddr=ipaddr, reject_hostports=reject_hostports, src=src), chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "input", handle)


def _hostports_reject_disable_ipt(src, ipaddr, reject_hostports, **kwargs):
    run_iptables(
        "-D", "INPUT", "-i", src, "--source", ipaddr, "-p", "tcp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )
    run_iptables(
        "-D", "INPUT", "-i", src, "--source", ipaddr, "-p", "udp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )


def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(settings.ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")


def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(settings.ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")


def dns_forward(action, vm_ip, dns_ip, dns_port="53"):
    """Route DNS requests from the VM to a custom DNS on a separate network."""
    if(s.iptables):
        _dns_forward_ipt(**locals())
    else:
        _dns_forward_nft(**locals())


def _dns_forward_nft(action, vm_ip, dns_ip, dns_port="53", **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", vm_ip, "tcp dport", "53", "dnat to", f"{dns_ip}:{dns_port}")
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", vm_ip, "udp dport", "53", "dnat to", f"{dns_ip}:{dns_port}")


def _dns_forward_ipt(action, vm_ip, dns_ip, dns_port="53", **kwargs):
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        "53",
        "--source",
        vm_ip,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (dns_ip, dns_port),
    )

    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "-p",
        "udp",
        "--dport",
        "53",
        "--source",
        vm_ip,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (dns_ip, dns_port),
    )

def inetsim_redirect_port(action, srcip, dstip, ports):
    """Note that the parameters (probably) mean the opposite of what they
    imply; this method adds or removes an iptables rule for redirect traffic
    from (srcip, srcport) to (dstip, dstport).
    E.g., if 192.168.56.101:80 -> 192.168.56.1:8080, then it redirects
    outgoing traffic from 192.168.56.101 to port 80 to 192.168.56.1:8080.
    """
    for entry in ports.split():
        if entry.count(":") != 1:
            log.debug("Invalid inetsim ports entry: %s", entry)
            continue
        srcport, dstport = entry.split(":")
        if not dstport.isdigit():
            log.debug("Invalid inetsim dstport entry: %s", dstport)
            continue

        # Handle srcport ranges
        if "-" in srcport:
            # We need a single hyphen to indicate that it is a range
            if srcport.count("-") != 1:
                log.debug("Invalid inetsim srcport range entry: %s", srcport)
                continue
            else:
                start_srcport, end_srcport = srcport.split("-")
                if not start_srcport.isdigit() or not end_srcport.isdigit() or start_srcport > end_srcport:
                    log.debug("Invalid inetsim srcport range entry: %s", srcport)
                    continue
                else:
                    if(s.iptables):
                    # Good to go! iptables takes port ranges as start:end
                        srcport = srcport.replace("-", ":")

        # Handle a single srcport
        else:
            if not srcport.isdigit():
                log.debug("Invalid inetsim srcport entry: %s", srcport)
                continue

        if(s.iptables):
            _inetsim_redirect_port_ipt(**locals())
        else:
            _inetsim_redirect_port_nft(**locals())
        

def _inetsim_redirect_port_nft(action, srcip, dstip, srcport, dstport, **kwargs):
    if(action == "-A"):
        run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", srcip, "tcp dport", srcport, "tcp flags", "syn", "dnat to", f"{dstip}:{dstport}")
    if(action == "-D"):
        chain, err = run_nft("list", "chain", "ip", "cape_filter", "prerouting")
        handlers = re.findall(r".*ip saddr {srcip} tcp dport {srcport} tcp flags syn dnat to {dstip}:{dstport} # handle ([0-9]+)".format(srcip=srcip, srcport=srcport, dstip=dstip, dstport=dstport), chain)
        for handle in handlers:
            run_nft("delete", "rule", "ip", "cape_filter", "prerouting", handle)


def _inetsim_redirect_port_ipt(action, srcip, dstip, srcport, dstport, **kwargs):
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        srcip,
        "-p",
        "tcp",
        "--syn",
        "--dport",
        srcport,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (dstip, dstport),
    )


def inetsim_service_port_trap(action, srcip, dstip, protocol):
    # Note that the multiport limit for ports specified is 15,
    # so we will split this up into two rules
    if(s.iptables):
        _inetsim_service_port_trap_ipt(**locals())
    else:
        _inetsim_service_port_trap_nft(**locals())
        

def _inetsim_service_port_trap_nft(action, srcip, dstip, protocol, **kwargs):
    if(action == '-A'):
        run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", srcip, protocol, "dport {7,9,13,17,19,21,22,25,37,69,79,80,110,113,123,443,465,514,990,995,6667}", "dnat to", dstip)
    if(action == "-D"):
        chain, err = run_nft("list", "chain", "ip", "cape_filter", "prerouting")
        handlers = re.findall(r".*ip saddr {srcip} {protocol} dport {7,9,13,17,19,21,22,25,37,69,79,80,110,113,123,443,465,514,990,995,6667} dnat to {dstip} # handle ([0-9]+)".format(srcip=srcip, protocol=protocol, dstip=dstip), chain)
        for handle in handlers:
            run_nft("delete", "rule", "ip", "cape_filter", "prerouting", handle)


def _inetsim_service_port_trap_ipt(action, srcip, dstip, protocol, **kwargs):
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        srcip,
        "-p",
        protocol,
        "-m",
        "multiport",
        "--dports",
        # The following ports are used for default services on Ubuntu
        "7,9,13,17,19,21,22,25,37,69,79,80,110,113",
        "-j",
        "DNAT",
        "--to-destination",
        dstip,
    )
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        srcip,
        "-p",
        protocol,
        "-m",
        "multiport",
        "--dports",
        # The following ports are used for default services on Ubuntu
        "123,443,465,514,990,995,6667",
        "-j",
        "DNAT",
        "--to-destination",
        dstip,
    )


def inetsim_trap(action, ipaddr, inetsim_ip, resultserver_port):
    # There are four options for protocol in iptables: tcp, udp, icmp and all
    # Since we want tcp, udp and icmp to be configured differently, we cannot use all
    # tcp
    if(s.iptables):
        _inetsim_trap_ipt(**locals())
    else:
        _inetsim_trap_nft(**locals())
    

def _inetsim_trap_nft(action, ipaddr, inetsim_ip, resultserver_port, **kwargs):
    if(action == "-A"):
        run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "tcp dport !=", resultserver_port, "tcp flags", "syn", "dnat to", f"{inetsim_ip}:1")
        run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "udp dport !=", resultserver_port, "tcp flags", "syn", "dnat to", f"{inetsim_ip}:1")
        run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "icmp", "dnat to", f"{inetsim_ip}:1")
    if(action == "-D"):
        chain, err = run_nft("list", "chain", "ip", "cape_filter", "prerouting")
        handlers = re.findall(r".*ip saddr {ipaddr} (?:tcp|udp) dport != {resultserver_port} tcp flags syn dnat to {inetsim_ip}:1 # handle ([0-9]+)".format(ipaddr=ipaddr, resultserver_port=resultserver_port, inetsim_ip=inetsim_ip), chain)
        handlers.extend(re.findall(r".*ip saddr {ipaddr} icmp dnat to {inetsim_ip}:1 # handle ([0-9]+)".format(ipaddr=ipaddr, inetsim_ip=inetsim_ip), chain))
        for handle in handlers:
            run_nft("delete", "rule", "ip", "cape_filter", "prerouting", handle)


def _inetsim_trap_ipt(action, ipaddr, inetsim_ip, resultserver_port, **kwargs):
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )
    # udp
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "udp",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )
    # icmp
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "icmp",
        "--icmp-type",
        "any",
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )


def inetsim_enable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Enable hijacking of all traffic and send it to InetSIM."""
    log.info("Enabling inetsim route.")
    if(re.match(r"127\..*", inetsim_ip)):
        interface = interface_with_network(ipaddr)
        with open(f"/proc/sys/net/ipv4/conf/{interface}/route_localnet") as f:
            if(not int(f.read())):
                raise CuckooNetworkError(f"When redirect to localhost need set route_localnet=1 on interface {interface}")
    inetsim_redirect_port("-A", ipaddr, inetsim_ip, ports)
    inetsim_service_port_trap("-A", ipaddr, inetsim_ip, "tcp")
    inetsim_service_port_trap("-A", ipaddr, inetsim_ip, "udp")
    dns_forward("-A", ipaddr, inetsim_ip, dns_port)
    inetsim_trap("-A", ipaddr, inetsim_ip, resultserver_port)
    # INetSim does not have an SSH service, so SSH traffic can get through to the host. We want to block this.
    if(s.iptables):
        _inetsim_enable_ipt(**locals())
    else:
        _inetsim_enable_nft(**locals())


def _inetsim_enable_nft(ipaddr, inetsim_ip, dns_port, resultserver_port, ports, **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "input", "ip saddr", ipaddr, "tcp dport", "22", "drop")
    run_nft("add", "rule", "ip", "cape_filter", "output", "ct state", "invalid", "drop")
    run_nft("add", "rule", "ip", "cape_filter", "output", "ip saddr", ipaddr, "drop")


def _inetsim_enable_ipt(ipaddr, inetsim_ip, dns_port, resultserver_port, ports, **kwargs):
    run_iptables("-A", "INPUT", "--source", ipaddr, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def inetsim_disable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Disable hijacking of all traffic and send it to InetSIM."""
    log.info("Disabling inetsim route.")
    inetsim_redirect_port("-D", ipaddr, inetsim_ip, ports)
    inetsim_service_port_trap("-D", ipaddr, inetsim_ip, "tcp")
    inetsim_service_port_trap("-D", ipaddr, inetsim_ip, "udp")
    dns_forward("-D", ipaddr, inetsim_ip, dns_port)
    inetsim_trap("-D", ipaddr, inetsim_ip, resultserver_port)
    if(s.iptables):
        _inetsim_disable_ipt(**locals())
    else:
        _inetsim_disable_nft(**locals())
        

def _inetsim_disable_nft(ipaddr, inetsim_ip, dns_port, resultserver_port, ports, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "input")
    handlers = re.findall(r".*ip saddr {ipaddr} tcp dport 22 drop # handle ([0-9]+)".format(ipaddr=ipaddr), chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "input", handle)
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "output")
    handlers = re.findall(r".*ct state invalid drop # handle ([0-9]+)".format(ipaddr=ipaddr), chain)
    handlers.extend(re.findall(r".*ip saddr {ipaddr} drop # handle ([0-9]+)".format(ipaddr=ipaddr), chain))
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "output", handle)


def _inetsim_disable_ipt(ipaddr, inetsim_ip, dns_port, resultserver_port, ports, **kwargs):
    run_iptables("-D", "INPUT", "--source", ipaddr, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def socks5_enable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to socks5."""
    log.info("Enabling socks route.")
    if(s.iptables):
        _socks5_enable_ipt(**locals())
    else:
        _socks5_enable_nft(**locals())


def _socks5_enable_nft(ipaddr, resultserver_port, dns_port, proxy_port, **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "tcp flags", "syn", "tcp dport !=", resultserver_port, "redirect to", proxy_port)
    run_nft("insert", "rule", "ip", "cape_filter", "output", "ct state", "invalid", "drop")
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "tcp dport", "53", "redirect to", dns_port)
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "udp dport", "53", "redirect to", dns_port)
    run_nft("add", "rule", "ip", "cape_filter", "output", "ip saddr", ipaddr, "drop")


def _socks5_enable_ipt(ipaddr, resultserver_port, dns_port, proxy_port, **kwargs):
    run_iptables(
        "-t",
        "nat",
        "-I",
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "REDIRECT",
        "--to-ports",
        proxy_port,
    )
    run_iptables("-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-I", "OUTPUT", "2", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables(
        "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables(
        "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables("-A", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def socks5_disable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to socks5."""
    log.info("Disabling socks route.")
    if(s.iptables):
        _socks5_disable_ipt(**locals())
    else:
        _socks5_disable_nft(**locals())


def _socks5_disable_nft(ipaddr, resultserver_port, dns_port, proxy_port, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "prerouting")
    handlers = re.findall(r".*ip saddr {ipaddr} tcp flags syn tcp dport != {resultserver_port} redirect to {proxy_port} # handle ([0-9]+)".format(ipaddr=ipaddr, resultserver_port=resultserver_port, proxy_port=proxy_port), chain)
    handlers.extend(re.findall(r".*ip saddr {ipaddr} (?:tcp|udp) dport 53 redirect to {dns_port} # handle ([0-9]+)".format(ipaddr=ipaddr, dns_port=dns_port), chain))
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "prerouting", handle)
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "output")
    handlers = re.findall(r".*ct state invalid drop # handle ([0-9]+)", chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "output", handle)


def _socks5_disable_ipt(ipaddr, resultserver_port, dns_port, proxy_port, **kwargs):
    run_iptables(
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "REDIRECT",
        "--to-ports",
        proxy_port,
    )
    run_iptables("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def drop_enable(ipaddr, resultserver_port):
    if(s.iptables):
        _drop_enable_ipt(**locals())
    else:
        _drop_enable_nft(**locals())


def _drop_enable_nft(ipaddr, resultserver_port, **kwargs):
    run_nft("add", "rule", "ip", "cape_filter", "prerouting", "ip saddr", ipaddr, "tcp flags", "syn", "tcp dport", resultserver_port, "accept")
    run_nft("add", "rule", "ip", "cape_filter", "input", "ip daddr", ipaddr, "tcp dport", "8000", "accept")
    run_nft("add", "rule", "ip", "cape_filter", "input", "ip daddr", ipaddr, "tcp sport", resultserver_port, "accept")
    run_nft("add", "rule", "ip", "cape_filter", "output", "ip daddr", ipaddr, "tcp dport", "8000", "accept")
    run_nft("add", "rule", "ip", "cape_filter", "output", "ip daddr", ipaddr, "tcp sport", resultserver_port, "accept")
    run_nft("add", "rule", "ip", "cape_filter", "output", "ip daddr", ipaddr, "drop")


def _drop_enable_ipt(ipaddr, resultserver_port, **kwargs):
    run_iptables(
        "-t", "nat", "-I", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT"
    )
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    # run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "LOG")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "DROP")


def drop_disable(ipaddr, resultserver_port):
    if(s.iptables):
        _drop_disable_ipt(**locals())
    else:
        _drop_disable_nft(**locals())


def _drop_disable_nft(ipaddr, resultserver_port, **kwargs):
    chain, err = run_nft("list", "chain", "ip", "cape_filter", "prerouting")
    handlers = re.findall(r".*ip saddr {ipaddr} tcp flags syn tcp dport {resultserver_port} accept # handle ([0-9]+)".format(ipaddr=ipaddr, resultserver_port=resultserver_port), chain)
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "prerouting", handle)

    chain, err = run_nft("list", "chain", "ip", "cape_filter", "input")
    handlers = re.findall(r".*ip daddr {ipaddr} tcp sport {resultserver_port} accept # handle ([0-9]+)".format(ipaddr=ipaddr, resultserver_port=resultserver_port), chain)
    handlers.extend(re.findall(r".*ip daddr {ipaddr} tcp dport 8000 accept # handle ([0-9]+)".format(ipaddr=ipaddr), chain))
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "input", handle)

    chain, err = run_nft("list", "chain", "ip", "cape_filter", "output")
    handlers = re.findall(r".*ip daddr {ipaddr} tcp sport {resultserver_port} accept # handle ([0-9]+)".format(ipaddr=ipaddr, resultserver_port=resultserver_port), chain)
    handlers.extend(re.findall(r".*ip daddr {ipaddr} tcp dport 8000 accept # handle ([0-9]+)".format(ipaddr=ipaddr), chain))
    handlers.extend(re.findall(r".*ip daddr {ipaddr} drop # handle ([0-9]+)".format(ipaddr=ipaddr), chain))
    for handle in handlers:
        run_nft("delete", "rule", "ip", "cape_filter", "output", handle)


def _drop_disable_ipt(ipaddr, resultserver_port, **kwargs):
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT"
    )
    run_iptables("-D", "INPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-D", "INPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    # run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-j", "LOG")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-j", "DROP")


handlers = {
    "nic_available": nic_available,
    "rt_available": rt_available,
    "vpn_status": vpn_status,
    "forward_drop": forward_drop,
    "state_enable": state_enable,
    "state_disable": state_disable,
    "enable_nat": enable_nat,
    "disable_nat": disable_nat,
    "init_rttable": init_rttable,
    "flush_rttable": flush_rttable,
    "forward_enable": forward_enable,
    "forward_disable": forward_disable,
    "forward_reject_enable": forward_reject_enable,
    "forward_reject_disable": forward_reject_disable,
    "hostports_reject_enable": hostports_reject_enable,
    "hostports_reject_disable": hostports_reject_disable,
    "srcroute_enable": srcroute_enable,
    "srcroute_disable": srcroute_disable,
    "inetsim_enable": inetsim_enable,
    "inetsim_disable": inetsim_disable,
    "socks5_enable": socks5_enable,
    "socks5_disable": socks5_disable,
    "drop_enable": drop_enable,
    "drop_disable": drop_disable,
    "cleanup_rooter": cleanup_rooter,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cape", help="Unix socket group")
    parser.add_argument("--systemctl", default="/bin/systemctl", help="Systemctl wrapper script for invoking OpenVPN")
    parser.add_argument("--iptables", default="/sbin/iptables", help="Path to iptables")
    parser.add_argument("--iptables-save", default="/sbin/iptables-save", help="Path to iptables-save")
    parser.add_argument("--iptables-restore", default="/sbin/iptables-restore", help="Path to iptables-restore")
    parser.add_argument("--ip", default="/sbin/ip", help="Path to ip")
    parser.add_argument("--nft", default="/sbin/nft", help="Path to nftables binary")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--legacy", action="store_true", help="Switch to use iptables")
    settings = parser.parse_args()

    if settings.verbose:
        # Verbose logging is not only controlled by the level. Some INFO logs are also
        # conditional (like here).
        log.setLevel(logging.DEBUG)
        log.info("Verbose logging enabled")

    if not settings.systemctl or not path_exists(settings.systemctl):
        sys.exit(
            "The systemctl binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --systemctl /bin/systemctl, "
            "rather than using the Ubuntu/Debian default /bin/systemctl."
        )

    if settings.legacy and (not settings.iptables or not path_exists(settings.iptables)):
        sys.exit("The `iptables` binary is not available, eh?!")

    if not settings.legacy and (not settings.nft or not path_exists(settings.nft)):
        sys.exit("The `nft` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if path_exists(settings.socket):
        path_delete(settings.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(settings.socket)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(settings.group)
    except KeyError:
        sys.exit(
            "The group (`%s`) does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "./utils/rooter.py -g myuser" % settings.group
        )

    # global username
    username = settings.group
    os.chown(settings.socket, 0, gr.gr_gid)
    os.chmod(settings.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    # Initialize global variables.
    if settings.legacy:
        s.iptables = settings.iptables
        s.iptables_save = settings.iptables_save
        s.iptables_restore = settings.iptables_restore
    else:
        s.nft = settings.nft
    s.ip = settings.ip
    

    # Simple object to allow a signal handler to stop the rooter loop

    class Run:
        def __init__(self):
            self.run = True

    do = Run()

    def handle_sigterm(sig, f):
        do.run = False
        server.shutdown(socket.SHUT_RDWR)
        server.close()
        cleanup_rooter()

    signal.signal(signal.SIGTERM, handle_sigterm)
    while do.run:
        try:
            command, addr = server.recvfrom(4096)
        except socket.error as e:
            if not do.run:
                # When the signal handler shuts the server down, do.run is False and
                # server.recvfrom raises an exception. Ignore that exception and exit.
                break
            if e.errno == errno.EINTR:
                continue
            raise e

        try:
            obj = json.loads(command)
        except Exception:
            log.info("Received invalid request: %r", command)
            continue

        command = obj.get("command")
        args = obj.get("args", [])
        kwargs = obj.get("kwargs", {})

        if not isinstance(command, str) or command not in handlers:
            log.warning("Received incorrect command: %r", command)
            continue

        if not isinstance(args, (tuple, list)):
            log.warning("Invalid arguments type: %r", args)
            continue

        if not isinstance(kwargs, dict):
            log.warning("Invalid keyword arguments: %r", kwargs)
            continue

        for arg in args + list(kwargs.keys()) + list(kwargs.values()):
            if not isinstance(arg, str):
                log.warning("Invalid argument type detected: %r (%s)", arg, type(arg))
                break
        else:
            if settings.verbose:
                log.info(
                    "Processing command: %s %s %s", command, " ".join(args), " ".join("%s=%s" % (k, v) for k, v in kwargs.items())
                )

            error = None
            output = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command: {}".format(command))
                error = str(e)
            server.sendto(
                json.dumps(
                    {
                        "output": output,
                        "exception": error,
                    }
                ).encode(),
                addr,
            )
