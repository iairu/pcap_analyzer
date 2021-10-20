"""
Communication sorting of frames:

TCP: HTTP, HTTPS, TELNET, SSH, FTP-CONTROL, FTP-DATA
TFTP
ICMP
ARP

"""

from _frame import Frame
from _reader import Protocols
from _byte import btoIPv4, btoi, delim
from _close import *



class SortComm:

    class SortableCommunication:
        def __init__(self, firstFrame: int, output: str):
            self._hash = firstFrame
            self.output = output
            return

        def __hash__(self) -> int:
            return self._hash

        def __lt__(self, _sortableFrame):
            return self._hash < hash(_sortableFrame)

    class SortableFrame:
        def __init__(self, ip_src: str, ip_dst: str, tcp_udp_icmp: str, protocol: str, frame: Frame):
            # Easily identify a given communication by equivalent hash
            # Hash is computed from a string of sorted IPs and a communication protocol

            ips = [ip_src, ip_dst]
            ips.sort()
            s = "|".join(ips)
            s += "|" + tcp_udp_icmp + "|" + protocol

            self._hash = hash(s)
            self.frame = frame
            return

        def __hash__(self) -> int:
            return self._hash

        def __lt__(self, _sortableFrame):
            return self._hash < hash(_sortableFrame)

    # ------------------------------------------

    def __init__(self, protocol: str, frames: list, protocols: Protocols, short: bool):

        # Sortable lists
        sorted_frames = [] # sorted frames for each communication, but communications in a random order
        self.sorted_communications = []

        # Building sortable lists using SortableFrame and commHash
        tftp_port = -1
        for f in frames: # all frames
            if not isinstance(f, Frame):
                continue

            # IPv4
            if (f.anal_ip != None and f.anal_t != None):
                # TCP or UDP
                if (f.anal_t.port_src != None and f.anal_t.port_dst != None):
                    ip_src = f.anal_ip.ip_src.hex()
                    ip_dst = f.anal_ip.ip_dst.hex()
                    port_src = f.anal_t.port_src
                    port_dst = f.anal_t.port_dst
                    tcp_udp_icmp = f.anal_t.protocol_str

                    # For TCP protocol
                    if (protocols.int_tcp(protocol) in [port_src, port_dst]):
                        sorted_frames.append(self.SortableFrame(ip_src, ip_dst, tcp_udp_icmp, protocol, f))

                    # UDP: TFTP switches matching port on new connection to source
                    if (protocol == "TFTP"):
                        if (protocols.int_udp(protocol) in [port_src, port_dst]):
                            tftp_port = port_src
                            sorted_frames.append(self.SortableFrame(ip_src, ip_dst, tcp_udp_icmp, protocol + str(tftp_port), f))
                        elif (tftp_port in [port_src, port_dst]):
                            sorted_frames.append(self.SortableFrame(ip_src, ip_dst, tcp_udp_icmp, protocol + str(tftp_port), f))
                        continue

                    # For UDP protocol
                    if (protocols.int_udp(protocol) in [port_src, port_dst]):
                        sorted_frames.append(self.SortableFrame(ip_src, ip_dst, tcp_udp_icmp, protocol, f))

                # Neither TCP nor UDP
                else:
                    # ICMP doesn't use TCP, UDP and doesn't have ports
                    if (protocol == "ICMP" and f.anal_t.protocol_str == "ICMP"):
                        ip_src = f.anal_ip.ip_src.hex()
                        ip_dst = f.anal_ip.ip_dst.hex()
                        sorted_frames.append(self.SortableFrame(ip_src, ip_dst, "ICMP", protocol, f))
            
            # Not IPv4
            else:
                    # ARP goes directly over ETH
                    if (protocol == "ARP" and f.anal.eth_type != None and protocols.str_eth_type(btoi(f.anal.eth_type)) == "ARP"):
                        eth_src = f.anal.eth_src.hex()
                        eth_dst = f.anal.eth_dst.hex()
                        sorted_frames.append(self.SortableFrame(eth_src, eth_dst, "ARP", protocol, f))




        # Sort frames into communications
        sorted_frames.sort()

        # Create output for communications
        last_hash = None
        count = 0
        out = ""
        server = ""
        client = ""
        first = -1 # for communication sorting
        from_server = 0
        from_client = 0
        for pair in sorted_frames:
            if not isinstance(pair, self.SortableFrame):
                continue

            # Frame in a communication
            f = pair.frame

            # Communication details for this frame
            if (f.anal_ip != None):
                ip_src = btoIPv4(f.anal_ip.ip_src)
                ip_dst = btoIPv4(f.anal_ip.ip_dst)
            else:
                ip_src = delim(f.anal.eth_src)
                ip_dst = delim(f.anal.eth_dst)

            if (f.anal_t != None):
                tcp_udp_icmp = f.anal_t.protocol_str
            else:
                tcp_udp_icmp = protocol
                
            port_src = ":" + str(f.anal_t.port_src) if (f.anal_t != None and f.anal_t.port_src != None) else ""
            port_dst = ":" + str(f.anal_t.port_dst) if (f.anal_t != None and f.anal_t.port_dst != None) else ""

            # Figure out if communication started/ended/continues
            curr_hash = hash(pair)

            if (last_hash != None and last_hash != curr_hash):
                # Previous ended
                out += f"{tcp_udp_icmp} communication between {ip_src} and {ip_dst} finished in {count} frames.\n"
                # out += f"Client was {client} with {from_client} requests.\n" # imprecise
                # out += f"Server was {server} with {from_server} responses.\n" # imprecise
                self.sorted_communications.append(self.SortableCommunication(first,out))

            if (last_hash == None or last_hash != curr_hash):
                # First or next communication started
                last_hash = curr_hash
                first = f.frame_no
                out = ""
                count = 1
                from_server = 0
                from_client = 0
            elif (last_hash == curr_hash):
                # Continuing
                count += 1
            
            # # Determine the server and count requests/responses
            # if (tcp_udp_icmp == "TCP" and port_src == protocols.int_tcp(protocol)) or (tcp_udp_icmp == "UDP" and port_src == protocols.int_udp(protocol)):
            #     if (count == 1):
            #         server = f"{ip_src}:{port_src}"
            #         client = f"{ip_dst}"
            #     from_server += 1
            # elif (tcp_udp_icmp == "TCP" and port_dst == protocols.int_tcp(protocol)) or (tcp_udp_icmp == "UDP" and port_dst == protocols.int_udp(protocol)):
            #     if (count == 1):
            #         server = f"{ip_dst}:{port_dst}"
            #         client = f"{ip_src}"
            #     from_client += 1

            # + Add some extra output
            if (not short):
                out += f"{count}: Frame #{f.frame_no} is {protocol} from {ip_src}{port_src} to {ip_dst}{port_dst}"
                if (protocol == "ICMP"):
                    out += f" - {f.anal_t.str_icmp(f.anal_t.type)}"
                out += "\n"

        if (count > 0):
            # Last ended (equivalent with Previous ended)
            if (f.anal_t != None):
                tcp_udp_icmp = f.anal_t.protocol_str
            else:
                tcp_udp_icmp = protocol
            out += f"{tcp_udp_icmp} communication between {ip_src} and {ip_dst} finished in {count} frames.\n"
            # out += f"Client was {client} with {from_client} requests.\n" # imprecise
            # out += f"Server was {server} with {from_server} responses.\n" # imprecise
            self.sorted_communications.append(self.SortableCommunication(first,out))

        # Sort communications
        self.sorted_communications.sort()

        # Ready for output :)
        return

    def output(self):
        self.print()
        return

    def print(self):
        for comm in self.sorted_communications:
            if not isinstance(comm, self.SortableCommunication):
                continue
            print(comm.output)
        return
