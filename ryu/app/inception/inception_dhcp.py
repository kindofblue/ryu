"""
Inception Cloud DHCP module
"""
import logging

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.app.inception import priority

LOGGER = logging.getLogger(__name__)


class InceptionDhcp(object):
    """
    Inception Cloud DHCP module for handling DHCP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # IP address -> MAC address: mapping from IP address to MAC address
        # of end hosts for address resolution
        self.ip_to_mac = {}
        # the switch to which DHCP server connects
        self.server_switch = None
        # the port of switch on which DHCP server connects
        self.server_port = None

    def update_server(self, switch, port):
        if self.server_port is not None and self.server_switch is not None:
            LOGGER.warning("More than one DHCP server!")
            return
        self.server_switch = switch
        self.server_port = port

    def handle(self, event):
        # process only if it is DHCP packet
        msg = event.msg
        whole_packet = packet.Packet(msg.data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        if ethernet_header.ethertype != ether.ETH_TYPE_IP:
            LOGGER.info("This is not an DHCP packet")
            return
        ip_header = whole_packet.get_protocol(ipv4.ipv4)
        if ip_header.proto != inet.IPPROTO_UDP:
            LOGGER.info("This is not an DHCP packet")
            return
        udp_header = whole_packet.get_protocol(udp.udp);
        if udp_header.src_port not in [68, 67]:
            LOGGER.info("This is not an DHCP packet")
            return

        LOGGER.info("Handle DHCP packet")
        dhcp_header = whole_packet.get_protocol(dhcp.dhcp)
        if self.server_switch is None or self.server_port is None:
            LOGGER.warning("No DHCP server has been found!")
            return
        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_header.src_port == 68:
            LOGGER.info("Forward DHCP message to DHCP server at switch=%s "
                        "port=%s", dpid_to_str(self.server_switch),
                        self.server_port)
            # get DHCP server datapath
            datapath = self.inception.dpset.get(self.server_switch)
            action_out = [ datapath.ofproto_parser.OFPActionOutput(self.server_port) ]
            msg = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                       buffer_id=0xffffffff,
                                                       in_port=datapath.ofproto.OFPP_LOCAL,
                                                       data=msg.data,
                                                       actions=action_out)
            datapath.send_msg(msg)

        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_header.src_port == 67:
            LOGGER.info("Forward DHCP message to client=%s",
                                        dhcp_header.chaddr)
            dpid, port = self.inception.mac_to_dpid_port[dhcp_header.chaddr]
            datapath = self.inception.dpset.get(dpid)
            action_out = [ datapath.ofproto_parser.OFPActionOutput(port) ]
            msg = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                       buffer_id=0xffffffff,
                                                       in_port=ofproto.OFPP_LOCAL,
                                                       data=msg.data,
                                                       actions=action_out)
            datapath.send_msg(msg)
