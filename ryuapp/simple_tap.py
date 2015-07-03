# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.topology.api import get_switch

import ryu.app.ofctl.api


class SimpleTap(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleTap, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.snort = kwargs['snortlib']
        self.network_a = 2
        self.network_b = 4

        self.monitor_a = 6
        self.monitor_b = 8

        self.monitor_tcp = 10
        self.monitor_udp = 12

        self.monitor_ab = 14

        socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg

        # Get all dpid from switches
        sw_dpid = [s.dp.id for s in get_switch(self.topology_api_app, None)]

        # Get datapath by dpid
        datapath = ryu.app.ofctl.api.get_datapath(self.topology_api_app,
                                                  sw_dpid[0])

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Use datapath to do OFPFlowMod DROP action here

        print('alertmsg: %s' % ''.join(msg.alertmsg))
        self.packet_print(msg.pkt)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)

        # Table 0 match packets coming in network port A forward to:
        # 1) network port B
        # 2) monitor port A
        # 3) monitor port AB
        match_port_a = parser.OFPMatch(in_port=self.network_a)
        actions_b_ma_mab = [parser.OFPActionOutput(self.network_b),
                            parser.OFPActionOutput(self.monitor_a),
                            parser.OFPActionOutput(self.monitor_ab)]
        self.add_flow_gototable(datapath, 0, 10,
                                match_port_a, actions_b_ma_mab)

        # Table 0 match packets coming in network port B forward to:
        # 1) network port A
        # 2) monitor port B
        # 3) monitor port AB
        match_port_b = parser.OFPMatch(in_port=self.network_b)
        actions_a_mb_mab = [parser.OFPActionOutput(self.network_a),
                            parser.OFPActionOutput(self.monitor_b),
                            parser.OFPActionOutput(self.monitor_ab)]
        self.add_flow_gototable(datapath, 0, 10,
                                match_port_b, actions_a_mb_mab)

        # Table 1 match TCP packets in network port A forward to:
        # monitor port TCP
        match_port_a = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ip_proto=inet.IPPROTO_TCP,
                                       in_port=self.network_a)
        actions_mtcp = [parser.OFPActionOutput(self.monitor_tcp)]
        self.add_flow(datapath, 1, 10, match_port_a, actions_mtcp)

        # Table 1 match TCP packets in network port B forward to:
        # monitor port TCP
        match_port_b = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ip_proto=inet.IPPROTO_TCP,
                                       in_port=self.network_b)
        self.add_flow(datapath, 1, 10, match_port_b, actions_mtcp)

        # Table 1 match UDP packets in network port A forward to:
        # monitor port UDP
        match_port_a = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ip_proto=inet.IPPROTO_UDP,
                                       in_port=self.network_a)
        actions_mudp = [parser.OFPActionOutput(self.monitor_udp)]
        self.add_flow(datapath, 1, 10, match_port_a, actions_mudp)

        # Table 1 match UDP packets in network port B forward to:
        # monitor port UDP
        match_port_b = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ip_proto=inet.IPPROTO_UDP,
                                       in_port=self.network_b)
        self.add_flow(datapath, 1, 10, match_port_b, actions_mudp)

    def add_flow(self, datapath, table_id, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def add_flow_gototable(self, datapath, table_id, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions),
                parser.OFPInstructionGotoTable(1)]

        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        pass
