# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from IPy import IP

import sys
import pymysql.cursors
connection = pymysql.connect(
    host='localhost',
    user='guest',
    password='110010',
    db='AUDB',
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor)

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, table_id, priority, match, inst, buffer_id=None, idle_timeout=0, hard_timeout=0, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    table_id=table_id, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    flags=flags)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    flags=flags)
        datapath.send_msg(mod)
     

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.logger.info("%s connect estiblished", ev.dp.id)

            ofproto = ev.dp.ofproto
            parser = ev.dp.ofproto_parser
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            #add flow: send to controller if match no rule
            for t_id in [1, 2, 3]:
                self.add_flow(ev.dp, t_id, 0, None, inst, None)

            #add flow: arp packet go to table 0
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

            #add flow: dhcp packet go to table 0
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_src=67, udp_dst=68)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_src=68, udp_dst=67)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

            #add flow: dns packet go to table 0
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_src=53)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_dst=53)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

            #add flow: login page go to table 0
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP, ip_src="10.0.2.9", tcp_src=8080)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP, ip_dst="10.0.2.9", tcp_dst=8080)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

            #add flow: ecn=1 packet go to table 0
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_ecn=1)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

            #add flow: go to table 3 if match no rule
            inst = [parser.OFPInstructionGotoTable(2)]
            self.add_flow(ev.dp, 0, 0, None, inst, None)
            
            #add flow: drop LLDP and IPV6 
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[])]
            self.add_flow(ev.dp, 0, 1, match, inst, None)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[])]
            self.add_flow(ev.dp, 0, 1, match, inst, None)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        self.logger.info("delete flow %s", msg.match['eth_src'])
        query = ("""DELETE FROM macpool WHERE mac = %d;""" % int(msg.match['eth_src'].replace(":", ""), 16))
        with connection.cursor() as cursor:
            cursor.execute(query)
            #cursor.commit()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        tb_id = msg.table_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %d %s %s %s %x", dpid, tb_id, src, dst, in_port, eth.ethertype)

        auth_result = 0
        role_result = 5
        if (tb_id == 2) or (tb_id == 3):
            dst_ip = pkt.get_protocol(ipv4.ipv4).dst
            mac_int = int(src.replace(":", ""), 16)
            query = ("""SELECT * FROM macpool WHERE mac = %s;""" % mac_int)
            with connection.cursor() as cursor:
                cursor.execute(query)
                res = cursor.fetchone()
                if not res: # if not in macpool drop
                    match = parser.OFPMatch(eth_src=src)
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[]), parser.OFPInstructionGotoTable(4)]
                    self.add_flow(datapath, 2, 1, match, inst, msg.buffer_id, idle_timeout=30)
                    return
                else:
                    auth_result = int(dst_ip.split('.')[0])
                    role_result = int(res['role'])
                    match = parser.OFPMatch(eth_src=src)
                    inst = [parser.OFPInstructionWriteMetadata(role_result, 0xf), parser.OFPInstructionGotoTable(3)]
                    if role_result==2:
                        hard_timeout=30
                        idle_timeout=0
                    else:
                        hard_timeout=0
                        idle_timeout=30
                        
                    self.add_flow(datapath, 2, 2, match, inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, flags=ofproto.OFPFF_SEND_FLOW_REM)
                    
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if (tb_id == 1):
            inst = inst + [parser.OFPInstructionGotoTable(4)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, 1, match, inst, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, 1, match, inst)
        
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        
        if (tb_id == 2) or (tb_id == 3): 
            if auth_result == 10 or auth_result == 192 or auth_result == 172: #private
                if role_result == 0:
                    actions = [parser.OFPActionSetField(ip_ecn=1)] + actions
                else:
                    actions = []
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst, metadata=role_result)
                self.add_flow(datapath, 3, 1, match, inst, idle_timeout=30)
            
            if auth_result != 10 and auth_result != 192 and auth_result != 172:              
                match = parser.OFPMatch(eth_dst=src, metadata=3)
                act = [parser.OFPActionOutput(in_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, act)]

                self.add_flow(datapath, 3, 1, match, inst, idle_timeout=30)
                
                match = parser.OFPMatch(eth_src=dst)
                inst = [parser.OFPInstructionWriteMetadata(3, 0xf), parser.OFPInstructionGotoTable(3)]

                self.add_flow(datapath, 2, 1, match, inst, idle_timeout=30)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)