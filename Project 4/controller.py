from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, lldp
import networkx as nx


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.data_paths = {}
        self.data_path_to_ports = {}
        self.network = nx.DiGraph()
        self.lldp_thread = hub.spawn(self.lldp_sender)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        data_path = ev.msg.datapath
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(of_proto.OFPP_CONTROLLER,
                                          of_proto.OFPCML_NO_BUFFER)]
        self.add_flow(data_path, 0, match, actions)

        # Install LLDP flow entry
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(of_proto.OFPP_CONTROLLER,
                                          of_proto.OFPCML_NO_BUFFER)]
        self.add_flow(data_path, 0, match, actions)

        # Request all ports' description
        self.request_ports(data_path)

    def add_flow(self, data_path, priority, match, actions, buffer_id=None):
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        inst = [parser.OFPInstructionActions(of_proto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=data_path, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=data_path, priority=priority,
                                    match=match, instructions=inst)
        data_path.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        data_path = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if data_path.id not in self.data_paths:
                self.logger.debug('register data path: %016x', data_path.id)
                self.data_paths[data_path.id] = data_path
                self.data_path_to_ports[data_path.id] = []
        elif ev.state == DEAD_DISPATCHER:
            if data_path.id in self.data_paths:
                self.logger.debug('unregister data path: %016x', data_path.id)
                del self.data_paths[data_path.id]
                del self.data_path_to_ports[data_path.id]
                data_path_id = str(data_path.id)
                if data_path_id in self.network:
                    for neighbor in self.network.adj[data_path_id]:
                        self.network.remove_edge(data_path_id, neighbor)

    @staticmethod
    def request_ports(data_path):
        """
        Send port description request to the switch
        :param data_path: the target switch
        :return: None
        """
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        req = parser.OFPPortDescStatsRequest(data_path, 0, of_proto.OFPP_ANY)
        data_path.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        """
        Collect all ports belong to the data path
        :param ev: received event
        :return: None
        """
        msg = ev.msg
        body = msg.body
        data_path = msg.datapath
        of_proto = data_path.ofproto

        for stat in body:
            if stat.port_no < of_proto.OFPP_MAX:
                self.data_path_to_ports[data_path.id].append((stat.port_no, stat.hw_addr))

    def lldp_sender(self):
        """
        Send LLDP every 5 seconds
        :return: None
        """
        while True:
            for data_path_id, data_path in self.data_paths.items():
                if data_path_id in self.data_path_to_ports:
                    port_no, hw_addr = self.data_path_to_ports[data_path_id]
                    self.send_lldp(data_path, port_no, hw_addr)
            hub.sleep(5)

    @staticmethod
    def send_lldp(data_path, port_no, hw_addr):
        ofp = data_path.ofproto
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP, src=hw_addr, dst=lldp.LLDP_MAC_NEAREST_BRIDGE))

        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(data_path.id))
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port_no))
        tlv_ttl = lldp.TTL(ttl=10)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()

        data = pkt.data
        parser = data_path.ofproto_parser
        actions = [parser.OFPActionOutput(port=port_no)]
        out = parser.OFPPacketOut(datapath=data_path, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        data_path.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        data_path = msg.datapath
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            if lldp_pkt:
                self.lldp_pkt_handler(data_path, in_port, lldp_pkt)
        else:
            self.normal_pkt_handler(data_path, msg, of_proto, parser, in_port, eth)

    def normal_pkt_handler(self, data_path, msg, of_proto, parser, in_port, eth):
        """
        Normal packet handler
        :return: None
        """
        dst = eth.dst
        src = eth.src
        data_path_id = str(data_path.id)

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(data_path_id, src, {'port': in_port})
            self.network.add_edge(src, data_path_id)

        if dst in self.network:
            path = nx.shortest_path(self.network, src, dst)
            next_hop = path[path.index(data_path_id) + 1]
            out_port = self.network[data_path_id][next_hop]['port']
        else:
            out_port = of_proto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != of_proto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != of_proto.OFP_NO_BUFFER:
                self.add_flow(data_path, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(data_path, 1, match, actions)
        data = None
        if msg.buffer_id == of_proto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=data_path, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        data_path.send_msg(out)

    def lldp_pkt_handler(self, data_path, in_port, lldp_pkt):
        """
        LLDP packet handler
        :return: None
        """
        sender_id = lldp_pkt.tlvs[0].chassis_id
        sender_port = lldp_pkt.tlvs[1].port_id
        receiver_id = str(data_path.id)
        receiver_port = in_port

        if sender_id not in self.network:
            self.network.add_node(sender_id)
        if receiver_id not in self.network:
            self.network.add_node(receiver_id)

        self.network.add_edge(sender_id, receiver_id, {'port': sender_port})
        self.network.add_edge(receiver_id, sender_id, {'port': receiver_port})
