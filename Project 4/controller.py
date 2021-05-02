from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types
import networkx as nx


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        data_path_id = format(data_path.id, "d").zfill(16)
        self.mac_to_port.setdefault(data_path_id, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[data_path_id][src] = in_port

        if dst in self.mac_to_port[data_path_id]:
            out_port = self.mac_to_port[data_path_id][dst]
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
