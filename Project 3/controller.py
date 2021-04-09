from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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


class SimpleMonitor13(SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.data_paths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        data_path = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if data_path.id not in self.data_paths:
                self.logger.debug('register data path: %016x', data_path.id)
                self.data_paths[data_path.id] = data_path
        elif ev.state == DEAD_DISPATCHER:
            if data_path.id in self.data_paths:
                self.logger.debug('unregister data path: %016x', data_path.id)
                del self.data_paths[data_path.id]

    def monitor(self):
        """
        Send state request every 5 seconds
        :return: None
        """
        while True:
            for data_path in self.data_paths.values():
                self.request_states(data_path)
            hub.sleep(5)

    @staticmethod
    def request_states(data_path):
        """
        Send all port state request to the switch
        :param data_path: the target switch
        :return: None
        """
        of_proto = data_path.ofproto
        parser = data_path.ofproto_parser

        req = parser.OFPPortStatsRequest(data_path, 0, of_proto.OFPP_ANY)
        data_path.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('****************************')
        self.logger.info('Switch ID: %s', str(ev.msg.datapath.id).strip())
        self.logger.info(' Port No  Tx-Bytes  Rx-Bytes')
        self.logger.info('--------  --------  --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%8x  %8d  %8d',
                             stat.port_no, stat.rx_bytes, stat.tx_bytes)
        self.logger.info('')
        self.logger.info('Mac Address Table    Port No')
        self.logger.info('----------------------------')
        for mac, port in self.mac_to_port[format(ev.msg.datapath.id, "d").zfill(16)].items():
            self.logger.info('%s%11d', mac, port)
        self.logger.info('****************************\n')
