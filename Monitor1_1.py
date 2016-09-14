from operator import attrgetter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager
import socket
import struct
import time
import LPR_final


class SimpleMonitor(LPR_final.SimpleSwitch):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
	self.timestart = time.time()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x' % datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x' % datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
	    for dpid in range (9, 17):
	        if dpid in self.datapaths:
	            self._request_stats(self.datapaths[dpid])
	    hub.sleep(10)

    def _request_stats(self, datapath):
	end = time.time()
	timedif = float(end - self.timestart)
        print('send stats request: %016x @ %8.2f' % 
		(datapath.id, timedif))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

	req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
	end = time.time()
        timedif = float(end - self.timestart)
        print('datapath         port     '
              'rx-bytes(MB)    tx-bytes(MB)    time    ')
        print('---------------- -------- '
              '--------------- --------------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            print('%016x %8x %15.3f %15.3f %8.2f' %
                  (ev.msg.datapath.id, stat.port_no,
                   float(stat.rx_bytes)/(1024**2),
                   float(stat.tx_bytes)/(1024**2), timedif))
