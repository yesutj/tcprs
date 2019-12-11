# This file was automatically generated by bifcl from /usr/local/tcprs/src/tcprs.bif (plugin mode).

##! Bif file for TCPRS


export {
module TCPRS;




## Enable use of communication.
##
## flags: used to tune the local Broker endpoint behavior.
##
## Returns: true if communication is successfully initialized.
global EnableTCPRSAnalyzer: function(): bool ;


global conn_spurious_dsack: event(c: connection , timestamp: time , seq: count , is_orig: bool , rtt: double , state: int , o_seq: count , beg_seq: count , end_seq: count , reason: int , rtype: int );

global conn_rexmit: event(c: connection , timestamp: time , seq: count , is_orig: bool , rtt: double , state: int , o_seq: count , beg_seq: count , end_seq: count , reason: int , rtype: int , confidence: double , flags: int );

global conn_rtx_summary: event(c: connection , timestamp: time , stats: TCPRS::rtx_stats , spurious: count );

global conn_rtx_types: event(c: connection , timestamp: time , rto: int , fastrtx: int , retrans: int , isdead: bool );

global tcp_dup_ack: event(c: connection , timestamp: time , seq: count , num_rtx: int , is_orig: bool );

global conn_state_change: event(c: connection , timestamp: time , prev: int , current: int , is_orig: bool );

global conn_dead_event: event(c: connection , timestamp: time , duration: double , state: int , is_orig: bool );

global conn_ooo_summary: event(c: connection , timestamp: time , orig: int , resp: int , total: int );

global conn_ooo_event: event(c: connection , timestamp: time , is_orig: bool , seq: count , gap: double , rtt: double , num_seq: int , o_seq: count , beg_seq: count , end_seq: count );

global conn_ambi_order: event(c: connection , timestamp: time , is_orig: bool , seq: count , gap: double , num_seq: int , o_seq: count , beg_seq: count , end_seq: count );

global conn_config: event(c: connection , timestamp: time , ts: bool , bad_conn: bool , sack: bool , o_sack_offer: bool , r_sack_offer: bool );

global conn_rtt_estimate: event(c: connection , timestamp: time , rtt: double , c_rtt: double , s_rtt: double );

global conn_limited_transmit: event(c: connection , timestamp: time , seq: count , is_orig: bool , rtt: double , state: int , o_seq: count , beg_seq: count , end_seq: count );

global conn_fast_recovery: event(c: connection , timestamp: time , seq: count , is_orig: bool , rtt: double , state: int , o_seq: count , beg_seq: count , end_seq: count );

global conn_initial_rtt: event(c: connection , timestamp: time , rtt: double , is_orig: bool );

global conn_initial_rto: event(c: connection , timestamp: time , rto: double , is_orig: bool );

} # end of export section
module GLOBAL;
