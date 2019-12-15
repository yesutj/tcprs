@load ./tcp_retransmissions
@load ./tcp_reordering
@load ./tcp_deadconn
@load ./tcp_options
@load ./tcp_recovery
@load ./tcp_rtt

event bro_init() 
{
	print "yesutj::TCPRS is loaded"; 
	TCPRS::EnableTCPRSAnalyzer();
}
