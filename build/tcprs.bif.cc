// This file was automatically generated by bifcl from /home/yesutj/tcprs/src/tcprs.bif (plugin mode).


#include "tcprs.bif.h"


#line 6 "tcprs.bif"

#include "Plugin.h"

#line 15 "tcprs.bif"
Val* BifFunc::TCPRS::bro_EnableTCPRSAnalyzer(Frame* frame, val_list* BiF_ARGS)
	
#line 16 "tcprs.bif"
{
	if ( BiF_ARGS->length() != 0 )
		{
		reporter->Error("TCPRS::EnableTCPRSAnalyzer() takes exactly 0 argument(s)");
		return 0;
		}

#line 16 "tcprs.bif"

	return new Val(plugin::yesutj_TCPRS::EnableTCPRS(), TYPE_BOOL);
	} // end of BifFunc::TCPRS::bro_EnableTCPRSAnalyzer

#line 18 "tcprs.bif"
namespace TCPRS { EventHandlerPtr conn_spurious_dsack;  }
void BifEvent::TCPRS::generate_conn_spurious_dsack(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_uint_t seq, int is_orig, double rtt, bro_int_t state, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq, bro_int_t reason, bro_int_t rtype)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_spurious_dsack is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_spurious_dsack is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_spurious_dsack, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetCount(seq),
	        val_mgr->GetBool(is_orig),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetInt(state),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        val_mgr->GetInt(reason),
	        val_mgr->GetInt(rtype),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_rexmit;  }
void BifEvent::TCPRS::generate_conn_rexmit(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_uint_t seq, int is_orig, double rtt, bro_int_t state, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq, bro_int_t reason, bro_int_t rtype, double confidence, bro_int_t flags)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_rexmit is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_rexmit is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_rexmit, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetCount(seq),
	        val_mgr->GetBool(is_orig),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetInt(state),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        val_mgr->GetInt(reason),
	        val_mgr->GetInt(rtype),
	        new Val(confidence, TYPE_DOUBLE),
	        val_mgr->GetInt(flags),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_rtx_summary;  }
void BifEvent::TCPRS::generate_conn_rtx_summary(analyzer::Analyzer* analyzer, Connection* c, double timestamp, Val* stats, bro_uint_t spurious)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_rtx_summary is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_rtx_summary is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_rtx_summary, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        stats,
	        val_mgr->GetCount(spurious),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_rtx_types;  }
void BifEvent::TCPRS::generate_conn_rtx_types(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_int_t rto, bro_int_t fastrtx, bro_int_t retrans, int isdead)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_rtx_types is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_rtx_types is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_rtx_types, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetInt(rto),
	        val_mgr->GetInt(fastrtx),
	        val_mgr->GetInt(retrans),
	        val_mgr->GetBool(isdead),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr tcp_dup_ack;  }
void BifEvent::TCPRS::generate_tcp_dup_ack(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_uint_t seq, bro_int_t num_rtx, int is_orig)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::tcp_dup_ack is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_tcp_dup_ack is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::tcp_dup_ack, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetCount(seq),
	        val_mgr->GetInt(num_rtx),
	        val_mgr->GetBool(is_orig),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_state_change;  }
void BifEvent::TCPRS::generate_conn_state_change(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_int_t prev, bro_int_t current, int is_orig)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_state_change is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_state_change is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_state_change, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetInt(prev),
	        val_mgr->GetInt(current),
	        val_mgr->GetBool(is_orig),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_dead_event;  }
void BifEvent::TCPRS::generate_conn_dead_event(analyzer::Analyzer* analyzer, Connection* c, double timestamp, double duration, bro_int_t state, int is_orig)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_dead_event is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_dead_event is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_dead_event, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        new Val(duration, TYPE_DOUBLE),
	        val_mgr->GetInt(state),
	        val_mgr->GetBool(is_orig),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_ooo_summary;  }
void BifEvent::TCPRS::generate_conn_ooo_summary(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_int_t orig, bro_int_t resp, bro_int_t total)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_ooo_summary is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_ooo_summary is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_ooo_summary, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetInt(orig),
	        val_mgr->GetInt(resp),
	        val_mgr->GetInt(total),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_ooo_event;  }
void BifEvent::TCPRS::generate_conn_ooo_event(analyzer::Analyzer* analyzer, Connection* c, double timestamp, int is_orig, bro_uint_t seq, double gap, double rtt, bro_int_t num_seq, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_ooo_event is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_ooo_event is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_ooo_event, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetBool(is_orig),
	        val_mgr->GetCount(seq),
	        new Val(gap, TYPE_DOUBLE),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetInt(num_seq),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_ambi_order;  }
void BifEvent::TCPRS::generate_conn_ambi_order(analyzer::Analyzer* analyzer, Connection* c, double timestamp, int is_orig, bro_uint_t seq, double gap, bro_int_t num_seq, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_ambi_order is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_ambi_order is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_ambi_order, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetBool(is_orig),
	        val_mgr->GetCount(seq),
	        new Val(gap, TYPE_DOUBLE),
	        val_mgr->GetInt(num_seq),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_config;  }
void BifEvent::TCPRS::generate_conn_config(analyzer::Analyzer* analyzer, Connection* c, double timestamp, int ts, int bad_conn, int sack, int o_sack_offer, int r_sack_offer)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_config is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_config is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_config, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetBool(ts),
	        val_mgr->GetBool(bad_conn),
	        val_mgr->GetBool(sack),
	        val_mgr->GetBool(o_sack_offer),
	        val_mgr->GetBool(r_sack_offer),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_rtt_estimate;  }
void BifEvent::TCPRS::generate_conn_rtt_estimate(analyzer::Analyzer* analyzer, Connection* c, double timestamp, double rtt, double c_rtt, double s_rtt)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_rtt_estimate is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_rtt_estimate is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_rtt_estimate, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        new Val(rtt, TYPE_DOUBLE),
	        new Val(c_rtt, TYPE_DOUBLE),
	        new Val(s_rtt, TYPE_DOUBLE),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_limited_transmit;  }
void BifEvent::TCPRS::generate_conn_limited_transmit(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_uint_t seq, int is_orig, double rtt, bro_int_t state, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_limited_transmit is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_limited_transmit is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_limited_transmit, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetCount(seq),
	        val_mgr->GetBool(is_orig),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetInt(state),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_fast_recovery;  }
void BifEvent::TCPRS::generate_conn_fast_recovery(analyzer::Analyzer* analyzer, Connection* c, double timestamp, bro_uint_t seq, int is_orig, double rtt, bro_int_t state, bro_uint_t o_seq, bro_uint_t beg_seq, bro_uint_t end_seq)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_fast_recovery is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_fast_recovery is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_fast_recovery, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        val_mgr->GetCount(seq),
	        val_mgr->GetBool(is_orig),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetInt(state),
	        val_mgr->GetCount(o_seq),
	        val_mgr->GetCount(beg_seq),
	        val_mgr->GetCount(end_seq),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_initial_rtt;  }
void BifEvent::TCPRS::generate_conn_initial_rtt(analyzer::Analyzer* analyzer, Connection* c, double timestamp, double rtt, int is_orig)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_initial_rtt is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_initial_rtt is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_initial_rtt, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        new Val(rtt, TYPE_DOUBLE),
	        val_mgr->GetBool(is_orig),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
namespace TCPRS { EventHandlerPtr conn_initial_rto;  }
void BifEvent::TCPRS::generate_conn_initial_rto(analyzer::Analyzer* analyzer, Connection* c, double timestamp, double rto, int is_orig)
	{
	// Note that it is intentional that here we do not
	// check if ::TCPRS::conn_initial_rto is NULL, which should happen *before*
	// BifEvent::TCPRS::generate_conn_initial_rto is called to avoid unnecessary Val
	// allocation.

	mgr.QueueEventFast(::TCPRS::conn_initial_rto, val_list{
	        c->BuildConnVal(),
	        new Val(timestamp, TYPE_TIME),
	        new Val(rto, TYPE_DOUBLE),
	        val_mgr->GetBool(is_orig),
	        },
	    SOURCE_LOCAL, analyzer->GetID(), timer_mgr, c);
	} // event generation
