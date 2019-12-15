#include "Plugin.h"
#include "TCPRS.h"
#include <iostream>
namespace plugin { namespace yesutj_TCPRS { Plugin plugin; } }

using namespace plugin::yesutj_TCPRS;

static bool use_tcprs_analyzer = false;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("TCPRS", ::analyzer::tcp::TCPRS_Analyzer::Instantiate));

	plugin::Configuration config;
	config.name = "yesutj::TCPRS";
	config.description = "A TCP retransmission and network reordering detection and classification analyzer";
	config.version.major = 0;
	config.version.minor = 2;

	EnableHook(HOOK_SETUP_ANALYZER_TREE, 0);

	return config;
	}

void Plugin::HookSetupAnalyzerTree(Connection *conn)
	{
		
	analyzer::tcp::TCP_Analyzer* tcp = 0;
	analyzer::TransportLayerAnalyzer* root = 0;

	if ( conn->ConnTransport() != TRANSPORT_TCP )
		return;

	if ( ! use_tcprs_analyzer )
		return;

	root = conn->GetRootAnalyzer();
	tcp = (analyzer::tcp::TCP_Analyzer *) root;

	analyzer::tcp::TCPRS_Analyzer* tcprs = new analyzer::tcp::TCPRS_Analyzer(conn);
	tcp->AddChildPacketAnalyzer(tcprs);

	/* init the new analyzer */
	tcprs->Init();
	}

bool plugin::yesutj_TCPRS::EnableTCPRS()
	{
	use_tcprs_analyzer = true;
	return use_tcprs_analyzer;
	}
