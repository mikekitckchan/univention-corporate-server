from univention.management.console.modules.setup.netconf.common import RestartService
from univention.management.console.modules.setup.netconf.conditions import NotNetworkOnly


class PhaseRestartDhcp(RestartService, NotNetworkOnly):
	service = "isc-dhcp-server"
	priority = 26
