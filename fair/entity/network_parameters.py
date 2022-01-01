class NetworkParametersEntity():
    def __init__(self, nic_guid, is_vpn, network_hint, ip, gateway, subnet, dhcp, dns, domain, last_lease_start, last_lease_end):
        self.nic_guid = nic_guid
        self.is_vpn = is_vpn
        self.network_hint = network_hint
        self.ip = ip
        self.gateway = gateway
        self.subnet = subnet
        self.dhcp = dhcp
        self.dns = dns
        self.domain = domain
        self.last_lease_start = last_lease_start
        self.last_lease_end = last_lease_end

    def to_dict(self):
        return {
            'nic_guid': self.nic_guid,
            'is_vpn': self.is_vpn,
            'network_hint': self.network_hint,
            'ip': self.ip,
            'gateway': self.gateway,
            'subnet': self.subnet,
            'dhcp': self.dhcp,
            'dns': self.dns,
            'domain': self.domain,
            'last_lease_start': str(self.last_lease_start),
            'last_lease_end': str(self.last_lease_end),
        }
