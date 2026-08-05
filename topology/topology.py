from mininet.topo import Topo


class TwoSwitchSDNTopo(Topo):
    def build(self):
        # Create two OpenFlow switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Create hosts under switch s1
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Primary attacker
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Secondary attacker (DDoS)
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Secondary attacker (DDoS)

        # Create hosts under switch s2
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Victim
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # Legitimate host
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Legitimate host

        # Connect hosts to switch s1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        # Connect hosts to switch s2
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        # Connect the two switches
        self.addLink(s1, s2)


topos = {
    'twoswitchtopo': lambda: TwoSwitchSDNTopo()
}
