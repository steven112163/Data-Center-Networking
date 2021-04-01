from mininet.topo import Topo


class MyTopo(Topo):
    """
    Topology is defined on p.7 in the description pdf
    """
    def build(self):
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/8', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/8', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/8', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/8', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/8', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/8', mac='00:00:00:00:00:06')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Add links between switches
        self.addLink(s1, s2, bw=1000, loss=5)
        self.addLink(s2, s3, bw=1000, loss=5)
        self.addLink(s3, s4, bw=1000, loss=5)

        # Add links between switch and host
        self.addLink(s1, h1, bw=100)
        self.addLink(s1, h2, bw=100)
        self.addLink(s2, h3, bw=100)
        self.addLink(s3, h4, bw=100)
        self.addLink(s4, h5, bw=100)
        self.addLink(s4, h6, bw=100)


topos = {'mytopo': (lambda: MyTopo())}
