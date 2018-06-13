from mininet.node import CPULimitedHost
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import Intf
import os

class ccTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        hosts  = [self.addHost('h%d'%(i), ip='0.0.0.0') for i in range(4)]
        sws = [self.addSwitch('s%d'%i, dpid='000000000000000%d'%(i+1)) for i in range(4)]

        self.addLink(hosts[0], sws[0])
        self.addLink(hosts[1], sws[0])
        self.addLink(hosts[2], sws[1])
        self.addLink(hosts[3], sws[3])

        self.addLink(sws[0], sws[1])
        self.addLink(sws[2], sws[3])    

def run():
    net = Mininet(topo=ccTopo(), host=CPULimitedHost, controller=None, autoSetMacs=True)
    net.addController(name='ryu', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    os.popen('ovs-vsctl add-port s1 enp0s8')
    os.popen('ovs-vsctl add-port s2 enp0s9')
    for i in range(4):
        host = net.get('h%d'%(i))
        host.cmdPrint('dhclient '+host.defaultIntf().name)
    
    CLI(net)

    for i in range(4):
        host = net.get('h%d'%(i))
        host.cmdPrint('dhclient -r '+host.defaultIntf().name)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
