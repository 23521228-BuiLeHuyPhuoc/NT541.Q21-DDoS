#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')  # External zone
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')  # Router trung tam
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')  # Server zone 1
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='4')  # Server zone 2
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='5')  # PC zone

    info( '*** Add hosts\n')
    # Zone 1 (External)
    h_att1 = net.addHost('h_att1', cls=Host, ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    h_ext1 = net.addHost('h_ext1', cls=Host, ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')
    
    # Zone 2 (Web/DNS)
    h_web1 = net.addHost('h_web1', cls=Host, ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
    h_dns1 = net.addHost('h_dns1', cls=Host, ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
    
    # Zone 3 (DB/App)
    h_db1 = net.addHost('h_db1', cls=Host, ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
    h_app1 = net.addHost('h_app1', cls=Host, ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')
    
    # Zone 4 (PCs)
    h_pc1 = net.addHost('h_pc1', cls=Host, ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
    h_pc2 = net.addHost('h_pc2', cls=Host, ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')

    info( '*** Add links\n')
    # Switch to Router links
    net.addLink(s1, s2)
    net.addLink(s3, s2)
    net.addLink(s4, s2)
    net.addLink(s5, s2)
    
    # Host to Switch links
    net.addLink(s1, h_att1)
    net.addLink(s1, h_ext1)
    net.addLink(s3, h_web1)
    net.addLink(s3, h_dns1)
    net.addLink(s4, h_db1)
    net.addLink(s4, h_app1)
    net.addLink(s5, h_pc1)
    net.addLink(s5, h_pc2)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
