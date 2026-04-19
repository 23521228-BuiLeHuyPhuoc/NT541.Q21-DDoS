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
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')  # Router trung tam
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')  # Server zone
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')  # External zone (attacker + client)

    info( '*** Add hosts\n')
    h_att1 = net.addHost('h_att1', cls=Host, ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')  # Attacker (DoS)
    h_ext1 = net.addHost('h_ext1', cls=Host, ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')  # Legitimate client
    h_web1 = net.addHost('h_web1', cls=Host, ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')  # Target server

    info( '*** Add links\n')
    # External zone
    net.addLink(s1, h_att1)
    net.addLink(s1, h_ext1)
    # Server zone
    net.addLink(s3, h_web1)
    # Router links
    net.addLink(s1, s2)
    net.addLink(s3, s2)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

