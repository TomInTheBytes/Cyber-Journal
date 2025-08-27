# diagram.py
from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.network import Opnsense
from diagrams.generic.os import LinuxGeneral
from diagrams.generic.os import Windows
from diagrams.custom import Custom

with Diagram("Lab Architecture", show=False):
    opnsense = Opnsense("OPNsense Firewall \n 192.168.1.1")
    windows = Windows("Windows Host \n 192.168.1.102")
    linux = LinuxGeneral("Linux Host \n 192.168.1.101")
    seconion = Custom("Security Onion \n 192.168.1.2", "./logo-so-onion.png")

    seconion >> Edge(label="test") >> opnsense
    opnsense >> Edge(label="Port spanning") >> seconion
    windows >> opnsense
    linux >> opnsense
