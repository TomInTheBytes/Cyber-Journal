# diagram.py
from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.network import Opnsense
from diagrams.generic.os import Ubuntu
from diagrams.generic.os import Windows
from diagrams.custom import Custom

with Diagram("Lab Network Architecture", show=False):
    

    with Cluster("Hyper-V Environment"):
        hyperv = Custom("Hyper-V\nManager", "./logo-hyperv.png")

        with Cluster("Hyper-V Network\n192.168.1.0/24"):
            opnsense = Opnsense("OPNsense Firewall\n192.168.1.1")
            windows = Windows("Windows Host\n192.168.1.102")
            ubuntu = Ubuntu("Linux Host\n192.168.1.101")
            seconion = Custom("Security Onion\n192.168.1.2\n(management)", "./logo-so-onion.png")

            seconion >> Edge() << opnsense
            ubuntu >> Edge() << opnsense
            windows >> Edge() << opnsense
            opnsense >> Edge(label="Port mirroring") >> hyperv
        
        
        hyperv >> Edge(label="Port mirroring") >> seconion  
    