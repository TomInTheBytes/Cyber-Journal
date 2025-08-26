# Security Onion
From Security Onion [documentation](https://docs.securityonion.net/en/2.4/introduction.html):

*Security Onion is a free and open platform built by defenders for defenders. It includes network visibility, host visibility, intrusion detection honeypots, log management, and case management.

For network visibility, we offer signature based detection via Suricata, rich protocol metadata and file extraction using either Zeek or Suricata, full packet capture using either Stenographer or Suricata, and file analysis. For host visibility, we offer the Elastic Agent which provides data collection, live queries via osquery, and centralized management using Elastic Fleet. Intrusion detection honeypots based on OpenCanary can be added to your deployment for even more enterprise visibility. All of these logs flow into Elasticsearch and we’ve built our own user interfaces for alerts, dashboards, threat hunting, case management, and grid management.*

## Elastic
Security Onion integrates the ELK stack (Elasticsearch, Logstash, Kibana) as its core log management and analysis layer. Logstash ingests and normalizes logs and network events from sensors, parsers, and other monitoring components within Security Onion. It applies filters and enrichments to make disparate log formats uniform. Elasticsearch stores the processed data as indexed documents, enabling rapid searching and correlation across large volumes of network, host, and security logs. Kibana provides the visualization and query interface, giving analysts dashboards for intrusion detection alerts, full packet capture metadata, endpoint logs, and system telemetry. Together, this stack supports Security Onion’s role as a SIEM: collection, normalization, storage, search, correlation, and visualization of security events.

Elastic also provides an agent that is deployed on endpoints to forward logs and serve as EDR solution to generate alerts. It replaces some of the functionality that Filebeat previously offered and can forward Sysmon logs. 

### Endpoint
#### Elastic Agent Policy
The Elastic Fleet is deploying a policy named 'endpoints-initial' to the endpoints. This includes the following integrations:

![endpoint_policy](../../media/lab/fleet_endpoint_policy.png){ align=left }
/// caption
Integrations included in the Elastic Agent policy for endpoints.
///

These include the following data:

- **elastic-defend-endpoints:** this is Elastic's EDR solution. However, it is not setup to replace Windows Defender as EDR as we want to ingest as many logs and alerts as possible and therefore not block any activity on the endpoints. It captures events on Windows (API, DLL and Driver Load, DNS, File, Network, Process, Registry, Security), MacOS (File, Process, Network), and Linux (File, Process, Network). 
- **osquery-endpoints:** this allows analysts to query information on the system directly through live queries when it's online. It does not provide logs on a continuous basis.
- **system-endpoints:** this collects logs from System instances and Windows Events (Application, Security, and System).
- **windows-defender:** this collects custom Windows Event (Operational) logs. 
- **windows-endpoints:** this collects logs from the channels ForwardedEvents, Powershell, Microsoft-Windows-Powershell/Operational, and Microsoft-Windows-Sysmon/Operational.


#### Elastic Defend
Out of the box not many detection rules enabled, enabled all.

### Kibana

# Network

- Endpoint (Elastic Agent)
- elastic_agent (Elastic agent fleet management logs)
- suricata (network)
- zeek (network)
- Windows (sysmon, PowerShell (filebeat))

