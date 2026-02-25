#!/usr/bin/env python3
"""
Azure Complexity Measurement Tool

Quantifies Azure's total configuration surface area across 4 layers:
  1. Native services (providers & resource types)
  2. Sub-tiers / SKUs
  3. Configuration parameters (fully recursed from OpenAPI specs)
  4. Licensing options

Outputs a polished, self-contained HTML report.

Usage:
  python3 az_complexity.py --mode preview   # 3 providers (default)
  python3 az_complexity.py --mode full       # All providers (requires local specs clone)
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = BASE_DIR / "cache"
OUTPUT_FILE = BASE_DIR / "azure_complexity_report.html"
SPECS_REPO = "https://github.com/Azure/azure-rest-api-specs.git"
# Clone to native Linux filesystem for performance (NTFS mounts are too slow)
SPECS_LOCAL = Path("/tmp/azure-rest-api-specs")

PREVIEW_PROVIDERS = ["Microsoft.Compute", "Microsoft.Web", "Microsoft.KeyVault"]

# Reference region for SKU enumeration (Azure's most complete region)
REFERENCE_REGION = "eastus"

# Provider descriptions (extracted from OpenAPI spec info fields)
PROVIDER_DESCRIPTIONS: dict[str, str] = {
    "Microsoft.AAD": "Azure Active Directory Domain Services",
    "Microsoft.ADHybridHealthService": "Azure AD Connect Health monitoring",
    "Microsoft.AVS": "Azure VMware Solution",
    "Microsoft.Aadiam": "Azure AD diagnostic settings and private link",
    "Microsoft.Addons": "Third-party addon management",
    "Microsoft.Advisor": "Azure Advisor optimization recommendations",
    "Microsoft.AgFoodPlatform": "Azure Data Manager for Agriculture",
    "Microsoft.AgriculturePlatform": "Agriculture platform services",
    "Microsoft.AlertsManagement": "Unified alert management across Azure Monitor",
    "Microsoft.AnalysisServices": "Azure Analysis Services (tabular models)",
    "Microsoft.ApiCenter": "API Center for API inventory and governance",
    "Microsoft.ApiManagement": "API Management gateway and developer portal",
    "Microsoft.App": "Azure Container Apps",
    "Microsoft.AppComplianceAutomation": "App Compliance Automation for Microsoft 365",
    "Microsoft.AppConfiguration": "App Configuration for feature flags and settings",
    "Microsoft.AppPlatform": "Azure Spring Apps",
    "Microsoft.Attestation": "Azure Attestation for TEE verification",
    "Microsoft.Authorization": "Role-based access control and Azure Policy",
    "Microsoft.Automanage": "Automanage for VM best practices",
    "Microsoft.Automation": "Azure Automation runbooks and DSC",
    "Microsoft.AwsConnector": "AWS Connector for multi-cloud management",
    "Microsoft.AzureActiveDirectory": "Azure AD B2C and External Identities",
    "Microsoft.AzureArcData": "Azure Arc-enabled data services",
    "Microsoft.AzureData": "Azure data resource management",
    "Microsoft.AzureDataTransfer": "Azure Data Transfer service",
    "Microsoft.AzureFleet": "Azure Compute Fleet",
    "Microsoft.AzureLargeInstance": "Azure Large Instances (BareMetal)",
    "Microsoft.AzurePlaywrightService": "Azure Playwright Testing service",
    "Microsoft.AzureSphere": "Azure Sphere IoT security",
    "Microsoft.AzureStack": "Azure Stack bridge and registration",
    "Microsoft.AzureStackHCI": "Azure Stack HCI hybrid infrastructure",
    "Microsoft.AzureTerraform": "Azure Terraform resource management",
    "Microsoft.BareMetalInfrastructure": "BareMetal Infrastructure instances",
    "Microsoft.Batch": "Azure Batch parallel and HPC workloads",
    "Microsoft.Billing": "Billing accounts and invoices",
    "Microsoft.BillingBenefits": "Savings plans and reservation benefits",
    "Microsoft.Blueprint": "Azure Blueprints for environment governance",
    "Microsoft.BotService": "Azure Bot Service",
    "Microsoft.Cache": "Azure Cache for Redis",
    "Microsoft.Capacity": "Azure Reservations for cost savings",
    "Microsoft.Carbon": "Carbon emissions reporting",
    "Microsoft.Cdn": "Azure CDN and Front Door",
    "Microsoft.CertificateRegistration": "App Service certificate management",
    "Microsoft.ChangeAnalysis": "Azure Change Analysis for diagnostics",
    "Microsoft.Chaos": "Azure Chaos Studio fault injection testing",
    "Microsoft.CloudHealth": "Cloud health monitoring",
    "Microsoft.CodeSigning": "Trusted Signing (code signing service)",
    "Microsoft.CognitiveServices": "Azure AI Services (OpenAI, Doc Intelligence, Vision, Speech, Language, and more)",
    "Microsoft.Commerce": "Azure usage and billing rates",
    "Microsoft.Communication": "Azure Communication Services (chat, SMS, voice)",
    "Microsoft.Community": "Community training platform",
    "Microsoft.Compute": "Virtual machines, scale sets, and compute resources",
    "Microsoft.ComputeBulkActions": "Compute bulk action operations",
    "Microsoft.ComputeLimit": "Compute limit management",
    "Microsoft.ComputeSchedule": "Scheduled compute operations",
    "Microsoft.ConfidentialLedger": "Confidential Ledger (tamper-proof data store)",
    "Microsoft.Confluent": "Confluent on Azure (Apache Kafka)",
    "Microsoft.ConnectedCache": "Connected Cache for content delivery",
    "Microsoft.ConnectedVMwarevSphere": "Azure Arc-enabled VMware vSphere",
    "Microsoft.Consumption": "Consumption and usage analytics",
    "Microsoft.ContainerInstance": "Serverless container instances",
    "Microsoft.ContainerRegistry": "Container Registry for Docker images",
    "Microsoft.ContainerService": "Azure Kubernetes Service (AKS)",
    "Microsoft.ContainerStorage": "Container storage for Kubernetes",
    "Microsoft.CostManagement": "Cost Management and billing optimization",
    "Microsoft.CustomProviders": "Custom Resource Providers for ARM extensibility",
    "Microsoft.CustomerInsights": "Customer Insights data platform",
    "Microsoft.CustomerLockbox": "Customer Lockbox access approval",
    "Microsoft.DBforMariaDB": "Azure Database for MariaDB",
    "Microsoft.DBforMySQL": "Azure Database for MySQL",
    "Microsoft.DBforPostgreSQL": "Azure Database for PostgreSQL",
    "Microsoft.Dashboard": "Azure Managed Grafana dashboards",
    "Microsoft.DataBox": "Data Box offline data transfer",
    "Microsoft.DataBoxEdge": "Azure Stack Edge devices",
    "Microsoft.DataCatalog": "Data Catalog metadata service",
    "Microsoft.DataFactory": "Data Factory data integration pipelines",
    "Microsoft.DataLakeAnalytics": "Data Lake Analytics",
    "Microsoft.DataLakeStore": "Data Lake Storage Gen1",
    "Microsoft.DataMigration": "Database Migration Service",
    "Microsoft.DataProtection": "Azure Backup for data protection",
    "Microsoft.DataReplication": "Data replication service",
    "Microsoft.DataShare": "Data Share for data collaboration",
    "Microsoft.DatabaseFleetManager": "Database Fleet Manager",
    "Microsoft.DatabaseWatcher": "Database performance watcher",
    "Microsoft.Databricks": "Azure Databricks workspaces",
    "Microsoft.Datadog": "Datadog on Azure (monitoring integration)",
    "Microsoft.DelegatedNetwork": "Delegated Network Controller (DNC)",
    "Microsoft.DependencyMap": "Application dependency mapping",
    "Microsoft.DesktopVirtualization": "Azure Virtual Desktop",
    "Microsoft.DevCenter": "Dev Box and Deployment Environments",
    "Microsoft.DevHub": "AKS Developer Hub for CI/CD",
    "Microsoft.DevOps": "Azure DevOps pipeline integration",
    "Microsoft.DevOpsInfrastructure": "Managed DevOps Infrastructure (agent pools)",
    "Microsoft.DevSpaces": "Dev Spaces for AKS (deprecated)",
    "Microsoft.DevTestLab": "DevTest Labs for dev/test environments",
    "Microsoft.DeviceRegistry": "IoT device registry",
    "Microsoft.DeviceUpdate": "Device Update for IoT Hub",
    "Microsoft.Devices": "IoT Hub and Device Provisioning Service",
    "Microsoft.DigitalTwins": "Digital Twins for IoT modeling",
    "Microsoft.Discovery": "Resource discovery service",
    "Microsoft.DocumentDB": "Azure Cosmos DB",
    "Microsoft.DomainRegistration": "App Service domain registration",
    "Microsoft.DurableTask": "Durable Task Framework service",
    "Microsoft.Easm": "Defender External Attack Surface Management",
    "Microsoft.Edge": "Edge disconnected operations",
    "Microsoft.EdgeMarketplace": "Edge marketplace extensions",
    "Microsoft.EdgeOrder": "Azure Edge Order for hardware",
    "Microsoft.EdgeZones": "Azure Edge Zones for low-latency compute",
    "Microsoft.Education": "Education sponsorships and labs",
    "Microsoft.Elastic": "Elastic on Azure (Elasticsearch integration)",
    "Microsoft.ElasticSan": "Elastic SAN block storage",
    "Microsoft.EventGrid": "Event Grid event-driven messaging",
    "Microsoft.EventHub": "Event Hubs streaming data ingestion",
    "Microsoft.ExtendedLocation": "Custom locations for Azure Arc",
    "Microsoft.Fabric": "Microsoft Fabric analytics platform",
    "Microsoft.Features": "Resource provider feature registration",
    "Microsoft.FluidRelay": "Fluid Relay real-time collaboration",
    "Microsoft.GraphServices": "Microsoft Graph metered services",
    "Microsoft.GuestConfiguration": "Guest configuration for Azure Policy",
    "Microsoft.HDInsight": "HDInsight managed Hadoop and Spark clusters",
    "Microsoft.HanaOnAzure": "SAP HANA on Azure instances",
    "Microsoft.HardwareSecurityModules": "Dedicated HSM and Managed HSM",
    "Microsoft.HealthBot": "Health Bot for healthcare virtual assistants",
    "Microsoft.HealthDataAIServices": "Health Data AI services",
    "Microsoft.HealthcareApis": "Health Data Services (FHIR, DICOM, MedTech)",
    "Microsoft.Help": "Azure help and diagnostics",
    "Microsoft.HybridCloud": "Hybrid cloud connectivity",
    "Microsoft.HybridCompute": "Azure Arc-enabled servers",
    "Microsoft.HybridConnectivity": "Hybrid connectivity endpoints",
    "Microsoft.HybridContainerService": "Azure Arc-enabled AKS hybrid",
    "Microsoft.HybridNetwork": "Hybrid network function management",
    "Microsoft.Impact": "Impact analysis and reporting",
    "Microsoft.ImportExport": "Import/Export disk-based data transfer",
    "Microsoft.Insights": "Azure Monitor metrics, logs, and autoscale",
    "Microsoft.IntegrationSpaces": "Integration spaces for business processes",
    "Microsoft.IoTCentral": "IoT Central application platform",
    "Microsoft.IoTFirmwareDefense": "Defender for IoT firmware analysis",
    "Microsoft.IoTOperations": "Azure IoT Operations for edge",
    "Microsoft.KeyVault": "Key Vault for keys, secrets, and certificates",
    "Microsoft.Kubernetes": "Azure Arc-enabled Kubernetes",
    "Microsoft.KubernetesConfiguration": "Flux and GitOps for Arc-enabled Kubernetes",
    "Microsoft.KubernetesRuntime": "Kubernetes runtime services on Arc",
    "Microsoft.Kusto": "Azure Data Explorer (Kusto)",
    "Microsoft.LabServices": "Lab Services for classroom and training labs",
    "Microsoft.LoadTestService": "Azure Load Testing",
    "Microsoft.Logic": "Logic Apps workflow automation",
    "Microsoft.MachineLearning": "Machine Learning classic workspaces",
    "Microsoft.MachineLearningServices": "Azure Machine Learning workspaces and models",
    "Microsoft.Maintenance": "Maintenance schedules for Azure resources",
    "Microsoft.ManagedIdentity": "Managed identities for Azure resources",
    "Microsoft.ManagedNetwork": "Managed virtual network peering policies",
    "Microsoft.ManagedNetworkFabric": "Operator Nexus network fabric",
    "Microsoft.ManagedServices": "Azure Lighthouse delegated management",
    "Microsoft.Management": "Management groups for subscription hierarchy",
    "Microsoft.Maps": "Azure Maps geospatial services",
    "Microsoft.Marketplace": "Azure Marketplace private stores",
    "Microsoft.MarketplaceOrdering": "Marketplace offer terms and agreements",
    "Microsoft.Migrate": "Azure Migrate assessment and migration",
    "Microsoft.Monitor": "Azure Monitor workspaces",
    "Microsoft.NetApp": "Azure NetApp Files",
    "Microsoft.Network": "Virtual networks, load balancers, DNS, and network security",
    "Microsoft.NetworkCloud": "Operator Nexus compute resources",
    "Microsoft.NetworkFunction": "Network traffic collector",
    "Microsoft.NotificationHubs": "Notification Hubs push notifications",
    "Microsoft.OffAzure": "Off-Azure discovery and assessment",
    "Microsoft.OpenEnergyPlatform": "Open Energy Platform (OSDU)",
    "Microsoft.OperationalInsights": "Log Analytics workspaces and queries",
    "Microsoft.OperationsManagement": "Operations Management Suite solutions",
    "Microsoft.Orbital": "Azure Orbital Ground Station",
    "Microsoft.Peering": "Peering Service for ISP connectivity",
    "Microsoft.PolicyInsights": "Policy compliance and attestations",
    "Microsoft.Portal": "Azure Portal dashboards and settings",
    "Microsoft.PowerBI": "Power BI Embedded workspace collections",
    "Microsoft.PowerBIdedicated": "Power BI Embedded dedicated capacities",
    "Microsoft.PowerPlatform": "Power Platform (Power Apps, Power Automate)",
    "Microsoft.ProviderHub": "Resource provider management and onboarding",
    "Microsoft.Purview": "Microsoft Purview data governance",
    "Microsoft.Quantum": "Azure Quantum computing",
    "Microsoft.Quota": "Resource quota management",
    "Microsoft.RecoveryServices": "Backup and Site Recovery vaults",
    "Microsoft.RedHatOpenShift": "Azure Red Hat OpenShift",
    "Microsoft.Relay": "Azure Relay hybrid connections",
    "Microsoft.ResourceConnector": "Azure Arc resource bridge appliance",
    "Microsoft.ResourceGraph": "Resource Graph cross-subscription queries",
    "Microsoft.ResourceHealth": "Resource health and availability status",
    "Microsoft.Resources": "Resource groups, deployments, and ARM templates",
    "Microsoft.ScVmm": "Azure Arc-enabled System Center VMM",
    "Microsoft.Search": "Azure AI Search (formerly Cognitive Search)",
    "Microsoft.Security": "Microsoft Defender for Cloud",
    "Microsoft.SecurityInsights": "Microsoft Sentinel (SIEM and SOAR)",
    "Microsoft.SerialConsole": "Serial console access for VMs",
    "Microsoft.ServiceBus": "Service Bus messaging queues and topics",
    "Microsoft.ServiceFabric": "Service Fabric cluster management",
    "Microsoft.ServiceFabricMesh": "Service Fabric Mesh serverless containers",
    "Microsoft.ServiceLinker": "Service Linker for connection configuration",
    "Microsoft.ServiceNetworking": "Application Gateway for Containers",
    "Microsoft.SignalRService": "SignalR Service real-time messaging",
    "Microsoft.SoftwarePlan": "Hybrid Benefit software plans",
    "Microsoft.Solutions": "Managed Applications and solutions",
    "Microsoft.Sql": "Azure SQL Database and SQL Managed Instance",
    "Microsoft.SqlVirtualMachine": "SQL Server on Azure Virtual Machines",
    "Microsoft.StandbyPool": "Standby pools for pre-provisioned instances",
    "Microsoft.Storage": "Storage accounts, blobs, files, queues, and tables",
    "Microsoft.StorageCache": "Managed Lustre and HPC Cache",
    "Microsoft.StorageMover": "Storage Mover for data migration",
    "Microsoft.StoragePool": "Disk Pool for iSCSI targets",
    "Microsoft.StorageSync": "Azure File Sync",
    "Microsoft.StreamAnalytics": "Stream Analytics real-time event processing",
    "Microsoft.Subscription": "Subscription lifecycle management",
    "Microsoft.Support": "Azure support tickets and services",
    "Microsoft.Synapse": "Azure Synapse Analytics",
    "Microsoft.TestBase": "Test Base for Microsoft 365 app testing",
    "Microsoft.TimeSeriesInsights": "Time Series Insights for IoT analytics",
    "Microsoft.VerifiedId": "Verified ID for decentralized identity",
    "Microsoft.VideoIndexer": "Video Indexer media AI",
    "Microsoft.VirtualMachineImages": "Image Builder for VM images",
    "Microsoft.VoiceServices": "Operator voice services",
    "Microsoft.Web": "App Service, Functions, and web apps",
    "Microsoft.WeightsAndBiases": "Weights & Biases MLOps on Azure",
    "Microsoft.Workloads": "Azure Center for SAP Solutions",
}

# Sub-services and distinct products bundled under umbrella providers.
# Many Azure providers contain multiple separately-marketed products that
# share a single resource provider namespace. This dict enumerates them
# so the report reflects the true breadth of knowledge required.
SUB_SERVICES: dict[str, list[str]] = {
    "Microsoft.CognitiveServices": [
        # Source: az cognitiveservices account list-kinds (22 kinds)
        "Azure OpenAI Service (GPT-4, GPT-4o, DALL-E, Whisper, Embeddings)",
        "Computer Vision (image analysis, OCR, spatial analysis)",
        "Content Moderator (text, image, video moderation)",
        "Content Safety (prompt shields, groundedness detection, jailbreak risk)",
        "Conversational Language Understanding (CLU intents and entities)",
        "Custom Vision \u2014 Prediction (image classification, object detection)",
        "Custom Vision \u2014 Training (model training, iteration management)",
        "Document Intelligence (form extraction, receipts, invoices, ID documents, custom models)",
        "Face API (detection, verification, identification, grouping, liveness)",
        "Health Insights (clinical NLP, patient timeline, radiology insights)",
        "Immersive Reader (text-to-speech, translation, syllabification for accessibility)",
        "Language Understanding (LUIS) \u2014 Authoring (intents, entities, utterances)",
        "Language Service \u2014 Authoring (sentiment, NER, key phrases, summarization, PII detection)",
        "Metrics Advisor (anomaly detection on multi-dimensional time series)",
        "Personalizer (real-time reinforcement learning recommendations)",
        "QnA Maker (knowledge base question answering)",
        "Speech Services (speech-to-text, text-to-speech, speech translation, speaker recognition, pronunciation assessment)",
        "Text Analytics (sentiment analysis, NER, key phrase extraction, language detection)",
        "Translator (text translation, document translation, transliteration, custom translator)",
        "AI Services (multi-service account \u2014 single key for all of the above)",
        "Cognitive Services (legacy multi-service account)",
    ],
    "Microsoft.Network": [
        "Virtual Network (VNet, subnets, peering, service endpoints, VNet integration)",
        "Network Security Group (NSG rules, application security group bindings)",
        "Application Security Group",
        "Load Balancer (Basic, Standard, Gateway; frontend IPs, backend pools, health probes, rules)",
        "Application Gateway (L7 load balancer, URL path routing, SSL termination, autoscale)",
        "Web Application Firewall (WAF policies, OWASP/CRS rules, custom rules, bot protection)",
        "Azure Firewall (network rules, application rules, NAT rules, threat intelligence, IDPS, TLS inspection)",
        "Firewall Policy (rule collection groups, rule collections, IP groups)",
        "Azure Bastion (secure RDP/SSH without public IPs; Basic, Standard, Developer SKUs)",
        "DDoS Protection Plan (Standard, network protection, IP protection)",
        "NAT Gateway (outbound SNAT, idle timeout, public IP association)",
        "Public IP Address (Basic, Standard; static, dynamic; IPv4, IPv6)",
        "Public IP Prefix (contiguous IP range, BYOIP)",
        "Custom IP Prefix (bring your own IP)",
        "Network Interface (NIC; IP configurations, accelerated networking, IP forwarding)",
        "Route Table (user-defined routes, BGP route propagation, next hop types)",
        "Route Filter (BGP community filtering for ExpressRoute)",
        "Virtual Network Gateway (VPN Gateway: S2S, P2S, VNet-to-VNet; IKEv2, OpenVPN, SSTP; active-active, zone-redundant)",
        "Local Network Gateway (on-premises VPN endpoint, BGP settings, address spaces)",
        "ExpressRoute Circuit (private peering, Microsoft peering; Standard, Premium; metered, unlimited)",
        "ExpressRoute Gateway (Standard, High Performance, Ultra Performance; FastPath)",
        "ExpressRoute Port (ExpressRoute Direct; 10 Gbps, 100 Gbps)",
        "Virtual WAN (hub-and-spoke topology, any-to-any connectivity)",
        "VPN Gateway (within Virtual WAN, S2S connections)",
        "P2S VPN Gateway (point-to-site within Virtual WAN)",
        "VPN Site (branch office connectivity definitions)",
        "Virtual Hub (routing, route tables, security partner providers)",
        "DNS Zone (public: A, AAAA, CAA, CNAME, DS, MX, NAPTR, NS, PTR, SOA, SRV, TLSA, TXT records)",
        "Private DNS Zone (private resolution within VNets; auto-registration, virtual network links)",
        "DNS Resolver (inbound endpoints, outbound endpoints, forwarding rules)",
        "DNS Resolver Policy (DNS security rules, virtual network links)",
        "Traffic Manager (DNS-based global load balancing; priority, weighted, performance, geographic, multivalue, subnet routing)",
        "Front Door (global load balancing, CDN, WAF, SSL offload, rules engine, caching; Classic, Standard, Premium)",
        "Private Endpoint (private connectivity to PaaS, custom Private Link services)",
        "Private Link Service (expose your own service via Private Endpoint)",
        "Network Watcher (topology, packet capture, IP flow verify, next hop, VPN diagnostics)",
        "Connection Monitor (end-to-end connectivity monitoring, latency, reachability)",
        "NSG Flow Logs (traffic analytics, retention policies)",
        "Network Manager (centralized connectivity configs, security admin rules, scope management)",
        "Network Security Perimeter (PaaS firewall, access rules, diagnostic logging)",
        "Network Virtual Appliance (orchestrated NVA deployment, boot diagnostics)",
        "DSCP Configuration (QoS traffic marking)",
        "IP Groups (reusable IP address collections for firewall rules)",
        "IP Allocation and IPAM (IP address management pools)",
        "Service Endpoint Policy (restrict VNet service endpoint access to specific resources)",
        "Virtual Network Tap (mirror network traffic for monitoring)",
        "Virtual Router (route server, BGP peering with NVAs)",
        "Azure Web Categories (URL categorization for firewall rules)",
        "Network Verifier (reachability analysis, intent verification)",
    ],
    "Microsoft.Compute": [
        "Virtual Machines (700+ SKU sizes across general purpose, compute, memory, storage, GPU, HPC, confidential families)",
        "Virtual Machine Scale Sets (uniform mode, flexible mode; autoscale, rolling upgrades, fault domains)",
        "Managed Disks (Ultra, Premium SSD v2, Premium SSD, Standard SSD, Standard HDD; bursting, shared disks)",
        "Disk Encryption Sets (platform-managed keys, customer-managed keys, double encryption, confidential encryption)",
        "Snapshots (incremental, full; cross-region copy, trusted launch)",
        "Disk Restore Points (crash-consistent, application-consistent)",
        "Images (generalized, specialized; managed images from VHDs)",
        "Compute Gallery (shared image galleries, image definitions, image versions, community galleries, direct shared galleries)",
        "VM Applications (VM application definitions, versions, custom script delivery)",
        "Availability Sets (fault domains, update domains)",
        "Proximity Placement Groups (low-latency co-location)",
        "Capacity Reservation Groups (guaranteed capacity, reservations per SKU)",
        "Dedicated Host Groups and Dedicated Hosts (single-tenant physical servers, host SKUs)",
        "SSH Public Keys (managed SSH keys for Linux VMs)",
        "VM Extensions (custom script, DSC, diagnostics, OMS agent, dependency agent, disk encryption, etc.)",
        "Cloud Services (extended support) (classic PaaS web and worker roles)",
        "Restore Point Collections (VM-level crash-consistent and app-consistent restore points)",
        "Disk Accesses (private endpoint access to managed disks)",
    ],
    "Microsoft.Security": [
        "Defender for Servers (Plan 1: basic EDR; Plan 2: full MDE, vulnerability assessment, file integrity monitoring, adaptive controls)",
        "Defender for App Service (threat detection for web apps and APIs)",
        "Defender for Azure SQL (threat detection, vulnerability assessment for SQL Database and Synapse)",
        "Defender for SQL on Machines (SQL Server on VMs and Arc-enabled SQL)",
        "Defender for Open-Source Relational Databases (PostgreSQL, MySQL, MariaDB threat detection)",
        "Defender for Storage (malware scanning, sensitive data threat detection, activity monitoring)",
        "Defender for Containers (runtime protection, image vulnerability scanning, Kubernetes policy, CI/CD scanning)",
        "Defender for Key Vault (anomalous access detection, secret/key enumeration alerts)",
        "Defender for DNS (domain generation algorithm detection, DNS tunneling, known malicious domains)",
        "Defender for Resource Manager (suspicious ARM operations, lateral movement, persistence)",
        "Defender for APIs (API threat detection, anomalous usage, OWASP API risks)",
        "Defender Cloud Security Posture Management (CSPM: attack path analysis, cloud security graph, agentless scanning)",
        "Security Alerts and Incidents (prioritized alerts, kill chain mapping)",
        "Security Assessments and Recommendations (benchmark-based security posture evaluation)",
        "Secure Score (quantified security posture across subscriptions)",
        "Regulatory Compliance (PCI DSS, ISO 27001, NIST 800-53, SOC 2, CIS Benchmarks, HIPAA, FedRAMP)",
        "Just-In-Time VM Access (time-limited RDP/SSH port opening)",
        "Adaptive Application Controls (allow-listing policy recommendations)",
        "Adaptive Network Hardening (NSG rule tightening recommendations)",
        "File Integrity Monitoring (registry, OS files, application files change detection)",
        "Workflow Automation (trigger Logic Apps on alerts, recommendations, compliance changes)",
        "Auto-Provisioning (automatic agent deployment: Log Analytics, Azure Monitor, MDE, Qualys)",
        "Multi-Cloud Connectors (AWS accounts, GCP projects \u2014 CSPM and CWP across clouds)",
        "DevOps Security (Azure DevOps, GitHub, GitLab: code scanning, IaC scanning, secrets detection)",
    ],
    "Microsoft.Insights": [
        "Azure Monitor Metrics (platform metrics, custom metrics, Prometheus metrics)",
        "Metric Alert Rules (static thresholds, dynamic thresholds, multi-resource, multi-condition)",
        "Activity Log (subscription-level operations, service health, autoscale events)",
        "Activity Log Alerts (administrative, service health, resource health, recommendation, security, policy)",
        "Scheduled Query Rules (log alerts using KQL, log search alerts, cross-resource queries)",
        "Action Groups (email, SMS, voice, push, webhook, ITSM, Event Hub, Logic App, Azure Function, Automation Runbook)",
        "Autoscale Settings (metric-based, schedule-based, predictive; scale-out/in rules, cooldown)",
        "Diagnostic Settings (platform logs and metrics routing to Log Analytics, Storage, Event Hub, partner solutions)",
        "Application Insights (APM: distributed tracing, dependency tracking, Live Metrics Stream, Availability Tests, smart detection)",
        "Application Insights \u2014 Profiler (code-level performance tracing)",
        "Application Insights \u2014 Snapshot Debugger (production exception debugging)",
        "Data Collection Rules (DCR: transformations, filtering, multi-destination routing, log ingestion API)",
        "Data Collection Endpoints (DCE: ingestion, configuration endpoints)",
        "Private Link Scopes (AMPLS: private connectivity for Monitor, Log Analytics, App Insights)",
        "Workbooks (interactive data visualization, parameterized queries, cross-resource dashboards)",
        "Webtests (classic URL ping tests, multi-step availability tests, standard web tests)",
    ],
    "Microsoft.Web": [
        "App Service Web Apps (Windows, Linux, custom containers; .NET, Java, Node.js, Python, PHP, Ruby)",
        "Azure Functions (Consumption, Flex Consumption, Premium, Dedicated; triggers: HTTP, Timer, Blob, Queue, Event Hub, Cosmos DB, etc.)",
        "App Service Plans (Free, Shared, Basic B1-B3, Standard S1-S3, Premium v3 P0v3-P3v3, Isolated v2 I1v2-I6v2)",
        "App Service Environments (ASE v3: internal/external load balancer, zone redundancy, dedicated isolated network)",
        "Deployment Slots (staging, canary, A/B testing; slot swaps, auto-swap, traffic routing percentages)",
        "App Service Certificates (standard, wildcard; Key Vault integration, auto-renewal)",
        "App Service Domains (domain registration, DNS management, privacy protection)",
        "Static Web Apps (global CDN, serverless API backends, GitHub/Azure DevOps CI/CD, auth providers)",
        "Hybrid Connections (TCP relay through Azure Relay, on-premises resource access without VPN)",
        "WebJobs (continuous, triggered background tasks within App Service)",
        "App Service Managed Certificates (free SSL certificates for custom domains)",
        "VNet Integration (regional VNet integration, gateway-required VNet integration, subnet delegation)",
    ],
    "Microsoft.Sql": [
        "SQL Database \u2014 Single Database (provisioned DTU, provisioned vCore, serverless vCore; General Purpose, Business Critical, Hyperscale)",
        "SQL Database \u2014 Elastic Pool (provisioned DTU, provisioned vCore; shared resources across databases)",
        "SQL Database \u2014 Hyperscale (up to 100 TB, read scale-out, named replicas, fast scale up/down, PITR up to 35 days)",
        "SQL Managed Instance (General Purpose, Business Critical; near 100% SQL Server compatibility, VNet injection, link feature)",
        "SQL Managed Instance \u2014 Pools (shared resources across multiple managed instances)",
        "Elastic Job Agent (cross-database T-SQL job scheduling)",
        "Failover Groups (automatic/manual geo-failover, read/write and read-only endpoints)",
        "Geo-Replication (active geo-replication, up to 4 readable secondaries)",
        "Long-Term Backup Retention (weekly, monthly, yearly backups up to 10 years)",
        "Short-Term Backup Retention (PITR: 1-35 days, locally redundant/zone-redundant/geo-redundant backup storage)",
        "Transparent Data Encryption (TDE: service-managed keys, customer-managed keys in Key Vault)",
        "Always Encrypted (client-side column encryption, secure enclaves)",
        "Auditing (server-level, database-level; to Storage, Log Analytics, Event Hub)",
        "Advanced Threat Protection (SQL injection detection, anomalous access, brute force)",
        "Vulnerability Assessment (security scanning, baseline management, remediation scripts)",
        "Dynamic Data Masking (default, email, random, custom string masking functions)",
        "Ledger (tamper-evident tables, append-only ledger tables, digest management)",
        "Sync Groups (bi-directional data sync between SQL databases and on-premises SQL Server)",
        "Server DNS Alias (CNAME indirection for connection string stability)",
        "Virtual Clusters (Managed Instance infrastructure grouping)",
        "DevOps Audit (Azure DevOps pipeline audit logging)",
    ],
    "Microsoft.ContainerService": [
        "AKS Cluster (managed Kubernetes control plane; free, standard, premium tiers)",
        "System Node Pools (CoreDNS, kube-proxy, metrics-server; taint-based workload segregation)",
        "User Node Pools (application workloads; auto-scaling, spot instances, ARM64, GPU, confidential VMs)",
        "Virtual Nodes (ACI burst-based serverless containers within AKS)",
        "AKS Fleet Manager (multi-cluster orchestration, update management, workload propagation)",
        "Cluster Extensions (Flux GitOps, Dapr, Azure ML, Azure Key Vault Secrets Provider, Azure Policy)",
        "Maintenance Configurations (planned maintenance windows for control plane and node OS updates)",
        "Managed Cluster Snapshots (node pool snapshots for rollback and cloning)",
        "Trusted Access Role Bindings (Azure service access to AKS clusters)",
        "AKS Network Policies (Azure NPM, Calico, Cilium; network plugin: kubenet, Azure CNI, Azure CNI Overlay, Cilium)",
        "Workload Identity (OIDC issuer, federated credentials, pod-level managed identity)",
        "AKS Automatic (opinionated Kubernetes with auto node provisioning, auto scaling, auto networking)",
        "Image Cleaner (stale image garbage collection)",
        "Backup (AKS backup via Velero integration with Azure Backup)",
    ],
    "Microsoft.Storage": [
        "Storage Accounts (general-purpose v2, BlobStorage, BlockBlobStorage premium, FileStorage premium; LRS, ZRS, GRS, GZRS, RA-GRS, RA-GZRS)",
        "Blob Storage (block blobs, append blobs, page blobs; hot, cool, cold, archive tiers; lifecycle management policies)",
        "Azure Data Lake Storage Gen2 (hierarchical namespace, POSIX ACLs, directory-level permissions)",
        "Azure Files (SMB 3.0/3.1.1, NFS 4.1; standard HDD, standard SSD, premium SSD; large file shares up to 100 TiB)",
        "Queue Storage (message queuing, 64 KB messages, 7-day retention, visibility timeout)",
        "Table Storage (NoSQL key-value store, OData protocol, partition/row key design)",
        "Immutable Storage (WORM: legal hold, time-based retention policies, version-level immutability)",
        "Blob Versioning (automatic version creation on overwrite/delete, version-level management)",
        "Soft Delete (blob, container, file share soft delete; retention period configuration)",
        "Encryption Scopes (Microsoft-managed keys, customer-managed keys per scope; infrastructure encryption)",
        "Object Replication (async cross-region or cross-account blob replication, prefix filters)",
        "Static Website Hosting (index document, error document, CDN integration)",
        "Storage Account Firewalls (IP rules, VNet rules, resource instance rules, trusted Azure services exceptions)",
        "Private Endpoints (per-service: blob, file, queue, table, DFS, web)",
        "Shared Access Signatures (account SAS, service SAS, user delegation SAS; stored access policies)",
        "Storage Tasks (data management actions, conditions, assignments, reporting)",
    ],
    "Microsoft.SecurityInsights": [
        "Microsoft Sentinel Workspace (SIEM/SOAR: analytics workspace, free trial, pay-as-you-go, commitment tiers)",
        "Data Connectors (Azure AD, Microsoft 365, AWS CloudTrail/S3/GuardDuty, GCP, Syslog, CEF, REST API, custom connectors, codeless connector platform)",
        "Analytics Rules (scheduled KQL, near-real-time NRT, Microsoft incident creation, ML-based Fusion, anomaly rules, threshold rules)",
        "Incidents (multi-alert correlation, severity, status, assignment, timeline, evidence, tasks)",
        "Investigation Graph (entity mapping, related alerts, timeline visualization, bookmark expansion)",
        "Automation Rules (trigger on incident/alert creation/update; run playbook, change severity, assign owner, add tags, close incident)",
        "Playbooks (Logic App-based SOAR workflows: containment, enrichment, notification, remediation)",
        "Workbooks (threat visualization dashboards, parameterized queries, cross-workspace templates)",
        "Watchlists (CSV-based lookup tables: IOCs, VIP users, exception lists, allow/deny lists)",
        "Threat Intelligence (STIX/TAXII feeds, TI indicators, threat intelligence platforms, Microsoft TI)",
        "Hunting Queries (KQL-based proactive threat hunting, livestream, bookmarks)",
        "Entity Behavior Analytics (UEBA: user/device/IP anomaly detection, peer group analysis, anomaly scoring)",
        "Notebooks (Jupyter notebooks, MSTICPy library, Azure ML compute, guided hunting notebooks)",
        "Content Hub (packaged solutions, data connectors, analytics rules, workbooks, playbooks per product/threat type)",
        "Repositories (GitHub/Azure DevOps CI/CD for Sentinel-as-code: analytics rules, automation, workbooks)",
        "SOC Optimizations (detection coverage analysis, data source health, MITRE ATT&CK mapping)",
    ],
    "Microsoft.MachineLearningServices": [
        "ML Workspace (Azure Machine Learning studio, notebooks, experiment tracking, model registry)",
        "Compute Instances (managed dev VMs: JupyterLab, VS Code, RStudio, terminal, SSH, auto-shutdown schedules)",
        "Compute Clusters (distributed training: auto-scaling, low-priority VMs, SSH, custom images)",
        "Kubernetes Compute (AKS or Arc-enabled Kubernetes attached to workspace)",
        "Online Endpoints (real-time inference: managed endpoints, blue/green deployments, traffic splitting, auto-scaling, SKU selection)",
        "Batch Endpoints (batch scoring: compute selection, mini-batch parallelism, output location, retry settings)",
        "Datastores (Azure Blob, Azure Files, ADLS Gen2, Azure SQL, credential-based and identity-based access)",
        "Environments (curated, custom Docker, Conda specifications; build context, environment versions)",
        "Models (registration, versioning, lineage tracking, model packaging, ONNX, MLflow, custom frameworks)",
        "Components (reusable pipeline steps: command, parallel, sweep, AutoML; input/output definitions)",
        "Pipelines and Jobs (training orchestration: pipeline jobs, command jobs, sweep jobs, AutoML jobs, spark jobs)",
        "Feature Stores (feature sets, materialization jobs, online/offline serving, feature retrieval specifications)",
        "Managed Online Endpoints (serverless model deployment, SKU-based scaling, request/response logging)",
        "Responsible AI Dashboard (fairness assessment, model explainability, error analysis, counterfactual analysis, causal inference)",
        "Prompt Flow (LLM orchestration: flow authoring, tool nodes, LLM nodes, Python nodes, variants, evaluation, deployment)",
        "Registries (cross-workspace asset sharing: models, environments, components, datasets)",
    ],
    "Microsoft.DocumentDB": [
        "Cosmos DB \u2014 NoSQL API (core SQL: document queries, stored procedures, triggers, UDFs, change feed, transactional batch)",
        "Cosmos DB \u2014 MongoDB API (vCore-based: dedicated compute; RU-based: shared throughput; wire protocol compatibility)",
        "Cosmos DB \u2014 Cassandra API (CQL compatible, throughput-provisioned tables, Cassandra driver support)",
        "Cosmos DB \u2014 Gremlin API (graph database: vertices, edges, traversal queries, graph partitioning)",
        "Cosmos DB \u2014 Table API (key-value store, OData protocol, Azure Table Storage compatible, global distribution)",
        "Cosmos DB \u2014 PostgreSQL API (Citus-based distributed PostgreSQL: sharding, distributed queries, columnar storage)",
        "Global Distribution (multi-region writes, automatic failover, configurable failover priorities, service-managed failover)",
        "Consistency Levels (strong, bounded staleness, session, consistent prefix, eventual \u2014 per-request overrides)",
        "Throughput Models (provisioned RU/s, serverless, autoscale with max RU/s, hierarchical partition keys)",
        "Continuous Backup (30-day PITR, 7-day PITR; per-account, per-container, per-database restore; Tier 1, Tier 2 retention)",
        "Analytical Store (column-oriented HTAP, auto-sync from transactional, Synapse Link, schema inference)",
        "Integrated Vector Database (vector indexing: flat, quantizedFlat, diskANN; vector search with distance functions)",
        "Materialized Views (auto-maintained read-optimized copies of data partitioned by alternate keys)",
    ],
    "Microsoft.RecoveryServices": [
        "Recovery Services Vault (unified backup and disaster recovery container; LRS, ZRS, GRS storage redundancy)",
        "Azure Backup \u2014 Azure VM (full, incremental, snapshot-based; application-consistent for Windows, crash-consistent for Linux)",
        "Azure Backup \u2014 SQL Server in Azure VM (full, differential, log backups; auto-protection of new databases)",
        "Azure Backup \u2014 SAP HANA in Azure VM (full, incremental, differential, log backups; Backint integration)",
        "Azure Backup \u2014 Azure Files (share-level snapshots, instant restore, retention policies)",
        "Azure Backup \u2014 Azure Blobs (vaulted backup, operational backup: continuous, point-in-time restore)",
        "Azure Backup \u2014 Azure Managed Disks (incremental snapshots, tag-based backup, exclude disk support)",
        "Azure Backup \u2014 Azure Database for PostgreSQL (long-term retention, full backup, user-managed identity)",
        "Azure Backup \u2014 Azure Kubernetes Service (AKS backup, namespace/label selection, Velero-based, vault/operational tiers)",
        "Azure Site Recovery \u2014 Azure to Azure (VM replication, recovery plans, failover/failback, network mapping)",
        "Azure Site Recovery \u2014 VMware/Physical to Azure (replication appliance, mobility agent, process server)",
        "Azure Site Recovery \u2014 Hyper-V to Azure (Hyper-V replica, Azure Site Recovery provider)",
        "Backup Policies (daily, weekly, monthly, yearly schedules; instant restore retention 1-5 days; LTR up to 99 years)",
        "Multi-User Authorization (MUA: Resource Guard, protected operations requiring secondary approval)",
        "Immutable Vaults (WORM for backup data, compliance-based and lock-based immutability)",
    ],
    "Microsoft.DataFactory": [
        "Data Factory Workspace (visual authoring, monitoring, management, Azure portal and desktop tools)",
        "Pipelines (orchestration activities: control flow, data movement, data transformation, scheduling, event-based triggers, tumbling window triggers)",
        "Datasets (90+ built-in connectors: Azure SQL, Blob, ADLS, Cosmos DB, REST, S3, SFTP, Snowflake, SAP, Oracle, HTTP, etc.)",
        "Linked Services (connection definitions: connection strings, managed identity, service principal, key vault references)",
        "Integration Runtimes (Azure IR: auto-resolve region, VNet-managed; self-hosted IR: on-premises/hybrid; Azure-SSIS IR: lift-and-shift SSIS packages)",
        "Data Flows (visual ETL: mapping data flows, wrangling data flows; Spark-based execution; 200+ transformations)",
        "Managed Virtual Network and Managed Private Endpoints (isolated network, private connectivity to data stores)",
        "Change Data Capture (CDC: continuous incremental data replication, mapping to sink, auto-publish)",
        "Source Control Integration (Git: Azure DevOps, GitHub; CI/CD pipelines, publish branches, auto-publish)",
        "Global Parameters (factory-level key-value pairs, overridable in CI/CD pipelines)",
    ],
    "Microsoft.Synapse": [
        "Synapse Workspace (unified analytics workspace: studio, pipelines, notebooks, SQL, Spark, KQL)",
        "Dedicated SQL Pool (formerly SQL Data Warehouse: MPP, DWU-based scaling, workload management, result set caching)",
        "Serverless SQL Pool (on-demand query: pay-per-TB processed, external tables, OPENROWSET, CETAS)",
        "Apache Spark Pool (Spark 3.x: notebooks, batch jobs, Spark SQL, MLlib, auto-scale, library management)",
        "Data Explorer Pool (Kusto: real-time analytics, time series, free-text search, KQL queries)",
        "Pipelines (inherited from Data Factory: 90+ connectors, orchestration, triggers, data movement)",
        "Integration Runtimes (Azure, self-hosted; managed VNet support)",
        "Managed Private Endpoints (private connectivity to Azure services from Synapse managed VNet)",
        "Synapse Link (zero-ETL live analytics: Cosmos DB, SQL, Dataverse; real-time analytical processing)",
    ],
    "Microsoft.DesktopVirtualization": [
        "Host Pools (pooled: shared multi-session; personal: dedicated single-session; depth-first, breadth-first load balancing)",
        "Application Groups (desktop: full desktop experience; RemoteApp: individual published applications)",
        "Workspaces (user-facing portal grouping, feed discovery, URL-based access)",
        "Session Hosts (Windows 10/11 Enterprise multi-session, Windows Server; Azure VM or Azure Stack HCI)",
        "Scaling Plans (autoscale: peak, off-peak, ramp-up, ramp-down schedules; pooled and personal plan types)",
        "MSIX App Attach (application delivery: MSIX packages, VHD/VHDX/CIM containers, dynamic app attachment)",
        "Multimedia Redirection (browser content redirection for media-heavy sites)",
        "RDP Properties (custom RDP settings: device redirection, display, clipboard, audio, camera, USB)",
        "Private Endpoints (private connectivity to host pool, workspace, feed, gateway)",
    ],
    "Microsoft.HealthcareApis": [
        "Healthcare Workspace (container for health data services, managed identity, private endpoints)",
        "FHIR Service (R4, STU3; SMART on FHIR; $export, $import, $convert-data, $member-match; custom search, versioning, conditional operations)",
        "DICOM Service (DICOMweb: STOW-RS, WADO-RS, QIDO-RS; medical imaging storage, retrieval, search; DICOM cast to FHIR)",
        "MedTech Service (IoT data ingestion: IoT Hub/Event Hub source, FHIR destination mapping, device-to-patient resolution, calculated content, group mapping)",
    ],
    "Microsoft.ApiManagement": [
        "API Management Service (Developer, Basic, Standard, Premium, Consumption, v2 tiers; single-region, multi-region, availability zones)",
        "APIs (REST, SOAP, WebSocket, GraphQL, gRPC; OpenAPI, WSDL, WADL import; versioning, revisions)",
        "API Operations and Policies (inbound, backend, outbound, on-error pipeline; rate-limit, quota, JWT validation, IP filter, rewrite, cache, CORS, mock)",
        "Products (API bundling for developer portal; subscription required/open; approval workflow; rate limits per product)",
        "Developer Portal (self-service: API documentation, try-it console, user registration, API keys, customization, self-hosted)",
        "Subscriptions and API Keys (primary/secondary keys, product-scoped, API-scoped, all-APIs scoped)",
        "Named Values (secrets, plain values, Key Vault references; used in policies)",
        "Backends (backend service entities: Service Fabric, Azure Functions, Logic Apps, custom URLs; circuit breaker, load balancing)",
        "Certificates (client certificates, CA certificates, gateway certificates; Key Vault integration)",
        "Diagnostics and Logging (Application Insights integration, Azure Monitor, custom logger; sampling, verbosity)",
        "Authorization Providers (OAuth 2.0, OpenID Connect; managed identity; credential manager for SaaS backends)",
        "Workspaces (multi-team API governance: isolated API sets per team with delegated management)",
    ],
    "Microsoft.KeyVault": [
        "Key Vault \u2014 Standard (software-protected keys, secrets, certificates; RBAC or access policy authorization)",
        "Key Vault \u2014 Premium (HSM-backed keys: FIPS 140-2 Level 2; software-protected secrets and certificates)",
        "Managed HSM (dedicated FIPS 140-2 Level 3 HSM; single-tenant, customer-controlled security domain; local RBAC)",
        "Keys (RSA 2048/3072/4096, EC P-256/P-384/P-521, AES 128/256; create, import, wrap/unwrap, sign/verify, encrypt/decrypt)",
        "Secrets (arbitrary byte sequences up to 25 KB; connection strings, passwords, API keys; versioning, expiry, activation date)",
        "Certificates (self-signed, CA-issued: DigiCert, GlobalSign; Let's Encrypt via renewal; PKCS#12, PEM; auto-renewal, lifetime actions)",
        "Key Rotation Policy (automatic key rotation: time-based trigger, notification before expiry)",
        "Access Control (vault access policies vs Azure RBAC; per-key, per-secret, per-certificate permissions)",
        "Soft Delete and Purge Protection (90-day retention, purge protection lock, recover deleted objects)",
        "Private Endpoints and Firewall Rules (IP rules, VNet rules, trusted Azure services bypass)",
        "Backup and Restore (individual key/secret/certificate backup; cross-region restore for Managed HSM)",
    ],
    "Microsoft.Cache": [
        "Azure Cache for Redis \u2014 Basic (single node, no SLA, development/testing only; C0-C6 sizes)",
        "Azure Cache for Redis \u2014 Standard (primary/replica pair, SLA, replication; C0-C6 sizes)",
        "Azure Cache for Redis \u2014 Premium (clustering up to 10 shards, VNet injection, persistence RDB/AOF, geo-replication; P1-P5 sizes)",
        "Azure Cache for Redis \u2014 Enterprise (Redis Enterprise: RediSearch, RedisJSON, RedisBloom, RedisTimeSeries; E10-E100 sizes)",
        "Azure Cache for Redis \u2014 Enterprise Flash (NVMe + RAM, cost-effective large caches; F300-F1500 sizes)",
        "Active Geo-Replication (Enterprise tier: multi-region active-active, conflict resolution, write to any replica)",
        "Passive Geo-Replication (Premium tier: async secondary, manual failover)",
        "Data Persistence (RDB snapshots, AOF logging: Premium, Enterprise; backup frequency, storage account)",
        "Redis Modules (Enterprise: RediSearch full-text search, RedisJSON document store, RedisBloom probabilistic data structures, RedisTimeSeries)",
        "Clustering (Premium: hash-based sharding up to 10 shards; Enterprise: up to 100+ shards, OSS cluster mode)",
    ],
    "Microsoft.EventHub": [
        "Event Hubs Namespace (Basic, Standard, Premium, Dedicated; throughput units, processing units, capacity units)",
        "Event Hubs (partitions: 1-1024; retention: 1-90 days; capture to Blob/ADLS; consumer groups up to 20/100)",
        "Consumer Groups ($Default and custom; independent read positions, checkpointing)",
        "Schema Registry (Avro, JSON Schema, custom; schema groups, versioning, compatibility modes)",
        "Event Hubs Capture (automatic archival to Blob/ADLS Gen2; Avro format, time/size windowing)",
        "Kafka Protocol Support (Apache Kafka 1.0+ compatible endpoint, no code change required for Kafka clients)",
        "Geo-Disaster Recovery (namespace pairing, metadata failover, alias endpoint)",
        "Application Groups (client-level throttling policies: SAS, AAD-based; rate limiting per connection/group)",
    ],
    "Microsoft.ServiceBus": [
        "Service Bus Namespace (Basic, Standard, Premium; messaging units 1-16; zone redundancy; geo-disaster recovery)",
        "Queues (FIFO, dead-letter queue, sessions, duplicate detection, message deferral, scheduled delivery, auto-forwarding, TTL)",
        "Topics (pub/sub messaging, up to 2000 subscriptions per topic, partitioned topics, auto-forwarding)",
        "Subscriptions (filter rules: SQL filter, correlation filter, boolean filter; actions; dead-letter on filter evaluation exception)",
        "Premium Features (message size up to 100 MB, VNet integration, private endpoints, customer-managed keys, Java Message Service 2.0)",
        "Geo-Disaster Recovery (namespace pairing, primary/secondary, alias connection string, manual failover)",
    ],
    "Microsoft.Logic": [
        "Logic Apps \u2014 Consumption (serverless multi-tenant; per-execution pricing; visual designer; 400+ managed connectors)",
        "Logic Apps \u2014 Standard (dedicated single-tenant; stateful and stateless workflows; VS Code authoring; VNet integration)",
        "Built-in Connectors (HTTP, Request/Response, Service Bus, Azure Blob, Azure Queue, Event Hub, Cosmos DB, SQL, Azure Functions, etc.)",
        "Managed Connectors (Office 365, SharePoint, Dynamics 365, Salesforce, SAP, Oracle, IBM MQ, Twitter, Slack, 400+ total)",
        "Custom Connectors (OpenAPI/Swagger-based, custom actions, authentication configuration, API key/OAuth/basic)",
        "Integration Service Environment (ISE: dedicated isolated environment, fixed pricing, private VNet access; retired but in use)",
        "Integration Account (B2B enterprise integration: EDI partners, agreements, AS2, X12, EDIFACT, schemas, maps, certificates, RosettaNet)",
        "Workflow Expressions (WDL: conditions, loops, variables, expressions, functions, error handling, retry policies, concurrency control)",
    ],
    "Microsoft.ContainerRegistry": [
        "Container Registry (Basic: 10 GiB; Standard: 100 GiB; Premium: 500 GiB; zone redundancy, content trust, customer-managed encryption)",
        "Repositories and Tags (Docker, OCI images and artifacts; tag locking, delete policies, retention policies)",
        "Geo-Replication (Premium: multi-region registry, network-close image pull; replica webhooks)",
        "Content Trust (Docker Notary v2, image signing, signature verification)",
        "Vulnerability Scanning (Defender for Containers integration, continuous scanning, scan-on-push)",
        "ACR Tasks (multi-step build, test, push; triggered by source code commit, base image update, timer; cross-registry, cross-platform)",
        "Token and Scope Maps (repository-level granular permissions, read/write/delete per repository, token management)",
        "Connected Registries (on-premises, IoT Edge, nested edge; sync with cloud registry; read-only or read-write modes)",
        "Private Endpoints and Firewall Rules (per-registry network restriction, dedicated data endpoints, trusted services)",
    ],
    "Microsoft.Databricks": [
        "Databricks Workspace (interactive notebooks, workspace management, access control, Unity Catalog integration)",
        "All-Purpose Clusters (interactive development: autoscale, spot instances, init scripts, Docker, custom images, libraries)",
        "Job Clusters (automated ETL/ML workflows: ephemeral, cost-optimized, multi-task jobs, retries, alerts)",
        "SQL Warehouses (Databricks SQL: serverless, pro, classic; T-shirt sizing, auto-stop, query caching)",
        "Unity Catalog (metastore, catalogs, schemas, tables, volumes; row/column security, data lineage, audit logging)",
        "Delta Lake (ACID transactions, time travel, schema enforcement/evolution, Z-ordering, liquid clustering)",
        "Delta Live Tables (declarative ETL pipelines: expectations/quality rules, auto-scaling, enhanced autoscaling)",
        "MLflow (experiment tracking, model registry, model serving, feature engineering, model signatures)",
        "Repos (Git integration: Azure DevOps, GitHub, GitLab, Bitbucket; branch management, CI/CD)",
        "DBFS (Databricks File System: workspace storage, mount points, Unity Catalog volumes)",
        "Databricks Connect (remote Spark execution from IDE)",
    ],
    "Microsoft.Automation": [
        "Automation Account (identity, modules, shared resources, hybrid worker groups, managed identity)",
        "Runbooks (PowerShell 5.1/7.2, Python 2/3, graphical, PowerShell workflow; draft/published versioning)",
        "Schedules and Jobs (one-time, recurring, hourly, daily, weekly, monthly; job streams, job history, fair share)",
        "DSC Configurations (Desired State Configuration: node configurations, compilation, node compliance reports)",
        "DSC Nodes (Windows, Linux managed nodes; pull mode, configuration drift detection, compliance status)",
        "Variables, Credentials, Certificates, Connections (encrypted shared resources across runbooks)",
        "Hybrid Runbook Workers (run on-premises or other clouds; user-based, extension-based; worker groups)",
        "Webhooks (HTTP trigger for runbooks, expiry date, parameter passing, token-based security)",
        "Update Management v2 (Azure Update Manager: VM patching, maintenance windows, periodic assessment, pre/post scripts)",
        "Source Control Integration (GitHub, Azure DevOps, local Git; auto-sync, folder-based runbook mapping)",
        "Python Packages (custom PyPI packages, Python 2 and Python 3 environments, package versioning)",
    ],
    "Microsoft.EventGrid": [
        "System Topics (Azure resource events: Blob Storage, Resource Group, IoT Hub, Service Bus, Event Hub, Key Vault, etc.)",
        "Custom Topics (application-defined events: JSON, CloudEvents schema; endpoint validation, input mapping)",
        "Event Domains (multi-tenant: up to 100,000 topics per domain, per-topic publishing, domain-scoped subscriptions)",
        "Event Subscriptions (webhook, Azure Functions, Storage Queue, Event Hub, Service Bus Queue/Topic, Hybrid Connection destinations)",
        "Partner Topics (third-party SaaS events: Auth0, Tribal Group, SAP; partner namespaces, channel authorization)",
        "Namespaces (MQTT v5/v3.1.1 broker: topic spaces, routing rules, clients, client groups, permission bindings; pull delivery: queue subscriptions)",
        "Dead-Letter Destinations (failed event delivery: blob storage, retry policies, max delivery attempts, event TTL)",
        "Advanced Filtering (string/number/boolean operators, nested field filtering, subject prefix/suffix, OR conditions)",
    ],
    "Microsoft.Kusto": [
        "Azure Data Explorer Cluster (Dev/Test, Extra Small, Small, Medium, Large, Storage Optimized; auto-scale, streaming ingestion, follower databases)",
        "Databases (read-write, read-only follower; soft delete period, hot cache period, table retention policies)",
        "Data Connections (Event Hub, IoT Hub, Event Grid: continuous ingestion, mapping, format: JSON, CSV, Avro, Parquet, ORC, etc.)",
        "Tables (schema management, retention policies, update policies, restricted view access, row-level security)",
        "Materialized Views (auto-updated aggregated views, deduplication, backfill, monitoring metrics)",
        "External Tables (Azure Blob, ADLS, SQL: query without ingestion, virtual columns, schema mapping)",
        "Managed Private Endpoints (private connectivity to data sources: Event Hub, Storage, SQL, Cosmos DB)",
        "Database Principal Assignments (admin, user, viewer, ingestor; AAD users, groups, service principals)",
        "Scripts (KQL management commands, run on attach, idempotent execution, continue-on-error)",
        "Sandboxes (Python, R plugins: isolated execution, cross-cluster queries, deep analytics)",
    ],
    "Microsoft.HDInsight": [
        "Hadoop Cluster (HDFS, MapReduce, YARN, Hive, HBase, Oozie, Ranger, Ambari; ESP, autoscale)",
        "Spark Cluster (Apache Spark 3.x: notebooks, Livy API, Spark SQL, structured streaming, MLlib)",
        "HBase Cluster (wide-column NoSQL: region servers, auto-failover, accelerated writes, enhanced writes)",
        "Interactive Query Cluster (Hive LLAP: low-latency analytical processing, in-memory caching, JDBC/ODBC)",
        "Kafka Cluster (Apache Kafka: topics, partitions, consumer groups, Kafka Connect, Schema Registry, MirrorMaker)",
        "HDInsight on AKS (next-gen: Trino, Flink, Spark; pool-based, auto-scale, integration with Unity Catalog)",
    ],
    "Microsoft.AVS": [
        "Azure VMware Solution Private Cloud (VMware vSphere, vSAN, NSX-T; AV36, AV36P, AV52, AV64 hosts)",
        "Clusters (vSphere clusters: 3-16 hosts, stretched clusters, fault domains)",
        "Datastores (vSAN, ANF-backed, Elastic SAN-backed external storage)",
        "HCX (Hybrid Cloud Extension: VM migration, network extension, disaster recovery)",
        "NSX-T Segments (network segments, DHCP, DNS, firewall rules, gateway, load balancing)",
        "vSphere RBAC (CloudAdmin role, custom roles, identity sources, LDAP/LDAPS integration)",
        "ExpressRoute Global Reach (on-premises to AVS connectivity)",
        "Internet Connectivity (managed SNAT, public IP down to workload level)",
        "Add-ons (VMware HCX, SRM, vRealize Operations, Arc integration)",
    ],
    "Microsoft.App": [
        "Container Apps Environment (managed Kubernetes: consumption, dedicated workload profiles; VNet injection, internal/external)",
        "Container Apps (HTTP, TCP, event-driven: revision-based deployment, traffic splitting, scale rules, Dapr sidecar)",
        "Container Apps Jobs (manual, scheduled, event-driven: one-off tasks, batch processing, cron expressions)",
        "Dapr Components (state stores, pub/sub, bindings, secret stores, configuration stores; per-app scoping)",
        "Managed Certificates (free SSL, custom domain binding, SNI)",
        "Authentication (built-in auth: Azure AD, Apple, Facebook, GitHub, Google, Twitter, custom OpenID Connect)",
        "Scale Rules (HTTP concurrent requests, TCP connections, Azure Queue, Azure Service Bus, Apache Kafka, custom KEDA scalers)",
        "Container Apps Connected Environments (Arc-enabled, on-premises Kubernetes, hybrid deployment)",
    ],
    "Microsoft.Purview": [
        "Microsoft Purview Data Governance (data catalog, data map, data estate insights, business glossary, classifications)",
        "Data Map (automated scanning: Azure SQL, Blob, ADLS, Synapse, Power BI, SQL Server, S3, Snowflake, SAP, Oracle, Teradata, etc.)",
        "Collections (hierarchical access control, data source grouping, role assignments per collection)",
        "Classification Rules (built-in: PII, financial, healthcare; custom regex patterns, dictionary-based, machine learning)",
        "Business Glossary (business terms, hierarchies, related terms, classifications, contacts, approved/draft/expired lifecycle)",
        "Data Lineage (automatic column-level lineage from Data Factory, Synapse, Databricks, Power BI; manual lineage)",
        "Data Estate Insights (data stewardship, classification distribution, sensitivity labels, glossary coverage, scan health)",
        "Self-Service Data Access Policies (request, approve, and manage access to data sources through Purview)",
    ],
    "Microsoft.Fabric": [
        # ARM layer is thin (capacities, private link), but SaaS layer is massive
        "Lakehouse (Delta Lake-based: tables, files, shortcuts, SQL analytics endpoint, default dataset, schema discovery)",
        "Warehouse (T-SQL distributed data warehouse: tables, views, stored procedures, cross-database queries, zero-copy table clone)",
        "Data Engineering — Spark Notebooks (PySpark, Spark SQL, Scala, R; session configuration, libraries, environment management)",
        "Data Engineering — Spark Job Definitions (batch Spark jobs: main file, reference files, arguments, retries)",
        "Data Pipeline (orchestration: 90+ connectors, copy activity, data flow, Notebook activity, stored procedure, web activity, ForEach, If, Until, Switch)",
        "Dataflow Gen2 (Power Query Online ETL: 300+ data sources, M-language transformations, staging, fast copy)",
        "Data Science — ML Experiments (experiment tracking, runs, metrics, parameters, model logging, MLflow integration)",
        "Data Science — ML Models (model registry: versions, deployment, endorsement, lineage)",
        "Power BI Reports (interactive visualizations: 80+ visual types, DAX, report themes, drill-through, bookmarks, Q&A natural language)",
        "Power BI Semantic Models (formerly datasets: import, DirectQuery, composite, hybrid tables, calculation groups, row-level security, OLS)",
        "Power BI Dashboards (pinned tiles, real-time streaming, data alerts, natural language Q&A)",
        "Power BI Paginated Reports (pixel-perfect reports: SSRS/RDL, sub-reports, nested data regions, export to PDF/Excel/Word)",
        "Power BI Datamart (self-service relational database: auto-generated SQL endpoint, visual query designer, row-level security)",
        "Real-Time Intelligence — KQL Database (Kusto-based: streaming ingestion, KQL queries, materialized views, data retention policies)",
        "Real-Time Intelligence — KQL Queryset (saved KQL queries, parameterized, shareable)",
        "Real-Time Intelligence — Eventstream (real-time data ingestion: Event Hub, IoT Hub, Custom App, Azure Blob; routing rules, transformations)",
        "Real-Time Intelligence — Activator (data-driven alerts: Reflex items, triggers, conditions, actions; email, Teams, Power Automate)",
        "Real-Time Intelligence — Real-Time Dashboard (live KQL-based dashboards: tiles, parameters, auto-refresh)",
        "OneLake (unified storage layer: Delta Parquet format, shortcuts to ADLS/S3/GCS/Dataverse, cross-workspace access, BCDR, one-copy architecture)",
        "OneLake Data Hub (centralized data catalog: discover, browse, endorse, certify items across all Fabric workspaces)",
        "Mirroring (continuous near-real-time replication: Azure SQL, Cosmos DB, Snowflake → OneLake Delta tables)",
        "Data Activator (event-driven triggers on data changes: no-code rule builder, Teams/email/Power Automate actions)",
        "Fabric Capacities (F2-F2048 SKUs; trial capacity; pause/resume; smoothing; cross-region; reservation via Azure portal)",
        "Fabric Domains (organizational grouping of workspaces: ownership, endorsement policies, governance boundaries)",
        "Fabric Git Integration (Azure DevOps, GitHub: branch-based source control for all item types, deployment pipelines)",
        "Fabric Deployment Pipelines (dev → test → prod promotion: comparison view, selective deployment, deployment rules, auto-binding)",
        "Fabric Copilot (AI-assisted: DAX generation, code suggestions, data insights, report creation, KQL generation)",
        "Industry Solutions — Healthcare (clinical analytics, FHIR-integrated reports)",
        "Industry Solutions — Retail (unified customer analytics, demand forecasting)",
        "Industry Solutions — Sustainability (ESG data analytics, emissions tracking dashboards)",
    ],
    "Microsoft.Devices": [
        "IoT Hub (Standard S1/S2/S3, Basic B1/B2/B3, Free; device-to-cloud, cloud-to-device, direct methods, device twins, module twins)",
        "IoT Hub — Message Routing (custom endpoints: Event Hub, Service Bus, Blob Storage; routing queries, enrichments, fallback route)",
        "IoT Hub — File Upload (device file upload via Blob Storage, notifications, SAS URI provisioning)",
        "IoT Hub — Device Provisioning Service (DPS: zero-touch enrollment; individual, group enrollments; TPM, X.509, symmetric key attestation; allocation policies)",
        "IoT Hub — Jobs (scheduled device twin updates, direct method invocations across device fleets)",
        "IoT Hub — Automatic Device Management (device configuration at scale: target conditions, metrics, priority, layered configurations)",
        "IoT Edge (edge compute runtime: custom modules, marketplace modules, deployment manifests, layered deployments, offline operation)",
        "IoT Edge — Module Twins (per-module desired/reported properties, module direct methods)",
        "IoT Edge — Nested Edge (ISA-95 network isolation: parent-child edge hierarchy, transparent gateway)",
        "IoT Central (SaaS IoT application platform: device templates, dashboards, rules, data export, jobs, organizations, edge gateway management)",
        "Device Update for IoT Hub (OTA firmware updates: deployment groups, compliance, rollback, delta updates, import manifests)",
        "Defender for IoT (agentless OT/IoT network monitoring: sensor deployment, PCAP analysis, CVE detection, MITRE ATT&CK for ICS mapping)",
    ],
    "Microsoft.Authorization": [
        "Role-Based Access Control (RBAC: 400+ built-in roles, custom role definitions, deny assignments)",
        "Role Assignments (scope hierarchy: management group → subscription → resource group → resource; conditions, principal types)",
        "Custom Role Definitions (JSON-based: actions, notActions, dataActions, notDataActions, assignable scopes)",
        "Azure Policy — Definitions (built-in: 1000+ policies; custom: Audit, Deny, Modify, DeployIfNotExists, Disabled, Manual effects)",
        "Azure Policy — Initiatives (policy sets: regulatory compliance, security baselines, organizational standards; parameter groups)",
        "Azure Policy — Assignments (scope, exclusions, enforcement mode, managed identity for remediation, non-compliance messages)",
        "Azure Policy — Remediation Tasks (resource remediation for DeployIfNotExists and Modify; re-evaluation, parallel remediation)",
        "Azure Policy — Exemptions (waiver, mitigated; time-bound, resource-specific policy exception)",
        "Resource Locks (CanNotDelete, ReadOnly; scope-based, inheritance, lock notes)",
        "Privileged Identity Management (PIM: just-in-time role activation, approval workflows, access reviews, time-bound assignments)",
        "Access Reviews (periodic recertification: role assignments, group membership, application access; auto-apply, recommendations)",
        "Blueprints (deprecated: environment templates with RBAC, policy, ARM templates, resource groups; assignment, locking)",
        "Conditions (ABAC: attribute-based access control, storage blob conditions, role assignment conditions)",
        "Eligible Role Assignments (PIM-managed: activation required, MFA, justification, ticket information, approval chain)",
    ],
    "Microsoft.Resources": [
        "ARM Deployments (JSON/Bicep: incremental, complete modes; what-if, deployment stacks, nested deployments, linked templates)",
        "Template Specs (versioned ARM templates: cross-subscription sharing, parameter file, UI form definitions)",
        "Deployment Stacks (managed deployment lifecycle: deny settings, unmanage actions for resources/resource groups, update behavior)",
        "Bicep (DSL for ARM: modules, parameters, variables, outputs, resource loops, conditional resources, user-defined types, compile-time validation)",
        "Resource Groups (logical container: tagging, RBAC, policy, region, deletion protection via locks)",
        "Tags (name-value pairs: cost allocation, automation, governance; tag inheritance policies, required tag policies)",
        "What-If Analysis (deployment preview: create, modify, delete, no-change predictions; property-level diff)",
        "Resource Providers (registration, feature flags, resource type discovery, API version management)",
        "Managed Applications (ISV marketplace: createUiDefinition, mainTemplate, authorization, managed resource group)",
        "Move Resources (cross-resource-group, cross-subscription moves; validation, supported resource types)",
    ],
    "Microsoft.Management": [
        "Management Groups (hierarchical subscription organization: up to 6 levels deep, root tenant group)",
        "Management Group Policies (policy/initiative assignment at management group scope, cascading inheritance)",
        "Management Group RBAC (role assignment at management group scope, inherited by all child subscriptions)",
        "Management Group Diagnostic Settings (activity log forwarding for all child subscriptions)",
    ],
    "Microsoft.Cdn": [
        "Azure CDN — Standard Microsoft (global PoPs, caching rules, geo-filtering, URL redirect/rewrite, HTTPS, custom domains)",
        "Azure CDN — Standard/Premium Verizon (advanced analytics, real-time stats, token auth, advanced HTTP features, mobile device rules)",
        "Azure CDN — Standard Akamai (large file optimization, dynamic site acceleration, video streaming optimization)",
        "Azure Front Door — Standard (global L7 load balancing, SSL offload, URL path routing, caching, compression, health probes)",
        "Azure Front Door — Premium (private link origins, WAF with managed rule sets, bot protection, DDoS protection, enhanced analytics)",
        "CDN Profiles and Endpoints (origin groups, origins, routes, rule sets, secret management, custom domain HTTPS)",
        "Rules Engine (request/response header modification, URL redirect/rewrite, route configuration override, cache key customization)",
        "WAF Policies for Front Door (custom rules, managed rules: Microsoft Default/Bot Manager, rate limiting, geo-filtering, IP restriction)",
    ],
    "Microsoft.SignalRService": [
        "Azure SignalR Service (Free, Standard, Premium; serverless, default, classic modes; unit-based scaling; 100K+ concurrent connections)",
        "Azure Web PubSub (WebSocket-based pub/sub: hubs, groups, permissions, event handlers, client protocols, REST API publishing)",
        "SignalR Shared Private Link (private connectivity to upstream Azure Functions, App Service, etc.)",
        "Web PubSub for Socket.IO (managed Socket.IO server: rooms, namespaces, auto-scaling, built-in auth)",
    ],
    "Microsoft.Maps": [
        "Render API (road maps, satellite imagery, weather tiles, traffic tiles, DEM tiles, indoor maps; vector, raster)",
        "Search API (geocoding, reverse geocoding, fuzzy search, POI search, address validation, structured address search)",
        "Route API (driving, walking, cycling, truck directions; waypoints, alternative routes, traffic-aware, EV routing, matrix routing)",
        "Traffic API (traffic flow, traffic incidents, real-time and predictive traffic data)",
        "Weather API (current conditions, hourly/daily/quarterly forecasts, severe weather alerts, weather along route, tropical storms, air quality, indices)",
        "Geolocation API (IP address to country/region lookup)",
        "Spatial API (geofencing, closest point, point in polygon, great circle distance, buffer/intersect operations)",
        "Timezone API (timezone by coordinates, timezone by ID, Windows IANA mapping)",
        "Elevation API (point, path, and bounding box elevation queries, DEM data)",
        "Data Registry API (upload and manage geospatial datasets: GeoJSON, KML, ZIP; spatial indexing, search)",
        "Creator — Indoor Maps (floor plans, wayfinding, facility management, custom styling, feature state management)",
        "Creator — Tileset/Dataset/Conversion (CAD/DWG/GeoJSON to map tiles, custom indoor map styling, feature queries)",
    ],
    "Microsoft.Communication": [
        "Communication Services Resource (multi-channel communication platform: SaaS endpoints, managed identity, event subscriptions)",
        "Chat (real-time messaging: threads, participants, typing indicators, read receipts, file attachments, inline images, push notifications)",
        "Calling (VoIP, PSTN: 1:1, group calls, call recording, call transcription, call automation, media composition, rooms)",
        "SMS (send/receive, toll-free, short code, alphanumeric sender ID, opt-out management, delivery reports)",
        "Email (high-volume transactional email: custom domains, DKIM/SPF/DMARC, attachments, tracking, suppression lists)",
        "Phone Numbers (toll-free, geographic, short codes; number porting, direct routing, SIP trunking via direct routing)",
        "Network Traversal (TURN relay tokens for WebRTC NAT traversal)",
        "Rooms (structured meetings: participant roles presenter/attendee/consumer, PSTN dial-out, scheduled sessions)",
        "Job Router (intelligent task routing: queues, distribution policies, classification policies, exception policies, worker matching)",
        "Call Automation (server-side call control: create, transfer, add participant, play audio, recognize DTMF/speech, recording)",
        "Advanced Messaging (WhatsApp Business: template messages, session messages, media messages, interactive messages)",
        "Virtual Appointments (Teams-integrated: scheduling, reminders, SMS notifications, waiting room, browser-based join)",
    ],
    "Microsoft.Monitor": [
        "Azure Monitor Workspace (Prometheus metrics: remote write, Grafana integration, data collection rules, rule groups)",
        "Pipeline Groups (data routing: exporters to Log Analytics, Azure Monitor, external destinations; processors for filtering/transformation)",
        "Prometheus Rule Groups (recording rules, alerting rules: PromQL, evaluation intervals, labels, annotations)",
    ],
    "Microsoft.OperationalInsights": [
        "Log Analytics Workspace (KQL-based log analytics: pay-as-you-go, commitment tiers 100-5000 GB/day; 30-730 day retention; dedicated clusters)",
        "Log Analytics — Tables (Azure tables, custom log tables, search-result tables; Analytics, Basic, Archive plans; table-level RBAC, transformations)",
        "Log Analytics — Saved Searches and Functions (reusable KQL queries, user/computer groups, function parameters)",
        "Log Analytics — Data Export Rules (continuous export to Storage/Event Hub; table selection, destination routing)",
        "Log Analytics — Linked Services (Automation account, cluster; dedicated cluster customer-managed keys)",
        "Log Analytics — Query Packs (shared KQL query collections: labels, descriptions, parameterized queries)",
        "Log Analytics — Solutions (legacy: VMInsights, ContainerInsights, SecurityInsights, ServiceMap; installed via workspace)",
        "Log Analytics Clusters (dedicated capacity: customer-managed keys, double encryption, cross-workspace queries, availability zones)",
    ],
    "Microsoft.Migrate": [
        "Azure Migrate Project (hub for migration/modernization: discovery, assessment, migration tools; multi-tool extensibility)",
        "Discovery and Assessment — Servers (VMware, Hyper-V, physical, AWS, GCP: configuration, performance, dependency analysis)",
        "Discovery and Assessment — SQL (SQL Server instances, databases: readiness, SKU sizing, Azure SQL target recommendations)",
        "Discovery and Assessment — Web Apps (ASP.NET, Java: Azure App Service readiness, plan recommendations)",
        "Server Migration (VMware agentless/agent-based, Hyper-V, physical; test migration, delta replication, cutover)",
        "Database Migration Service (DMS: SQL Server → Azure SQL Database/MI/VM; online/offline migration, schema, data, validation)",
        "Web App Migration Assistant (App Service Migration Assistant: compatibility check, hybrid connection, deployment)",
        "Azure Migrate — Business Case (TCO analysis, ROI estimation, Azure vs on-premises cost comparison, migration wave planning)",
        "Movere (discovery: device inventory, application dependency, utilization patterns; imported into Migrate)",
    ],
    "Microsoft.DBforPostgreSQL": [
        "Azure Database for PostgreSQL — Flexible Server (Burstable B-series, General Purpose D-series, Memory Optimized E-series; zone-redundant HA, same-zone HA)",
        "Intelligent Performance (Query Store, Query Performance Insight, Performance Recommendations, intelligent tuning, auto-vacuum tuning)",
        "Read Replicas (up to 10 replicas, cross-region, promote to standalone; async replication, geo-redundant backup)",
        "Extensions (50+ PostgreSQL extensions: PostGIS, pg_cron, pgvector, pg_stat_statements, pgAudit, Azure AI, pg_trgm, TimescaleDB community)",
        "Server Parameters (300+ configurable PostgreSQL parameters: shared_buffers, work_mem, max_connections, effective_cache_size, wal_level, etc.)",
        "Azure AI Integration (azure_ai extension: Azure OpenAI, Azure Cognitive Services, ML predictions directly from SQL queries)",
        "Backup and PITR (automated backups: locally redundant, zone-redundant, geo-redundant; PITR up to 35 days; long-term retention preview)",
        "Connection Pooling (built-in PgBouncer: transaction, session pooling; pool_size configuration; reduces connection overhead)",
        "Networking (VNet injection/delegated subnet, private endpoints, public access with firewall rules, SSL/TLS enforcement)",
        "Major Version Upgrades (in-place upgrade: PG 13→14→15→16→17; validation, rollback, extension compatibility checks)",
    ],
    "Microsoft.DBforMySQL": [
        "Azure Database for MySQL — Flexible Server (Burstable B-series, General Purpose D-series, Memory Optimized E-series; zone-redundant HA, same-zone HA)",
        "Read Replicas (up to 10 replicas, cross-region, replica promotion; binlog-based async replication, GTID)",
        "Server Parameters (500+ configurable MySQL parameters: innodb_buffer_pool_size, max_connections, query_cache, binlog_format, etc.)",
        "Data-in Replication (replicate from external MySQL: on-premises, other clouds, EC2; binlog position or GTID)",
        "Backup and PITR (automated daily snapshots + transaction log: PITR up to 35 days; geo-redundant backup storage)",
        "High Availability (same-zone HA, zone-redundant HA: automatic failover 60-120s, health monitoring, transparent redirection)",
        "Slow Query Logs (logging, query optimization: Query Performance Insight, Performance Recommendations)",
        "Import/Export (Azure DMS, mydumper/myloader, MySQL Workbench, Azure Database Migration: schema + data migration)",
    ],
    "Microsoft.Search": [
        "Azure AI Search Service (Free, Basic, Standard S1-S3, Storage Optimized L1-L2; replicas, partitions, semantic ranker, availability zones)",
        "Indexes (field definitions: searchable, filterable, sortable, facetable; Edm types, complex types, collections, scoring profiles)",
        "Indexers (automated ingestion: Blob Storage, Azure SQL, Cosmos DB, Table Storage, MySQL, SharePoint Online; incremental, change detection)",
        "Skillsets (AI enrichment pipeline: OCR, key phrases, entity recognition, sentiment, image analysis, custom Web API, Azure OpenAI, document cracking)",
        "Knowledge Store (enrichment output: table projections, object projections, file projections → Storage/Cosmos DB)",
        "Semantic Search (Microsoft-trained L2 ranker: semantic captions, semantic answers, semantic configuration per index)",
        "Vector Search (vector fields, HNSW/eKNN algorithms, vector profiles, integrated vectorization, multi-vector queries, hybrid search)",
        "Integrated Vectorization (built-in chunking + embedding: Azure OpenAI embedding skill, Text Split skill, index projection)",
        "Synonym Maps (query-time synonym expansion: equivalent, one-way mappings; Solr format)",
        "Debug Sessions (visual skillset debugger: node inspection, enrichment tree, cached execution, skill modification)",
    ],
    "Microsoft.ServiceFabric": [
        "Service Fabric Cluster (self-managed: Bronze/Silver/Gold/Platinum reliability; Windows, Linux; custom, auto OS upgrades)",
        "Service Fabric Managed Clusters (fully managed: Basic, Standard SKUs; automatic OS upgrades, node type management)",
        "Stateless Services (horizontally scalable microservices: instance count, placement constraints, load metrics)",
        "Stateful Services (reliable collections: ReliableDictionary, ReliableQueue; partition schemes: singleton, named, uniform int64, low-key/high-key)",
        "Reliable Actors (virtual actor model: state management, timers, reminders, actor lifecycle, reentrant/non-reentrant)",
        "Guest Executables (deploy existing .exe, Java, Node.js as Service Fabric services; health reporting, endpoint exposure)",
        "Container Services (Docker container orchestration: Windows, Linux containers; compose deployment, container health monitoring)",
        "Application Lifecycle (versioned application packages: upgrade domains, rolling upgrades, monitored/manual/unmonitored modes, rollback)",
        "Placement Constraints and Load Balancing (node properties, capacity, balancing metrics, defragmentation, affinity, anti-affinity)",
    ],
    "Microsoft.Batch": [
        "Batch Account (user subscription mode, batch service mode; auto-storage, pool allocation mode, managed identity)",
        "Pools (dedicated VMs, Spot/Low-Priority VMs: auto-scale formulas, fixed size, start tasks, certificates, application packages)",
        "Jobs and Job Schedules (task collections: job manager task, job preparation/release, dependency tasks, multi-instance tasks, recurrence schedules)",
        "Tasks (command line, container task, resource files, output files, environment variables, constraints: max retries, max wall clock time, retention time)",
        "Task Dependencies (task-ID dependency, task-ID range dependency; many-to-one, one-to-many patterns)",
        "Application Packages (versioned zips: pool-level, task-level; auto-deployment to compute nodes, version management)",
        "Compute Node Configuration (VM sizes, OS images: marketplace, custom; node agent SKU, container support, data disks, ephemeral OS disk)",
        "Virtual Network Integration (VNet/subnet injection, NSG requirements, public IP configuration, no public IP mode)",
    ],
    "Microsoft.NetApp": [
        "Azure NetApp Files Account (regional container: Active Directory connection, LDAP, Kerberos, CMK encryption)",
        "Capacity Pools (Standard, Premium, Ultra service levels; manual QoS, auto QoS; 1-500 TiB; cool access tiering)",
        "Volumes — NFS (NFSv3, NFSv4.1: export policies, Unix permissions, LDAP extended groups, Kerberos 5/5i/5p)",
        "Volumes — SMB (SMB 3.x: Active Directory integration, continuously available shares, access-based enumeration, non-browsable)",
        "Volumes — Dual Protocol (simultaneous NFS + SMB access: NTFS/Unix security style, identity mapping, LDAP)",
        "Cross-Region Replication (async disaster recovery: RPO 10-minute, 1-hour, daily; relationship management, break/resync/reverse)",
        "Snapshots (instantaneous, space-efficient: manual, snapshot policies hourly/daily/weekly/monthly; snapshot restore, revert volume)",
        "Backup (vault-based: policy-based scheduling, baseline + incremental; cross-region restore, long-term retention)",
        "Volume Placement Groups (anti-affinity: co-locate across availability zones, latency optimization, SAP HANA, Oracle RAC)",
        "Application Volume Groups (SAP HANA: data, log, shared, log-backup, data-backup volumes; optimized placement, proximity)",
        "Large Volumes (up to 500 TiB regular, 1 PiB large volumes: single namespace, high throughput, cool access)",
    ],
    "Microsoft.BotService": [
        "Azure Bot Service (channels registration: Teams, Slack, Facebook, Telegram, Email, DirectLine, Web Chat, LINE, Twilio; MSA, managed identity, single-tenant)",
        "Bot Framework Composer (visual dialog authoring: adaptive dialogs, LUIS intents, QnA Maker, language generation, interruptions)",
        "DirectLine API (REST-based bot communication: activities, conversations, watermark-based polling, WebSocket streaming)",
        "DirectLine Speech (voice-first bots: Speech SDK, keyword activation, custom voice, audio streaming)",
        "Bot Framework Skills (reusable conversational capabilities: skill manifest, skill dialog, multi-bot composition)",
        "Power Virtual Agents Integration (low-code/no-code bot building, topic routing, entity extraction, Power Automate actions)",
    ],
    "Microsoft.PowerBIdedicated": [
        "Power BI Embedded Capacities (A-SKUs: A1-A8; EM-SKUs: EM1-EM3; P-SKUs: P1-P5; auto-scale, pause/resume, multi-geo)",
        "Embedded Analytics (embed reports, dashboards, Q&A in custom applications: App Owns Data, User Owns Data patterns)",
        "Capacity Management (workload settings: dataflows, paginated reports, AI; memory limits, query timeout, max result rows)",
    ],
    "Microsoft.Chaos": [
        "Chaos Studio Experiments (fault injection: sequential/parallel steps, branches, duration, selectors, fault parameters)",
        "Agent-Based Faults (VM-level: CPU pressure, memory pressure, disk I/O pressure, process kill, network disconnect/latency/packet loss, DNS failure, time change)",
        "Service-Direct Faults (resource-level: Cosmos DB failover, AKS Chaos Mesh, NSG security rule, Key Vault deny access, App Service stop/restart)",
        "Targets and Capabilities (fault-injectable resources: enable/disable capabilities per resource, agent registration, managed identity access)",
    ],
    "Microsoft.LoadTestService": [
        "Azure Load Testing Resource (managed JMeter service: test plans, test runs, CI/CD integration, auto-stop criteria)",
        "Load Tests (JMX file upload, URL-based quick test: virtual users, test duration, ramp-up time, engine instances, fail criteria)",
        "Test Runs (execution history: metrics, logs, errors, response time percentiles, throughput, server-side metrics correlation)",
        "CI/CD Integration (Azure DevOps task, GitHub Action: parameterized tests, pass/fail criteria, regression detection)",
    ],
    "Microsoft.DigitalTwins": [
        "Azure Digital Twins Instance (IoT knowledge graph: DTDL models, twins, relationships, event routes, time series integration)",
        "DTDL Models (Digital Twins Definition Language v3: interfaces, telemetry, properties, commands, relationships, components, inheritance)",
        "Digital Twins and Relationships (graph-based: create, update, query twins; relationship types, property updates, event notification)",
        "Event Routes (dead-letter, filtering: Event Hub, Event Grid, Service Bus endpoints; twin lifecycle events, relationship events, telemetry)",
        "Twin Graph Queries (SQL-like query language: traverse relationships, filter properties, projection, aggregation, JOIN operations)",
        "3D Scenes (3D Scenes Studio: visual twin mapping, behaviors, data-driven alerts, time series data overlay, custom meshes)",
    ],
    "Microsoft.Orbital": [
        "Azure Orbital Ground Station (satellite communication: downlink/uplink scheduling, EIRP, G/T, contact profiles, spacecraft registration)",
        "Spacecraft (registered satellite objects: TLE tracking, link configurations, center frequency, bandwidth, polarization, direction)",
        "Contact Profiles (RF chain configuration: channels, demodulation, decoding, endpoint destination: Event Hub, VNet, Storage)",
        "Contacts (scheduled satellite passes: reservation window, ground station selection, real-time telemetry, data delivery)",
    ],
    "Microsoft.Workloads": [
        "Azure Center for SAP Solutions — VIS (Virtual Instance for SAP: 3-tier, distributed, HA deployment; ASCS, DB, App server)",
        "SAP Sizing Recommendations (SKU recommendation based on SAPS, memory, storage IOPS requirements)",
        "SAP Quality Checks (pre-deployment validation: networking, OS, storage, clustering, backup configuration)",
        "SAP Monitoring (Azure Monitor for SAP: providers for HANA, SQL Server, HA cluster, OS, NetWeaver; alerts, workbooks)",
        "SAP Discovery (agentless discovery of existing SAP landscapes: SID, system type, database, instance details)",
    ],
    "Microsoft.HybridCompute": [
        "Azure Arc-Enabled Servers (Windows, Linux on-premises/multi-cloud: Azure management plane, policy, monitoring, extensions, managed identity)",
        "Machine Extensions (Log Analytics, dependency agent, custom script, DSC, Qualys, Azure Monitor Agent; auto-upgrade)",
        "Arc Private Link Scopes (private connectivity for Arc agent communication: configuration, monitoring endpoints)",
        "Run Commands (execute scripts on Arc-enabled servers: PowerShell, Bash; async execution, output streaming)",
        "ESU Licenses (Extended Security Updates: Windows Server 2012/2012 R2 ESU via Arc; license assignment, compliance tracking)",
    ],
    "Microsoft.KubernetesConfiguration": [
        "Flux GitOps Configurations (Flux v2: source-controller, kustomize-controller, helm-controller, notification-controller; Git, Bucket, Helm sources)",
        "Flux Kustomizations (path-based deployment: prune, force, target namespace, dependencies between kustomizations, health checks, substitution variables)",
        "Extensions (AKS/Arc cluster extensions: Azure Monitor, Azure Policy, Azure Key Vault Secrets Provider, Azure ML, Dapr, Flux)",
    ],
    "Microsoft.DataProtection": [
        "Backup Vault (next-gen backup container: immutable vaults, multi-user authorization, cross-region restore, soft delete)",
        "Backup Policies (rule-based: trigger schedule, retention rules, lifecycle tiering vault/archive; per-datasource-type policies)",
        "Backup Instances (protected resources: AKS, Blobs, Disks, PostgreSQL; operational, vault, archive tiers; restore, stop/resume protection)",
        "Resource Guards (cross-subscription/tenant authorization: protected operations, JIT access, approval workflows)",
    ],
    "Microsoft.Dashboard": [
        "Azure Managed Grafana (Grafana 9/10: workspace tiers Essential/Standard; Azure Monitor, Prometheus, Data Explorer, Log Analytics data sources)",
        "Dashboards and Folders (imported/custom dashboards: organization, permissions, team-based access, panel plugins)",
        "Data Source Configuration (managed identity auth to Azure services: Prometheus, Azure Monitor Logs/Metrics, Data Explorer, Azure SQL, Cosmos DB)",
        "Alerting (Grafana-managed alerts: alert rules, contact points, notification policies, silences, mute timings; Azure Monitor data source)",
        "Team Sync and RBAC (AAD group sync: admin, editor, viewer roles; service accounts for API access, API key management)",
    ],
    "Microsoft.ElasticSan": [
        "Elastic SAN Resource (regional storage: base capacity 1-100 TiB, additional capacity up to 100+ TiB; total IOPS/throughput scaling)",
        "Volume Groups (management container: encryption, protocol, private endpoints, virtual network rules per group)",
        "Volumes (iSCSI block storage: 1 GiB-64 TiB per volume; snapshot, delete; connect to AKS, VMs, AVS, Arc VMs)",
        "Snapshots (volume snapshots: incremental, copy volumes from snapshots, cross-volume-group snapshot management)",
    ],
    "Microsoft.Marketplace": [
        "Azure Marketplace (8,000+ ISV offerings: virtual machines, SaaS, containers, managed apps, ARM templates, consulting services)",
        "Private Azure Marketplace (tenant-scoped marketplace: approved offer collections, governance rules, admin-curated catalog)",
        "SaaS Subscriptions (ISV SaaS integration: subscription lifecycle, metering API, quantity-based billing, change plan, renewal)",
        "Private Offers (ISV-to-customer private pricing: custom terms, custom pricing, multi-party offers, CSP partner offers)",
    ],
    "Microsoft.CostManagement": [
        "Cost Analysis (multi-dimensional cost exploration: grouping, filtering, granularity daily/monthly; forecast, budgets, amortized, actual views)",
        "Budgets (spend thresholds: action groups for notifications, email alerts at percentage thresholds; resource group, subscription, management group scope)",
        "Exports (scheduled cost data export: daily, weekly, monthly; CSV to Storage account; actual cost, amortized cost, usage)",
        "Cost Alerts (budget alerts, anomaly alerts, credit alerts, department spending, EA commitment alerts; action groups, email)",
        "Cost Allocation Rules (shared cost distribution: tag-based, proportional, fixed split; chargeback/showback across departments/projects)",
        "Azure Advisor Cost Recommendations (right-sizing, reserved instance purchase, shutdown idle resources, storage tier optimization)",
    ],
    "Microsoft.Billing": [
        "Billing Accounts (Enterprise Agreement, MCA, MOSP, MPA, CSP: account structure, enrollment, billing profiles, invoice sections)",
        "Billing Profiles (invoice grouping, payment methods, purchase order, tax ID, bill-to address; MCA hierarchy)",
        "Invoice Sections (cost organization within billing profile: department mapping, project allocation, cost tracking)",
        "Payment Methods (credit card, check/wire transfer, Azure credits, prepayment; auto-pay, payment history)",
        "Reservations Management (RI purchases: VM, SQL, Cosmos DB, Storage, App Service; scope: shared, single subscription, resource group; exchange, refund)",
        "Savings Plans (1-year, 3-year commitment: compute, hourly commitment amount; scope, utilization tracking, exchange)",
    ],
    "Microsoft.Consumption": [
        "Usage Details (line-item consumption records: meters, quantity, cost, resource metadata; daily, monthly, billing-period granularity)",
        "Price Sheets (EA, MCA: meter prices, unit of measure, currency, included quantity; current and historical)",
        "Reservation Recommendations (single vs shared scope: VM, SQL, Cosmos DB; usage lookback 7/30/60 days; net savings)",
        "Reservation Details and Summaries (utilization reports: used hours, reserved hours, on-demand equivalent; daily, monthly aggregation)",
        "Marketplace Charges (third-party ISV charges: publisher, plan, meter, quantity, cost; separate from Azure consumption)",
        "Charge Summaries (billing period totals: Azure charges, marketplace charges, credits applied, new purchases, tax; by enrollment, billing profile)",
    ],
    "Microsoft.AzureStackHCI": [
        "Azure Stack HCI Cluster (hybrid hyperconverged infrastructure: 1-16 nodes, Windows Server, Azure Arc integration, stretch clustering)",
        "Virtual Machines (Arc VMs on HCI: Windows, Linux; marketplace images, custom images, VM sizes, GPU passthrough, live migration)",
        "AKS on Azure Stack HCI (AKS hybrid: Kubernetes clusters, node pools, load balancer, persistent volumes, Azure Arc GitOps)",
        "Azure Virtual Desktop on HCI (AVD session hosts on-premises: low-latency, data residency, local processing)",
        "Storage (Storage Spaces Direct S2D: hybrid, all-flash, all-NVMe; ReFS, deduplication, compression, tiering; volumes, mirrors)",
        "Networking (SDN: virtual networks, virtual switches, load balancing, micro-segmentation, network controller)",
        "Updates (lifecycle management: OS updates, solution updates, firmware; update runs, maintenance windows, cluster-aware updating)",
        "Monitoring (Azure Monitor, Insights: cluster health, node health, VM performance, storage, networking metrics)",
    ],
    "Microsoft.ConnectedVMwarevSphere": [
        "vCenter (Arc-connected vCenter Server: discovery, inventory sync, Azure projection of VMs, templates, networks, datastores)",
        "Virtual Machines (Arc-enabled VMware VMs: lifecycle management from Azure portal, guest management extensions, Azure policy)",
        "Virtual Machine Templates (Azure-projected VM templates: deploy VMs from Azure portal using on-premises templates)",
        "Resource Pools (Azure-projected resource pools: compute resource allocation, DRS clusters, scheduling)",
        "Virtual Networks (Azure-projected vSphere networks: standard switches, distributed switches, port groups)",
        "Datastores (Azure-projected datastores: storage capacity, VM placement, datastore clusters)",
    ],
    "Microsoft.ContainerInstance": [
        "Container Groups (single-host multi-container deployment: sidecar pattern, shared network/storage, managed identity, confidential containers)",
        "Container Instances (Linux, Windows: CPU/memory allocation, GPU, restart policies always/on-failure/never, command override, environment variables)",
        "Spot Containers (evictable, discounted pricing: best-effort workloads, batch processing, testing; eviction policies)",
        "Virtual Network Deployment (VNet-injected ACI: private IP, subnet delegation, NSG, UDR, service endpoints)",
        "Persistent Storage (Azure Files mount: SMB shares, empty dir, git repo, secret volumes; shared state across containers)",
    ],
    "Microsoft.Quantum": [
        "Azure Quantum Workspace (quantum computing hub: provider management, job submission, credit allocation, hybrid quantum-classical jobs)",
        "Quantum Providers (IonQ: trapped ion; Quantinuum: trapped ion; Rigetti: superconducting; Microsoft: resource estimation)",
        "Resource Estimation (quantum resource estimation: qubit counts, gate counts, error correction overhead, algorithm analysis)",
        "Quantum Jobs (circuit execution: Qiskit, Cirq, Q#; shot count, target machine, job monitoring, results retrieval)",
        "Azure Quantum Credits (free credits program, pay-as-you-go per provider, cost estimation before submission)",
    ],
    "Microsoft.ConfidentialLedger": [
        "Azure Confidential Ledger (tamper-proof data store: CCF-based, Intel SGX enclaves, multi-party governance, immutable append-only)",
        "Managed CCF (managed Confidential Consortium Framework: custom application logic, JavaScript endpoints, governance proposals/voting)",
    ],
    "Microsoft.Relay": [
        "Azure Relay — Hybrid Connections (WebSocket-based tunneling: HTTP request/response, bi-directional binary streams; no firewall changes needed)",
        "Azure Relay — WCF Relay (legacy WCF-based: netTcp, basicHttp, webHttp relay bindings; on-premises service exposure to cloud)",
    ],
    "Microsoft.NotificationHubs": [
        "Notification Hub Namespace (Free, Basic, Standard tiers: shared access policies, geo-redundancy, telemetry, scheduled send)",
        "Notification Hubs (multi-platform push: APNS iOS, FCM Android, WNS Windows, MPNS, Baidu, ADM; registration/installation management)",
        "Templates (cross-platform templates: device-specific payload rendering, tag expressions, bulk operations, direct send)",
    ],
    "Microsoft.FluidRelay": [
        "Fluid Relay Service (real-time collaboration infrastructure: distributed data structures, operational transform, session management)",
        "Fluid Containers (collaboration sessions: SharedMap, SharedString, SharedTree, SharedCounter; transient and persisted data)",
    ],
    "Microsoft.DomainRegistration": [
        "App Service Domains (domain registration: .com, .net, .org, .co.uk, .in, etc.; auto-renewal, domain lock, WHOIS privacy)",
        "Domain Contact Information (registrant, admin, tech contacts; WHOIS, GDPR privacy, domain transfer authorization)",
    ],
    "Microsoft.CertificateRegistration": [
        "App Service Certificates (Standard single-domain, Wildcard: auto-renewal, Key Vault storage, domain verification, rekey, export)",
        "Certificate Orders (DigiCert-issued: domain validation, order lifecycle, DNS/email/manual verification, certificate binding to App Service)",
    ],
    "Microsoft.StorageSync": [
        "Azure File Sync Service (hybrid file services: sync groups, cloud tiering, multi-server endpoints, Azure Files integration)",
        "Sync Groups (topology definition: cloud endpoint (Azure Files share), server endpoints (Windows Server paths), conflict resolution)",
        "Server Endpoints (registered Windows Server paths: cloud tiering, tiering policies free-space/date, offline data transfer, initial download)",
        "Registered Servers (Windows Server agents: server certificate, agent version management, auto-upgrade, server endpoint health)",
        "Cloud Tiering (intelligent storage tiering: volume free-space policy, date policy, heat-map based recall, ghost files, seamless access)",
    ],
    "Microsoft.StorageCache": [
        "Azure HPC Cache (high-performance NAS cache: 2-48 TiB cache, read-intensive workloads; NFS, Blob backends; VNet integration)",
        "Storage Targets (backend storage: NFS 3.0 exports, ADLS Gen2 containers; namespace aggregation, usage models, write-back/write-through)",
        "Namespace Junctions (virtual filesystem: path mapping, access policies; NFS client-facing namespace aggregating multiple backends)",
    ],
    "Microsoft.StreamAnalytics": [
        "Stream Analytics Jobs (real-time event processing: SQL-like query language, windowing functions, temporal joins; Standard, V2 SKUs)",
        "Inputs (streaming: Event Hub, IoT Hub, Blob; reference: Blob, SQL Database; serialization: JSON, CSV, Avro, Parquet, Delta)",
        "Outputs (25+ destinations: Event Hub, SQL, Blob/ADLS, Cosmos DB, Power BI, Synapse, Service Bus, Azure Functions, Dataverse, PostgreSQL)",
        "User-Defined Functions (JavaScript UDFs, Azure ML UDFs; scalar, aggregate; machine learning scoring in stream processing)",
        "Windowing Functions (tumbling, hopping, sliding, session, snapshot windows; GROUP BY, DATEDIFF, time policies, watermarks)",
        "Stream Analytics Cluster (dedicated compute: up to 36 SUs, VNet integration, private endpoints, custom capacity; shared across jobs)",
    ],
    "Microsoft.TimeSeriesInsights": [
        "TSI Environment — Gen2 (warm store + cold store: time series model, hierarchies, instances, types; Power BI connector)",
        "Event Sources (IoT Hub, Event Hub: consumer groups, timestamp property, initial ingestion start time, data access policies)",
        "Time Series Model (instances, types, hierarchies: semantic tagging, categorization, contextualization of raw IoT/sensor data)",
        "Reference Data Sets (Gen1: lookup table enrichment, key-property matching, join behavior inner/outer)",
    ],
    "Microsoft.IoTOperations": [
        "Azure IoT Operations (edge-native: Kubernetes-based IoT runtime, MQTT broker, data processor, OPC UA connector, Akri device discovery)",
        "MQTT Broker (Kubernetes-native: hierarchical topics, TLS, X.509 auth, SAT token auth, QoS 0/1, shared subscriptions, message routes)",
        "Data Processor (edge data pipelines: inputs, pipeline stages, transformations, enrichments, outputs; reference data, ML inference)",
        "OPC UA Broker (industrial connectivity: OPC UA server discovery, secure channel, certificate trust lists, asset endpoints, data collection)",
        "Akri (device discovery: USB, ONVIF cameras, OPC UA, custom protocols; Kubernetes-native device plugin framework)",
        "Azure Device Registry (unified asset registry: device metadata, twin synchronization, edge-cloud consistency)",
        "Layered Network Management (ISA-95 network segmentation: level 3/4 proxy, isolated edge networks, nested edge support)",
    ],
    "Microsoft.DevCenter": [
        "Dev Center (organizational hub: projects, dev box definitions, catalogs, environment types, managed identity)",
        "Projects (developer-facing: dev box pools, environment types, project admin/dev roles, limits, catalogs)",
        "Dev Box Definitions (VM image + SKU: marketplace images, custom images, compute gallery images; 8-32 vCPU, SSD sizes)",
        "Dev Box Pools (self-service VM pools: auto-stop schedules, network connection, single sign-on, Intune management, hibernation)",
        "Dev Boxes (developer workstations: Windows 11 Enterprise, Visual Studio, dev tools; create, stop, start, snapshot, restore)",
        "Catalogs (IaC template repos: GitHub, Azure DevOps; ARM/Bicep environment definitions, auto-sync)",
        "Environment Types (deployment ring configuration: dev, test, staging, prod; subscription mapping, identity, permissions, creator roles)",
        "Deployment Environments (self-service infrastructure: ARM/Bicep/Terraform/Pulumi templates, environment lifecycle, cost tracking)",
    ],
    # Note: Front Door also spans Microsoft.Network (classic). See Microsoft.Cdn above and Microsoft.Network.
    "Microsoft.DevTestLab": [
        "DevTest Labs (lab environments: auto-shutdown, auto-start, cost thresholds, allowed VM sizes, marketplace image control)",
        "Lab Virtual Machines (claimable VMs, formulas, custom images, artifacts; Windows, Linux; GPU, nested virtualization)",
        "Artifacts (install scripts: Visual Studio, Docker, Chrome, Git, custom PowerShell/bash scripts; artifact repository)",
        "Formulas (reusable VM templates: base image, size, artifacts, network settings; quick-create from formula)",
        "Lab Policies (VM size restrictions, VMs per user, VMs per lab, auto-shutdown schedule, auto-start, cost target, allowed images)",
        "Virtual Networks (lab VNet configuration: shared public IP, subnet overrides, external virtual networks)",
        "Environments (ARM template-based multi-resource environments: App Service, SQL, AKS; Git-backed template repos)",
    ],
    "Microsoft.Attestation": [
        "Azure Attestation Provider (SGX enclave attestation, TPM attestation, VBS enclave attestation; default/isolated providers)",
        "Attestation Policies (custom JWT claims: policy signing, policy hash, RSASSA-PSS certificates; per-attestation-type policies)",
    ],
    "Microsoft.AppConfiguration": [
        "App Configuration Store (Free, Standard: key-value pairs, feature flags, labels, content types; snapshots, soft delete, purge protection)",
        "Feature Flags (boolean, conditional: targeting filters percentage/group/user, time window filter, custom filter; telemetry, variants)",
        "Key-Value References (Key Vault references: dynamic secret resolution; sentinel keys for configuration refresh triggering)",
        "Labels (configuration versioning/environment tagging: dev, staging, prod labels; same key different values per label)",
        "Snapshots (point-in-time configuration capture: composition type key, key-label; immutable, archival compliance)",
        "Configuration Sync (Kubernetes ConfigMap sync, App Service settings sync, Azure Functions references; pull and push refresh models)",
    ],
    "Microsoft.AlertsManagement": [
        "Alert Processing Rules (suppress, route, enrich alerts: scope-based, schedule-based, one-time maintenance windows, recurring schedules)",
        "Smart Groups (automatic alert correlation: machine learning grouping of related alerts, smart group lifecycle, summary notifications)",
        "Prometheus Rule Groups (cloud-native alerting: PromQL expressions, recording rules, alert rules; Azure Monitor workspace integration)",
    ],
    "Microsoft.AppPlatform": [
        "Azure Spring Apps — Basic (dev/test: managed Spring Boot, 25 app instances, 1 GiB memory, built-in service registry and config server)",
        "Azure Spring Apps — Standard (production: auto-scale, VNet injection, custom domains, managed identity, Application Insights APM, blue-green deployment)",
        "Azure Spring Apps — Enterprise (Tanzu components: VMware Tanzu Build Service, Spring Cloud Gateway, API Portal, Application Configuration Service, Application Live View, Service Registry)",
        "Application Deployments (blue-green: active/staging, traffic routing, canary deployments, deployment history, rollback)",
        "Service Registry (Eureka-based: service discovery, health check, load balancing; or Tanzu Service Registry in Enterprise tier)",
        "Config Server (Spring Cloud Config: Git-backed centralized configuration, refresh, encryption, label/profile-based configuration)",
        "Build Service (Tanzu Build Service in Enterprise: buildpacks, custom builders, Maven/Gradle/custom build agents, OCI images)",
    ],
    "Microsoft.Advisor": [
        "Azure Advisor Recommendations (personalized best practices: cost, security, reliability, operational excellence, performance categories)",
        "Recommendation Digests (weekly email summaries: filtered by category, resource type, subscription; action group integration)",
        "Advisor Score (posture scoring: weighted category scores, trend tracking, subscription-level, management-group-level comparison)",
        "Suppressions/Postponements (snooze recommendations: time-based dismissal, permanent dismissal, per-resource or per-recommendation)",
    ],
    "Microsoft.PolicyInsights": [
        "Policy States (compliance evaluation records: compliant, non-compliant, exempt, conflict, not-started; per-resource, per-policy)",
        "Policy Events (compliance change events: created, updated; timestamp, policy assignment, resource details; queryable, filterable)",
        "Remediation Tasks (remediate non-compliant resources: deployIfNotExists, modify; re-evaluation, parallel deployment, failure handling)",
        "Attestations (manual policy compliance evidence: compliance state override, evidence links, expiry date, owner assignment)",
    ],
    "Microsoft.GuestConfiguration": [
        "Azure Automanage Machine Configuration (DSC-based compliance: Windows, Linux; audit, enforce (apply and monitor) modes)",
        "Built-in Configuration Packages (security baselines: Windows, Linux CIS benchmarks, Azure security baseline, custom InSpec/DSC/Chef packages)",
        "Custom Configuration Packages (author with DSC/InSpec/Chef: publish to Azure, versioning, parameter support, test-compliance or remediate)",
    ],
    "Microsoft.ManagedIdentity": [
        "System-Assigned Managed Identity (per-resource lifecycle: automatic creation/deletion, Azure AD token, RBAC assignments, single-resource scope)",
        "User-Assigned Managed Identity (independent lifecycle: reusable across resources, federated identity credentials, workload identity federation for external IdPs)",
        "Federated Identity Credentials (trust external tokens: GitHub Actions, Kubernetes, Google Cloud, any OIDC provider; subject/issuer/audience matching)",
    ],
    "Microsoft.AwsConnector": [
        # 135 ARM resource types mirroring AWS across 40 service categories
        "EC2 (Instances, Security Groups, VPCs, Subnets, Key Pairs, Images, Transit Gateways, Internet Gateways, Route Tables, Flow Logs, Volumes, Addresses, Snapshots, Network Interfaces, Launch Templates, Placement Groups, Network ACLs)",
        "IAM (Roles, Policies, Instance Profiles, Access Key Info, Groups, Users, Password Policies, MFA Devices, Server Certificates, Policy Versions, SAML Providers, MFA Virtual Devices)",
        "S3 (Buckets, Access Points, Bucket Policies, Multi-Region Access Points, Control Access Point Policies)",
        "Lambda (Functions, Function Configurations, Function Code Properties, Event Source Mappings, Aliases)",
        "RDS (DB Instances, DB Clusters, DB Snapshots, DB Parameter Groups, DB Subnet Groups, Event Subscriptions)",
        "Bedrock (Agent, Agent Alias, Custom Model, Foundation Model, Guardrail, Knowledge Base, Model Customization Job, Model Invocation Job, Provisioned Model Throughput, Inference Profile)",
        "ECS (Clusters, Services, Task Definitions, Container Instances)",
        "EKS (Clusters, Node Groups, Fargate Profiles, Add-ons)",
        "CloudFormation (Stacks, Stack Sets, Types)",
        "CloudWatch (Metric Alarms, Log Groups, Composite Alarms)",
        "SNS (Topics, Subscriptions, Platforms)",
        "SQS (Queues, Queue Policies)",
        "DynamoDB (Tables, Global Tables)",
        "CloudFront (Distributions, Origin Access Identities, Functions, Cache Policies)",
        "Route53 (Hosted Zones, Health Checks, Domain Registrations)",
        "Elastic Load Balancing (Load Balancers, Target Groups, Listeners, Rules)",
        "Auto Scaling (Auto Scaling Groups, Launch Configurations, Scaling Policies)",
        "SSM (Parameters, Instances, Associations, Documents)",
        "Kinesis (Streams, Firehose Delivery Streams)",
        "SageMaker (Notebook Instances, Endpoints, Models, Training Jobs, Apps)",
        "GuardDuty (Detectors, Findings, Publishing Destinations)",
        "Organizations (Accounts, OUs, Policies)",
        "KMS (Keys, Aliases)",
        "ECR (Repositories, Images)",
        "Step Functions (State Machines, Activities, Executions)",
        "Secrets Manager (Secrets, Resource Policies)",
        "ACM (Certificates, PCA Certificate Authorities)",
        "CodeBuild (Source Credentials, Projects)",
        "Config (Compliance Summaries, Delivery Channels, Configuration Recorders)",
        "Redshift (Clusters, Cluster Parameter Groups, Cluster Subnet Groups)",
        "Athena (Work Groups, Data Catalogs)",
        "Glue (Databases, Crawlers, Jobs)",
        "EMR (Clusters, Security Configurations, Instance Fleets)",
        "API Gateway (REST APIs, Usage Plans, Domain Names)",
        "AppSync (GraphQL APIs)",
        "CloudTrail (Trails)",
        "CodeDeploy (Deployment Groups, Applications)",
        "CodePipeline (Pipelines)",
        "DAX (Clusters, Parameter Groups)",
        "ElastiCache (Clusters, Replication Groups, Parameter Groups)",
        "Lightsail (Instances, Buckets)",
        "Macie (Classification Jobs, Allow Lists)",
        "Network Firewall (Firewalls, Rule Groups, Policies)",
        "WAFv2 (Web ACLs, Rule Groups, IP Sets, Logging Configurations)",
        "Logs Insights (Log Groups, Query Definitions)",
    ],
    "Microsoft.LabServices": [
        "Lab Plans (organizational defaults: allowed VM images, allowed regions, networking, marketplace images, default auto-shutdown)",
        "Labs (classroom/training environments: VM template, student VM quota, schedules, auto-shutdown, access control, published/unpublished)",
        "Virtual Machines (student VMs: Windows, Linux; nested virtualization, GPU; connect via RDP/SSH; start, stop, reimage, reset password)",
    ],
    "Microsoft.Capacity": [
        "Reservations (1-year, 3-year: VM, SQL, Cosmos DB, App Service, Storage, Databricks, Synapse, AVS, Red Hat, SUSE; scope, quantity)",
        "Reservation Orders (purchase container: billing scope, auto-renew, exchange, refund, split, merge; utilization tracking)",
        "Savings Plans (flexible compute commitment: 1-year, 3-year; hourly commitment; scope: shared, subscription, resource group, management group)",
    ],
    "Microsoft.Portal": [
        "Azure Portal Dashboards (custom dashboards: tiles, markdown, metrics, logs, resource groups; shared, private; JSON-based templates)",
        "Portal Settings (user preferences: language, region, theme, startup behavior, toast notifications, inactivity timeout)",
    ],
    "Microsoft.Maintenance": [
        "Maintenance Configurations (Guest OS, InGuestPatch, Host, ARMResource: schedule, recurrence, scope, dynamic scoping by tags/location/OS/resource group)",
        "Configuration Assignments (resource-to-maintenance-config binding: VM, VMSS, Arc server, AKS, dedicated host, Service Fabric)",
        "Public Maintenance Configurations (Microsoft-managed defaults: Windows security patching, Linux security patching, custom schedules)",
    ],
    "Microsoft.Subscription": [
        "Subscription Creation (EA, MCA, CSP: programmatic, portal; offer type, billing scope, management group placement, tags)",
        "Subscription Aliases (friendly name mapping, subscription ID aliasing, cross-tenant subscription transfer preparation)",
        "Subscription Policies (tenant-level governance: block subscription creation by non-admins, allowed offer types, billing enforcement)",
    ],
    "Microsoft.AzureArcData": [
        "Arc-Enabled SQL Managed Instance (SQL MI on Kubernetes: General Purpose, Business Critical; HA, PITR, AD auth, monitoring, Azure billing)",
        "Arc-Enabled PostgreSQL (Citus-based distributed PostgreSQL on Kubernetes: scale workers, Citus extensions, monitoring, backup)",
        "Data Controller (Kubernetes-deployed control plane: direct/indirect connectivity, monitoring, log upload, usage upload, metrics export)",
        "Active Directory Connector (Kubernetes-integrated AD auth: customer-managed keytab, system-managed keytab; DNS, SPN management)",
    ],
    "Microsoft.Sovereign": [
        "Sovereign Landing Zone (compliance-first deployment: data residency, encryption, policy baselines for regulated industries)",
        "Sovereign Controls (configurable guardrails: allowed regions, encryption requirements, network isolation, logging mandates)",
    ],
    "Microsoft.NetworkCloud": [
        "Network Cloud Cluster (operator-managed bare-metal Kubernetes: rack-level compute, storage, networking for telco/edge workloads)",
        "Bare Metal Machines (physical server lifecycle: provisioning, reimaging, cordon/uncordon, power management, serial console)",
        "Virtual Machines (tenant VMs on Network Cloud: cloud-hypervisor-based, SR-IOV, DPDK networking, persistent storage)",
        "Storage Appliances (managed NFS/iSCSI storage: volumes, capacity management, performance tiers)",
        "Layer 2 Networks (VLAN-based flat networks: isolation, MTU, BPDU guard, port channel aggregation)",
        "Layer 3 Networks (BGP-peered routed networks: IPv4/IPv6, VRRP, route advertisements, peering policies)",
        "Trunked Networks (multi-VLAN trunk ports: VLAN range, native VLAN, allowed VLANs, trunk encapsulation)",
    ],
    "Microsoft.VoiceServices": [
        "Communications Gateway (Teams Direct Routing / Operator Connect: SBC functionality, number management, call routing, emergency calling)",
        "Test Lines (gateway testing: manual/auto-answer test lines, diagnostics, SIP trace, media quality validation)",
    ],
    "Microsoft.PlayFab": [
        "PlayFab Title (game backend: player authentication, economy, data, leaderboards, matchmaking, UGC, experimentation)",
        "Multiplayer Servers (dedicated game servers: Thunderhead/Halo containers, standby pools, auto-scaling, regions, VM sizes)",
        "Party (real-time communication: voice chat, text chat, networking, translation, accessibility, cross-platform)",
    ],
    "Microsoft.VideoIndexer": [
        "Azure Video Indexer Account (ARM-connected: managed identity, storage account, Azure AI Services connection; trial, paid)",
        "Video/Audio Indexing (AI analysis: transcription, translation, OCR, face detection, named entities, topics, keywords, labels, brands, sentiments, emotions)",
        "Custom Models (custom language, brands, person, pronunciation, speech models; training, accuracy tuning, custom vocabulary)",
        "Widgets and API (embed video insights, player widgets; programmatic indexing, search, streaming URL, access tokens)",
    ],
    "Microsoft.Peering": [
        "Peering Service (Microsoft optimized routing: BGP community, route prefix, latency measurement, ISP-Microsoft direct peering)",
        "Direct Peering (private network interconnection with Microsoft: peering locations, bandwidth, ExpressRoute Direct, CDN Interconnect)",
        "Exchange Peering (public exchange point peering: IXP connections, route servers, peering facility bandwidth)",
    ],
    "Microsoft.ResourceGraph": [
        "Azure Resource Graph Queries (cross-subscription KQL: join, project, summarize, extend; 1000+ resource types, changes, advisorResources, policyStates tables)",
        "Shared Queries (saved and shared ARG queries: parameterized, permissions, organizational query library)",
    ],
    "Microsoft.SecurityDevOps": [
        "GitHub Connector (GitHub Advanced Security: code scanning, secret scanning, Dependabot; GHAS alert surfacing in Defender for Cloud)",
        "Azure DevOps Connector (ADO Advanced Security: code scanning (CodeQL), secret scanning, dependency scanning; policy enforcement)",
        "GitLab Connector (GitLab Ultimate: SAST, secret detection, dependency scanning; security posture in Defender for Cloud)",
    ],
    "Microsoft.Intune": [
        # Intune is primarily SaaS, but ARM integration includes:
        "Device Compliance Policies (OS version, encryption, jailbreak detection, password complexity, threat level; platform-specific: Windows, iOS, Android, macOS)",
        "Device Configuration Profiles (VPN, Wi-Fi, certificates, email, device restrictions, custom OMA-URI, settings catalog: 5000+ settings)",
        "App Management (MAM: app protection policies, app configuration policies; managed apps, LOB apps, Win32 apps, Microsoft Store apps)",
        "Endpoint Security (antivirus, firewall, disk encryption, attack surface reduction, endpoint detection and response, account protection policies)",
        "Conditional Access (identity-driven: require device compliance, approved apps, app protection, MFA, session controls, grant/block access)",
        "Autopilot (zero-touch deployment: self-deploying, user-driven, pre-provisioning; deployment profiles, enrollment status page, group tags)",
        "Windows Update for Business (update rings, feature updates, driver updates, expedited quality updates, safeguard holds, compliance deadlines)",
        "Remote Actions (wipe, retire, restart, lock, reset passcode, sync, remote diagnostics, collect logs, custom notifications)",
    ],
    "Microsoft.OffAzure": [
        "Azure Migrate Appliance (on-premises discovery agent: VMware, Hyper-V, physical; agentless dependency analysis, performance collection)",
        "Software Inventory (installed applications, features, roles, services, SQL instances; web apps discovery, dependencies)",
    ],
    "Microsoft.ConnectedCache": [
        "Microsoft Connected Cache (content caching: Windows Update, DOCCM, Intune, Edge/Arc-enabled; bandwidth optimization, ISP/enterprise deployment)",
    ],
    "Microsoft.NetworkFunction": [
        "Azure Traffic Collector (network monitoring: VNet flow logs, ExpressRoute Direct-level traffic mirroring; collector policies, emission policies)",
    ],
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("az-complexity")


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ResourceTypeInfo:
    name: str
    api_version: str
    locations: list[str] = field(default_factory=list)
    flat_params: int = 0
    recursive_params: int = 0
    max_depth: int = 0
    writable_params: int = 0
    readonly_params: int = 0


@dataclass
class ProviderData:
    namespace: str
    registration_state: str = "NotRegistered"
    resource_types: list[ResourceTypeInfo] = field(default_factory=list)
    operations_count: int = 0
    skus: dict[str, int] = field(default_factory=dict)  # resource_type -> count
    total_skus: int = 0
    total_flat_params: int = 0
    total_recursive_params: int = 0
    licensing_options: list[str] = field(default_factory=list)
    complexity_score: float = 0.0
    spec_definitions_count: int = 0
    sub_services: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cache Manager
# ---------------------------------------------------------------------------

class CacheManager:
    """Simple file-based cache for API and HTTP responses."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, identifier: str) -> Path:
        h = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        safe = re.sub(r'[^\w\-.]', '_', identifier)[:80]
        return self.cache_dir / f"{safe}_{h}.json"

    def get(self, identifier: str) -> Optional[Any]:
        p = self._key(identifier)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def put(self, identifier: str, data: Any) -> None:
        p = self._key(identifier)
        p.write_text(json.dumps(data, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Azure CLI / REST helpers
# ---------------------------------------------------------------------------

def az_cli(args: list[str], cache: CacheManager) -> Any:
    """Run an az CLI command and return parsed JSON, with caching."""
    key = "az_" + "_".join(args)
    cached = cache.get(key)
    if cached is not None:
        return cached

    cmd = ["az"] + args + ["-o", "json"]
    log.info("Running: az %s", " ".join(args[:4]))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            log.warning("az CLI error: %s", result.stderr[:200])
            return None
        data = json.loads(result.stdout)
        cache.put(key, data)
        return data
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("az CLI failed: %s", e)
        return None


def az_rest(url: str, cache: CacheManager) -> Any:
    """Call Azure REST API via az rest, with caching."""
    key = "rest_" + url
    cached = cache.get(key)
    if cached is not None:
        return cached

    log.info("REST: %s", url[:100])
    try:
        result = subprocess.run(
            ["az", "rest", "--method", "get", "--url", url],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            log.warning("REST error for %s: %s", url[:60], result.stderr[:200])
            return None
        data = json.loads(result.stdout)
        cache.put(key, data)
        return data
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("REST failed: %s", e)
        return None



# ---------------------------------------------------------------------------
# Layer 1: Provider Discovery
# ---------------------------------------------------------------------------

class ProviderDiscovery:
    """Discovers Azure providers, resource types, and API versions."""

    def __init__(self, cache: CacheManager):
        self.cache = cache

    def get_subscription_id(self) -> str:
        data = az_cli(["account", "show", "--query", "id"], self.cache)
        return data.strip('"') if isinstance(data, str) else str(data)

    def list_providers(self, target: list[str] | None = None) -> list[ProviderData]:
        """List Azure providers. If target is given, only return those."""
        raw = az_cli(["provider", "list"], self.cache)
        if not raw:
            log.error("Failed to list providers")
            return []

        providers = []
        for p in raw:
            ns = p.get("namespace", "")
            if not ns.startswith("Microsoft."):
                continue
            if target and ns not in target:
                continue

            pd = ProviderData(
                namespace=ns,
                registration_state=p.get("registrationState", "Unknown"),
            )
            providers.append(pd)

        log.info("Found %d providers%s", len(providers),
                 f" (filtered to {len(target)})" if target else "")
        return sorted(providers, key=lambda x: x.namespace)

    def enrich_resource_types(self, provider: ProviderData) -> None:
        """Fetch detailed resource type info for a provider."""
        data = az_cli(["provider", "show", "--namespace", provider.namespace], self.cache)
        if not data:
            return

        for rt in data.get("resourceTypes", []):
            api_versions = rt.get("apiVersions", [])
            rti = ResourceTypeInfo(
                name=rt.get("resourceType", "unknown"),
                api_version=api_versions[0] if api_versions else "unknown",
                locations=rt.get("locations", []),
            )
            provider.resource_types.append(rti)


# ---------------------------------------------------------------------------
# Layer 2: Operations & SKU Enumeration
# ---------------------------------------------------------------------------

class OperationsEnumerator:
    """Counts RBAC/management operations per provider."""

    def __init__(self, cache: CacheManager):
        self.cache = cache

    def count_operations(self, provider: ProviderData) -> None:
        ns = provider.namespace

        # Use the provider's own latest stable API version first,
        # then fall back to common versions
        provider_versions = set()
        for rt in provider.resource_types:
            v = rt.api_version
            if v and v != "unknown" and "preview" not in v:
                provider_versions.add(v)

        # Sort descending (newest first), then add common fallbacks
        versions = sorted(provider_versions, reverse=True)[:3]
        for fallback in ["2023-01-01", "2022-09-01", "2021-04-01"]:
            if fallback not in versions:
                versions.append(fallback)

        for api_version in versions:
            url = (f"https://management.azure.com/providers/{ns}"
                   f"/operations?api-version={api_version}")
            data = az_rest(url, self.cache)
            if data and "value" in data:
                provider.operations_count = len(data["value"])
                log.info("  %s: %d operations (api-version %s)",
                         ns, provider.operations_count, api_version)
                return

        log.warning("  %s: could not fetch operations", ns)


# Curated SKU counts for providers without a standard SKU API endpoint
CURATED_SKUS: dict[str, dict[str, int]] = {
    "Microsoft.Web": {
        "serverFarms": 12,         # Free, Shared, Basic(B1-B3), Standard(S1-S3), Premium(P1v3-P3v3), Isolated(I1v2-I3v2)
        "sites": 6,                # WebApp, FunctionApp, LogicApp, StaticSite, ContainerApp, WordPress
        "certificates": 3,         # App Service Certificate variants
        "hostingEnvironments": 3,  # ASE v1, v2, v3
    },
    "Microsoft.KeyVault": {
        "vaults": 2,               # Standard, Premium
        "managedHSMs": 1,          # Standard_B1
        "keys": 3,                 # RSA, EC, Symmetric
    },
}


class SkuEnumerator:
    """Enumerates SKUs per provider, filtered to reference region."""

    def __init__(self, cache: CacheManager, subscription_id: str):
        self.cache = cache
        self.sub_id = subscription_id

    def enumerate_skus(self, provider: ProviderData) -> None:
        ns = provider.namespace

        # Compute has a dedicated SKU endpoint
        if ns == "Microsoft.Compute":
            url = (f"https://management.azure.com/subscriptions/{self.sub_id}"
                   f"/providers/Microsoft.Compute/skus"
                   f"?api-version=2021-07-01"
                   f"&$filter=location eq '{REFERENCE_REGION}'")
            data = az_rest(url, self.cache)
            if data and "value" in data:
                counts: dict[str, int] = Counter()
                for sku in data["value"]:
                    rt = sku.get("resourceType", "unknown")
                    counts[rt] += 1
                provider.skus = dict(counts)
                provider.total_skus = sum(counts.values())
                log.info("  %s: %d SKUs across %d resource types",
                         ns, provider.total_skus, len(counts))
                return

        # Generic approach: try the provider-level SKU list
        # Some providers support /skus on specific resource types
        # For now, try a general approach via resource type enumeration
        total = 0
        for rt in provider.resource_types[:5]:  # Limit to avoid too many calls
            for api_ver in [rt.api_version, "2023-01-01"]:
                url = (f"https://management.azure.com/subscriptions/{self.sub_id}"
                       f"/providers/{ns}/skus"
                       f"?api-version={api_ver}")
                data = az_rest(url, self.cache)
                if data and "value" in data:
                    counts = Counter()
                    for sku in data["value"]:
                        srt = sku.get("resourceType", rt.name)
                        counts[srt] += 1
                    provider.skus.update(dict(counts))
                    total += sum(counts.values())
                    break

        if total > 0:
            provider.total_skus = total
            log.info("  %s: %d SKUs", ns, total)
        else:
            # Use curated SKU data for providers without a standard SKU endpoint
            curated = CURATED_SKUS.get(ns)
            if curated:
                provider.skus = curated
                provider.total_skus = sum(curated.values())
                log.info("  %s: %d SKUs (curated)", ns, provider.total_skus)



# ---------------------------------------------------------------------------
# Layer 3: OpenAPI Spec Crawling & Property Counting
# ---------------------------------------------------------------------------

class OpenApiCrawler:
    """Parses Azure OpenAPI specs from local clone to count configuration parameters."""

    def __init__(self, cache: CacheManager):
        self.cache = cache

    def analyze_provider(self, provider: ProviderData) -> None:
        """Analyze OpenAPI specs for a provider and populate param counts."""
        ns = provider.namespace
        spec_groups = self._discover_specs_local(ns)

        if not spec_groups:
            log.warning("  %s: no spec paths found", ns)
            return

        # For each spec group (sub-RP), merge definitions and count
        all_resource_params: dict[str, dict] = {}

        for group in spec_groups:
            merged_defs = {}
            files_loaded = 0

            for fname in group["files"]:
                spec = self._load_local_spec(group["base"], fname)
                if spec:
                    defs = spec.get("definitions", {})
                    merged_defs.update(defs)
                    files_loaded += 1

                    # Also extract resource type hints from paths
                    self._extract_resource_params(spec, merged_defs, all_resource_params)

            if files_loaded == 0:
                continue

            log.info("  %s/%s: loaded %d files, %d definitions",
                     ns, group.get("sub_rp", "root"), files_loaded, len(merged_defs))

            # Count parameters for all *Properties definitions
            self._count_properties(ns, merged_defs, all_resource_params)

        # Map results back to resource types
        provider.spec_definitions_count = sum(
            1 for rp in all_resource_params.values() if rp.get("recursive", 0) > 0
        )
        self._apply_to_provider(provider, all_resource_params)

    def _extract_resource_params(self, spec: dict, merged_defs: dict,
                                  all_resource_params: dict) -> None:
        """Extract resource type to properties-definition mappings from paths."""
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            segments = [s for s in path.split("/") if s and not s.startswith("{")]
            if len(segments) < 2:
                continue

            rt_name = self._path_to_resource_type(path)
            if not rt_name:
                continue

            # Prefer PUT over PATCH (PUT has the full resource definition)
            for method_key in ("put", "patch"):
                method_data = methods.get(method_key)
                if not isinstance(method_data, dict):
                    continue
                params = method_data.get("parameters", [])
                for param in params:
                    if param.get("in") == "body":
                        schema = param.get("schema", {})
                        ref = schema.get("$ref", "")
                        if ref:
                            def_name = ref.split("/")[-1]
                            if def_name:
                                existing = all_resource_params.get(rt_name, {})
                                # Only set if not already set, or if this is PUT replacing PATCH
                                if "definition" not in existing or method_key == "put":
                                    all_resource_params.setdefault(rt_name, {})
                                    all_resource_params[rt_name]["definition"] = def_name
                                break  # Found body param for this method
                break  # Found a usable method (PUT preferred)

    def _path_to_resource_type(self, path: str) -> str | None:
        """Extract a resource type name from an API path."""
        # Pattern: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.X/resourceTypes/{name}
        parts = path.rstrip("/").split("/")
        # Find the last non-parameter segment
        resource_parts = []
        found_providers = False
        for i, part in enumerate(parts):
            if part == "providers":
                found_providers = True
                resource_parts = []
                continue
            if found_providers and not part.startswith("{"):
                resource_parts.append(part)

        if len(resource_parts) >= 2:
            # Skip the namespace (Microsoft.X), return the resource type
            return "/".join(resource_parts[1:])
        return None

    def _count_properties(self, ns: str, merged_defs: dict,
                          all_resource_params: dict) -> None:
        """Count properties for all resource definitions."""
        # Strategy 1: Count from mapped definitions (from paths)
        for rt_name, info in all_resource_params.items():
            def_name = info.get("definition")
            if not def_name or def_name not in merged_defs:
                continue

            definition = merged_defs[def_name]
            flat = self._count_flat(definition)
            recursive, depth = self._count_recursive(def_name, merged_defs)
            writable, readonly = self._count_access(def_name, merged_defs)

            info["flat"] = flat
            info["recursive"] = recursive
            info["max_depth"] = depth
            info["writable"] = writable
            info["readonly"] = readonly

        # Strategy 2: Find *Properties definitions that weren't mapped
        for def_name, definition in merged_defs.items():
            if not def_name.endswith("Properties"):
                continue

            # Derive resource type name from definition name
            base = def_name[:-len("Properties")]
            # Check if this maps to a known resource type
            rt_name = self._fuzzy_match_resource_type(base, all_resource_params)
            if rt_name and all_resource_params[rt_name].get("recursive", 0) > 0:
                continue  # Already counted

            flat = self._count_flat(definition)
            recursive, depth = self._count_recursive(def_name, merged_defs)

            if recursive > 0:
                key = rt_name or base
                all_resource_params.setdefault(key, {})
                if all_resource_params[key].get("recursive", 0) < recursive:
                    all_resource_params[key]["flat"] = flat
                    all_resource_params[key]["recursive"] = recursive
                    all_resource_params[key]["max_depth"] = depth
                    writable, readonly = self._count_access(def_name, merged_defs)
                    all_resource_params[key]["writable"] = writable
                    all_resource_params[key]["readonly"] = readonly

    def _fuzzy_match_resource_type(self, base_name: str,
                                     existing: dict) -> str | None:
        """Try to match a definition base name to an existing resource type."""
        lower = base_name.lower()
        for rt in existing:
            rt_lower = rt.lower().replace("/", "")
            if lower == rt_lower or lower in rt_lower or rt_lower in lower:
                return rt
        return None

    def _count_flat(self, definition: dict) -> int:
        """Count top-level properties (flat count)."""
        props = definition.get("properties", {})
        count = len(props)
        # Also check allOf for inherited properties
        for item in definition.get("allOf", []):
            count += len(item.get("properties", {}))
        return count

    def _count_recursive(self, def_name: str, all_defs: dict,
                          visited: set | None = None, depth: int = 0) -> tuple[int, int]:
        """Recursively count all leaf properties, tracking max depth."""
        if visited is None:
            visited = set()

        if def_name in visited:
            return 0, depth
        visited.add(def_name)

        definition = all_defs.get(def_name, {})
        count = 0
        max_depth = depth

        # Collect properties from direct and allOf
        all_props = {}
        for item in definition.get("allOf", []):
            ref = item.get("$ref", "")
            if ref:
                ref_name = ref.split("/")[-1]
                sub_count, sub_depth = self._count_recursive(
                    ref_name, all_defs, visited, depth + 1)
                count += sub_count
                max_depth = max(max_depth, sub_depth)
            all_props.update(item.get("properties", {}))
        all_props.update(definition.get("properties", {}))

        for prop_name, prop in all_props.items():
            ref = prop.get("$ref", "")
            if ref:
                ref_name = ref.split("/")[-1]
                sub_count, sub_depth = self._count_recursive(
                    ref_name, all_defs, visited, depth + 1)
                count += sub_count
                max_depth = max(max_depth, sub_depth)
            elif prop.get("type") == "object" and "properties" in prop:
                # Inline object — count its properties recursively
                for sub_name, sub_prop in prop["properties"].items():
                    sub_ref = sub_prop.get("$ref", "")
                    if sub_ref:
                        ref_name = sub_ref.split("/")[-1]
                        sc, sd = self._count_recursive(
                            ref_name, all_defs, visited, depth + 2)
                        count += sc
                        max_depth = max(max_depth, sd)
                    else:
                        count += 1
                        max_depth = max(max_depth, depth + 2)
            elif prop.get("type") == "array":
                items = prop.get("items", {})
                items_ref = items.get("$ref", "")
                if items_ref:
                    ref_name = items_ref.split("/")[-1]
                    sub_count, sub_depth = self._count_recursive(
                        ref_name, all_defs, visited, depth + 1)
                    count += sub_count
                    max_depth = max(max_depth, sub_depth)
                else:
                    count += 1
                    max_depth = max(max_depth, depth + 1)
            else:
                # Leaf property (string, int, bool, enum)
                count += 1
                max_depth = max(max_depth, depth + 1)

        return count, max_depth

    def _count_access(self, def_name: str, all_defs: dict,
                       visited: set | None = None) -> tuple[int, int]:
        """Count writable vs read-only properties recursively."""
        if visited is None:
            visited = set()
        if def_name in visited:
            return 0, 0
        visited.add(def_name)

        definition = all_defs.get(def_name, {})
        writable = 0
        readonly = 0

        all_props = {}
        for item in definition.get("allOf", []):
            ref = item.get("$ref", "")
            if ref:
                ref_name = ref.split("/")[-1]
                w, r = self._count_access(ref_name, all_defs, visited)
                writable += w
                readonly += r
            all_props.update(item.get("properties", {}))
        all_props.update(definition.get("properties", {}))

        for prop_name, prop in all_props.items():
            is_readonly = prop.get("readOnly", False)
            ref = prop.get("$ref", "")
            if ref:
                ref_name = ref.split("/")[-1]
                w, r = self._count_access(ref_name, all_defs, visited)
                writable += w
                readonly += r
            elif prop.get("type") == "array":
                items_ref = prop.get("items", {}).get("$ref", "")
                if items_ref:
                    ref_name = items_ref.split("/")[-1]
                    w, r = self._count_access(ref_name, all_defs, visited)
                    writable += w
                    readonly += r
                else:
                    if is_readonly:
                        readonly += 1
                    else:
                        writable += 1
            else:
                if is_readonly:
                    readonly += 1
                else:
                    writable += 1

        return writable, readonly

    def _discover_specs_local(self, namespace: str) -> list[dict]:
        """Discover spec file groups from local clone (full mode)."""
        # Map namespace to spec directory name
        short = namespace.split(".")[-1].lower()
        spec_base = SPECS_LOCAL / "specification"

        # Try common patterns
        candidates = [
            spec_base / short / "resource-manager" / namespace,
            spec_base / short / "resource-manager",
        ]

        for base in candidates:
            if not base.exists():
                continue

            groups = []
            # Pattern 1: sub-RP directories (e.g., Microsoft.Compute has ComputeRP, DiskRP)
            # Pattern 2: direct stable/ directory
            for child in sorted(base.iterdir()):
                if child.is_dir() and child.name not in ("common-types", "examples"):
                    stable_dir = child / "stable" if child.name != "stable" else child
                    if not stable_dir.exists():
                        continue

                    # Find latest version
                    versions = sorted(
                        [d.name for d in stable_dir.iterdir() if d.is_dir()],
                        reverse=True
                    )
                    if not versions:
                        continue

                    latest = versions[0]
                    version_dir = stable_dir / latest
                    json_files = [
                        f.name for f in version_dir.iterdir()
                        if f.is_file() and f.suffix == ".json"
                    ]
                    if json_files:
                        rel_base = str(version_dir.relative_to(SPECS_LOCAL))
                        groups.append({
                            "sub_rp": child.name if child.name != "stable" else None,
                            "version": latest,
                            "base": rel_base,
                            "files": json_files,
                        })

            if groups:
                return groups

        return []

    def _load_local_spec(self, base: str, fname: str) -> dict | None:
        """Load a spec file from local clone."""
        path = SPECS_LOCAL / base / fname
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Failed to load %s: %s", path, e)
            return None

    def _apply_to_provider(self, provider: ProviderData,
                            resource_params: dict) -> None:
        """Map analyzed spec data back to provider resource types."""
        # Build lookups with priority: full name > last segment
        # Use separate dicts to avoid collisions
        rt_by_full_name: dict[str, ResourceTypeInfo] = {}
        rt_by_last_segment: dict[str, ResourceTypeInfo] = {}

        for rt in provider.resource_types:
            rt_by_full_name[rt.name.lower()] = rt
            last = rt.name.split("/")[-1].lower()
            # Only use last-segment if it's the same as full (no slash)
            # This prevents virtualMachineScaleSets/virtualMachines from
            # stealing the virtualMachines slot
            if "/" not in rt.name:
                rt_by_last_segment[last] = rt

        matched = set()
        unmatched_flat = 0
        unmatched_recursive = 0

        for rt_key, params in resource_params.items():
            if params.get("recursive", 0) == 0:
                continue

            key_lower = rt_key.lower()
            last_lower = rt_key.split("/")[-1].lower()

            # Priority 1: exact full-name match
            rt_info = rt_by_full_name.get(key_lower)
            # Priority 2: last segment (only for top-level types)
            if not rt_info:
                rt_info = rt_by_last_segment.get(last_lower)
            # Priority 3: case-insensitive fuzzy (PascalCase definition names)
            if not rt_info:
                # Try matching PascalCase to camelCase resource types
                # e.g., "VirtualMachineImage" -> "virtualMachineImages"
                for rt in provider.resource_types:
                    rt_lower = rt.name.lower().replace("/", "")
                    if (key_lower == rt_lower or
                        key_lower + "s" == rt_lower or
                        key_lower == rt_lower + "s"):
                        rt_info = rt
                        break

            if rt_info:
                # Only update if we have better data (higher recursive count)
                if params.get("recursive", 0) > rt_info.recursive_params:
                    rt_info.flat_params = params.get("flat", 0)
                    rt_info.recursive_params = params.get("recursive", 0)
                    rt_info.max_depth = params.get("max_depth", 0)
                    rt_info.writable_params = params.get("writable", 0)
                    rt_info.readonly_params = params.get("readonly", 0)
                matched.add(rt_info.name)
            else:
                unmatched_flat += params.get("flat", 0)
                unmatched_recursive += params.get("recursive", 0)

        # Sum totals from matched resource types
        provider.total_flat_params = (
            sum(rt.flat_params for rt in provider.resource_types) + unmatched_flat
        )
        provider.total_recursive_params = (
            sum(rt.recursive_params for rt in provider.resource_types) + unmatched_recursive
        )

        log.info("  %s: matched %d resource types, total recursive params: %d (unmatched: %d)",
                 provider.namespace, len(matched), provider.total_recursive_params,
                 unmatched_recursive)


# ---------------------------------------------------------------------------
# Layer 4: Licensing Mapping
# ---------------------------------------------------------------------------

LICENSING_MAP: dict[str, list[str]] = {
    "Microsoft.Compute": ["Reserved Instances", "AHUB", "Savings Plans", "Spot", "Dev/Test"],
    "Microsoft.Sql": ["Reserved Instances", "AHUB", "Dev/Test"],
    "Microsoft.DBforMySQL": ["Reserved Instances", "Dev/Test"],
    "Microsoft.DBforPostgreSQL": ["Reserved Instances", "Dev/Test"],
    "Microsoft.DBforMariaDB": ["Reserved Instances"],
    "Microsoft.DocumentDB": ["Reserved Instances", "Savings Plans"],
    "Microsoft.Cache": ["Reserved Instances"],
    "Microsoft.Synapse": ["Reserved Instances", "Dev/Test"],
    "Microsoft.Databricks": ["Reserved Instances"],
    "Microsoft.HDInsight": ["Reserved Instances"],
    "Microsoft.Kusto": ["Reserved Instances"],
    "Microsoft.Storage": ["Reserved Instances", "Savings Plans"],
    "Microsoft.NetApp": ["Reserved Instances"],
    "Microsoft.Web": ["Reserved Instances", "Savings Plans", "Dev/Test"],
    "Microsoft.App": ["Savings Plans"],
    "Microsoft.ContainerService": ["Reserved Instances", "Savings Plans", "Spot"],
    "Microsoft.RedHatOpenShift": ["Reserved Instances", "AHUB"],
    "Microsoft.VMwareCloudSimple": ["Reserved Instances", "AHUB"],
    "Microsoft.AVS": ["Reserved Instances", "AHUB"],
    "Microsoft.Network": ["Savings Plans"],
    "Microsoft.Cdn": ["Savings Plans"],
    "Microsoft.ApiManagement": ["Reserved Instances", "Dev/Test"],
    "Microsoft.KeyVault": ["Dev/Test"],
    "Microsoft.CognitiveServices": ["Reserved Instances", "Savings Plans"],
    "Microsoft.MachineLearningServices": ["Reserved Instances", "Savings Plans"],
    "Microsoft.SignalRService": ["Reserved Instances"],
    "Microsoft.AppPlatform": ["Reserved Instances"],
    "Microsoft.DesktopVirtualization": ["Reserved Instances", "AHUB"],
    "Microsoft.SqlVirtualMachine": ["AHUB", "Dev/Test"],
    "Microsoft.AzureArcData": ["AHUB"],
}


class LicensingMapper:
    """Maps providers to their licensing/pricing options."""

    @staticmethod
    def apply(provider: ProviderData) -> None:
        provider.licensing_options = LICENSING_MAP.get(provider.namespace, [])


# ---------------------------------------------------------------------------
# Layer 5: Complexity Scoring
# ---------------------------------------------------------------------------

class ComplexityScorer:
    """Computes a weighted complexity score per provider."""

    WEIGHTS = {
        "config_params": 2.0,
        "resource_types": 1.0,
        "operations": 0.5,
        "skus": 0.1,
        "licensing": 3.0,
    }

    @staticmethod
    def score(provider: ProviderData) -> float:
        w = ComplexityScorer.WEIGHTS
        raw = (
            provider.total_recursive_params * w["config_params"]
            + len(provider.resource_types) * w["resource_types"]
            + provider.operations_count * w["operations"]
            + provider.total_skus * w["skus"]
            + len(provider.licensing_options) * w["licensing"]
        )
        provider.complexity_score = round(raw, 1)
        return raw


# ---------------------------------------------------------------------------
# Layer 6: HTML Report Generator
# ---------------------------------------------------------------------------

class HtmlReportGenerator:
    """Generates a self-contained HTML report with inline CSS and JS."""

    def __init__(self, providers: list[ProviderData], mode: str):
        self.providers = sorted(providers, key=lambda p: p.complexity_score, reverse=True)
        self.mode = mode
        self.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def generate(self) -> str:
        total_providers = len(self.providers)
        total_rt = sum(len(p.resource_types) for p in self.providers)
        total_params = sum(p.total_recursive_params for p in self.providers)
        total_flat = sum(p.total_flat_params for p in self.providers)
        total_skus = sum(p.total_skus for p in self.providers)
        total_ops = sum(p.operations_count for p in self.providers)
        total_score = sum(p.complexity_score for p in self.providers)
        max_score = max((p.complexity_score for p in self.providers), default=0)
        umbrella_providers = sum(1 for p in self.providers if p.sub_services)
        total_sub_services = sum(len(p.sub_services) for p in self.providers)

        # Licensing matrix data
        all_license_types = sorted(set(
            lt for p in self.providers for lt in p.licensing_options
        ))

        provider_rows = "\n".join(
            self._provider_summary_row(p, max_score) for p in self.providers
        )
        provider_details = "\n".join(
            self._provider_detail(p, max_score) for p in self.providers
        )
        licensing_matrix = self._licensing_matrix(all_license_types)

        # Human cost narrative
        pages_equiv = total_params * 3 // 400  # ~3 lines per param, ~400 lines per page
        hours_5min = total_params * 5 / 60
        days_8hr = hours_5min / 8
        years_equiv = days_8hr / 260

        human_cost = self._human_cost_section(
            total_params, pages_equiv, hours_5min, days_8hr, years_equiv
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure Complexity Report</title>
{self._css()}
</head>
<body>
<div class="container">

<!-- Hero / Executive Summary -->
<header class="hero">
    <h1>Azure Complexity Report</h1>
    <p class="subtitle">Every knob, switch, and dropdown that a single Azure Lead must understand</p>
    <p class="mode-badge">{"Preview (3 providers)" if self.mode == "preview" else f"Full sweep &mdash; {total_providers} resource providers"}</p>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-number">{total_providers:,}</div>
            <div class="stat-label">Resource Providers</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_sub_services:,}</div>
            <div class="stat-label">Distinct Products Inside {umbrella_providers} Umbrella Providers</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_rt:,}</div>
            <div class="stat-label">Resource Types</div>
        </div>
        <div class="stat-card accent">
            <div class="stat-number">{total_params:,}</div>
            <div class="stat-label">Config Parameters (Recursive)</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_skus:,}</div>
            <div class="stat-label">SKU Variants</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_ops:,}</div>
            <div class="stat-label">API Operations</div>
        </div>
    </div>
</header>

<!-- Human Cost -->
{human_cost}

<!-- Methodology -->
<section class="section" id="methodology">
    <h2>Methodology</h2>
    <div class="methodology-grid">
        <div class="method-card">
            <h3>Provider Discovery</h3>
            <p>Enumerated via <code>az provider list</code> and <code>az provider show</code>. Captures all resource types and their latest API versions.</p>
        </div>
        <div class="method-card">
            <h3>Operations Count</h3>
            <p>Fetched via Azure REST API <code>/providers/{{ns}}/operations</code>. Each operation represents an RBAC-relevant management action.</p>
        </div>
        <div class="method-card">
            <h3>SKU Enumeration</h3>
            <p>Queried from the Azure SKU API filtered to <strong>{REFERENCE_REGION}</strong> (Azure's most complete region). Grouped by resource type.</p>
        </div>
        <div class="method-card">
            <h3>Config Parameters</h3>
            <p>Parsed from Azure OpenAPI specs on GitHub. Each spec's <code>definitions</code> are recursively walked to count every leaf property (string, int, bool, enum). Circular references are detected and broken.</p>
        </div>
        <div class="method-card">
            <h3>Licensing Options</h3>
            <p>Curated mapping of {len(LICENSING_MAP)} providers to applicable commercial options: Reserved Instances, AHUB, Savings Plans, Spot pricing, and Dev/Test pricing.</p>
        </div>
        <div class="method-card">
            <h3>Complexity Score</h3>
            <p>Weighted composite: Config params (&times;{ComplexityScorer.WEIGHTS['config_params']}), Resource types (&times;{ComplexityScorer.WEIGHTS['resource_types']}), Operations (&times;{ComplexityScorer.WEIGHTS['operations']}), SKUs (&times;{ComplexityScorer.WEIGHTS['skus']}), Licensing (&times;{ComplexityScorer.WEIGHTS['licensing']}).</p>
        </div>
        <div class="method-card">
            <h3>Sub-Service Breakdown</h3>
            <p>Many providers are umbrella namespaces containing multiple separately-marketed products. For {umbrella_providers} providers, we enumerate every distinct product bundled within &mdash; <strong>{total_sub_services} products</strong> total. For example, CognitiveServices alone contains 21 distinct AI services (from <code>az cognitiveservices account list-kinds</code>). These are listed in full per provider below.</p>
        </div>
    </div>
</section>

<!-- Provider Rankings -->
<section class="section" id="rankings">
    <h2>Providers Ranked by Complexity</h2>

    <div class="section-intro">
        <p>The table below ranks all <strong>{total_providers} Azure resource providers</strong> by a weighted complexity score. This score is not a subjective assessment &mdash; it is a <strong>computed composite</strong> derived from five measurable dimensions of each provider's management surface area: the number of configuration parameters (weighted &times;{ComplexityScorer.WEIGHTS['config_params']}), resource types (&times;{ComplexityScorer.WEIGHTS['resource_types']}), API operations (&times;{ComplexityScorer.WEIGHTS['operations']}), SKU variants (&times;{ComplexityScorer.WEIGHTS['skus']}), and licensing options (&times;{ComplexityScorer.WEIGHTS['licensing']}).</p>
        <p>Configuration parameters carry the heaviest weight because they represent the deepest layer of domain knowledge &mdash; the individual fields, nested objects, enums, and conditional properties that an administrator must understand to correctly deploy and operate a resource. A single misconfigured parameter (an NSG rule, a TLS version, a replication setting) can cause outages, security breaches, or unexpected costs.</p>
        <p>Click any column header to re-sort. The <strong>Products</strong> column shows how many distinct, separately-marketed services are bundled inside each provider namespace &mdash; a measure of conceptual breadth that no single metric captures. Providers without a products count are single-purpose namespaces (one provider, one service). The <strong>Score</strong> bar visualises each provider's complexity relative to the most complex provider in the dataset.</p>
    </div>

    <table class="data-table sortable" id="rankings-table">
        <thead>
            <tr>
                <th onclick="sortTable('rankings-table', 0)">Rank</th>
                <th onclick="sortTable('rankings-table', 1)">Provider</th>
                <th onclick="sortTable('rankings-table', 2, true)">Products</th>
                <th onclick="sortTable('rankings-table', 3, true)">Resource Types</th>
                <th onclick="sortTable('rankings-table', 4, true)">Config Params</th>
                <th onclick="sortTable('rankings-table', 5, true)">SKUs</th>
                <th onclick="sortTable('rankings-table', 6, true)">Operations</th>
                <th onclick="sortTable('rankings-table', 7, true)">Licensing</th>
                <th onclick="sortTable('rankings-table', 8, true)">Complexity Score</th>
                <th>Score</th>
            </tr>
        </thead>
        <tbody>
{provider_rows}
        </tbody>
    </table>
</section>

<!-- Provider Details -->
<section class="section" id="details">
    <div style="display:flex;justify-content:space-between;align-items:center">
        <h2 style="border-bottom:none;margin-bottom:0;padding-bottom:0">Provider-by-Provider Breakdown</h2>
        <button id="toggle-all" class="toggle-btn">Expand All</button>
    </div>
    <hr style="border:none;border-top:2px solid var(--azure-blue);margin:0.5rem 0 1.25rem">

    <div class="section-intro">
        <p>Below is the <strong>complete, provider-by-provider breakdown</strong> of every service namespace registered in Azure Resource Manager. Each collapsible section represents one <em>resource provider</em> &mdash; Azure's fundamental unit of service organisation. A resource provider is the namespace through which Azure exposes all management operations, resource types, SKUs, and configuration settings for a given service.</p>

        <p>For each provider you will find:</p>
        <ul>
            <li><strong>Distinct Products</strong> &mdash; where a single provider namespace is an umbrella for multiple separately-marketed services (e.g.&nbsp;Cognitive Services bundles 21 distinct AI services; Network spans firewalls, load balancers, VPN gateways, DNS, and dozens more), we enumerate every product individually. {umbrella_providers} of the {total_providers} providers are umbrella namespaces, collectively housing <strong>{total_sub_services:,} distinct products</strong>.</li>
            <li><strong>Resource Types</strong> &mdash; every ARM resource type the provider exposes. These are the building blocks you create, configure, and manage &mdash; from virtual machines and databases to policy assignments and diagnostic settings. Each resource type has its own lifecycle, RBAC actions, and API surface.</li>
            <li><strong>Configuration Parameters</strong> &mdash; the total number of individual settings (strings, integers, booleans, enums, nested objects) found by recursively walking the Azure OpenAPI specification for each resource type's PUT body. This is the true measure of the "knob count" &mdash; every field a practitioner could conceivably need to understand or configure.</li>
            <li><strong>SKU Variants</strong> &mdash; the number of distinct SKU/size/tier options available in <strong>{REFERENCE_REGION}</strong> (Azure's most feature-complete region). SKU selection is one of the highest-impact decisions, governing performance, availability, cost, and feature set.</li>
            <li><strong>API Operations</strong> &mdash; the count of RBAC-relevant management actions (create, read, update, delete, plus service-specific actions). These define the full management surface an administrator interacts with.</li>
            <li><strong>Licensing Options</strong> &mdash; applicable commercial models such as Reserved Instances, Azure Hybrid Benefit, Savings Plans, Spot pricing, and Dev/Test pricing, each requiring separate evaluation and optimisation.</li>
        </ul>
        <p>Resource types with zero detected configuration parameters are shown dimmed &mdash; these are typically read-only resources, sub-resources that inherit parent configuration, list endpoints, or types whose specs could not be resolved. They are included for completeness because they still represent management surface area (RBAC, API operations, diagnostics, etc.).</p>
    </div>

{provider_details}
</section>

<!-- Licensing Matrix -->
<section class="section" id="licensing">
    <h2>Licensing &amp; Pricing Matrix</h2>

    <div class="section-intro">
        <p>Azure's complexity extends beyond technical configuration into <strong>commercial optimisation</strong>. Many services offer multiple pricing levers, each with its own commitment terms, discount structures, and eligibility rules. Choosing incorrectly &mdash; or simply failing to choose &mdash; can mean overspending by 30&ndash;72% on the same workload.</p>
        <p>The matrix below maps {len(LICENSING_MAP)} providers to five commercial models that an Azure practitioner must evaluate:</p>
        <ul>
            <li><strong>Reserved Instances (RI)</strong> &mdash; 1-year or 3-year capacity commitments for a specific SKU and region, offering up to 72% savings. Requires accurate capacity forecasting; incorrect reservations are exchangeable but not always refundable.</li>
            <li><strong>Azure Hybrid Benefit (AHUB)</strong> &mdash; bring existing Windows Server or SQL Server licenses (with Software Assurance) to Azure, eliminating the OS/SQL licence cost component. Requires licence inventory tracking and compliance management.</li>
            <li><strong>Savings Plans</strong> &mdash; flexible compute commitments (1-year or 3-year) at a fixed hourly spend that applies across VM families, regions, and services. Less specific than RIs but broader coverage; requires spend forecasting.</li>
            <li><strong>Spot Pricing</strong> &mdash; deeply discounted (up to 90%) access to unused Azure capacity, with the caveat that VMs can be evicted with 30 seconds' notice. Requires fault-tolerant architecture and eviction handling.</li>
            <li><strong>Dev/Test Pricing</strong> &mdash; reduced rates for non-production workloads under Visual Studio subscriptions or Enterprise Dev/Test offers. Requires subscription-level segregation and governance to prevent production workloads running at dev/test rates.</li>
        </ul>
        <p>Each of these models interacts differently with each service and must be evaluated independently. A provider marked with multiple options requires a <strong>layered optimisation strategy</strong> &mdash; for example, Compute workloads may combine Reserved Instances for baseline, Savings Plans for flexible growth, Spot for batch processing, AHUB for Windows licensing, and Dev/Test for non-production environments, all simultaneously within the same subscription.</p>
    </div>

{licensing_matrix}
</section>

<!-- Footer -->
<footer class="footer">
    <p><a href="graph.html" style="color:var(--neon-cyan);text-decoration:none;text-shadow:0 0 8px rgba(34,211,238,0.3)">View Resource Relationship Graph &rarr;</a></p>
    <p>Generated on {self.generated_at} | Mode: {self.mode} | Data sources: Azure CLI, Azure REST API, Azure OpenAPI specs (GitHub)</p>
    <p>Azure Complexity Measurement Tool &mdash; quantifying the knowledge burden of Azure administration</p>
</footer>

</div>
{self._js()}
</body>
</html>"""

    def _human_cost_section(self, total_params: int, pages: int,
                             hours: float, days: float, years: float) -> str:
        top3 = self.providers[:3]
        top3_text = ", ".join(
            f"{self._short_name(p.namespace)} ({p.total_recursive_params:,})"
            for p in top3
        )
        providers_with_licensing = sum(1 for p in self.providers if p.licensing_options)
        umbrella_count = sum(1 for p in self.providers if p.sub_services)
        total_sub = sum(len(p.sub_services) for p in self.providers)

        # Find the most bundled provider
        most_bundled = max(self.providers, key=lambda p: len(p.sub_services), default=None)
        most_bundled_text = ""
        if most_bundled and most_bundled.sub_services:
            most_bundled_text = (
                f" The most densely packed is <strong>{self._short_name(most_bundled.namespace)}</strong>, "
                f"which alone contains <strong>{len(most_bundled.sub_services)} separately-marketed products</strong> "
                f"behind what Azure counts as a single resource provider."
            )

        return f"""<section class="section human-cost" id="human-cost">
    <h2>The Human Cost of Azure</h2>
    <div class="narrative">
        <p>Microsoft Azure is not one product &mdash; it is <strong>{len(self.providers)} resource providers</strong>,
        each its own domain of expertise. Every provider ships a set of resource types, and every resource type
        exposes a tree of configuration parameters: networking rules nested inside security profiles nested inside
        deployment definitions nested inside orchestration templates. When you recurse through every branch of
        every resource type's OpenAPI specification, Azure reveals
        <strong>{total_params:,} individually configurable parameters</strong>.</p>

        <p>That number is the <em>configuration surface area</em> &mdash; the total count of knobs, switches,
        toggles, enums, and free-text fields that an Azure administrator may encounter. It does not include
        the read-only status fields, the deprecated properties, or the preview-only features hidden behind
        feature flags. It is the <strong>minimum</strong> an Azure Lead needs to be aware of.</p>

        <p>But the numbers above only tell part of the story. Azure's {len(self.providers)} resource providers
        are not {len(self.providers)} products &mdash; many are <strong>umbrella namespaces that bundle multiple
        distinct, separately-marketed products</strong> under a single resource provider.
        {umbrella_count} of these providers collectively contain <strong>{total_sub} distinct products</strong>,
        each with its own concepts, documentation, pricing model, and failure modes.{most_bundled_text}</p>

        <p>To put this in human terms:</p>
        <ul>
            <li>Printed at 3 lines per parameter, that is roughly <strong>{pages:,} pages</strong> of
                configuration reference &mdash; a bookshelf, not a book</li>
            <li>If each parameter took just <strong>5 minutes to learn</strong> &mdash; its purpose,
                valid values, defaults, interactions with other parameters, and failure modes &mdash;
                that totals <strong>{hours:,.0f} hours</strong> of study</li>
            <li>Working 8 hours a day with no interruptions, that is
                <strong>{days:,.0f} working days</strong>, or <strong>{years:.1f} years</strong> of
                full-time study doing nothing else</li>
            <li>On top of the parameters, there are <strong>{sum(p.total_skus for p in self.providers):,} SKU
                variants</strong> (sizes, tiers, generations) to choose between, and
                <strong>{sum(p.operations_count for p in self.providers):,} distinct API operations</strong>
                that map to RBAC permissions your security team will ask about</li>
            <li>{providers_with_licensing} of these providers have special commercial licensing
                options &mdash; Reserved Instances, Savings Plans, Hybrid Use Benefit, Spot pricing,
                Dev/Test discounts &mdash; each with its own eligibility rules, commitment terms,
                and cost implications</li>
            <li>Those {len(self.providers)} resource providers actually contain <strong>{total_sub}
                individually marketed products and features</strong>, each requiring its own learning
                path, architecture patterns, operational runbooks, and cost management strategy</li>
        </ul>

        <p>The most complex providers by parameter count are {top3_text}.
        But complexity is not just depth &mdash; it is also breadth: the sheer number of services
        that interact, the cross-cutting concerns of networking, identity, monitoring, and compliance
        that span every one of these {len(self.providers)} providers. A single deployment may touch
        Compute, Network, Storage, KeyVault, Insights, Security, and Authorization simultaneously &mdash;
        each with its own parameter tree, SKU selection, and RBAC surface.</p>

        <p class="callout">In many organisations, one person &mdash; the Azure Lead &mdash; is expected
        to understand all of this. Not superficially, but well enough to architect solutions, review
        pull requests on Bicep templates, advise on cost optimisation, and answer security audit
        questions. The {total_sub} distinct products, {total_params:,} configurable parameters,
        {sum(p.total_skus for p in self.providers):,} SKU variants, and
        {sum(p.operations_count for p in self.providers):,} API operations are not static &mdash;
        they grow with every Azure release, every Generally Available announcement, every new region
        and compliance certification.</p>
    </div>
</section>"""

    def _provider_summary_row(self, p: ProviderData, max_score: float) -> str:
        rank = self.providers.index(p) + 1
        bar_pct = (p.complexity_score / max_score * 100) if max_score > 0 else 0
        license_badges = " ".join(
            f'<span class="badge badge-{self._license_class(lt)}">{lt}</span>'
            for lt in p.licensing_options
        ) or '<span class="badge badge-none">None</span>'
        desc = PROVIDER_DESCRIPTIONS.get(p.namespace, "")
        desc_html = f'<br><span class="provider-desc">{desc}</span>' if desc else ""

        products_count = len(p.sub_services) if p.sub_services else ""

        return f"""            <tr>
                <td>{rank}</td>
                <td><a href="#detail-{p.namespace}">{self._short_name(p.namespace)}</a>{desc_html}</td>
                <td>{products_count}</td>
                <td>{len(p.resource_types):,}</td>
                <td>{p.total_recursive_params:,}</td>
                <td>{p.total_skus:,}</td>
                <td>{p.operations_count:,}</td>
                <td>{license_badges}</td>
                <td>{p.complexity_score:,.1f}</td>
                <td><div class="bar-container"><div class="bar" style="width: {bar_pct:.1f}%"></div></div></td>
            </tr>"""

    def _provider_detail(self, p: ProviderData, max_score: float) -> str:
        bar_pct = (p.complexity_score / max_score * 100) if max_score > 0 else 0
        desc = PROVIDER_DESCRIPTIONS.get(p.namespace, "")

        # Resource types table rows — ALL resource types, params first then zero-param
        rt_with_data = sorted(
            [rt for rt in p.resource_types if rt.recursive_params > 0],
            key=lambda r: r.recursive_params, reverse=True,
        )
        rt_without_data = sorted(
            [rt for rt in p.resource_types if rt.recursive_params == 0],
            key=lambda r: r.name,
        )
        rt_rows = "\n".join(
            f"""                <tr>
                    <td>{self._humanize_name(rt.name)}</td>
                    <td>{rt.flat_params}</td>
                    <td>{rt.recursive_params:,}</td>
                    <td>{rt.max_depth}</td>
                    <td>{rt.writable_params:,}</td>
                    <td>{rt.readonly_params:,}</td>
                </tr>"""
            for rt in rt_with_data
        )
        rt_rows += "\n".join(
            f"""                <tr class="zero-param-row">
                    <td>{self._humanize_name(rt.name)}</td>
                    <td>0</td><td>0</td><td>&mdash;</td><td>&mdash;</td><td>&mdash;</td>
                </tr>"""
            for rt in rt_without_data
        )

        # SKU breakdown
        sku_rows = "\n".join(
            f'                <tr><td>{self._humanize_name(rt)}</td><td>{count:,}</td></tr>'
            for rt, count in sorted(p.skus.items(), key=lambda x: x[1], reverse=True)
        ) if p.skus else '<tr><td colspan="2">No SKU data available</td></tr>'

        license_badges = " ".join(
            f'<span class="badge badge-{self._license_class(lt)}">{lt}</span>'
            for lt in p.licensing_options
        ) or '<span class="badge badge-none">No special licensing</span>'

        desc_html = f'\n            <p class="provider-desc-detail">{desc}</p>' if desc else ""

        # Sub-services section
        sub_services_html = ""
        if p.sub_services:
            sub_items = "\n".join(
                f'                <li>{svc}</li>' for svc in p.sub_services
            )
            sub_services_html = f"""
            <h4>Distinct Products &amp; Features ({len(p.sub_services)})</h4>
            <ul class="sub-services-list">
{sub_items}
            </ul>"""

        products_stat = ""
        if p.sub_services:
            products_stat = f"""
                <div class="mini-stat">
                    <span class="mini-number">{len(p.sub_services)}</span>
                    <span class="mini-label">Distinct Products</span>
                </div>"""

        return f"""    <details class="provider-detail" id="detail-{p.namespace}">
        <summary>
            <span class="provider-name">{self._short_name(p.namespace)}</span>
            <span class="provider-score">Score: {p.complexity_score:,.1f}</span>
            <span class="provider-sub-count">{f'{len(p.sub_services)} products' if p.sub_services else ''}</span>
            <div class="bar-container summary-bar"><div class="bar" style="width: {bar_pct:.1f}%"></div></div>
        </summary>

        <div class="detail-content">{desc_html}
            <div class="detail-stats">{products_stat}
                <div class="mini-stat">
                    <span class="mini-number">{len(p.resource_types)}</span>
                    <span class="mini-label">Resource Types</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-number">{p.total_recursive_params:,}</span>
                    <span class="mini-label">Config Params</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-number">{p.total_skus:,}</span>
                    <span class="mini-label">SKUs</span>
                </div>
                <div class="mini-stat">
                    <span class="mini-number">{p.operations_count}</span>
                    <span class="mini-label">Operations</span>
                </div>
            </div>
{sub_services_html}
            <h4>Licensing &amp; Pricing Options</h4>
            <div class="license-badges">{license_badges}</div>

            <h4>Resource Types ({len(p.resource_types)})</h4>
            <div class="table-scroll">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Resource Type</th>
                        <th>Flat Params</th>
                        <th>Recursive Params</th>
                        <th>Max Depth</th>
                        <th>Writable</th>
                        <th>Read-Only</th>
                    </tr>
                </thead>
                <tbody>
{rt_rows}
                </tbody>
            </table>
            </div>

            <h4>SKU Breakdown</h4>
            <table class="data-table sku-table">
                <thead>
                    <tr><th>Resource Type</th><th>SKU Count</th></tr>
                </thead>
                <tbody>
{sku_rows}
                </tbody>
            </table>
        </div>
    </details>"""

    def _licensing_matrix(self, license_types: list[str]) -> str:
        if not license_types:
            return '<p>No licensing data for analyzed providers.</p>'

        header_cells = "".join(f"<th>{lt}</th>" for lt in license_types)
        rows = []
        for p in self.providers:
            cells = []
            for lt in license_types:
                if lt in p.licensing_options:
                    cells.append('<td class="matrix-yes">&#10003;</td>')
                else:
                    cells.append('<td class="matrix-no">&mdash;</td>')
            rows.append(f'        <tr><td>{self._short_name(p.namespace)}</td>{"".join(cells)}</tr>')

        return f"""    <div class="table-scroll">
    <table class="data-table matrix-table">
        <thead>
            <tr><th>Provider</th>{header_cells}</tr>
        </thead>
        <tbody>
{"".join(rows)}
        </tbody>
    </table>
    </div>"""

    @classmethod
    def _short_name(cls, namespace: str) -> str:
        """Drop 'Microsoft.' prefix and humanize for cleaner display."""
        raw = namespace.removeprefix("Microsoft.")
        return cls._humanize_name(raw)

    # Known acronyms to uppercase when found as standalone words after camelCase split
    _ACRONYMS = {
        'dns', 'ip', 'nsg', 'vpn', 'ssl', 'tls', 'sql', 'vm', 'hsm', 'sas',
        'acl', 'api', 'arm', 'cdn', 'waf', 'bgp', 'nat', 'nic', 'ase',
        'sku', 'aad', 'hci', 'nva', 'tcp', 'udp', 'http', 'https', 'ssh',
        'rdp', 'ftp', 'sftp', 'nfs', 'smb', 'tde', 'dsc', 'aks', 'acr',
        'oci', 'dscp', 'fqdn', 'rbac', 'kql', 'etl', 'cdc', 'iot', 'ai',
        'ml', 'uri', 'url', 'sso', 'mfa', 'oidc', 'hpc', 'gpu', 'ssd',
        'hdd', 'nvme', 'cpu', 'pii', 'dtc', 'dtu', 'byoip',
    }
    # Special-case acronym casing (where all-uppercase isn't right)
    _ACRONYM_CASE = {
        'ddos': 'DDoS', 'vnet': 'VNet', 'ipv4': 'IPv4', 'ipv6': 'IPv6',
        'devops': 'DevOps', 'github': 'GitHub', 'p2s': 'P2S', 's2s': 'S2S',
        'b2b': 'B2B', 'b2c': 'B2C', 'signalr': 'SignalR', 'netapp': 'NetApp',
        'powerbi': 'Power BI', 'documentdb': 'Cosmos DB', 'apis': 'APIs',
    }
    # All-lowercase or awkward names that need manual word splitting
    _LOWERCASE_SPLITS = {
        'dnszones': 'DNS Zones', 'dnssecconfigs': 'DNSSEC Configs',
        'frontdoors': 'Front Doors', 'frontendendpoints': 'Frontend Endpoints',
        'trafficmanagerprofiles': 'Traffic Manager Profiles',
        'trafficmanagergeographichierarchies': 'Traffic Manager Geographic Hierarchies',
        'trafficmanagerusermetricskeys': 'Traffic Manager User Metrics Keys',
        'azureendpoints': 'Azure Endpoints', 'externalendpoints': 'External Endpoints',
        'nestedendpoints': 'Nested Endpoints', 'recordsets': 'Record Sets',
        'elasticpools': 'Elastic Pools', 'metricdefinitions': 'Metric Definitions',
        'validatelink': 'Validate Link', 'heatmaps': 'Heat Maps',
        'customhttpsconfiguration': 'Custom HTTPS Configuration',
        'importexportoperationresults': 'Import Export Operation Results',
        # Provider short names with awkward camelCase boundaries
        'hdinsight': 'HDInsight', 'connectedvmwarevsphere': 'Connected VMware vSphere',
        'powerbidedicated': 'Power BI Dedicated', 'signalrservice': 'SignalR Service',
        'healthcareapis': 'Healthcare APIs', 'documentdb': 'Cosmos DB (DocumentDB)',
        'netapp': 'NetApp', 'databricks': 'Databricks', 'iotoperations': 'IoT Operations',
        'devtestlab': 'Dev/Test Labs', 'awsconnector': 'AWS Connector',
        'azureactivedirectory': 'Azure Active Directory', 'azurearcdata': 'Azure Arc Data',
        'azurestackhci': 'Azure Stack HCI', 'playfab': 'PlayFab',
        'dbforpostgresql': 'Database for PostgreSQL', 'dbformysql': 'Database for MySQL',
        'dbformariadb': 'Database for MariaDB',
        'sqlvirtualmachine': 'SQL Virtual Machine',
        'kubernetesconfiguration': 'Kubernetes Configuration',
        'confidentialledger': 'Confidential Ledger',
        'certificateregistration': 'Certificate Registration',
        'domainregistration': 'Domain Registration', 'storagesync': 'Storage Sync',
        'storagecache': 'Storage Cache', 'streamanalytics': 'Stream Analytics',
        'timeseriesinsights': 'Time Series Insights', 'loadtestservice': 'Load Testing',
        'containerinstance': 'Container Instances', 'fluidrelay': 'Fluid Relay',
        'notificationhubs': 'Notification Hubs', 'botservice': 'Bot Service',
        'videoindexer': 'Video Indexer', 'voiceservices': 'Voice Services',
        'networkcloud': 'Network Cloud', 'digitaltwins': 'Digital Twins',
        'operationalinsights': 'Log Analytics', 'securityinsights': 'Microsoft Sentinel',
        'desktopvirtualization': 'Azure Virtual Desktop',
        'recoveryservices': 'Recovery Services', 'cognitiveservices': 'Cognitive Services',
        'containerservice': 'Kubernetes Service (AKS)',
        'containerregistry': 'Container Registry',
        'machinelearningservices': 'Machine Learning',
        'apimanagement': 'API Management', 'keyvault': 'Key Vault',
        'eventhub': 'Event Hubs', 'servicebus': 'Service Bus',
        'datafactory': 'Data Factory', 'eventgrid': 'Event Grid',
        'appconfiguration': 'App Configuration', 'appplatform': 'Spring Apps',
        'alertsmanagement': 'Alerts Management', 'policyinsights': 'Policy Insights',
        'managedidentity': 'Managed Identity', 'labservices': 'Lab Services',
        'costmanagement': 'Cost Management', 'dataprotection': 'Data Protection',
        'hybridcompute': 'Azure Arc Servers', 'resourcegraph': 'Resource Graph',
        'securitydevops': 'Security DevOps', 'guestconfiguration': 'Guest Configuration',
        'managednetworkfabric': 'Managed Network Fabric',
        'servicefabric': 'Service Fabric', 'servicefabricmesh': 'Service Fabric Mesh',
        'azurefleet': 'Azure Compute Fleet', 'virtualmachineimages': 'VM Image Builder',
        'workloadbuilder': 'Workload Builder', 'networkfunction': 'Network Function',
        'connectedcache': 'Connected Cache', 'storagemover': 'Storage Mover',
        'storageactions': 'Storage Actions', 'storagetasks': 'Storage Tasks',
        'storagediscovery': 'Storage Discovery',
    }

    @classmethod
    def _humanize_name(cls, name: str) -> str:
        """Convert camelCase/PascalCase resource type names to human-readable form."""
        parts = name.split("/")
        humanized = []
        for part in parts:
            low = part.lower()
            # Check for known all-lowercase names that can't be regex-split
            if low in cls._LOWERCASE_SPLITS:
                humanized.append(cls._LOWERCASE_SPLITS[low])
                continue
            # Insert space before uppercase letters following lowercase/digits
            s = re.sub(r'([a-z\d])([A-Z])', r'\1 \2', part)
            # Split acronym runs: "NSGFlow" → "NSG Flow"
            s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', s)
            words = s.split()
            processed = []
            for word in words:
                wl = word.lower()
                if wl in cls._ACRONYM_CASE:
                    processed.append(cls._ACRONYM_CASE[wl])
                elif wl in cls._ACRONYMS:
                    processed.append(word.upper())
                else:
                    processed.append(word[0].upper() + word[1:] if word else word)
            humanized.append(" ".join(processed))
        return " / ".join(humanized)

    @staticmethod
    def _license_class(lt: str) -> str:
        return {
            "Reserved Instances": "ri",
            "AHUB": "ahub",
            "Savings Plans": "sp",
            "Spot": "spot",
            "Dev/Test": "devtest",
        }.get(lt, "other")

    @staticmethod
    def _css() -> str:
        return """<style>
:root {
    --bg-primary: #0a0e1a;
    --bg-secondary: #111827;
    --bg-card: #1a2035;
    --bg-card-alt: #141b2d;
    --bg-elevated: #1e2a42;
    --border: #1e2d4a;
    --border-glow: #0d4f8b;
    --text: #e2e8f0;
    --text-muted: #8892a8;
    --text-bright: #f1f5f9;
    --azure-blue: #3b9eff;
    --azure-dark: #1a6fd4;
    --azure-light: rgba(59,158,255,0.08);
    --azure-accent: #50E6FF;
    --neon-cyan: #22d3ee;
    --neon-blue: #60a5fa;
    --neon-purple: #a78bfa;
    --neon-pink: #f472b6;
    --neon-green: #34d399;
    --neon-orange: #fb923c;
    --glow-cyan: 0 0 20px rgba(34,211,238,0.3), 0 0 40px rgba(34,211,238,0.1);
    --glow-blue: 0 0 20px rgba(59,158,255,0.3), 0 0 40px rgba(59,158,255,0.1);
    --glow-subtle: 0 0 10px rgba(59,158,255,0.15);
    --success: #34d399;
    --warning: #fbbf24;
    --danger: #f87171;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg-primary);
    color: var(--text);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
}

/* Hero */
.hero {
    background: linear-gradient(135deg, #0c1929 0%, #0d2847 40%, #112240 100%);
    border: 1px solid var(--border-glow);
    color: white;
    padding: 3rem 2.5rem;
    border-radius: 16px;
    margin-bottom: 2rem;
    text-align: center;
    position: relative;
    overflow: hidden;
    box-shadow: 0 0 60px rgba(59,158,255,0.08), inset 0 1px 0 rgba(255,255,255,0.05);
}
.hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 30% 0%, rgba(59,158,255,0.12) 0%, transparent 60%),
                radial-gradient(ellipse at 70% 100%, rgba(80,230,255,0.08) 0%, transparent 50%);
    pointer-events: none;
}
.hero h1 {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    text-shadow: 0 0 30px rgba(59,158,255,0.5), 0 0 60px rgba(59,158,255,0.2);
    letter-spacing: -0.02em;
    position: relative;
}
.hero .subtitle {
    font-size: 1.15rem;
    opacity: 0.8;
    margin-bottom: 0.75rem;
    position: relative;
}
.mode-badge {
    display: inline-block;
    background: rgba(59,158,255,0.15);
    border: 1px solid rgba(59,158,255,0.3);
    border-radius: 20px;
    padding: 0.25rem 1rem;
    font-size: 0.85rem;
    margin-bottom: 2rem;
    color: var(--neon-cyan);
    text-shadow: 0 0 8px rgba(34,211,238,0.4);
    position: relative;
}

.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
    position: relative;
}
.stat-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(59,158,255,0.2);
    border-radius: 10px;
    padding: 1.25rem 1rem;
    backdrop-filter: blur(4px);
    transition: border-color 0.3s, box-shadow 0.3s;
}
.stat-card:hover {
    border-color: rgba(59,158,255,0.5);
    box-shadow: var(--glow-subtle);
}
.stat-card.accent {
    background: rgba(80,230,255,0.08);
    border-color: rgba(80,230,255,0.35);
}
.stat-card.accent .stat-number {
    color: var(--neon-cyan);
    text-shadow: 0 0 20px rgba(34,211,238,0.5);
}
.stat-number {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.2;
    color: var(--text-bright);
}
.stat-label {
    font-size: 0.8rem;
    opacity: 0.65;
    margin-top: 0.25rem;
}

/* Sections */
.section {
    background: var(--bg-card);
    border-radius: 12px;
    border: 1px solid var(--border);
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 4px 24px rgba(0,0,0,0.2);
}
.section h2 {
    font-size: 1.5rem;
    color: var(--neon-blue);
    margin-bottom: 1.25rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--border-glow);
    text-shadow: 0 0 15px rgba(96,165,250,0.3);
}
.section-intro {
    background: rgba(59,158,255,0.06);
    border-left: 3px solid var(--azure-blue);
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    border-radius: 0 8px 8px 0;
    line-height: 1.7;
    color: var(--text);
}
.section-intro p { margin: 0 0 0.75rem 0; }
.section-intro ul { margin: 0.5rem 0 0.75rem 1.25rem; padding: 0; }
.section-intro li { margin-bottom: 0.5rem; }
.section-intro strong { color: var(--neon-cyan); }
.section-intro em { color: var(--text-muted); }
.section-intro code {
    background: rgba(59,158,255,0.12);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.84rem;
    color: var(--neon-cyan);
}

/* Human Cost */
.human-cost .narrative {
    font-size: 1.05rem;
    max-width: 800px;
}
.human-cost .narrative strong {
    color: var(--neon-cyan);
    text-shadow: 0 0 8px rgba(34,211,238,0.2);
}
.human-cost ul {
    margin: 1rem 0 1rem 1.5rem;
}
.human-cost li {
    margin-bottom: 0.5rem;
}
.callout {
    background: rgba(59,158,255,0.08);
    border-left: 4px solid var(--azure-blue);
    padding: 1rem 1.25rem;
    border-radius: 0 8px 8px 0;
    margin-top: 1.5rem;
    font-weight: 600;
    color: var(--neon-cyan);
    text-shadow: 0 0 10px rgba(34,211,238,0.2);
}

/* Methodology */
.methodology-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1rem;
}
.method-card {
    background: var(--bg-card-alt);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.method-card:hover {
    border-color: rgba(59,158,255,0.3);
    box-shadow: var(--glow-subtle);
}
.method-card h3 {
    font-size: 0.95rem;
    color: var(--neon-blue);
    margin-bottom: 0.5rem;
    text-shadow: 0 0 8px rgba(96,165,250,0.2);
}
.method-card p {
    font-size: 0.88rem;
    color: var(--text-muted);
}
.method-card code {
    background: rgba(59,158,255,0.12);
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.82rem;
    color: var(--neon-cyan);
}

/* Tables */
.table-scroll {
    overflow-x: auto;
}
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
}
.data-table th, .data-table td {
    text-align: left;
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border);
}
.data-table th {
    background: var(--bg-elevated);
    font-weight: 600;
    color: var(--neon-blue);
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    text-shadow: 0 0 6px rgba(96,165,250,0.15);
}
.data-table th:hover {
    background: rgba(59,158,255,0.15);
    color: var(--neon-cyan);
}
.data-table tbody tr:nth-child(even) {
    background: rgba(255,255,255,0.015);
}
.data-table tbody tr:hover {
    background: rgba(59,158,255,0.06);
}
.data-table a {
    color: var(--azure-blue);
    text-decoration: none;
    transition: color 0.2s, text-shadow 0.2s;
}
.data-table a:hover {
    color: var(--neon-cyan);
    text-shadow: 0 0 8px rgba(34,211,238,0.3);
}

/* Score bars */
.bar-container {
    width: 120px;
    height: 12px;
    background: rgba(255,255,255,0.06);
    border-radius: 6px;
    overflow: hidden;
    display: inline-block;
    vertical-align: middle;
}
.summary-bar {
    width: 150px;
    margin-left: 1rem;
}
.bar {
    height: 100%;
    background: linear-gradient(90deg, var(--azure-blue), var(--neon-cyan));
    border-radius: 6px;
    transition: width 0.3s ease;
    box-shadow: 0 0 8px rgba(34,211,238,0.3);
}

/* Badges */
.badge {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 0.15rem 0.5rem;
    border-radius: 10px;
    margin: 0.1rem;
    white-space: nowrap;
}
.badge-ri { background: rgba(52,211,153,0.12); color: var(--neon-green); border: 1px solid rgba(52,211,153,0.25); }
.badge-ahub { background: rgba(96,165,250,0.12); color: var(--neon-blue); border: 1px solid rgba(96,165,250,0.25); }
.badge-sp { background: rgba(251,146,60,0.12); color: var(--neon-orange); border: 1px solid rgba(251,146,60,0.25); }
.badge-spot { background: rgba(244,114,182,0.12); color: var(--neon-pink); border: 1px solid rgba(244,114,182,0.25); }
.badge-devtest { background: rgba(167,139,250,0.12); color: var(--neon-purple); border: 1px solid rgba(167,139,250,0.25); }
.badge-none { background: rgba(255,255,255,0.04); color: #4a5568; border: 1px solid rgba(255,255,255,0.06); }

.license-badges { margin-bottom: 1.25rem; }

/* Provider detail sections */
.provider-detail {
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 0.75rem;
    overflow: hidden;
    transition: border-color 0.3s;
}
.provider-detail:hover {
    border-color: rgba(59,158,255,0.3);
}
.provider-detail[open] {
    border-color: rgba(59,158,255,0.4);
    box-shadow: 0 0 20px rgba(59,158,255,0.05);
}
.provider-detail summary {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem 1.25rem;
    background: var(--bg-card-alt);
    cursor: pointer;
    font-size: 0.95rem;
    list-style: none;
    transition: background 0.2s;
}
.provider-detail summary::-webkit-details-marker { display: none; }
.provider-detail summary::before {
    content: '\\25B6';
    font-size: 0.7rem;
    color: var(--azure-blue);
    transition: transform 0.2s;
    text-shadow: 0 0 6px rgba(59,158,255,0.3);
}
.provider-detail[open] summary::before {
    transform: rotate(90deg);
}
.provider-detail summary:hover {
    background: rgba(59,158,255,0.06);
}
.provider-name {
    font-weight: 600;
    color: var(--text-bright);
}
.provider-score {
    color: var(--text-muted);
    font-size: 0.85rem;
}
.detail-content {
    padding: 1.5rem;
    border-top: 1px solid var(--border);
    background: var(--bg-card);
}
.detail-content h4 {
    font-size: 1rem;
    color: var(--neon-blue);
    margin: 1.25rem 0 0.75rem;
    text-shadow: 0 0 6px rgba(96,165,250,0.15);
}
.detail-content h4:first-child {
    margin-top: 0;
}
.detail-stats {
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
}
.mini-stat {
    text-align: center;
}
.mini-number {
    display: block;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--neon-cyan);
    text-shadow: 0 0 12px rgba(34,211,238,0.3);
}
.mini-label {
    font-size: 0.78rem;
    color: var(--text-muted);
}
.provider-desc {
    font-size: 0.78rem;
    color: var(--text-muted);
    font-weight: 400;
}
.provider-desc-detail {
    font-size: 0.92rem;
    color: var(--text-muted);
    margin-bottom: 1rem;
    font-style: italic;
}
.provider-sub-count {
    font-size: 0.75rem;
    color: var(--neon-cyan);
    background: rgba(34,211,238,0.1);
    padding: 0.15rem 0.5rem;
    border-radius: 10px;
    font-weight: 600;
    border: 1px solid rgba(34,211,238,0.2);
}
.sub-services-list {
    columns: 2;
    column-gap: 2rem;
    margin: 0.5rem 0 1.25rem 1.25rem;
    font-size: 0.85rem;
    line-height: 1.5;
    color: var(--text);
}
.sub-services-list li {
    margin-bottom: 0.3rem;
    break-inside: avoid;
}
@media (max-width: 768px) {
    .sub-services-list { columns: 1; }
}
.sku-table { max-width: 400px; }
.zero-param-row td { color: var(--text-muted); font-size: 0.82rem; opacity: 0.45; }
.zero-param-row td:first-child { opacity: 0.7; color: var(--text); }
.toggle-btn {
    background: linear-gradient(135deg, var(--azure-blue), var(--neon-cyan));
    color: var(--bg-primary);
    border: none;
    border-radius: 6px;
    padding: 0.4rem 1rem;
    font-size: 0.82rem;
    cursor: pointer;
    font-family: inherit;
    font-weight: 600;
    transition: box-shadow 0.3s, transform 0.2s;
}
.toggle-btn:hover {
    box-shadow: 0 0 16px rgba(34,211,238,0.4);
    transform: translateY(-1px);
}
.note {
    font-size: 0.82rem;
    color: var(--text-muted);
    font-style: italic;
    margin-top: 0.5rem;
}

/* Licensing matrix */
.matrix-table th, .matrix-table td { text-align: center; }
.matrix-table td:first-child { text-align: left; font-weight: 500; }
.matrix-yes { color: var(--neon-green); font-weight: 700; font-size: 1.1rem; text-shadow: 0 0 6px rgba(52,211,153,0.3); }
.matrix-no { color: #2d3748; }

/* Footer */
.footer {
    text-align: center;
    padding: 2rem 1rem;
    color: var(--text-muted);
    font-size: 0.82rem;
    border-top: 1px solid var(--border);
    margin-top: 1rem;
}
.footer p { margin-bottom: 0.25rem; }

/* Print */
@media print {
    :root {
        --bg-primary: white; --bg-secondary: white; --bg-card: white;
        --bg-card-alt: #f9f9f9; --bg-elevated: #f0f0f0;
        --border: #ddd; --border-glow: #ccc;
        --text: #1a1a1a; --text-muted: #666; --text-bright: #000;
        --azure-blue: #0078D4; --neon-cyan: #0078D4; --neon-blue: #0078D4;
        --neon-green: #107C10; --neon-orange: #E65100; --neon-pink: #C62828;
        --neon-purple: #6A1B9A;
    }
    body { background: white; color: black; }
    .container { max-width: 100%; padding: 0; }
    .hero { break-inside: avoid; background: #0078D4 !important; }
    .hero::before { display: none; }
    .section { break-inside: avoid; border: 1px solid #ddd; box-shadow: none; }
    .provider-detail { break-inside: avoid; }
    .provider-detail[open] .detail-content { display: block; }
    .bar-container { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    .badge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
    * { text-shadow: none !important; box-shadow: none !important; }
}

/* Responsive */
@media (max-width: 768px) {
    .hero h1 { font-size: 1.75rem; }
    .stat-grid { grid-template-columns: repeat(2, 1fr); }
    .detail-stats { gap: 1rem; }
    .bar-container { width: 80px; }
    .container { padding: 1rem; }
}
</style>"""

    @staticmethod
    def _js() -> str:
        return """<script>
function sortTable(tableId, colIdx, numeric) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Determine current sort direction
    const th = table.querySelectorAll('th')[colIdx];
    const asc = th.dataset.sort !== 'asc';
    table.querySelectorAll('th').forEach(h => delete h.dataset.sort);
    th.dataset.sort = asc ? 'asc' : 'desc';

    rows.sort((a, b) => {
        let va = a.cells[colIdx].textContent.trim().replace(/,/g, '');
        let vb = b.cells[colIdx].textContent.trim().replace(/,/g, '');
        if (numeric) {
            va = parseFloat(va) || 0;
            vb = parseFloat(vb) || 0;
        }
        if (va < vb) return asc ? -1 : 1;
        if (va > vb) return asc ? 1 : -1;
        return 0;
    });

    rows.forEach(r => tbody.appendChild(r));
}

// Toggle all provider details open/closed
document.addEventListener('DOMContentLoaded', () => {
    const details = document.querySelectorAll('.provider-detail');
    const toggleBtn = document.getElementById('toggle-all');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const anyOpen = Array.from(details).some(d => d.open);
            details.forEach(d => d.open = !anyOpen);
            toggleBtn.textContent = anyOpen ? 'Expand All' : 'Collapse All';
        });
    }
});
</script>"""


# ---------------------------------------------------------------------------
# Layer 7: Graph HTML Generator
# ---------------------------------------------------------------------------

class GraphHtmlGenerator:
    """Generates a force-directed graph visualization from provider data.

    Reads graph.html as a template (CSS/JS engine), replaces the data section
    between %%GRAPH_DATA_START%% and %%GRAPH_DATA_END%% markers with
    dynamically generated provider data.
    """

    TEMPLATE_FILE = BASE_DIR / "graph.html"
    GRAPH_OUTPUT = BASE_DIR / "graph.html"

    # Category definitions (must match JS CATEGORIES object structure)
    CATEGORIES = {
        "compute":     {"color": "#3b9eff", "glow": "rgba(59,158,255,0.5)",  "label": "Compute"},
        "networking":  {"color": "#22d3ee", "glow": "rgba(34,211,238,0.5)",  "label": "Networking"},
        "data":        {"color": "#a78bfa", "glow": "rgba(167,139,250,0.5)", "label": "Data & Storage"},
        "security":    {"color": "#f472b6", "glow": "rgba(244,114,182,0.5)", "label": "Security & Identity"},
        "app":         {"color": "#34d399", "glow": "rgba(52,211,153,0.5)",  "label": "App Platform"},
        "monitoring":  {"color": "#fb923c", "glow": "rgba(251,146,60,0.5)",  "label": "Monitoring & Mgmt"},
        "ai":          {"color": "#818cf8", "glow": "rgba(129,140,248,0.5)", "label": "AI & ML"},
        "integration": {"color": "#fbbf24", "glow": "rgba(251,191,36,0.5)",  "label": "Integration"},
        "devtools":    {"color": "#f87171", "glow": "rgba(248,113,113,0.5)", "label": "Developer Tools"},
        "iot":         {"color": "#2dd4bf", "glow": "rgba(45,212,191,0.5)",  "label": "IoT & Edge"},
        "hybrid":      {"color": "#c084fc", "glow": "rgba(192,132,252,0.5)", "label": "Hybrid & Arc"},
        "management":  {"color": "#94a3b8", "glow": "rgba(148,163,184,0.5)", "label": "Governance"},
    }

    # Provider namespace → category
    _CATEGORY_MAP: dict[str, str] = {
        # Compute
        "Microsoft.Compute": "compute", "Microsoft.ContainerService": "compute",
        "Microsoft.ContainerInstance": "compute", "Microsoft.Batch": "compute",
        "Microsoft.ServiceFabric": "compute", "Microsoft.ServiceFabricMesh": "compute",
        "Microsoft.AzureFleet": "compute", "Microsoft.DesktopVirtualization": "compute",
        "Microsoft.VirtualMachineImages": "compute", "Microsoft.AzureLargeInstance": "compute",
        "Microsoft.BareMetalInfrastructure": "compute", "Microsoft.CloudService": "compute",
        # Networking
        "Microsoft.Network": "networking", "Microsoft.Cdn": "networking",
        "Microsoft.Peering": "networking", "Microsoft.NetworkCloud": "networking",
        "Microsoft.NetworkFunction": "networking", "Microsoft.ManagedNetworkFabric": "networking",
        "Microsoft.VoiceServices": "networking", "Microsoft.Communication": "networking",
        "Microsoft.SignalRService": "networking", "Microsoft.ConnectedCache": "networking",
        # Data & Storage
        "Microsoft.Storage": "data", "Microsoft.Sql": "data",
        "Microsoft.DocumentDB": "data", "Microsoft.DBforPostgreSQL": "data",
        "Microsoft.DBforMySQL": "data", "Microsoft.DBforMariaDB": "data",
        "Microsoft.Cache": "data", "Microsoft.Synapse": "data",
        "Microsoft.Databricks": "data", "Microsoft.Kusto": "data",
        "Microsoft.HDInsight": "data", "Microsoft.ElasticSan": "data",
        "Microsoft.NetApp": "data", "Microsoft.StorageSync": "data",
        "Microsoft.StorageCache": "data", "Microsoft.StorageMover": "data",
        "Microsoft.DataFactory": "data", "Microsoft.StreamAnalytics": "data",
        "Microsoft.TimeSeriesInsights": "data", "Microsoft.Fabric": "data",
        "Microsoft.PowerBIdedicated": "data", "Microsoft.AnalysisServices": "data",
        "Microsoft.ConfidentialLedger": "data", "Microsoft.SqlVirtualMachine": "data",
        "Microsoft.AzureData": "data", "Microsoft.Purview": "data",
        "Microsoft.DataMigration": "data", "Microsoft.DataBox": "data",
        "Microsoft.DataBoxEdge": "data", "Microsoft.StorageActions": "data",
        "Microsoft.StorageTasks": "data",
        # Security & Identity
        "Microsoft.Security": "security", "Microsoft.SecurityInsights": "security",
        "Microsoft.KeyVault": "security", "Microsoft.Authorization": "security",
        "Microsoft.AAD": "security", "Microsoft.AzureActiveDirectory": "security",
        "Microsoft.Attestation": "security", "Microsoft.ManagedIdentity": "security",
        "Microsoft.GuestConfiguration": "security", "Microsoft.SecurityDevOps": "security",
        "Microsoft.Sovereign": "security", "Microsoft.AzureSphere": "security",
        "Microsoft.Aadiam": "security", "Microsoft.CodeSigning": "security",
        # App Platform
        "Microsoft.Web": "app", "Microsoft.App": "app",
        "Microsoft.AppPlatform": "app", "Microsoft.ContainerRegistry": "app",
        "Microsoft.Logic": "app", "Microsoft.ApiManagement": "app",
        "Microsoft.DomainRegistration": "app", "Microsoft.CertificateRegistration": "app",
        "Microsoft.Maps": "app", "Microsoft.HealthcareApis": "app",
        "Microsoft.Marketplace": "app",
        # Monitoring & Management
        "Microsoft.Insights": "monitoring", "Microsoft.Monitor": "monitoring",
        "Microsoft.OperationalInsights": "monitoring", "Microsoft.AlertsManagement": "monitoring",
        "Microsoft.Dashboard": "monitoring", "Microsoft.ChangeAnalysis": "monitoring",
        "Microsoft.Chaos": "monitoring", "Microsoft.LoadTestService": "monitoring",
        # AI & ML
        "Microsoft.CognitiveServices": "ai", "Microsoft.MachineLearningServices": "ai",
        "Microsoft.Search": "ai", "Microsoft.BotService": "ai",
        "Microsoft.VideoIndexer": "ai", "Microsoft.Quantum": "ai",
        "Microsoft.AzurePlaywrightService": "ai",
        # Integration & Messaging
        "Microsoft.EventHub": "integration", "Microsoft.ServiceBus": "integration",
        "Microsoft.EventGrid": "integration", "Microsoft.Relay": "integration",
        "Microsoft.NotificationHubs": "integration", "Microsoft.FluidRelay": "integration",
        # Developer Tools
        "Microsoft.DevCenter": "devtools", "Microsoft.DevTestLab": "devtools",
        "Microsoft.LabServices": "devtools", "Microsoft.PlayFab": "devtools",
        "Microsoft.AppConfiguration": "devtools", "Microsoft.Automation": "devtools",
        "Microsoft.Blueprint": "devtools",
        # IoT & Edge
        "Microsoft.Devices": "iot", "Microsoft.IoTOperations": "iot",
        "Microsoft.DigitalTwins": "iot", "Microsoft.Orbital": "iot",
        "Microsoft.ConnectedVMwarevSphere": "iot",
        # Hybrid & Arc
        "Microsoft.HybridCompute": "hybrid", "Microsoft.KubernetesConfiguration": "hybrid",
        "Microsoft.AzureStackHCI": "hybrid", "Microsoft.AzureStack": "hybrid",
        "Microsoft.AzureArcData": "hybrid", "Microsoft.ExtendedLocation": "hybrid",
        "Microsoft.AVS": "hybrid", "Microsoft.Workloads": "hybrid",
        # Governance & Management
        "Microsoft.Resources": "management", "Microsoft.Management": "management",
        "Microsoft.Advisor": "management", "Microsoft.CostManagement": "management",
        "Microsoft.Billing": "management", "Microsoft.Consumption": "management",
        "Microsoft.PolicyInsights": "management", "Microsoft.Capacity": "management",
        "Microsoft.BillingBenefits": "management", "Microsoft.Portal": "management",
        "Microsoft.Maintenance": "management", "Microsoft.Subscription": "management",
        "Microsoft.ResourceGraph": "management", "Microsoft.Commerce": "management",
        "Microsoft.Carbon": "management", "Microsoft.Migrate": "management",
        "Microsoft.RecoveryServices": "management", "Microsoft.DataProtection": "management",
        "Microsoft.Intune": "management", "Microsoft.OffAzure": "management",
    }

    # Keyword fallback for uncategorized providers
    _CATEGORY_KEYWORDS: list[tuple[str, str]] = [
        ("storage", "data"), ("sql", "data"), ("db", "data"), ("cache", "data"),
        ("data", "data"), ("fabric", "data"),
        ("network", "networking"), ("cdn", "networking"), ("peering", "networking"),
        ("security", "security"), ("auth", "security"), ("identity", "security"),
        ("keyvault", "security"),
        ("web", "app"), ("app", "app"), ("api", "app"), ("logic", "app"),
        ("insight", "monitoring"), ("monitor", "monitoring"), ("alert", "monitoring"),
        ("dashboard", "monitoring"),
        ("cognitive", "ai"), ("ml", "ai"), ("search", "ai"), ("openai", "ai"),
        ("bot", "ai"),
        ("event", "integration"), ("servicebus", "integration"), ("relay", "integration"),
        ("notification", "integration"),
        ("iot", "iot"), ("device", "iot"), ("digital", "iot"),
        ("arc", "hybrid"), ("stack", "hybrid"), ("hybrid", "hybrid"),
        ("dev", "devtools"), ("lab", "devtools"), ("test", "devtools"),
        ("automation", "devtools"),
        ("cost", "management"), ("billing", "management"), ("advisor", "management"),
        ("resource", "management"), ("policy", "management"), ("migrate", "management"),
    ]

    # Curated parent-parent relationships: (src_ns, tgt_ns, strength)
    _PARENT_RELATIONSHIPS: list[tuple[str, str, float]] = [
        # Compute ↔ foundational
        ("Microsoft.Compute", "Microsoft.Network", 0.9),
        ("Microsoft.Compute", "Microsoft.Storage", 0.7),
        ("Microsoft.Compute", "Microsoft.KeyVault", 0.5),
        ("Microsoft.Compute", "Microsoft.Insights", 0.6),
        ("Microsoft.Compute", "Microsoft.Security", 0.5),
        # AKS ↔ ecosystem
        ("Microsoft.ContainerService", "Microsoft.Network", 0.8),
        ("Microsoft.ContainerService", "Microsoft.Compute", 0.7),
        ("Microsoft.ContainerService", "Microsoft.ContainerRegistry", 0.8),
        ("Microsoft.ContainerService", "Microsoft.KeyVault", 0.5),
        ("Microsoft.ContainerService", "Microsoft.Insights", 0.5),
        ("Microsoft.ContainerService", "Microsoft.Security", 0.5),
        # Web ↔ ecosystem
        ("Microsoft.Web", "Microsoft.Network", 0.6),
        ("Microsoft.Web", "Microsoft.Insights", 0.8),
        ("Microsoft.Web", "Microsoft.Sql", 0.6),
        ("Microsoft.Web", "Microsoft.Storage", 0.5),
        ("Microsoft.Web", "Microsoft.KeyVault", 0.5),
        # SQL ↔ ecosystem
        ("Microsoft.Sql", "Microsoft.Network", 0.5),
        ("Microsoft.Sql", "Microsoft.KeyVault", 0.7),
        ("Microsoft.Sql", "Microsoft.Security", 0.5),
        ("Microsoft.Sql", "Microsoft.Insights", 0.4),
        # Storage ↔ ecosystem
        ("Microsoft.Storage", "Microsoft.Network", 0.6),
        ("Microsoft.Storage", "Microsoft.KeyVault", 0.6),
        ("Microsoft.Storage", "Microsoft.Security", 0.4),
        ("Microsoft.Storage", "Microsoft.Insights", 0.4),
        # Security ↔ monitoring
        ("Microsoft.Security", "Microsoft.Insights", 0.5),
        ("Microsoft.Security", "Microsoft.Authorization", 0.7),
        ("Microsoft.Security", "Microsoft.OperationalInsights", 0.6),
        ("Microsoft.SecurityInsights", "Microsoft.OperationalInsights", 0.9),
        ("Microsoft.SecurityInsights", "Microsoft.Security", 0.7),
        # Authorization ↔ ecosystem
        ("Microsoft.Authorization", "Microsoft.Insights", 0.4),
        ("Microsoft.Authorization", "Microsoft.PolicyInsights", 0.8),
        # Monitoring cluster
        ("Microsoft.Insights", "Microsoft.OperationalInsights", 0.8),
        ("Microsoft.Insights", "Microsoft.Monitor", 0.7),
        ("Microsoft.Insights", "Microsoft.AlertsManagement", 0.6),
        ("Microsoft.Dashboard", "Microsoft.Insights", 0.7),
        ("Microsoft.Dashboard", "Microsoft.OperationalInsights", 0.6),
        # Data platform cluster
        ("Microsoft.DocumentDB", "Microsoft.Network", 0.4),
        ("Microsoft.DocumentDB", "Microsoft.KeyVault", 0.4),
        ("Microsoft.Synapse", "Microsoft.Storage", 0.8),
        ("Microsoft.Synapse", "Microsoft.Sql", 0.6),
        ("Microsoft.Synapse", "Microsoft.KeyVault", 0.4),
        ("Microsoft.DataFactory", "Microsoft.Storage", 0.7),
        ("Microsoft.DataFactory", "Microsoft.Sql", 0.6),
        ("Microsoft.DataFactory", "Microsoft.KeyVault", 0.4),
        ("Microsoft.Databricks", "Microsoft.Storage", 0.7),
        ("Microsoft.Databricks", "Microsoft.KeyVault", 0.4),
        ("Microsoft.Fabric", "Microsoft.Storage", 0.6),
        ("Microsoft.Fabric", "Microsoft.PowerBIdedicated", 0.5),
        ("Microsoft.Kusto", "Microsoft.EventHub", 0.6),
        ("Microsoft.Kusto", "Microsoft.Storage", 0.4),
        ("Microsoft.HDInsight", "Microsoft.Storage", 0.7),
        ("Microsoft.HDInsight", "Microsoft.KeyVault", 0.4),
        ("Microsoft.Purview", "Microsoft.Storage", 0.5),
        ("Microsoft.Purview", "Microsoft.Sql", 0.4),
        ("Microsoft.DBforPostgreSQL", "Microsoft.Network", 0.5),
        ("Microsoft.DBforPostgreSQL", "Microsoft.KeyVault", 0.4),
        ("Microsoft.DBforMySQL", "Microsoft.Network", 0.5),
        ("Microsoft.Cache", "Microsoft.Network", 0.5),
        ("Microsoft.Cache", "Microsoft.KeyVault", 0.3),
        # Integration cluster
        ("Microsoft.EventHub", "Microsoft.Storage", 0.4),
        ("Microsoft.EventHub", "Microsoft.Insights", 0.3),
        ("Microsoft.ServiceBus", "Microsoft.Insights", 0.3),
        ("Microsoft.EventGrid", "Microsoft.EventHub", 0.5),
        ("Microsoft.EventGrid", "Microsoft.ServiceBus", 0.5),
        ("Microsoft.EventGrid", "Microsoft.Storage", 0.3),
        # App platform cluster
        ("Microsoft.App", "Microsoft.Network", 0.5),
        ("Microsoft.App", "Microsoft.ContainerRegistry", 0.6),
        ("Microsoft.App", "Microsoft.Insights", 0.4),
        ("Microsoft.AppPlatform", "Microsoft.Network", 0.4),
        ("Microsoft.AppPlatform", "Microsoft.Insights", 0.4),
        ("Microsoft.Logic", "Microsoft.EventGrid", 0.4),
        ("Microsoft.Logic", "Microsoft.ServiceBus", 0.4),
        ("Microsoft.ApiManagement", "Microsoft.Network", 0.5),
        ("Microsoft.ApiManagement", "Microsoft.KeyVault", 0.5),
        ("Microsoft.ContainerRegistry", "Microsoft.Network", 0.3),
        # AI cluster
        ("Microsoft.CognitiveServices", "Microsoft.Network", 0.3),
        ("Microsoft.CognitiveServices", "Microsoft.KeyVault", 0.3),
        ("Microsoft.MachineLearningServices", "Microsoft.Compute", 0.6),
        ("Microsoft.MachineLearningServices", "Microsoft.Storage", 0.6),
        ("Microsoft.MachineLearningServices", "Microsoft.KeyVault", 0.5),
        ("Microsoft.MachineLearningServices", "Microsoft.ContainerRegistry", 0.5),
        ("Microsoft.Search", "Microsoft.CognitiveServices", 0.5),
        ("Microsoft.Search", "Microsoft.Storage", 0.3),
        # IoT cluster
        ("Microsoft.Devices", "Microsoft.EventHub", 0.7),
        ("Microsoft.Devices", "Microsoft.Storage", 0.5),
        ("Microsoft.Devices", "Microsoft.IoTOperations", 0.5),
        ("Microsoft.DigitalTwins", "Microsoft.EventHub", 0.4),
        ("Microsoft.DigitalTwins", "Microsoft.Devices", 0.5),
        # Hybrid cluster
        ("Microsoft.HybridCompute", "Microsoft.Security", 0.5),
        ("Microsoft.HybridCompute", "Microsoft.Insights", 0.5),
        ("Microsoft.KubernetesConfiguration", "Microsoft.ContainerService", 0.7),
        ("Microsoft.AzureStackHCI", "Microsoft.Compute", 0.5),
        ("Microsoft.AzureStackHCI", "Microsoft.ContainerService", 0.4),
        ("Microsoft.AzureArcData", "Microsoft.Sql", 0.5),
        ("Microsoft.AVS", "Microsoft.Network", 0.4),
        # Backup/Recovery
        ("Microsoft.RecoveryServices", "Microsoft.Compute", 0.6),
        ("Microsoft.RecoveryServices", "Microsoft.Storage", 0.4),
        ("Microsoft.RecoveryServices", "Microsoft.Sql", 0.3),
        ("Microsoft.DataProtection", "Microsoft.RecoveryServices", 0.5),
        # Other
        ("Microsoft.DesktopVirtualization", "Microsoft.Compute", 0.7),
        ("Microsoft.DesktopVirtualization", "Microsoft.Network", 0.5),
        ("Microsoft.Batch", "Microsoft.Compute", 0.6),
        ("Microsoft.Batch", "Microsoft.Storage", 0.5),
        ("Microsoft.Batch", "Microsoft.Network", 0.4),
        ("Microsoft.ServiceFabric", "Microsoft.Compute", 0.6),
        ("Microsoft.ServiceFabric", "Microsoft.Network", 0.4),
        ("Microsoft.NetApp", "Microsoft.Network", 0.5),
        ("Microsoft.NetApp", "Microsoft.Compute", 0.4),
        ("Microsoft.Cdn", "Microsoft.Network", 0.6),
        ("Microsoft.Cdn", "Microsoft.Web", 0.5),
        ("Microsoft.AwsConnector", "Microsoft.Security", 0.3),
        ("Microsoft.Automation", "Microsoft.Compute", 0.4),
        ("Microsoft.Automation", "Microsoft.Insights", 0.3),
        ("Microsoft.CostManagement", "Microsoft.Billing", 0.7),
        ("Microsoft.Advisor", "Microsoft.CostManagement", 0.4),
        ("Microsoft.Advisor", "Microsoft.Insights", 0.3),
        ("Microsoft.GuestConfiguration", "Microsoft.Compute", 0.3),
        ("Microsoft.GuestConfiguration", "Microsoft.HybridCompute", 0.4),
        ("Microsoft.Migrate", "Microsoft.Compute", 0.4),
        ("Microsoft.Migrate", "Microsoft.Network", 0.3),
        ("Microsoft.SqlVirtualMachine", "Microsoft.Compute", 0.6),
        ("Microsoft.SqlVirtualMachine", "Microsoft.Sql", 0.5),
        ("Microsoft.ElasticSan", "Microsoft.Network", 0.4),
        ("Microsoft.HealthcareApis", "Microsoft.EventHub", 0.3),
        ("Microsoft.Communication", "Microsoft.EventGrid", 0.3),
        ("Microsoft.StreamAnalytics", "Microsoft.EventHub", 0.5),
        ("Microsoft.StreamAnalytics", "Microsoft.Storage", 0.4),
        ("Microsoft.DevCenter", "Microsoft.Compute", 0.5),
        ("Microsoft.DevCenter", "Microsoft.Network", 0.3),
        ("Microsoft.Intune", "Microsoft.Security", 0.4),
        ("Microsoft.Intune", "Microsoft.Authorization", 0.3),
    ]

    # Keywords in sub-service text that indicate cross-provider relationships
    # Maps keyword → target provider namespace
    _CROSS_KEYWORDS: dict[str, str] = {
        "vnet": "Microsoft.Network", "virtual network": "Microsoft.Network",
        "nsg": "Microsoft.Network", "firewall": "Microsoft.Network",
        "load balancer": "Microsoft.Network", "private endpoint": "Microsoft.Network",
        "bastion": "Microsoft.Network", "expressroute": "Microsoft.Network",
        "vpn gateway": "Microsoft.Network", "dns zone": "Microsoft.Network",
        "front door": "Microsoft.Network",
        "key vault": "Microsoft.KeyVault", "customer-managed key": "Microsoft.KeyVault",
        "cmk": "Microsoft.KeyVault",
        "rbac": "Microsoft.Authorization", "azure policy": "Microsoft.Authorization",
        "role assignment": "Microsoft.Authorization",
        "managed identity": "Microsoft.ManagedIdentity",
        "azure monitor": "Microsoft.Insights", "application insights": "Microsoft.Insights",
        "diagnostic setting": "Microsoft.Insights", "autoscale": "Microsoft.Insights",
        "log analytics": "Microsoft.OperationalInsights",
        "blob storage": "Microsoft.Storage", "storage account": "Microsoft.Storage",
        "adls": "Microsoft.Storage", "azure files": "Microsoft.Storage",
        "event hub": "Microsoft.EventHub",
        "service bus": "Microsoft.ServiceBus",
        "event grid": "Microsoft.EventGrid",
        "sql database": "Microsoft.Sql", "sql server": "Microsoft.Sql",
        "cosmos db": "Microsoft.DocumentDB",
        "aks": "Microsoft.ContainerService", "kubernetes": "Microsoft.ContainerService",
        "app service": "Microsoft.Web", "azure functions": "Microsoft.Web",
        "container registry": "Microsoft.ContainerRegistry",
        "defender": "Microsoft.Security", "security center": "Microsoft.Security",
        "sentinel": "Microsoft.SecurityInsights",
        "data factory": "Microsoft.DataFactory",
        "synapse": "Microsoft.Synapse",
        "power bi": "Microsoft.PowerBIdedicated",
        "grafana": "Microsoft.Dashboard",
        "redis": "Microsoft.Cache",
        "iot hub": "Microsoft.Devices",
    }

    def __init__(self, providers: list[ProviderData]):
        self.providers = sorted(
            providers, key=lambda p: p.complexity_score, reverse=True
        )
        self._ns_to_id: dict[str, str] = {}
        self._ns_set: set[str] = set()
        for p in self.providers:
            pid = p.namespace.removeprefix("Microsoft.")
            self._ns_to_id[p.namespace] = pid
            self._ns_set.add(p.namespace)

    def _categorize(self, namespace: str) -> str:
        if namespace in self._CATEGORY_MAP:
            return self._CATEGORY_MAP[namespace]
        low = namespace.lower()
        for keyword, cat in self._CATEGORY_KEYWORDS:
            if keyword in low:
                return cat
        return "management"

    @staticmethod
    def _get_regions(p: ProviderData) -> list[str]:
        regions: set[str] = set()
        for rt in p.resource_types:
            regions.update(rt.locations)
        return sorted(regions) if regions else ["Global"]

    @staticmethod
    def _make_label(name: str) -> str:
        """Create a multi-line label for circle nodes (max ~10 chars/line)."""
        if len(name) <= 10:
            return name
        words = name.split()
        if len(words) == 1:
            return name
        lines: list[str] = []
        cur = words[0]
        for w in words[1:]:
            if len(cur) + 1 + len(w) <= 10:
                cur += " " + w
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
        return "\n".join(lines[:3])

    @staticmethod
    def _js_str(s: str) -> str:
        """Escape a Python string for a JS single-quoted literal."""
        return (
            s.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "")
        )

    @staticmethod
    def _parse_sub_service(text: str) -> tuple[str, str]:
        """Split 'Product Name (description...)' → (name, desc)."""
        # Try parenthetical first
        paren = text.find("(")
        dash = text.find(" — ")
        if paren > 0 and (dash < 0 or paren < dash):
            name = text[:paren].strip()
            # Find matching close paren
            depth, end = 1, paren + 1
            while end < len(text) and depth > 0:
                if text[end] == "(":
                    depth += 1
                elif text[end] == ")":
                    depth -= 1
                end += 1
            desc = text[paren + 1 : end - 1] if depth == 0 else text[paren + 1 :]
        elif dash > 0:
            name = text[:dash].strip()
            desc = text[dash + 3 :].strip()
        else:
            name = text.strip()
            desc = ""
        return name, desc

    def _build_data_js(self) -> str:
        """Generate all JavaScript data constants for the graph."""
        parts: list[str] = []

        # ---- CATEGORIES ----
        cat_lines = []
        for key, cat in self.CATEGORIES.items():
            cat_lines.append(
                f"    {key}:{{color:'{cat['color']}',"
                f"glow:'{cat['glow']}',label:'{cat['label']}'}}"
            )
        parts.append(
            "// ============================================================\n"
            "// DATA — CATEGORIES\n"
            "// ============================================================\n"
            "const CATEGORIES = {\n" + ",\n".join(cat_lines) + "\n};\n"
        )

        # ---- PARENT NODES ----
        node_lines = []
        for p in self.providers:
            pid = self._ns_to_id[p.namespace]
            cat = self._categorize(p.namespace)
            short = HtmlReportGenerator._short_name(p.namespace)
            label = self._make_label(short)
            desc = PROVIDER_DESCRIPTIONS.get(
                p.namespace, p.namespace.removeprefix("Microsoft.")
            )
            regions = self._get_regions(p)
            node_lines.append(
                f"    {{id:'{self._js_str(pid)}',"
                f"label:'{self._js_str(label)}',"
                f"category:'{cat}',isParent:true,"
                f"score:{p.complexity_score},"
                f"params:{p.total_recursive_params},"
                f"resourceTypes:{len(p.resource_types)},"
                f"skus:{p.total_skus},"
                f"operations:{p.operations_count},"
                f"products:{len(p.sub_services)},"
                f"desc:'{self._js_str(desc)}',"
                f"regions:{json.dumps(regions)}}}"
            )
        parts.append(
            "\n// ============================================================\n"
            "// DATA — PARENT NODES\n"
            "// ============================================================\n"
            "const parentNodes = [\n" + ",\n".join(node_lines) + "\n];\n"
        )

        # ---- SUB-NODE DEFINITIONS ----
        sub_defs: list[str] = []
        sub_descs: dict[str, str] = {}
        for p in self.providers:
            if not p.sub_services:
                continue
            pid = self._ns_to_id[p.namespace]
            for i, svc_text in enumerate(p.sub_services):
                name, desc = self._parse_sub_service(svc_text)
                sub_id = f"{pid.lower()}-{i}"
                sub_label = self._make_label(name)
                sub_defs.append(
                    f"    ['{sub_id}',"
                    f"'{self._js_str(sub_label)}',"
                    f"'{self._js_str(pid)}']"
                )
                if desc:
                    sub_descs[sub_id] = desc

        parts.append(
            "\n// ============================================================\n"
            "// DATA — SUB-NODE DEFINITIONS [id, label, parentId]\n"
            "// ============================================================\n"
            "const SUB_DEFS = [\n" + ",\n".join(sub_defs) + "\n];\n"
        )

        # ---- SUB-NODE DESCRIPTIONS ----
        desc_lines = [
            f"    '{sid}':'{self._js_str(d)}'" for sid, d in sub_descs.items()
        ]
        parts.append(
            "\n// Sub-node descriptions for detail panel\n"
            "const SUB_DESCS = {\n" + ",\n".join(desc_lines) + "\n};\n"
        )

        # ---- PARENT-PARENT EDGES ----
        parent_edges: list[str] = []
        for src_ns, tgt_ns, strength in self._PARENT_RELATIONSHIPS:
            if src_ns in self._ns_set and tgt_ns in self._ns_set:
                src_id = self._ns_to_id[src_ns]
                tgt_id = self._ns_to_id[tgt_ns]
                parent_edges.append(
                    f"    ['{self._js_str(src_id)}',"
                    f"'{self._js_str(tgt_id)}',"
                    f"{strength}]"
                )
        parts.append(
            "\n// ============================================================\n"
            "// DATA — PARENT-PARENT EDGES [source, target, strength]\n"
            "// ============================================================\n"
            "const PARENT_EDGES = [\n" + ",\n".join(parent_edges) + "\n];\n"
        )

        # ---- CROSS-PROVIDER EDGES (sub-node → parent) ----
        cross_edges: list[str] = []
        seen: set[tuple[str, str]] = set()
        for p in self.providers:
            if not p.sub_services:
                continue
            pid = self._ns_to_id[p.namespace]
            for i, svc_text in enumerate(p.sub_services):
                sub_id = f"{pid.lower()}-{i}"
                text_lower = svc_text.lower()
                matched_count = 0
                matched_ns: set[str] = set()
                for keyword, target_ns in self._CROSS_KEYWORDS.items():
                    if target_ns == p.namespace:
                        continue
                    if target_ns not in self._ns_set:
                        continue
                    if target_ns in matched_ns:
                        continue
                    if keyword in text_lower:
                        matched_ns.add(target_ns)
                        edge_key = (sub_id, target_ns)
                        if edge_key not in seen:
                            seen.add(edge_key)
                            tgt_id = self._ns_to_id[target_ns]
                            cross_edges.append(
                                f"    ['{sub_id}',"
                                f"'{self._js_str(tgt_id)}',"
                                f"0.4]"
                            )
                            matched_count += 1
                            if matched_count >= 3:
                                break
        parts.append(
            "\n// ============================================================\n"
            "// DATA — CROSS-PROVIDER EDGES [sub-node, parent, strength]\n"
            "// ============================================================\n"
            "const CROSS_EDGES = [\n" + ",\n".join(cross_edges) + "\n];\n"
        )

        return (
            "// %%GRAPH_DATA_START%%\n"
            + "\n".join(parts)
            + "// %%GRAPH_DATA_END%%"
        )

    def generate(self) -> str:
        """Generate graph HTML by replacing data section in template."""
        template = self.TEMPLATE_FILE.read_text(encoding="utf-8")

        start_marker = "// %%GRAPH_DATA_START%%"
        end_marker = "// %%GRAPH_DATA_END%%"

        start_idx = template.index(start_marker)
        end_idx = template.index(end_marker) + len(end_marker)

        data_js = self._build_data_js()

        # Update subtitle with actual counts
        result = template[:start_idx] + data_js + template[end_idx:]

        return result


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Azure Complexity Measurement Tool"
    )
    parser.add_argument(
        "--mode", choices=["preview", "full"], default="preview",
        help="preview = 3 providers (default), full = all providers"
    )
    parser.add_argument(
        "--output", type=str, default=str(OUTPUT_FILE),
        help="Output HTML file path"
    )
    args = parser.parse_args()

    log.info("Azure Complexity Measurement Tool")
    log.info("Mode: %s", args.mode)

    cache = CacheManager(CACHE_DIR)

    # Step 1: Provider Discovery
    log.info("=== Step 1: Provider Discovery ===")
    discovery = ProviderDiscovery(cache)
    sub_id = discovery.get_subscription_id()
    log.info("Subscription: %s", sub_id)

    target = PREVIEW_PROVIDERS if args.mode == "preview" else None
    providers = discovery.list_providers(target)

    for p in providers:
        discovery.enrich_resource_types(p)
        log.info("  %s: %d resource types", p.namespace, len(p.resource_types))

    # Step 2: Operations & SKUs
    log.info("=== Step 2: Operations & SKU Enumeration ===")
    ops_enum = OperationsEnumerator(cache)
    sku_enum = SkuEnumerator(cache, sub_id)

    for p in providers:
        ops_enum.count_operations(p)
        sku_enum.enumerate_skus(p)

    # Step 3: OpenAPI Spec Crawling
    log.info("=== Step 3: OpenAPI Spec Crawling ===")
    if not SPECS_LOCAL.exists():
        log.info("Cloning azure-rest-api-specs to %s (one-time)...", SPECS_LOCAL)
        log.info("Using sparse checkout — only fetching specification/ directory.")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none",
             "--sparse", SPECS_REPO, str(SPECS_LOCAL)],
            check=True, timeout=300,
        )
        subprocess.run(
            ["git", "-C", str(SPECS_LOCAL), "sparse-checkout", "set", "specification"],
            check=True, timeout=300,
        )
        log.info("Specs clone ready at %s", SPECS_LOCAL)
    else:
        log.info("Using local specs clone: %s", SPECS_LOCAL)

    crawler = OpenApiCrawler(cache)
    for p in providers:
        log.info("Analyzing specs for %s...", p.namespace)
        crawler.analyze_provider(p)

    # Step 4: Licensing & Sub-Services
    log.info("=== Step 4: Licensing Mapping & Sub-Services ===")
    sub_svc_lookup = {k.lower(): v for k, v in SUB_SERVICES.items()}
    for p in providers:
        LicensingMapper.apply(p)
        p.sub_services = sub_svc_lookup.get(p.namespace.lower(), [])

    # Step 5: Complexity Scoring
    log.info("=== Step 5: Complexity Scoring ===")
    for p in providers:
        score = ComplexityScorer.score(p)
        log.info("  %s: %.1f", p.namespace, score)

    # Step 6: Generate Report
    log.info("=== Step 6: Generating HTML Report ===")
    generator = HtmlReportGenerator(providers, args.mode)
    html = generator.generate()

    output_path = Path(args.output)
    output_path.write_text(html, encoding="utf-8")
    log.info("Report written to %s", output_path)

    # Step 7: Generate Graph
    graph_tmpl = GraphHtmlGenerator.TEMPLATE_FILE
    if graph_tmpl.exists() and "%%GRAPH_DATA_START%%" in graph_tmpl.read_text(encoding="utf-8"):
        log.info("=== Step 7: Generating Relationship Graph ===")
        graph_gen = GraphHtmlGenerator(providers)
        graph_html = graph_gen.generate()
        graph_tmpl.write_text(graph_html, encoding="utf-8")
        log.info("Graph written to %s", graph_tmpl)
    else:
        log.info("=== Step 7: Skipped (graph.html template not found) ===")

    # Summary
    print("\n" + "=" * 60)
    print("  AZURE COMPLEXITY REPORT GENERATED")
    print("=" * 60)
    total_params = sum(p.total_recursive_params for p in providers)
    total_rt = sum(len(p.resource_types) for p in providers)
    total_skus = sum(p.total_skus for p in providers)
    total_ops = sum(p.operations_count for p in providers)
    print(f"  Providers:          {len(providers)}")
    print(f"  Resource Types:     {total_rt:,}")
    print(f"  Config Parameters:  {total_params:,}")
    print(f"  SKU Variants:       {total_skus:,}")
    print(f"  API Operations:     {total_ops:,}")
    print(f"  Output:             {output_path}")
    if graph_tmpl.exists():
        print(f"  Graph:              {graph_tmpl}")
    print("=" * 60)


if __name__ == "__main__":
    main()
