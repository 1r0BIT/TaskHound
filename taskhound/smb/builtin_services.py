# Known Windows default service names that always run as built-in accounts
# (LocalSystem, LocalService, NetworkService, NT AUTHORITY\*, NT SERVICE\*).
#
# Compiled from Windows Server 2022 + Windows 11 22H2 defaults.
# Used to skip hRQueryServiceConfigW RPC calls during enumeration —
# saves ~75% of round-trips on a typical host.

BUILTIN_SERVICE_NAMES: frozenset[str] = frozenset(s.lower() for s in {
    # Core OS
    "AarSvc", "AJRouter", "ALG", "AppIDSvc", "Appinfo", "AppMgmt",
    "AppReadiness", "AppVClient", "AppXSvc", "AssignedAccessManagerSvc",
    "AudioEndpointBuilder", "Audiosrv", "autotimesvc", "AxInstSV",
    # B
    "BDESVC", "BFE", "BITS", "BrokerInfrastructure", "BTAGService",
    "BthAvctpSvc", "bthserv",
    # C
    "camsvc", "CaptureService", "cbdhsvc", "CDPSvc", "CDPUserSvc",
    "CertPropSvc", "ClipSVC", "COMSysApp", "ConsentUxUserSvc",
    "CoreMessagingRegistrar", "CryptSvc", "CscService",
    # D
    "DcomLaunch", "defragsvc", "DeviceAssociationBrokerSvc",
    "DeviceAssociationService", "DeviceInstall", "DevicePickerUserSvc",
    "DevicesFlowUserSvc", "DevQueryBroker", "Dhcp",
    "diagnosticshub.standardcollector.service",
    "diagsvc", "DiagTrack", "DisplayEnhancementService", "DmEnrollmentSvc",
    "dmwappushservice", "Dnscache", "DoSvc", "dot3svc", "DPS",
    "DsmSvc", "DsSvc", "DusmSvc",
    # E
    "EapHost", "EFS", "embeddedmode", "EntAppSvc", "EventLog",
    "EventSystem",
    # F
    "Fax", "fdPHost", "FDResPub", "fhsvc", "FontCache",
    # G
    "gpsvc", "GraphicsPerfSvc",
    # H
    "hidserv", "HNS", "HomeGroupListener", "HomeGroupProvider",
    "HvHost",
    # I
    "icssvc", "IKEEXT", "InstallService", "iphlpsvc", "IpxlatCfgSvc",
    # K
    "KeyIso", "KtmRm",
    # L
    "LanmanServer", "LanmanWorkstation", "lfsvc", "LicenseManager",
    "lltdsvc", "lmhosts", "LSM",
    # M
    "MapsBroker", "McpManagementService", "MessagingService",
    "MicrosoftEdgeElevationService", "MixedRealityOpenXRSvc",
    "MMCSS", "MpsSvc", "MSDTC", "MSiSCSI", "msiserver",
    "MsKeyboardFilter",
    # N
    "NaturalAuthentication", "NcaSvc", "NcbService", "NcdAutoSetup",
    "Netlogon", "Netman", "netprofm", "NetSetupSvc", "NetTcpPortSharing",
    "NgcCtnrSvc", "NgcSvc", "NlaSvc", "nsi",
    # O
    "OneSyncSvc",
    # P
    "p2pimsvc", "p2psvc", "PcaSvc", "PeerDistSvc", "PenService",
    "perceptionsimulation", "PerfHost", "PhoneSvc", "PimIndexMaintenanceSvc",
    "pla", "PlugPlay", "PNRPAutoReg", "PNRPsvc", "PolicyAgent",
    "Power", "PrintNotify", "PrintWorkflowUserSvc", "ProfSvc",
    "PushToInstall",
    # Q-R
    "QWAVE", "RasAuto", "RasMan", "RemoteAccess", "RemoteRegistry",
    "RetailDemo", "RmSvc", "RpcEptMapper", "RpcLocator", "RpcSs",
    "RSoPProv",
    # S
    "sacsvr", "SamSs", "SCardSvr", "ScDeviceEnum", "Schedule",
    "SCPolicySvc", "SDRSVC", "seclogon", "SecurityHealthService",
    "SEMgrSvc", "SENS", "Sense", "SensorDataService", "SensorService",
    "SensrSvc", "SessionEnv", "SgrmBroker", "SharedAccess",
    "SharedRealitySvc", "ShellHWDetection", "shpamsvc", "smphost",
    "SmsRouter", "SNMPTRAP", "Spooler", "sppsvc", "SSDPSRV",
    "ssh-agent", "SstpSvc", "StateRepository", "stisvc",
    "StorSvc", "svsvc", "swprv", "SysMain", "SystemEventsBroker",
    # T
    "TabletInputService", "TapiSrv", "TermService", "Themes",
    "TieringEngineService", "TimeBrokerSvc", "TokenBroker",
    "TrkWks", "TroubleshootingSvc", "TrustedInstaller",
    # U
    "tzautoupdate", "UdkUserSvc", "UevAgentService",
    "UmRdpService", "UnistoreSvc", "upnphost", "UserDataSvc",
    "UserManager", "UsoSvc",
    # V
    "VaultSvc", "vds", "vmcompute", "vmicguestinterface",
    "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown",
    "vmictimesync", "vmicvmsession", "vmicvss", "VMAuthdService",
    "VMnetDHCP", "VMUSBArbService", "VMwareHostd", "VSS",
    # W
    "W32Time", "W3SVC", "WaaSMedicSvc", "WalletService",
    "WarpJITSvc", "wbengine", "WbioSrvc", "Wcmsvc", "wcncsvc",
    "WdiServiceHost", "WdiSystemHost", "WdNisSvc", "WebClient",
    "Wecsvc", "WEPHOSTSVC", "wercplsupport", "WerSvc",
    "WFDSConMgrSvc", "WiaRpc", "WinDefend", "WinHttpAutoProxySvc",
    "Winmgmt", "WinRM", "wisvc", "WlanSvc", "wlidsvc",
    "wlpasvc", "WManSvc", "WMPNetworkSvc", "workfolderssvc",
    "WpcMonSvc", "WPDBusEnum", "WpnService", "WpnUserService",
    "WSearch", "WSService", "wuauserv", "WwanSvc",
    # X
    "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    # AD / Server roles (always SYSTEM / LocalService / NetworkService)
    "ADWS", "CertSvc", "DFS", "DFSR", "DHCPServer", "DNS",
    "IsmServ", "Kdc", "KdsSvc", "NTDS", "NtFrs",
    "TBS", "TSGateway", "WAS", "ClusSvc",
})
