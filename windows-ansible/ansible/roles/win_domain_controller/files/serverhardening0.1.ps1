$DomainOU = Get-ADDomain | foreach {$_.DistinguishedName}
set-addefaultdomainpasswordpolicy -ComplexityEnabled True -MinPasswordLength 14 -MaxPasswordAge 30

#Create Workbench hardening GPO
New-GPO -Name "RDS WB hardening" -comment "hardening for the workbench"
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RelaxMinimumPasswordLengthLimits" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SAM" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoConnectedUser" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 3 -Type DWord 
$newuser = $DomainOU + "_" + "user"
useraccount where name='Guest' rename $newuser
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DontDisplayLastUserName" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "InactivityTimeoutSecs" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 900 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "CachedLogonsCount" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 4 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ForceUnlockLogon" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ScRemoveOption" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 1 -Type String
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RequireSecuritySignature" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RequireSecuritySignature" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableSecuritySignature" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RestrictAnonymous" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableDomainCreds" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "UseMachineId" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
#Need to work out how to set the value wazuh 27063
#Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "SupportedEncryptionTypes" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LmCompatibilityLevel" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 5 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NTLMMinServerSec" -key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -Value 537395200 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "FilterAdministratorToken" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ConsentPromptBehaviorUser" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableNotifications" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFilePath" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value "%SystemRoot%\System32\logfiles\firewall\domainfw.log" -Type String
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFileSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value 16384 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogDroppedPackets" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogSuccessfulConnections" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableNotifications" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFilePath" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Value "%SystemRoot%\System32\logfiles\firewall\privatefw.log" -Type String
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFileSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Value 537395200 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogDroppedPackets" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Value 16384 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogSuccessfulConnections" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableNotifications" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowLocalPolicyMerge" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowLocalIPsecPolicyMerge" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFilePath" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Value "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type string
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogFileSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Value 16384 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogDroppedPackets" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LogSuccessfulConnections" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoLockScreenCamera" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoLockScreenSlideshow" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowInputPersonalization" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowOnlineTips" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "SMB1" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PwdExpirationProtectionEnabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AdmPwdEnabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PasswordComplexity" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value 4 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PasswordLength" -key "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value 15 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PasswordAgeDays" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value 30 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NodeType" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableIPSourceRouting" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableIPSourceRouting" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableICMPRedirect" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "KeepAliveTime" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 300000 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PerformRouterDiscovery" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "TcpMaxDataRetransmissions" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Value 3 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "TcpMaxDataRetransmissions" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Value 3 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableMulticast" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableFontProviders" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowInsecureGuestAuth" -key "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "Disabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableFontProviders" -key "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Value 537395200 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowInsecureGuestAuth" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "Disabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NC_AllowNetBridge_NLA" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NC_ShowSharedAccessUI" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NC_StdDomainUserSetLocation" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisabledComponents" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Value 255 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableWcnUi" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fMinimizeConnections" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Value 3 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fBlockNonDomain" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RegisterSpoolerRemoteRpcEndPoint" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoCloudApplicationNotification" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowEncryptionOracle" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowProtectedCreds" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableVirtualizationBasedSecurity" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "RequirePlatformSecurityFeatures" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 3 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "HypervisorEnforcedCodeIntegrity" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "HVCIMATRequired" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LsaCfgFlags" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ConfigureSystemGuardLaunch" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PreventDeviceMetadataFromNetwork" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DriverLoadPolicy" -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Value 3 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoBackgroundPolicy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoGPOListChanges" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableCdp" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableWebPnPDownload" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PreventHandwritingDataSharing" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PreventHandwritingErrorReports" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ExitOnMSICW" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoWebServices" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableHTTPPrinting" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoRegistration" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableContentFileUpdates" -key "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoOnlinePrintsWizard" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoPublishingWizard" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "CEIP" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "CEIPEnable" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "Disabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DeviceEnumerationPolicy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fAllowToGetHelp" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableAuthEpResolution" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableQueryRemoteServer" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ScenarioExecutionEnabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisabledByGroupPolicy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "Enabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MSAOptional" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoAutoplayfornonVolume" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoAutorun" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoDriveTypeAutoRun" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 255 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnhancedAntiSpoofing" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowCamera" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableConsumerAccountStateContent" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableWindowsConsumerFeatures" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisablePasswordReveal" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableEnterpriseAuthProxy" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableOneSettingsDownloads" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DoNotShowFeedbackNotifications" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableOneSettingsAuditing" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LimitDiagnosticLogCollection" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "LimitDumpCollection" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowBuildPreview" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Value 196608 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxSize" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableLocation" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowMessageSync" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableUserAuth" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ExploitGuard_ASR_Rules" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableNetworkProtection" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableFileHashComputation" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableGenericRePorts" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableRemovableDriveScanning" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableEmailScanning" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "PUAProtection" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableFileSyncNGSC" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisablePushToInstall" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisablePasswordSaving" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableUiaRedirection" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fDisableCcm" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fDisableCdm" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fDisableLocationRedir" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fDisableLPT" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fDisablePNPRedir" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fPromptForPassword " -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "fEncryptRPCTraffic" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "SecurityLayer" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 2 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxDisconnectionTime" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 432000 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "DisableEnclosureDownload " -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowCloudSearch" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "NoGenTicket" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "EnableSmartScreen" -key ":HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ShellSmartScreenLevel" -key ":HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Value Block -Type String
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowSuggestedAppsInWindowsInkWorkspace" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "AllowDigest" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Value 0 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "MaxIdleTime" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Value 900000 -Type DWord
Set-GPRegistryValue -Name "RDS WB hardening" -ValueName "ScenarioExecutionEnabled" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Value 0 -Type DWord
