set-timezone -Id 'GMT Standard Time'

$DomainInfo = Get-ADDomain

# Get Windows Project
$winProject = $DomainInfo.DNSRoot.split('.')[0]

# Get DC01 name
$DC01 = (Get-ADComputer -Identity "$winProject-DC01").Name

# Set RDS Server
$RDSServer = $DC01

#Workbench OU
$DomainOU = $DomainInfo.DistinguishedName
$domainID = $DomainInfo.DNSRoot
$workbenchOU = (Get-ADOrganizationalUnit -Identity "OU=Workbench,$DomainOU").DistinguishedName

$computersOU = $DomainInfo.ComputersContainer
$domaincontrollersOU = $DomainInfo.DomainControllersContainer

#get wsus server name
$wsusserver = (Get-ADComputer -Identity "$winProject-WSUS").Name # Fails since WSUS server isn't part of the domain when this is run.

$homepage = "https://www.epcc.ed.ac.uk/"

#Move WB machines (when prefix is wb) SHOULD NOT BE NEEDED ANSIBLE DOES THIS. CAN CHANGE REGEX TO ALSO ADD APP AND GPU
$computers = Get-ADComputer -Filter * | Where-Object { $_.name -match "^.*(wb|app|gpu)[0-9]+$" } | ForEach-Object { $_.Name }
#$computers | move-adobject -TargetPath $workbenchOU

#Create RDS Settings GPO
New-GPO -Name "RDS Settings" -comment "RDS Settings for the workbench"
Set-GPRegistryValue -Name "RDS Settings" -ValueName "LicensingMode" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 4 -Type DWord 
Set-GPRegistryValue -Name "RDS Settings" -ValueName "LicenseServers" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value $RDSServer -Type String
Set-GPRegistryValue -Name "RDS Settings" -ValueName "MaxInstanceCount" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 999999 -Type DWord
Set-GPRegistryValue -Name "RDS Settings" -ValueName "fDenyTSCConnections" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord

#Create Default Domain Policy GPO
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAUShutdownOption" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "UseWUServer" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value $RDSServer -Type String
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "IncludeRecommendedUpdates" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 999999 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAutoRebootWithLoggedOnUsers" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "LicensingMode" -key "HKEY_LOCAL_MACHINE\system\CurrentControlSet\Control\Lsa\LmCompatibility" -Value 0 -Type DWord 
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoWebServices" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoOnlinePrintsWizard" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoPublishingWizard" -key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAutorun" -key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoDriveTypeAutoRun" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 255 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowEncryptionOracle" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MSAOptional" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DevicePKInitEnabled" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DevicePKInitBehavior" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MSAOptional" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MSAOptional" -Key "HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnhancedAntiSpoofing" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Biometrics\FacialFeatures" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowCamera" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Camera" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "BlockUserInputMethodsForSignIn" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Control Panel\International" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowInputPersonalization" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\InputPersonalization" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableEnclosureDownload" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Internet Explorer\Feeds" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "CEIP" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Messenger\Client" -Value 2 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableUserAuth" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\MicrosoftAccount" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DoReport" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\PCHealth\ErrorReporting" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "Disabled" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Peernet" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DCSettingIndex" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ACSettingIndex" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisablePushToInstall" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\PushToInstall" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableContentFileUpdates" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\SearchCompanion" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "CEIPEnable" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\SQMClient\Windows" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "Enabled" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\W32time\TimeProviders\NtpClient" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisabledByGroupPolicy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\AdvertisingInfo" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableWindowsConsumerFeatures" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\CloudContent" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequirePinForPairing" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Connect" -Value 2 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowProtectedCreds" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\CredentialsDelegation" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisablePasswordReveal" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\CredUI" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoCloudApplicationNotification" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowTelemetry" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableEnterpriseAuthProxy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableOneSettingsDownloads" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DoNotShowFeedbackNotifications" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableOneSettingsAuditing" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "LimitDiagnosticLogCollection" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "LimitDumpCollection" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DataCollection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PreventDeviceMetadataFromNetwork" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Device Metadata" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableVirtualizationBasedSecurity" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequirePlatformSecurityFeatures" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "HypervisorEnforcedCodeIntegrity" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 3 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "HVCIMATRequired" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "LsaCfgFlags" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 3 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ConfigureSystemGuardLaunch" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\DeviceGuard" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxSize" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\EventLog\Application" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxSize" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\EventLog\Security" -Value 196608 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxSize" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\EventLog\Setup" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxSize" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\EventLog\System" -Value 32768 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAutoplayfornonVolume" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoBackgroundPolicy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoGPOListChanges" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PreventHandwritingErrorReports" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\HandwritingErrorReports" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ExitOnMSICW" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Internet Connection Wizard" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DeviceEnumerationPolicy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Kernel DMA Protection" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowInsecureGuestAuth" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\LanmanWorkstation" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableLocation" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\LocationAndSensors" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowMessageSync" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Messaging" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NC_AllowNetBridge_NLA" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Network Connections" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NC_ShowSharedAccessUI" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Network Connections" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NC_StdDomainUserSetLocation" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Network Connections" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequireMutualAuthentication" -key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequirePrivacy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableFileSyncNGSC" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\OneDrive" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoLockScreenCamera"-Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Personalization" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoLockScreenSlideshow" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Personalization" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowBuildPreview" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\PreviewBuilds" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoRegistration" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Registration Wizard Control" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableQueryRemoteServer" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DoNotOpenAtLogon" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Server\InitialConfigurationTasks" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DoNotOpenAtLogon" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Server\ServerManager" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowCrossDeviceClipboard" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableFontProviders" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableCdp" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "BlockUserFromShowingAccountDetailsOnSignin" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DontDisplayNetworkSelectionUI" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DontEnumerateConnectedUsers" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableLockScreenAppNotifications" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "BlockDomainPicturePassword" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "UploadUserActivities" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableSmartScreen" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ShellSmartScreenLevel" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\System" -Value Block -Type String
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PreventHandwritingDataSharing" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\TabletPC" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fMinimizeConnections" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Value 3 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fBlockNonDomain" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableRegistrars" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableUPnPRegistrar" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableInBand802DOT11Registrar" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableFlashConfigRegistrar" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableWPDRegistrar" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxWCNDeviceNumber" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "HigherPrecedenceRegistrar" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\Registrars" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableWcnUi" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WCN\UI" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ScenarioExecutionEnabled" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "Disabled" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Windows Error Reporting" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowCloudSearch" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Windows Search" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAUShutdownOption" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "UseWUServer" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value SGSTD-DC01 -Type String
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DeferQualityUpdates" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DeferQualityUpdatesPeriodInDays" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PauseQualityUpdatesStartTime" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value -Type DWord #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DeferFeatureUpdates" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DeferFeatureUpdatesPeriodInDays" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PauseFeatureUpdatesStartTime" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WindowsUpdate" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowDigest" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WinRM\Client" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowRemoteShellAccess" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableRunAs" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\WinRM\Service" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableFileHashComputation" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender\MpEngine" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableGenericRePorts" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender\Reporting" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableRemovableDriveScanning" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender\Scan" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableEmailScanning" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender\Scan" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableNetworkProtection" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "PUAProtection" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisallowExploitProtectionOverride" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoGenTicket" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DoHPolicy" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\DNSClient" -Value 2 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableMulticast" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\DNSClient" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RegisterSpoolerRemoteRpcEndPoint" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Printers" -Value 2 -Type Dword
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableWebPnPDownload" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Printers" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableHTTPPrinting" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Printers" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableAuthEpResolution" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Rpc" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "IncludeRecommendedUpdates" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 999999 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NoAutoRebootWithLoggedOnUsers" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fAllowToGetHelp" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fAllowFullControl" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxTicketExpiry" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxTicketExpiryUnits" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fUseMailto" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value -Type String #MISSING_VALUE
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisablePasswordSaving" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fDisableCcm" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fDisableLPT" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fDisablePNPRedir" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxDisconnectionTime" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 60000 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "MaxIdleTime" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 900000 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "UserAuthentication" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "fPromptForPassword" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowWindowsInkWorkspace" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsInkWorkspace" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "AllowSuggestedAppsInWindowsInkWorkspace" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsInkWorkspace" -Value 0 -Type DWord
#new
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DontDisplayLastUserName" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "InactivityTimeoutSecs" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 900 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "CachedLogonsCount" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 4 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ForceUnlockLogon" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 1 -Type DWord
#work out value Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ScRemoveOption" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value 4 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequireSecuritySignature" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RequireSecuritySignature" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "EnableSecuritySignature" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value 1 -Type DWord
#work out value  Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "SMBServerNameHardeningLevel" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Value 
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "RestrictAnonymous" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "DisableDomainCreds" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Value 1 -Type DWord
#Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NullSessionPipes" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" -Value LSARPC, NETLOGON, SAMR -Type ExpandString
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "UseMachineId" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Value 1 -Type DWord
#Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "SupportedEncryptionTypes" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Value AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types -Type ExpandString
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "LmCompatibilityLevel" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -Value 5 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "NTLMMinServerSec" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -Value 537395200 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "FilterAdministratorToken" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 1 -Type Dword
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ConsentPromptBehaviorAdmin" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 2 -Type DWord
Set-GPRegistryValue -Name "Default Domain Policy" -ValueName "ConsentPromptBehaviourUser" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value 0 -Type DWord



#Folder redirection - Doesn't run - MISSING MODULE??
#enable-folderredirection -AllFolder

#Domain Password Policy
Set-ADDefaultDomainPasswordPolicy -identity $DomainID -MaxPasswordAge "42" -MinPasswordAge "1" -MinPasswordLength "12" -PasswordHistoryCount "24" -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -LockoutThreshold "0"
Get-LocalUser Guest | Disable-LocalUser
#Get-localuser Administrator | Disable-LocalUser


#Create WSUS GPO
New-GPO -Name "WSUS" -comment "WSUS Settings for the workbench"
Set-GPRegistryValue -Name "WSUS" -ValueName "DoNotConnectToWindowsUpdateInternetLocations" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "SetProxyBehaviorForUpdateDetection" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value 0 -Type DWord 
#Value is a varible we'll need to change
#Set-GPRegistryValue -Name "WSUS" -ValueName "TargetGroup" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value Space_Std -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "TargetGroupEnabled" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value 1 -Type DWord 
#WSUS server IP address
#Doesn't work
#Set-GPRegistryValue -Name "WSUS" -ValueName "WUServer" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value $wsusserver -Type DWord 
#Set-GPRegistryValue -Name "WSUS" -ValueName "WUStatusServer" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Value $wsusserver -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "AUOptions" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 4 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "AutoInstallMinorUpdates" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "DetectionFrequency" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 2 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "DetectionFrequencyEnabled" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord
Set-GPRegistryValue -Name "WSUS" -ValueName "NoAutoUpdate" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 0 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "ScheduledInstallDay" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 0 -Type DWord 
Set-GPRegistryValue -Name "WSUS" -ValueName "ScheduledInstallEveryWeek" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord
Set-GPRegistryValue -Name "WSUS" -ValueName "ScheduledInstallTime" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 3 -Type DWord
Set-GPRegistryValue -Name "WSUS" -ValueName "UseWUServer" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Value 1 -Type DWord

#Create Log on Notification GPO - chaned to string
New-GPO -Name "Logon message" -comment "Log on Message for the workbench"
Set-GPRegistryValue -Name "Logon message" -ValueName "LegalNoticeCaption" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value "NOTICE TO USERS" -Type String
Set-GPRegistryValue -Name "Logon message" -ValueName "LegalNoticeText" -key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Value "Please adhere to the agreed terms and conditions accepted during account creation." -Type String

#Create Disable Internet Explorer GPO
New-GPO -Name "Disable Internet Explorer" -comment "IE Settings for the workbench"
Set-GPRegistryValue -Name "Disable Internet Explorer" -ValueName "NotifyDisableIEOptions" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main" -Value 1 -Type DWord

#Create File History
New-GPO -Name "File History" -comment "File History Settings for the workbench"
Set-GPRegistryValue -Name "File History" -ValueName "Disabled" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\FileHistory" -Value 0 -Type DWord

#Create Chrome GPO
New-GPO -Name "Chrome" -comment "Chrome Settings for the workbench"

Set-GPRegistryValue -Name "Chrome" -ValueName "ImportBookmarks" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "ImportHistory" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "ImportHomepage" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "ImportSavedPasswords" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "ImportSearchEngine" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "UserFeedbackAllowed" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Chrome" -ValueName "ProxySettings" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" -Value $homepage -Type String


#Create Firefox GPO
New-GPO -Name "Firefox" -comment "Firefox Settings for the workbench"
Set-GPRegistryValue -Name "Firefox" -ValueName "installlanguage" -key "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\common\languageresources" -Value 2057 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "preferrededitinglanguage" -key "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\common\languageresources" -Value en-GB -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "SkipOnboarding" -key "HKEY_CURRENT_USER\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "WhatsNew" -key "HKEY_CURRENT_USER\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "DisableProfileImport" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "DisableTelemetry" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "ExtensionRecommendations" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "FeatureRecommendations" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "MoreFromMozilla" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "SkipOnboarding" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "WhatsNew" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\UserMessaging" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Firefox" -ValueName "URL" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\Homepage" -Value $homepage -Type String
Set-GPRegistryValue -Name "Firefox" -ValueName "StartPage" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\Homepage" -Value $homepage -Type DWord


#Create Edge GPO
New-GPO -Name "Edge" -comment "Edge Settings for the workbench"
Set-GPRegistryValue -Name "Edge" -ValueName "AllowSurfGame" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Edge" -ValueName "ConfigureDoNotTrack" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" -Value 0 -Type DWord
Set-GPRegistryValue -Name "Edge" -ValueName "EnhanceSecurityModeOptOutUXEnabled" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" -Value 1 -Type DWord
Set-GPRegistryValue -Name "Edge" -ValueName "URL" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" -Value $homepage -Type String
Set-GPRegistryValue -Name "Edge" -ValueName "StartPage" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge" -Value $homepage -Type String


#Create Profile redirection GPO
#New-GPO -Name "Profile Redirection" -comment "Profile Settings for the workbench"
#there must be more

#Create StartMenu GPO - sort out file name
New-GPO -Name "StartMenu" -comment "StartMenu Settings for the workbench"
Set-GPRegistryValue -Name "StartMenu" -ValueName "HideSCAPower" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "NoClose" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "NoStartMenuEjectPC" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "NoStartMenuMYGames" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "LockedStartLayout" -key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "StartLayoutFile" -key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" -Value "C:\eidf\$winProject.xml" -Type String
Set-GPRegistryValue -Name "StartMenu" -ValueName "LockedStartLayout" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" -Value 1 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "StartLayoutFile" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" -Value "C:\eidf\$winProject.xml" -Type String
Set-GPRegistryValue -Name "StartMenu" -ValueName "AllowWindows" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Appx" -Value 0 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "AllowWindows" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Dll" -Value 0 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "AllowWindows" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe" -Value 0 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "AllowWindows" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Msi" -Value 0 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "AllowWindows" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Script" -Value 0 -Type DWord
Set-GPRegistryValue -Name "StartMenu" -ValueName "UserPolicyMode" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Value 2 -Type DWord

#Create wb_server GPO
New-GPO -Name "wb servers" -comment "WorkBench Settings for the workbench"
Set-GPRegistryValue -Name "wb servers" -ValueName "ShutdownReasonOn" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Reliability" -Value 0 -Type DWord
# Delete this key - Set-GPRegistryValue -Name "wb servers" -ValueName "ShutdownReasonUI" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Reliability" -Value 0 -Type DWord


#Create firewall GPO
New-GPO -Name "firewall" -comment "firewall Settings for the end user servers"
Set-GPRegistryValue -Name "firewall" -ValueName "EnableFirewall" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Value 0 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "EnableFirewall" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Value 0 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "EnableFirewall" -key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Value 0 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "fEnableWddmDriver" -key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Value 1 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "LogFilePath" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value %systemroot%\system32\logfiles\firewall\domainfw.log -Type String
Set-GPRegistryValue -Name "firewall" -ValueName "LogFileSize" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Value 32096 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "DisableNotifications" -Key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Value 1 -Type DWord
Set-GPRegistryValue -Name "firewall" -ValueName "PolicyVersion" -key "HKEY_LOCAL_MACHINE\software\Policies\Microsoft\WindowsFirewall" -Value 543 -Type DWord

############# Workaround - Adam #############
$GpoName = "Disable Windows Firewall"
$DomainName = "$winProject.loc"

# Create and link GPO
New-GPO -Name $GpoName

# Configure GPO to disable Windows Firewall
Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "EnableFirewall" -Type DWord -Value 0
Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "EnableFirewall" -Type DWord -Value 0

New-GPLink -Name $GpoName -Target "DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1])"
New-GPLink -Name $GpoName -Target $workbenchOU
############# Workaround - Adam #############

#Import-Module -Name NetSecurity
#
#$fwgpo = Get-GPO -Name "Firewall"
#$fwgponame = $fwgpo.DomainName + "\" + $fwgpo.DisplayName
#$FWGPOSession = Open-NetGPO -PolicyStore $fwgponame
#New-NetFirewallRule -DisplayName "Allow Ansible" -Action Allow -Direction Inbound -LocalPort 5985-5986 -Protocol TCP -GPOSession $FWGPOSession
#Save-NetGPO -GPOSession $FWGPOSession

#Create proxy GPO
New-GPO -Name "proxy" -comment "proxy Settings for the end user servers"
#ff
Set-GPRegistryValue -Name "proxy" -ValueName "Mode" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox\Proxy" -Value "system" -Type String
#chrome

#edge


# four group memberships to add
#Security Template	Group Membership	*S-1-5-32-544__Memberof
#Security Template	Group Membership	*S-1-5-32-544__Members	*S-1-5-21-1607635393-2609548545-3408924799-512	
#Security Template	Group Membership	*S-1-5-32-555__Memberof	
#	*S-1-5-21-1607635393-2609548545-3408924799-1109
 #   *S-1-5-21-1607635393-2609548545-3408924799-512
 	
 # set sebackup privilege 

 #https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1
 #https://blakedrumm.com/blog/set-and-check-user-rights-assignment/

 #maybe food for access rights - https://stackoverflow.com/questions/74256553/how-to-enable-local-account-lockout-policies-through-powershell

#Set up Auditing 
#https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set

$computers | ForEach-Object {
     Set-GPPermission -Name "rds settings" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
     Set-GPPermission -Name "Chrome" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
     Set-GPPermission -Name "Firefox" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
     Set-GPPermission -Name "Edge" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
     Set-GPPermission -Name "wb servers" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
     Set-GPPermission -Name "Disable Internet Explorer" -TargetName $_ -TargetType Computer -PermissionLevel GpoApply
}

#Set permissions
Set-GPPermission -Name "rds settings" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
#Set-GPPermission -Name "NTLM" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
#Set-GPPermission -Name "NTLM" -TargetName $computers -TargetType Computer -PermissionLevel GpoApply
Set-GPPermission -Name "Chrome" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Firefox" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Edge" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "wb servers" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Disable Internet Explorer" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "WSUS" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "WSUS" -TargetName "Domain computers" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Disable Internet Explorer" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Disable Internet Explorer" -TargetName "Domain Computers" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Default Domain Policy" -TargetName "Domain Computers" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Default Domain Controllers Policy" -TargetName "Domain Controllers" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "WSUS" -TargetName "Domain Computers" -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "firewall" -TargetName "Domain Computers" -TargetType Group -PermissionLevel GpoApply

#Link to OU
New-GPLink -name "rds settings" -Target $workbenchOU
#New-GPLink -Name "NTLM" -Target $domaincontrollersOU
New-GPLink -Name "WSUS" -Target $DomainOU
New-GPLink -Name "Logon message" -Target $workbenchOU
New-GPLink -Name "Disable Internet Explorer" -Target $DomainOU
New-GPLink -Name "File History" -Target $workbenchOU
New-GPLink -Name "StartMenu" -Target $workbenchou
New-GPLink -Name "wb servers" -Target $workbenchou
New-GPLink -Name "Edge" -Target $workbenchou
New-GPLink -Name "Firefox" -Target $workbenchou
New-GPLink -Name "Chrome" -Target $workbenchou
#New-GPLink -Name "firewall" -Target $workbenchou

#add entry for WSUS


     #Profile Redirection
     #keyboard settings

Write-Output "THIS SCRIPT ACTUALLY RAN" | Out-File -FilePath 'C:\eidf\BuildScript.txt'
