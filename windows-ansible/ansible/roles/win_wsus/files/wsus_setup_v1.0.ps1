###############
## Variables ##
###############
 
##//INSTALLATION//##

# Do you want to install .NET FRAMEWORK 3.5? If true, provide a location for the Windows OS media in the next variable
    $DotNet = $True
# Do you want to download and install MS Report Viewer 2008 SP1 (required for WSUS Reports)?
    $RepViewer = $True
# WSUS Installation Type.  Enter "WID" (for WIndows Internal Database), "SQLExpress" (to download and install a local SQLExpress), or "SQLRemote" (for an existing SQL Instance).
    $WSUSType = "WID"
# Location to store WSUS Updates (will be created if doesn't exist)
    $WSUSDir = "W:\WSUS"
# Temporary location for installation files (will be created if doesn't exist)
    $TempDir = "W:\temp"
 
##//CONFIGURATION//##
 
# Do you want to configure WSUS (equivalent of WSUS Configuration Wizard, plus some additional options)?  If $false, no further variables apply.
# You can customise the configurations, such as Products and Classifications etc, in the "Begin Initial Configuration of WSUS" section of the script.
    $ConfigureWSUS = $True
# Do you want to decline some unwanted updates?
    $DeclineUpdates = $True
# Do you want to configure and enable the Default Approval Rule?
    $DefaultApproval = $True
# Do you want to run the Default Approval Rule after configuring?
    $RunDefaultRule = $False


# Install .Net Framework 3.5
if($DotNet -eq $true)
{
write-host 'Installing .Net Framework 3.5'
Install-WindowsFeature -name NET-Framework-Core
}

if (Test-Path -Path $WSUSDir) {
    Write-Host 'Content Directory Exists'
} else {
    sl "C:\Program Files\Update Services\Tools"
    .\wsusutil.exe postinstall CONTENT_DIR=$WSUSDir
}

# Get WSUS Server Object
$wsus = Get-WSUSServer
 
# Connect to WSUS server configuration
$wsusConfig = $wsus.GetConfiguration()
 
# Set to download updates from Microsoft Updates
Set-WsusServerSynchronization -SyncFromMU
 
# Set Update Languages to English and save configuration settings
$wsusConfig.AllUpdateLanguagesEnabled = $false
$wsusConfig.SetEnabledUpdateLanguages("en")
$wsusConfig.Save()




# Get WSUS Subscription and perform initial synchronization to get latest categories
$subscription = $wsus.GetSubscription()
$subscription.StartSynchronizationForCategoryOnly()
write-host 'Beginning first WSUS Sync to get available Products etc' -ForegroundColor Magenta
write-host 'Will take some time to complete'
While ($subscription.GetSynchronizationStatus() -ne 'NotProcessing') {
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 5
}
write-host ' '
Write-Host "Sync is done." -ForegroundColor Green




# Configure the Platforms that we want WSUS to receive updates
write-host 'Setting WSUS Products'
Get-WsusProduct | where-Object {
    $_.Product.Title -in (
    '.NET 5.0',
    '.NET 6.0',
    '.NET 7.0',
    '.NET 8.0',
    '.NET Core 2.1',
    '.NET Core 3.1',
    'Active Directory',
    'Microsoft 365 Apps/Office 2019/Office LTSC',
    'Microsoft Defender Antivirus',
    'Microsoft Security Essentials',
    'Microsoft Server operating system-21H2',
    'Microsoft Server Operating System-22H2',
    'Microsoft Server Operating System-23H2',
    'Microsoft Server Operating System-24H2',
    'Microsoft SQL Server 2012',
    'Microsoft SQL Server 2014',
    'Microsoft SQL Server 2016',
    'Microsoft SQL Server 2017',
    'Microsoft SQL Server 2019',
    'Microsoft SQL Server 2022',
    'Microsoft SQL Server Management Studio v17',
    'Microsoft SQL Server Management Studio v18',
    'Microsoft SQL Server Management Studio v19',
    'Microsoft SQL Server Management Studio v20',
    'MS Security Essentials',
    'PowerShell - x64',
    'PowerShell',
    'Security Essentials',
    'Server 2022 Hotpatch Category',
    'Silverlight',
    'Silverlight',
    'Visual Studio 2012',
    'Visual Studio 2013',
    'Visual Studio 2015 Update 3',
    'Visual Studio 2015',
    'Visual Studio 2017',
    'Visual Studio 2019',
    'Visual Studio 2022',
    'Windows Admin Center',
    'Windows - Server, version 21H2 and later, Servicing Drivers',
    'Windows - Server, version 21H2 and later, Upgrade & Servicing Drivers',
    'Windows - Server, version 24H2 and later, Upgrade & Servicing Drivers',
    'Windows Dictionary Updates',
    'Windows Security platform',
    'Windows Server 2019 and later, Servicing Drivers',
    'Windows Server 2019 and later, Upgrade & Servicing Drivers',
    'Windows Server 2019',
    'Windows Server 2019',
    'Windows Server Drivers',
    'Windows Server Manager   Windows Server Update Services (WSUS) Dynamic Installer',
    'Windows Server Technical Preview Language Packs',
    'Windows Server, version 1903 and later')
} | Set-WsusProduct

Get-WsusProduct | where-Object { $_.Product.Title -eq 'Windows' } | Set-WsusProduct -Disable
Get-WsusProduct | where-Object { $_.Product.Title -eq 'Developer Tools, Runtimes, and Redistributables' } | Set-WsusProduct -Disable

# Configure the Classifications
write-host 'Setting WSUS Classifications'
Get-WsusClassification | Where-Object {
    $_.Classification.Title -in (
    'Critical Updates',
    'Definition Updates',
    'Security Updates')
} | Set-WsusClassification





# Prompt to check products are set correctly
write-host 'Before continuing, please open the WSUS Console, cancel the WSUS Configuration Wizard,' - -ForegroundColor Red
write-host 'Go to Options > Products and Classifications, and check that the Products are set correctly.' - -ForegroundColor Red
write-host 'Pausing script' -ForegroundColor Yellow
$Shell = New-Object -ComObject "WScript.Shell"
$Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0) # Using Pop-up in case script is running in ISE




# Configure Synchronizations
write-host 'Enabling WSUS Automatic Synchronisation'
$subscription.SynchronizeAutomatically=$true
 
# Set synchronization scheduled for midnight each night
$subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
$subscription.NumberOfSynchronizationsPerDay=1
$subscription.Save()
 
# Kick off a synchronization
$subscription.StartSynchronization()



# Monitor Progress of Synchronisation
 
write-host 'Starting WSUS Sync, will take some time' -ForegroundColor Magenta
Start-Sleep -Seconds 60 # Wait for sync to start before monitoring
while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
    Write-Progress -PercentComplete (
    $subscription.GetSynchronizationProgress().ProcessedItems*100/($subscription.GetSynchronizationProgress().TotalItems)
    ) -Activity "WSUS Sync Progress"
}
Write-Host "Sync is done." -ForegroundColor Green


### DECLINE STUFF


#NEED TO try set-wsusproduct -disable

# Configure Default Approval Rule
 
if ($DefaultApproval -eq $True)
{
write-host 'Configuring default automatic approval rule'
[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
$rule = $wsus.GetInstallApprovalRules() | Where {
    $_.Name -eq "Default Automatic Approval Rule"}
$class = $wsus.GetUpdateClassifications() | ? {$_.Title -In (
    'Critical Updates',
    'Definition Updates',
    'Feature Packs',
    'Security Updates',
    'Service Packs',
    'Update Rollups',
    'Updates')}
$class_coll = New-Object Microsoft.UpdateServices.Administration.UpdateClassificationCollection
$class_coll.AddRange($class)
$rule.SetUpdateClassifications($class_coll)
$rule.Enabled = $True
$rule.Save()
}

$Apply = $rule.ApplyRule()

