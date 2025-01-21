
 $Directoryex = Get-ChildItem -Path "S:\" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "Export"}
$Directoryex | ForEach {
    $fullnameex= "$($_.FullName)"
    $ParentDirectoryNameex = "$($_.parent)"

    $filenameex = Get-ChildItem -path $fullnameex -Force -File | Foreach {

    $Sourceex = $fullnameex + "\" + "$($_.name)"
    $Destinationex = "T:\Export\" + $ParentDirectoryNameex + "\"
    Move-Item -path $Sourceex -Destination $Destinationex

    #logging
    $Logfileex2="T:\Logs\TransferexportLog.txt"
    $dateex2 = (Get-Date)
    $dateex2, $Sourceex, $Destinationex | out-file $Logfileex2 -Append}}
    write-host $sourceex
    $Sourceex = $fullnameex + "\" + "$($_.name)"
    $NewName = "Standard" + "_" + $ParentDirectoryNameex + "_" + "$($_.name)"
    Rename-Item -Path $Sourceex -NewName $NewName
    write-host $sourceeex

    Write-Host $Sourceex
    Write-Host $Destinationex

    $sizeex=Format-FileSize((Get-Item $sourceex).length)

   
    $Directoryex2 = Get-ChildItem -Path "S:\" -Recurse -Force | Where-Object {$_.Name -eq "Export"}
    $Directoryex2 | ForEach {
    $fullnameex2= "$($_.FullName)"
    $ParentDirectoryNameex2 = "$($_.parent)"

    $filenameex2 = Get-ChildItem -path $fullnameex2 -Force -File | Foreach {

    $Sourceex2 = $fullnameex2 + "\" + "$($_.name)"
    $Destinationex2 = "T:\Export\" + $ParentDirectoryNameex2 + "\"

    Move-Item -path $Sourceex2 -Destination $Destinationex2

    $Logfileex2="T:\Logs\TransferexportLog.txt"
    $dateex2 = (Get-Date)
    $dateex2, $Sourceex, $Destinationex | out-file $Logfileex2 -Append
    }
    }
    
    
      
      Function Format-FileSize() {
Param ([int]$sizeex)
If ($sizeex -gt 1TB) {[string]::Format("{0:0.00} TB", $sizeex / 1TB)}
ElseIf ($sizeex -gt 1GB) {[string]::Format("{0:0.00} GB", $sizeex / 1GB)}
ElseIf ($sizeex -gt 1MB) {[string]::Format("{0:0.00} MB", $sizeex / 1MB)}
ElseIf ($sizeex -gt 1KB) {[string]::Format("{0:0.00} kB", $sizeex / 1KB)}
ElseIf ($sizeex -gt 0) {[string]::Format("{0:0.00} B", $sizeex)}
Else {""}
}