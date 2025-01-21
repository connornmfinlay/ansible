$Directory = "T:\Import\"
Get-ChildItem -Path $Directory -Recurse -Force -File -Exclude ".*" | ForEach {
    $filename= "$($_.Name)"
    $ParentDirectoryName = "$($_.Directory.Name)"

    Write-host $ParentDirectoryName, $filename
    $Source = "T:\Import\" +"$($_.Directory.Name)" + "\" + $filename
    $Destination = "S:\" + "$($_.Directory.Name)" + "\" + "Import" + "\"

    #Write-Host $Source
    #Write-Host $Destination

    $size=Format-FileSize((Get-Item $source).length)

    Move-Item -path $Source -Destination $Destination

    $Logfile="T:\Logs\TransferLog.txt"
    $date = (Get-Date)
    $date, $Source, $size, $Destination | out-file $Logfile -Append
    



   
    #Change permissions
       Function Format-FileSize() {
Param ([int]$size)
If ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
ElseIf ($size -gt 0) {[string]::Format("{0:0.00} B", $size)}
Else {""}
}



    }