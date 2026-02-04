param(
    [string]$Public,
    [string]$PrivateDesc
)

# 创建 COM 对象
$nsMgr = New-Object -ComObject HNetCfg.HNetShare.1
$allConns = $nsMgr.EnumEveryConnection() 

$publicConn = $null
$privateConn = $null

foreach ($conn in $allConns) {
    $props = $nsMgr.NetConnectionProps($conn)

    # Public 用名字匹配
    if ($props.Name -eq $Public) {
        $publicConn = $conn
        Write-Host "-> Selected PUBLIC: $($props.Name)"
    }

    # Private 用描述匹配
    if ($props.DeviceName -like "*$PrivateDesc*") {
        $privateConn = $conn
        Write-Host "-> Selected PRIVATE: $($props.DeviceName)"
    }

    $Cfg = $nsMgr.INetSharingConfigurationForINetConnection($conn)
    $Cfg.DisableSharing()
}

if (-not $publicConn -or -not $privateConn) {
    Write-Error "Public or Private adapter not found!"
    exit 1
}

$pubCfg = $nsMgr.INetSharingConfigurationForINetConnection($publicConn)
$priCfg = $nsMgr.INetSharingConfigurationForINetConnection($privateConn)


# 启用 ICS
$pubCfg.EnableSharing(0)   # Public
Start-Sleep -Milliseconds 500
$priCfg.EnableSharing(1)   # Private

Write-Host "ICS Enabled successfully!"
exit 0
