# Scans the home network for security cameras and writes scan-results.json
# next to this script. Import that file from the page: Settings -> import scan.
$ErrorActionPreference = 'SilentlyContinue'

$cfg = Get-NetIPConfiguration |
  Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
  Select-Object -First 1
if (-not $cfg) { Write-Host 'No active network connection found.'; exit 1 }
$localIp = @($cfg.IPv4Address)[0].IPAddress
$base = ($localIp -split '\.')[0..2] -join '.'
Write-Host "Scanning $base.1-254 (this computer: $localIp)..."

# 1. ONVIF discovery: most IP cameras answer a WS-Discovery probe
$probe = @"
<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header><w:MessageID>uuid:$([guid]::NewGuid())</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>
<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>
"@
$onvif = @{}
$udp = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($localIp)), 0)
$udp.Client.ReceiveTimeout = 500
$bytes = [Text.Encoding]::UTF8.GetBytes($probe)
$target = New-Object Net.IPEndPoint ([Net.IPAddress]::Parse('239.255.255.250')), 3702
[void]$udp.Send($bytes, $bytes.Length, $target)
[void]$udp.Send($bytes, $bytes.Length, $target)
$deadline = (Get-Date).AddSeconds(3)
while ((Get-Date) -lt $deadline) {
  $remote = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
  try { $data = $udp.Receive([ref]$remote) } catch { continue }
  $xml = [Text.Encoding]::UTF8.GetString($data)
  $scopes = [regex]::Match($xml, 'Scopes[^>]*>([^<]*)<').Groups[1].Value
  $onvif[$remote.Address.ToString()] = @{
    name  = [uri]::UnescapeDataString([regex]::Match($scopes, 'onvif://www\.onvif\.org/name/(\S+)').Groups[1].Value)
    model = [uri]::UnescapeDataString([regex]::Match($scopes, 'onvif://www\.onvif\.org/hardware/(\S+)').Groups[1].Value)
  }
}
$udp.Close()

# 2. Port scan: RTSP and the vendor ports of the common camera / NVR brands
$ports = 554, 8554, 80, 8000, 37777, 34567
$attempts = foreach ($i in 1..254) {
  $addr = "$base.$i"
  if ($addr -eq $localIp) { continue }
  foreach ($p in $ports) {
    $c = New-Object Net.Sockets.TcpClient
    [pscustomobject]@{ Ip = $addr; Port = $p; Client = $c; Task = $c.ConnectAsync($addr, $p) }
  }
}
Start-Sleep -Milliseconds 2000
$open = @{}
foreach ($a in $attempts) {
  if ($a.Task.IsCompleted -and -not $a.Task.IsFaulted -and $a.Client.Connected) {
    if (-not $open[$a.Ip]) { $open[$a.Ip] = @() }
    $open[$a.Ip] += $a.Port
  }
  $a.Client.Close()
}

# 3. Keep only devices that look like cameras, and guess the brand
$ips = @($open.Keys) + @($onvif.Keys) | Sort-Object -Unique { [version]$_ }
$cams = foreach ($addr in $ips) {
  $p = @($open[$addr])
  $isCam = $onvif[$addr] -or ($p -contains 554) -or ($p -contains 8554) -or ($p -contains 8000) -or ($p -contains 37777) -or ($p -contains 34567)
  if (-not $isCam) { continue }

  $info = ''
  if ($p -contains 80) {
    try {
      $r = Invoke-WebRequest "http://$addr/" -UseBasicParsing -TimeoutSec 2 -MaximumRedirection 2
      $info = "$($r.Headers['Server']) $([regex]::Match($r.Content, '<title>([^<]*)</title>', 'IgnoreCase').Groups[1].Value)"
    } catch {
      $resp = $_.Exception.Response
      if ($resp) { $info = "$($resp.Headers['Server']) $($resp.Headers['WWW-Authenticate'])" }
    }
  }
  $model = if ($onvif[$addr]) { "$($onvif[$addr].name) $($onvif[$addr].model)".Trim() } else { '' }
  $text = "$model $info".ToLower()

  $brand =
    if ($text -match 'hikvision|hik|ds-2|ds-7|ezviz' -or $p -contains 8000) { 'hikvision' }
    elseif ($text -match 'dahua|imou|amcrest|lorex' -or $p -contains 37777) { 'dahua' }
    elseif ($text -match 'reolink') { 'reolink' }
    elseif ($p -contains 34567) { 'xmeye' }
    else { 'unknown' }

  $snapshot = switch ($brand) {
    'hikvision' { "http://$addr/ISAPI/Streaming/channels/101/picture" }
    'dahua'     { "http://$addr/cgi-bin/snapshot.cgi" }
    'reolink'   { "http://$addr/cgi-bin/api.cgi?cmd=Snap&channel=0" }
    default     { '' }
  }
  $rtsp = switch ($brand) {
    'hikvision' { "rtsp://${addr}:554/Streaming/Channels/101" }
    'dahua'     { "rtsp://${addr}:554/cam/realmonitor?channel=1&subtype=0" }
    'reolink'   { "rtsp://${addr}:554/h264Preview_01_main" }
    'xmeye'     { "rtsp://${addr}:554/user=admin&password=&channel=1&stream=0.sdp" }
    default     { "rtsp://${addr}:554/" }
  }

  [pscustomobject]@{
    ip = $addr; brand = $brand; model = $model; info = $info.Trim()
    ports = $p; snapshot = $snapshot; rtsp = $rtsp
  }
}
$cams = @($cams)

if ($cams.Count -eq 0) {
  Write-Host 'No cameras found.'
} else {
  Write-Host "Found $($cams.Count) camera(s):"
  $cams | Format-Table ip, brand, model, ports -AutoSize | Out-String | Write-Host
}

$out = Join-Path $PSScriptRoot 'scan-results.json'
$json = ConvertTo-Json -InputObject @{ scanned = (Get-Date).ToString('s'); network = "$base.0/24"; cameras = $cams } -Depth 4
[IO.File]::WriteAllText($out, $json, (New-Object Text.UTF8Encoding $false))
Write-Host "Saved: $out"
