# V2 iteracion 9: proceso, red y archivo; SOLO laboratorio.
param([switch]$ActiveTest)
$ErrorActionPreference = 'Stop'
$Log = Join-Path $PSScriptRoot 'edr_response.log'
if (-not (Test-Path -LiteralPath $Log)) { throw 'Inicia el monitor V2 primero.' }
$Before = (Get-Item -LiteralPath $Log).Length
$exe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$cmd = @'
# EDR_LAB_CONTAINMENT_V2_9
$p = Join-Path $env:TEMP ('edr_lab_v2_9_' + [guid]::NewGuid().ToString('N') + '.vbs')
try {
    [System.IO.File]::WriteAllText($p, "' Archivo inocuo")
    Start-Sleep -Seconds 2
    $t = [System.Net.Sockets.TcpClient]::new()
    try {
        $t.Connect('1.1.1.1',853)
        Write-Output 'CONNECTED'
        Start-Sleep -Seconds 30
    } finally { $t.Dispose() }
} finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host '[TEST2] Iniciando proceso de laboratorio...'
$p = Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(22)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 400
        $fs = [IO.File]::Open($Log,'Open','Read','ReadWrite')
        try {
            [void]$fs.Seek($Before,[IO.SeekOrigin]::Begin)
            $reader = [IO.StreamReader]::new($fs)
            $newText = $reader.ReadToEnd()
            $reader.Dispose()
        } finally { $fs.Dispose() }
        $lines = @($newText -split "`r?`n" | Where-Object { $_ -match 'RiskScore=100\s+RiskLevel=HIGH\s+ResponsePolicy=PREPARE_CONTAINMENT' })
        foreach ($line in $lines) {
            if ($ActiveTest -and $line -match 'Mode=Active' -and $line -match 'Containment=SUCCESS') {
                Start-Sleep -Milliseconds 500
                $p.Refresh()
                if ($p.HasExited) {
                    $Rule = @(Get-NetFirewallRule -Name 'EDR_LAB_V2_10_*' -ErrorAction SilentlyContinue)
                    $QFile = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'edr_lab_quarantine') -Filter 'edr_lab_v2_9_*.vbs' -File -ErrorAction SilentlyContinue)
                    if ($line -match 'Firewall=SUCCESS' -and $line -match 'Quarantine=SUCCESS' -and $line -match 'Containment=SUCCESS' -and
                        $Rule.Count -gt 0 -and $QFile.Count -gt 0) {
                        Write-Host '[PASS] Proceso, Firewall y cuarentena verificados.' -ForegroundColor Green
                        Write-Host $line
                        exit 0
                    }
                    Write-Host '[FAIL] Proceso terminado, pero falta validar red o archivo.' -ForegroundColor Red
                    Write-Host $line
                    exit 1
                }
            }
            if (-not $ActiveTest -and $line -match 'Mode=DryRun' -and $line -match 'Containment=DRYRUN') {
                Write-Host '[PASS] DryRun: correlacion detectada, proceso no terminado por EDR.' -ForegroundColor Green
                Write-Host $line; exit 0
            }
        }
    }
    Write-Host '[FAIL] No se confirmo la contencion esperada.' -ForegroundColor Red
    Get-Content -LiteralPath $Log -Tail 6
    exit 1
}
finally {
    $p.Refresh()
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
