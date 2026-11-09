# Iteracion 10: revertir exclusivamente acciones registradas por este EDR.
# Ejecutar como administrador despues de detener el monitor.
$ErrorActionPreference = 'Stop'
$Ledger = Join-Path $PSScriptRoot 'edr_lab_actions.jsonl'
$QDir = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'edr_lab_quarantine')).TrimEnd('\') + '\'
$TempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
if (-not (Test-Path -LiteralPath $Ledger)) { Write-Host '[OK] No hay acciones registradas.'; return }
$Entries = @(Get-Content -LiteralPath $Ledger | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
$Reverted = @{}
foreach ($Entry in $Entries) {
    if ($Entry.Kind -eq 'Rollback' -and $Entry.Status -eq 'SUCCESS') { $Reverted[[string]$Entry.Key] = $true }
}
foreach ($Entry in $Entries) {
    if ($Entry.Status -ne 'APPLIED') { continue }
    $Key = if ($Entry.Kind -eq 'Firewall') { 'Firewall:' + $Entry.RuleId } else { 'File:' + $Entry.QuarantinePath }
    if ($Reverted.ContainsKey($Key)) { continue }
    $Status = 'FAILED'
    try {
        if ($Entry.Kind -eq 'Firewall') {
            if ([string]$Entry.RuleId -notmatch '^EDR_LAB_V2_10_[a-f0-9]{32}$') { throw 'Identificador de regla no autorizado' }
            $Rule = Get-NetFirewallRule -Name $Entry.RuleId -ErrorAction SilentlyContinue
            if ($null -ne $Rule) {
                # No borrar una regla ajena que haya reutilizado el nombre.
                $App = $Rule | Get-NetFirewallApplicationFilter
                $Addr = $Rule | Get-NetFirewallAddressFilter
                $Port = $Rule | Get-NetFirewallPortFilter
                $ExpectedExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
                if ($Rule.Action -ne 'Block' -or $Rule.Direction -ne 'Outbound' -or
                    $App.Program -ine $ExpectedExe -or $Addr.RemoteAddress -notcontains '1.1.1.1' -or
                    $Port.RemotePort -notcontains '853' -or $Port.Protocol -ne 'TCP') {
                    throw 'La regla ya no coincide con la creada por el EDR'
                }
                Remove-NetFirewallRule -Name $Entry.RuleId -ErrorAction Stop
            }
            if ($null -eq (Get-NetFirewallRule -Name $Entry.RuleId -ErrorAction SilentlyContinue)) { $Status = 'SUCCESS' }
        } elseif ($Entry.Kind -eq 'File') {
            $Source = [IO.Path]::GetFullPath([string]$Entry.QuarantinePath)
            $Destination = [IO.Path]::GetFullPath([string]$Entry.OriginalPath)
            $Name = [IO.Path]::GetFileName($Source)
            if (-not $Source.StartsWith($QDir, [StringComparison]::OrdinalIgnoreCase) -or
                -not $Destination.StartsWith($TempRoot, [StringComparison]::OrdinalIgnoreCase) -or
                $Name -cne [IO.Path]::GetFileName($Destination) -or
                $Name -notmatch '^edr_lab_v2_9_[a-f0-9]{32}\.vbs$') { throw 'Rutas no autorizadas' }
            if (Test-Path -LiteralPath $Destination) { throw 'Destino existente: no sobrescribir' }
            if (Test-Path -LiteralPath $Source -PathType Leaf) {
                Move-Item -LiteralPath $Source -Destination $Destination -ErrorAction Stop
                if ((Test-Path -LiteralPath $Destination -PathType Leaf) -and
                    -not (Test-Path -LiteralPath $Source)) { $Status = 'SUCCESS' }
            } else { throw 'Archivo en cuarentena no encontrado' }
        } else { continue }
    } catch { Write-Warning "$Key : $($_.Exception.Message)" }
    $Record = @{ Kind='Rollback'; Key=$Key; Status=$Status; Time=(Get-Date).ToString('o') } | ConvertTo-Json -Compress
    Add-Content -LiteralPath $Ledger -Value $Record -Encoding UTF8
    Write-Host "Rollback $Key : $Status"
}
