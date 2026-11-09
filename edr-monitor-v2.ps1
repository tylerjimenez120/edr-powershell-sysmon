
param([switch]$ActiveContainment)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================
# EDR MONITOR - SYSMON EVENT WATCHER
# Version: 2.10 - CONTENCION LAB AUDITADA
# ============================================================

$ErrorActionPreference = "Stop"
# Opt-in explicito: .\edr-monitor-v2.ps1 -ActiveContainment


# ------------------------------------------------------------
# 1. VALIDAR PRIVILEGIOS
# ------------------------------------------------------------

$IsAdmin = ([Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdmin) {
    Write-Host "[-] Ejecuta PowerShell como administrador." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------
# 2. RUTAS ABSOLUTAS
# ------------------------------------------------------------

$BaseDir = $PSScriptRoot

$Global:EdrLogFile    = Join-Path $BaseDir "edr_alerts.log"
$Global:NormalLogFile = Join-Path $BaseDir "edr_normal.log"
$Global:ErrorLogFile  = Join-Path $BaseDir "edr_errors.log"
$Global:ResponseLogFile = Join-Path $BaseDir "edr_response.log"

$LogName = "Microsoft-Windows-Sysmon/Operational"

# Inicializar archivos para garantizar que existan
foreach ($Path in @(
    $Global:EdrLogFile,
    $Global:NormalLogFile,
    $Global:ErrorLogFile,
    $Global:ResponseLogFile
)) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType File -Force | Out-Null
    }
}

# No eliminar reglas al iniciar: las acciones deben persistir hasta rollback autorizado.
$LedgerPath = Join-Path $BaseDir 'edr_lab_actions.jsonl'
if (-not (Test-Path -LiteralPath $LedgerPath)) {
    New-Item -Path $LedgerPath -ItemType File | Out-Null
}

# ------------------------------------------------------------
# 3. LIMPIEZA DE SUSCRIPCIONES ANTERIORES
# ------------------------------------------------------------

Get-EventSubscriber |
    Where-Object { $_.SourceIdentifier -like "EDR_*" } |
    ForEach-Object {
        Unregister-Event -SourceIdentifier $_.SourceIdentifier `
            -ErrorAction SilentlyContinue
    }

Get-Job |
    Where-Object { $_.Name -like "EDR_*" } |
    Remove-Job -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------
# 4. INICIALIZAR EVENT WATCHER
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "          EDR MONITOR - VERSION 2.0        " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

try {

    $Query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        $LogName,
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*"
    )

    $Watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new(
        $Query
    )

}
catch {

    Write-Host "[-] Error inicializando Sysmon:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1

}

# ------------------------------------------------------------
# 5. DATOS COMPARTIDOS CON EL EVENTO
# ------------------------------------------------------------

$JobName = "EDR_" + [guid]::NewGuid().ToString("N")

$MessageData = @{
    AlertLog  = $Global:EdrLogFile
    NormalLog = $Global:NormalLogFile
    ErrorLog  = $Global:ErrorLogFile
    ResponseLog = $Global:ResponseLogFile
    Correlation = [hashtable]::Synchronized(@{})
    ProcessSignals = [hashtable]::Synchronized(@{})
    FileSignals = [hashtable]::Synchronized(@{})
    LabProcessStart = [hashtable]::Synchronized(@{})
    LabFiles = [hashtable]::Synchronized(@{})
    LabFirewallRules = [hashtable]::Synchronized(@{})
    ContainedGuids = [hashtable]::Synchronized(@{})
    LedgerPath = $LedgerPath
    QuarantineDir = (Join-Path $BaseDir 'edr_lab_quarantine')
    ActiveContainment = [bool]$ActiveContainment
}

# ------------------------------------------------------------
# 6. PROCESAMIENTO DE EVENTOS
# ------------------------------------------------------------

$Action = {

    $Record = $null

    try {

        # Obtener evento recibido
        $Record = $Event.SourceEventArgs.EventRecord

        if ($null -eq $Record) {

            $Exception = $Event.SourceEventArgs.EventException

            if ($null -ne $Exception) {
                Add-Content -LiteralPath $Event.MessageData.ErrorLog `
                    -Value "[$(Get-Date)] Error de Sysmon: $($Exception.Message)" `
                    -Encoding UTF8
            }

            return
        }

        $EventID = $Record.Id

        # Solo procesar eventos relevantes
        if ($EventID -notin @(1, 3, 10, 11)) {
            return
        }

        $EventTime = $Record.TimeCreated

        # Obtener XML original
        [xml]$Xml = $Record.ToXml()

        # Extraer campos sin depender del namespace
        $Fields = @{}

        foreach ($Node in $Xml.SelectNodes("//*[local-name()='Data']")) {

            $FieldName = $Node.GetAttribute("Name")

            if ($FieldName) {
                $Fields[$FieldName] = $Node.InnerText
            }

        }

        # ----------------------------------------------------
        # CLASIFICACION
        # ----------------------------------------------------

        $RuleName = [string]$Fields["RuleName"]

        if ([string]::IsNullOrWhiteSpace($RuleName)) {
            $RuleName = "SIN_REGLA"
        }

        $ProcessName = "Desconocido"

        if ($Fields["Image"]) {
            $ProcessName = Split-Path -Path $Fields["Image"] -Leaf
        }
        elseif ($Fields["SourceImage"]) {
            $ProcessName = Split-Path -Path $Fields["SourceImage"] -Leaf
        }

        # ----------------------------------------------------
        # DETALLES SEGUN EVENT ID
        # ----------------------------------------------------

        switch ($EventID) {

            1 {
                $Details = "Proceso: $($Fields['Image']) | PID: $($Fields['ProcessId']) | Comando: $($Fields['CommandLine'])"
            }

            3 {
                $Details = "Proceso: $($Fields['Image']) | PID: $($Fields['ProcessId']) | Destino: $($Fields['DestinationIp']):$($Fields['DestinationPort']) | Iniciado: $($Fields['Initiated'])"
            }

            10 {
                $Details = "Origen: $($Fields['SourceImage']) | PID: $($Fields['SourceProcessId']) | Objetivo: $($Fields['TargetImage']) | Acceso: $($Fields['GrantedAccess'])"
            }

            11 {
                $Details = "Proceso: $($Fields['Image']) | PID: $($Fields['ProcessId']) | Archivo: $($Fields['TargetFilename'])"
            }

        }

        # ----------------------------------------------------
        # CONSTRUIR MENSAJE
        # ----------------------------------------------------

        $Message = @"
====================================================
HORA       : $EventTime
EVENTO     : $EventID
REGLA      : $RuleName
PROCESO    : $ProcessName
DETALLES   : $Details
====================================================

"@

        # ----------------------------------------------------
        # ESCRITURA DIRECTA EN LOGS
        # ----------------------------------------------------

        if ($RuleName -match '^Alerta_') {

            Add-Content -LiteralPath $Event.MessageData.AlertLog `
                -Value $Message -Encoding UTF8

            # V2: decision de respuesta en modo simulacion.
            # No bloquear ni finalizar procesos en esta iteracion.
            $Decision = switch -Regex ($RuleName) {
                '^Alerta_C2_Beacon$'           { 'WOULD_BLOCK_NETWORK'; break }
                '^Alerta_ArchivoInfostealer$'  { 'WOULD_REVIEW_QUARANTINE'; break }
                '^Alerta_CredentialDump$'      { 'WOULD_REVIEW_PROCESS'; break }
                default                       { 'ALERT_ONLY' }
            }

            $GuidValue = if ($EventID -eq 10) {
                [string]$Fields['SourceProcessGUID']
            } else {
                [string]$Fields['ProcessGuid']
            }
            # ID 1: guardar tiempo de creacion Sysmon para proteger contra reutilizacion del PID.
            if ($EventID -eq 1 -and -not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $Event.MessageData.LabProcessStart[$GuidValue] = $Record.TimeCreated
            }
            # Iteracion 3: correlacion ligera de eventos ID 3 por ProcessGuid.
            # Ventana deslizante: 60 s. No hay acciones reales.
            $CorrelationCount = 0
            if ($EventID -eq 3 -and $RuleName -eq 'Alerta_C2_Beacon' -and
                -not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $NowUtc = [datetime]::UtcNow
                $State = $Event.MessageData.Correlation
                $History = @($State[$GuidValue] | Where-Object {
                    $_ -is [datetime] -and ($NowUtc - $_).TotalSeconds -ge 0 -and
                    ($NowUtc - $_).TotalSeconds -le 60
                })
                $History += $NowUtc
                $State[$GuidValue] = $History
                $CorrelationCount = $History.Count
                if ($CorrelationCount -ge 2) {
                    $Decision = 'WOULD_BLOCK_NETWORK_CORRELATED'
                }
            }
            # Iteracion 4 de V2: correlacion ID 1 -> ID 3 por ProcessGuid.
            # Unicamente si ambos eventos son alertas y llegan en 60 segundos.
            # No equiparar este patron a una infeccion confirmada.
            if (-not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $NowUtc = [datetime]::UtcNow
                $Signals = $Event.MessageData.ProcessSignals
                if ($EventID -eq 1) {
                    $Signals[$GuidValue] = $NowUtc
                }
                elseif ($EventID -eq 3 -and $RuleName -eq 'Alerta_C2_Beacon') {
                    $SeenAt = $Signals[$GuidValue]
                    if ($SeenAt -is [datetime] -and
                        ($NowUtc - $SeenAt).TotalSeconds -ge 0 -and
                        ($NowUtc - $SeenAt).TotalSeconds -le 60) {
                        $Decision = 'WOULD_REVIEW_PROCESS_NETWORK_CORRELATED'
                    }
                }
            }
            # Conservar la ruta exacta de ID 11 para la cuarentena de laboratorio.
            if ($EventID -eq 11 -and $RuleName -eq 'Alerta_ArchivoInfostealer' -and
                -not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $Event.MessageData.LabFiles[$GuidValue] = [string]$Fields['TargetFilename']
            }
            # Iteracion 5: ID 1 + ID 11 + ID 3 del MISMO proceso en 60 s.
            # La creacion del archivo no implica que este haya sido ejecutado.
            if (-not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $NowUtc = [datetime]::UtcNow
                $Files = $Event.MessageData.FileSignals
                if ($EventID -eq 11 -and $RuleName -eq 'Alerta_ArchivoInfostealer') {
                    $Files[$GuidValue] = $NowUtc
                }
                elseif ($EventID -eq 3 -and $RuleName -eq 'Alerta_C2_Beacon') {
                    $ProcSeen = $Event.MessageData.ProcessSignals[$GuidValue]
                    $FileSeen = $Files[$GuidValue]
                    if ($ProcSeen -is [datetime] -and $FileSeen -is [datetime] -and
                        ($NowUtc - $ProcSeen).TotalSeconds -ge 0 -and
                        ($NowUtc - $ProcSeen).TotalSeconds -le 60 -and
                        ($NowUtc - $FileSeen).TotalSeconds -ge 0 -and
                        ($NowUtc - $FileSeen).TotalSeconds -le 60) {
                        $Decision = 'WOULD_REVIEW_THREE_SIGNALS'
                    }
                }
            }
            # Iteracion 6: puntuacion experimental de riesgo, sin acciones reales.
            # La puntuacion usa las senales ya correlacionadas por ProcessGuid.
            $RiskScore = 0
            $RiskNow = [datetime]::UtcNow
            $RiskProcSeen = $null
            $RiskFileSeen = $null
            if (-not [string]::IsNullOrWhiteSpace($GuidValue)) {
                $RiskProcSeen = $Event.MessageData.ProcessSignals[$GuidValue]
                $RiskFileSeen = $Event.MessageData.FileSignals[$GuidValue]
            }
            $RiskHasProc = $RiskProcSeen -is [datetime] -and
                ($RiskNow - $RiskProcSeen).TotalSeconds -ge 0 -and
                ($RiskNow - $RiskProcSeen).TotalSeconds -le 60
            $RiskHasFile = $RiskFileSeen -is [datetime] -and
                ($RiskNow - $RiskFileSeen).TotalSeconds -ge 0 -and
                ($RiskNow - $RiskFileSeen).TotalSeconds -le 60
            $RiskHasNetwork = $EventID -eq 3 -and $RuleName -eq 'Alerta_C2_Beacon'
            if ($RiskHasProc) { $RiskScore += 20 }
            if ($RiskHasFile) { $RiskScore += 25 }
            if ($RiskHasNetwork) { $RiskScore += 30 }
            if ($RiskHasProc -and $RiskHasNetwork) { $RiskScore += 10 }
            if ($RiskHasProc -and $RiskHasFile -and $RiskHasNetwork) { $RiskScore += 15 }
            $RiskLevel = if ($RiskScore -ge 75) { 'HIGH' }
                elseif ($RiskScore -ge 40) { 'MEDIUM' }
                else { 'LOW' }
            $CurrentMode = if ($Event.MessageData.ActiveContainment) { 'Active' } else { 'DryRun' }
            $ResponseLine = '[{0}] RecordId={1} EventID={2} Rule={3} ProcessGuid={4} Decision={5} Mode={6} CorrelationCount={7}' -f `
                (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), `
                $Record.RecordId, $EventID, $RuleName, $GuidValue, $Decision, $CurrentMode, $CorrelationCount
            # Iteracion 7: politica de respuesta, solo clasificacion en DryRun.
            # No ejecuta acciones sobre procesos, archivos o firewall.
            $ResponsePolicy = switch ($RiskLevel) {
                'HIGH'   { 'PREPARE_CONTAINMENT'; break }
                'MEDIUM' { 'COLLECT_EVIDENCE'; break }
                default  { 'OBSERVE' }
            }
            $ResponseLine += " RiskScore=$RiskScore RiskLevel=$RiskLevel"
            $ResponseLine += " ResponsePolicy=$ResponsePolicy"
            # Iteracion 10: contencion idempotente, verificada y registrada.
            # Solo laboratorio. La marca en el comando NO basta: se exige imagen,
            # PID/fecha de inicio, ruta TEMP, nombre y destino de prueba.
            if ($EventID -eq 3 -and $RiskScore -eq 100 -and
                $Decision -eq 'WOULD_REVIEW_THREE_SIGNALS') {
                $ResponseLine += ' Containment=ELIGIBLE'
                if (-not $Event.MessageData.ActiveContainment) {
                    $ResponseLine += ' Containment=DRYRUN'
                }
                elseif ($Event.MessageData.ContainedGuids.ContainsKey($GuidValue)) {
                    $ResponseLine += ' Containment=ALREADY_CONTAINED'
                }
                else {
                    # Marcar antes de actuar: el callback no repetira acciones por GUID.
                    $Event.MessageData.ContainedGuids[$GuidValue] = $true
                    $ContainmentResult = 'DENIED_NOT_LAB'
                    $FirewallStatus = 'SKIPPED'
                    $QuarantineStatus = 'SKIPPED'
                    try {
                        $PidText = [string]$Fields['ProcessId']
                        $SysmonStart = $Event.MessageData.LabProcessStart[$GuidValue]
                        $RemoteIp = [string]$Fields['DestinationIp']
                        $RemotePort = [string]$Fields['DestinationPort']
                        $LabFile = [string]$Event.MessageData.LabFiles[$GuidValue]
                        $TempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
                        $FileFull = if ($LabFile) { [IO.Path]::GetFullPath($LabFile) } else { '' }
                        $FileName = if ($FileFull) { [IO.Path]::GetFileName($FileFull) } else { '' }
                        $ValidFile = $FileFull.StartsWith($TempRoot, [StringComparison]::OrdinalIgnoreCase) -and
                            $FileName -match '^edr_lab_v2_9_[a-f0-9]{32}\.vbs$' -and
                            (Test-Path -LiteralPath $FileFull -PathType Leaf)
                        if ($PidText -match '^\d+$' -and $SysmonStart -is [datetime] -and
                            $RemoteIp -eq '1.1.1.1' -and $RemotePort -eq '853' -and $ValidFile) {
                            $TargetPid = [int]$PidText
                            $Target = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction Stop
                            $ExpectedExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
                            if ($null -ne $Target -and $Target.Name -ieq 'powershell.exe' -and
                                $Target.ExecutablePath -ieq $ExpectedExe) {
                                $PayloadMatch = [regex]::Match([string]$Target.CommandLine,
                                    '(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)')
                                if ($PayloadMatch.Success) {
                                    $Decoded = [Text.Encoding]::Unicode.GetString(
                                        [Convert]::FromBase64String($PayloadMatch.Groups[1].Value))
                                    $Skew = [math]::Abs((([datetime]$Target.CreationDate) - $SysmonStart).TotalSeconds)
                                    if ($Decoded.Contains('EDR_LAB_CONTAINMENT_V2_9') -and $Skew -le 10) {
                                        # Proceso: Stop-Process + verificacion posterior.
                                        Stop-Process -Id $TargetPid -Force -ErrorAction Stop
                                        Start-Sleep -Milliseconds 150
                                        $StillRunning = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction SilentlyContinue
                                        if ($null -eq $StillRunning -or
                                            [math]::Abs((([datetime]$StillRunning.CreationDate) - $SysmonStart).TotalSeconds) -gt 10) {
                                            $ContainmentResult = 'SUCCESS'
                                        } else { $ContainmentResult = 'FAILED' }
                                        # Firewall: persistir hasta rollback explicito; verificar filtros.
                                        $RuleId = 'EDR_LAB_V2_10_' + [guid]::NewGuid().ToString('N')
                                        try {
                                            New-NetFirewallRule -Name $RuleId -DisplayName $RuleId `
                                                -Direction Outbound -Action Block -Enabled True `
                                                -Profile Any -Program $ExpectedExe `
                                                -RemoteAddress '1.1.1.1' -Protocol TCP -RemotePort 853 `
                                                -ErrorAction Stop | Out-Null
                                            $Rule = Get-NetFirewallRule -Name $RuleId -ErrorAction Stop
                                            $AppFilter = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
                                            $AddrFilter = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
                                            $PortFilter = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
                                            if ($Rule.Action -eq 'Block' -and $Rule.Direction -eq 'Outbound' -and
                                                $Rule.Enabled -eq 'True' -and $AppFilter.Program -ieq $ExpectedExe -and
                                                $AddrFilter.RemoteAddress -contains '1.1.1.1' -and
                                                $PortFilter.RemotePort -contains '853' -and $PortFilter.Protocol -eq 'TCP') {
                                                $FirewallStatus = 'SUCCESS'
                                                $Event.MessageData.LabFirewallRules[$RuleId] = $true
                                                # Registrar de inmediato, para permitir rollback tras una caida.
                                                $Entry = @{ Kind='Firewall'; RuleId=$RuleId; ProcessGuid=$GuidValue;
                                                    CreatedAt=(Get-Date).ToString('o'); Status='APPLIED' } | ConvertTo-Json -Compress
                                                Add-Content -LiteralPath $Event.MessageData.LedgerPath -Value $Entry -Encoding UTF8
                                            } else {
                                                $FirewallStatus = 'FAILED'
                                                Remove-NetFirewallRule -Name $RuleId -ErrorAction SilentlyContinue
                                            }
                                        } catch {
                                            $FirewallStatus = 'FAILED'
                                            Remove-NetFirewallRule -Name $RuleId -ErrorAction SilentlyContinue
                                            $ResponseLine += (' FirewallError=' + ($_.Exception.Message -replace '\s+', '_'))
                                        }
                                        # Archivo: mover sin sobrescribir y verificar origen/destino.
                                        try {
                                            $QDir = [string]$Event.MessageData.QuarantineDir
                                            if (-not (Test-Path -LiteralPath $QDir)) {
                                                New-Item -ItemType Directory -Path $QDir -Force | Out-Null
                                            }
                                            $QPath = Join-Path $QDir $FileName
                                            if (Test-Path -LiteralPath $QPath) { throw 'Destino de cuarentena ya existe' }
                                            Move-Item -LiteralPath $FileFull -Destination $QPath -ErrorAction Stop
                                            if ((Test-Path -LiteralPath $QPath -PathType Leaf) -and
                                                -not (Test-Path -LiteralPath $FileFull)) {
                                                $QuarantineStatus = 'SUCCESS'
                                                $Entry = @{ Kind='File'; OriginalPath=$FileFull; QuarantinePath=$QPath;
                                                    ProcessGuid=$GuidValue; CreatedAt=(Get-Date).ToString('o'); Status='APPLIED' } | ConvertTo-Json -Compress
                                                Add-Content -LiteralPath $Event.MessageData.LedgerPath -Value $Entry -Encoding UTF8
                                                $ResponseLine += " QuarantinePath=$QPath OriginalPath=$FileFull"
                                            } else { $QuarantineStatus = 'FAILED' }
                                        } catch {
                                            $QuarantineStatus = 'FAILED'
                                            $ResponseLine += (' QuarantineError=' + ($_.Exception.Message -replace '\s+', '_'))
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        $ContainmentResult = 'FAILED'
                        $ResponseLine += (' ContainmentError=' + ($_.Exception.Message -replace '\s+', '_'))
                    }
                    $ResponseLine += " Firewall=$FirewallStatus Quarantine=$QuarantineStatus Containment=$ContainmentResult"
                }
            }
            Add-Content -LiteralPath $Event.MessageData.ResponseLog `
                -Value $ResponseLine -Encoding UTF8

        }
        else {

            $NormalMessage = "[$EventTime] ID:$EventID | Regla:$RuleName | $Details"

            Add-Content -LiteralPath $Event.MessageData.NormalLog `
                -Value $NormalMessage -Encoding UTF8

        }

    }
    catch {

        $ErrorMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $($_.Exception.ToString())"

        try {

            Add-Content -LiteralPath $Event.MessageData.ErrorLog `
                -Value $ErrorMessage -Encoding UTF8

        }
        catch {

            Write-Error $ErrorMessage

        }

    }
    finally {

        if ($null -ne $Record) {
            $Record.Dispose()
        }

    }

}

# ------------------------------------------------------------
# 7. REGISTRAR EVENT WATCHER
# ------------------------------------------------------------

try {

    $Subscription = Register-ObjectEvent `
        -InputObject $Watcher `
        -EventName EventRecordWritten `
        -SourceIdentifier $JobName `
        -MessageData $MessageData `
        -Action $Action `
        -ErrorAction Stop

    $Watcher.Enabled = $true

}
catch {

    Write-Host "[-] Error registrando el observador:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    $Watcher.Dispose()
    exit 1

}

# ------------------------------------------------------------
# 8. MONITOR EN TIEMPO REAL
# ------------------------------------------------------------

Write-Host ""
Write-Host "[+] Sysmon conectado correctamente." -ForegroundColor Green
Write-Host "[+] Event ID: 1, 3, 10, 11" -ForegroundColor Green
Write-Host "[+] Monitor escuchando eventos..." -ForegroundColor Green
Write-Host ""
Write-Host "[LOGS]" -ForegroundColor Cyan
Write-Host "Alertas   : $Global:EdrLogFile"
Write-Host "Normal    : $Global:NormalLogFile"
Write-Host "Errores   : $Global:ErrorLogFile"
Write-Host "Respuesta : $Global:ResponseLogFile ($(if ($ActiveContainment) { 'Active - SOLO LAB' } else { 'DryRun' }))"
Write-Host ""
Write-Host "[+] Pulsa Q para detener el monitor." -ForegroundColor Yellow

try {

    while ($true) {

        if ([Console]::KeyAvailable) {

            $Key = [Console]::ReadKey($true)

            if ($Key.Key -eq [ConsoleKey]::Q) {
                break
            }

        }

        Start-Sleep -Milliseconds 200

    }

}
finally {

    Write-Host ""
    Write-Host "[-] Deteniendo EDR..." -ForegroundColor Yellow

    $Watcher.Enabled = $false

    Unregister-Event -SourceIdentifier $JobName `
        -ErrorAction SilentlyContinue

    if ($Subscription) {
        Remove-Job -Job $Subscription -Force `
            -ErrorAction SilentlyContinue
    }

    $Watcher.Dispose()
    # Las reglas persisten hasta ejecutar rollback-lab.ps1 de forma explicita.

    Write-Host "[+] Monitor detenido." -ForegroundColor Green

}
