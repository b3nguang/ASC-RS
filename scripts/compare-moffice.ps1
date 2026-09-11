param(
    [string]$OriginalRoot = 'C:\Users\11277\Downloads\ASC',
    [string]$Apk = 'C:\Users\11277\Downloads\moffice_26.9.0_0x0804_cn00563_multidex_64_0c8b155ab49.apk',
    [int]$Runs = 5,
    [string]$CaseFilter = '*'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv-asc-original312\Scripts\python.exe'
$original = Join-Path $OriginalRoot 'main.py'
$rust = Join-Path $projectRoot 'target\release\asc-rs.exe'
$jadx = (Get-Command jadx -ErrorAction Stop).Source

$cases = @(
    @{
        Name = 'first DEX class'
        Operation = 'getclass'
        Class = 'cn.wps.sdk.fcsync.Fcsync'
        Tools = @('ASC-RS', 'Original ASC')
        JadxOutput = Join-Path $projectRoot 'target\jadx-single-moffice-first.java'
    },
    @{
        Name = 'launcher in classes25.dex'
        Operation = 'getclass'
        Class = 'cn.wps.moffice.documentmanager.PreStartActivity'
        Tools = @('ASC-RS', 'Original ASC', 'JADX single-class')
        JadxOutput = Join-Path $projectRoot 'target\jadx-single-moffice-launcher.java'
    },
    @{
        Name = 'type reference search'
        Operation = 'findrefs-type'
        Query = 'PreStartActivity'
        Tools = @('ASC-RS', 'Original ASC')
    }
)
$cases = @($cases | Where-Object { $_.Name -like $CaseFilter })

foreach ($path in @($python, $original, $rust, $Apk)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing benchmark input: $path"
    }
}
if ($Runs -lt 3 -or $Runs % 2 -eq 0) {
    throw 'Runs must be an odd integer of at least 3.'
}
if ($cases.Count -eq 0) {
    throw "No benchmark case matches: $CaseFilter"
}

function Measure-One([string]$tool, [hashtable]$case) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    switch ($tool) {
        'ASC-RS' {
            if ($case.Operation -eq 'getclass') {
                & $rust getclass --engine builtin --threads 8 $Apk $case.Class *> $null
            } else {
                & $rust findrefs --threads 8 $Apk type $case.Query *> $null
            }
        }
        'Original ASC' {
            if ($case.Operation -eq 'getclass') {
                & $python $original getclass --threads 8 $Apk $case.Class *> $null
            } else {
                & $python $original findrefs --threads 8 $Apk type $case.Query *> $null
            }
        }
        'JADX single-class' {
            & $jadx --no-res --threads-count 8 --single-class $case.Class `
                --single-class-output $case.JadxOutput --log-level quiet $Apk *> $null
        }
        default { throw "Unknown tool: $tool" }
    }
    $exitCode = $LASTEXITCODE
    $timer.Stop()
    if ($exitCode -ne 0) {
        throw "$tool failed for $($case.Name) with exit code $exitCode"
    }
    $timer.Elapsed.TotalMilliseconds
}

function Summarize([double[]]$values) {
    $sorted = @($values | Sort-Object)
    $middle = [math]::Floor($sorted.Count / 2)
    @{
        Median = $sorted[$middle]
        Min = $sorted[0]
        Max = $sorted[-1]
    }
}

$results = @()
foreach ($case in $cases) {
    Write-Output "Warming $($case.Name)..."
    foreach ($tool in $case.Tools) {
        $null = Measure-One $tool $case
    }

    $times = @{}
    foreach ($tool in $case.Tools) { $times[$tool] = @() }
    for ($run = 0; $run -lt $Runs; $run++) {
        $offset = $run % $case.Tools.Count
        $order = @($case.Tools[$offset..($case.Tools.Count - 1)])
        if ($offset -gt 0) { $order += @($case.Tools[0..($offset - 1)]) }
        foreach ($tool in $order) {
            $elapsed = Measure-One $tool $case
            $times[$tool] += $elapsed
            Write-Output ('{0} run {1}/{2}: {3} = {4:F3} ms' -f `
                $case.Name, ($run + 1), $Runs, $tool, $elapsed)
        }
    }

    foreach ($tool in $case.Tools) {
        $summary = Summarize $times[$tool]
        $results += [pscustomobject]@{
            Sample = $case.Name
            Target = if ($case.Operation -eq 'getclass') { $case.Class } else { $case.Query }
            Tool = $tool
            MedianMs = [math]::Round($summary.Median, 3)
            MinMs = [math]::Round($summary.Min, 3)
            MaxMs = [math]::Round($summary.Max, 3)
            Runs = $Runs
            AllMs = (($times[$tool] | ForEach-Object { '{0:F3}' -f $_ }) -join ',')
        }
    }
}

'---RESULTS---'
$results | Format-Table -AutoSize
'---JSON---'
$results | ConvertTo-Json -Depth 3
