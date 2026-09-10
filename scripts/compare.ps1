param(
    [string]$OriginalRoot = 'C:\Users\11277\Downloads\ASC',
    [string]$Apk = 'C:\Users\11277\Downloads\教程demo(更新).apk',
    [int]$Runs = 7
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv-asc-original312\Scripts\python.exe'
$original = Join-Path $OriginalRoot 'main.py'
$rust = Join-Path $projectRoot 'target\release\asc-rs.exe'

foreach ($path in @($python, $original, $rust, $Apk)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing benchmark input: $path"
    }
}

$cases = @(
    @{ Name = 'getclass'; Args = @('getclass', $Apk, 'com.zj.wuaipojie.ui.MainActivity') },
    @{ Name = 'string'; Args = @('findrefs', $Apk, 'string', 'FIRST_START') },
    @{ Name = 'type'; Args = @('findrefs', $Apk, 'type', 'Lcom/zj/wuaipojie/util/SPUtils;') },
    @{ Name = 'method'; Args = @('findrefs', $Apk, 'method', 'saveString', '--class', 'com.zj.wuaipojie.util.SPUtils') },
    @{ Name = 'field'; Args = @('findrefs', $Apk, 'field', 'INSTANCE', '--class', 'com.zj.wuaipojie.util.SPUtils') }
)

function Measure-Original([string[]]$Arguments) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    & $python $original @Arguments *> $null
    $timer.Stop()
    if ($LASTEXITCODE -ne 0) { throw "Original ASC failed with $LASTEXITCODE" }
    $timer.Elapsed.TotalMilliseconds
}

function Measure-Rust([string[]]$Arguments) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    & $rust @Arguments *> $null
    $timer.Stop()
    if ($LASTEXITCODE -ne 0) { throw "ASC-RS failed with $LASTEXITCODE" }
    $timer.Elapsed.TotalMilliseconds
}

foreach ($case in $cases) {
    $null = Measure-Original $case.Args
    $null = Measure-Rust $case.Args
    $originalTimes = @()
    $rustTimes = @()
    for ($index = 1; $index -le $Runs; $index++) {
        if ($index % 2) {
            $rustTimes += Measure-Rust $case.Args
            $originalTimes += Measure-Original $case.Args
        } else {
            $originalTimes += Measure-Original $case.Args
            $rustTimes += Measure-Rust $case.Args
        }
    }
    $originalSorted = @($originalTimes | Sort-Object)
    $rustSorted = @($rustTimes | Sort-Object)
    $middle = [math]::Floor($Runs / 2)
    [pscustomobject]@{
        Case = $case.Name
        OriginalMedianMs = [math]::Round($originalSorted[$middle], 3)
        RustMedianMs = [math]::Round($rustSorted[$middle], 3)
        Speedup = [math]::Round($originalSorted[$middle] / $rustSorted[$middle], 2)
        OriginalRangeMs = '{0:N3}-{1:N3}' -f $originalSorted[0], $originalSorted[-1]
        RustRangeMs = '{0:N3}-{1:N3}' -f $rustSorted[0], $rustSorted[-1]
    }
}
