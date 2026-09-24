#Requires -Version 5.1
<#
    Compila Aegis.exe (GUI + motor) e AegisApply.exe (helper privilegiado
    pontual) com PyInstaller, um arquivo so cada um, em dist/.

    A filosofia nao muda: sem instalador, sem escrita fora da propria pasta.
    O Aegis.exe NUNCA roda elevado; quando o humano aplica uma regra, ele da
    Start-Process -Verb RunAs no AegisApply.exe IRMAO (resolucao em
    aegis.cli._resolver_helper). Copiar os dois exes juntos para qualquer
    pasta funciona.

    Roda direto da fonte continua valendo: python aegis.py (GUI) / aegis.py status (CLI).
    Uso:  .\build.ps1
#>
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$OutDir = Join-Path $Root 'dist'
$Work = Join-Path $Root '.build'
New-Item -ItemType Directory -Force -Path $OutDir, $Work | Out-Null

# Interpreter: o padrao do ambiente, com fallback pinado para 3.13 (mesma
# decisao da Task 0). PyInstaller NAO vai para o runtime; so para o build.
# Padrao de splatting limpo (PS 5.1): $PyCmd e o executavel, $PyPre os
# prefixos de argumento; cada chamada monta um array unico e faz & $PyCmd $args.
#
# Sob $ErrorActionPreference='Stop' uma chamada nativa que falha LANCA
# (CommandNotFoundException / NativeCommandError no stderr) ANTES de lermos
# $LASTEXITCODE, o que deixaria o fallback py -3.13 inalcanavel. Por isso a
# sonda e um helper: gate por Get-Command + try/catch com os fluxos mesclados
# (*>&1), lendo o codigo de saida real no caminho de sucesso. O EAP e rebaixado
# para 'Continue' so dentro da sonda, para ruido no stderr de um import bom nao
# fingir falha; o try/catch cobre comando ausente / erro terminante.
function Test-PyImport {
    param([string]$Exe, [string[]]$PreArgs = @(), [string]$Code)
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $false }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe ($PreArgs + @('-c', $Code)) *>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $prev
    }
}

$PyCmd = 'python'
$PyPre = @()
if (-not (Test-PyImport -Exe 'python' -Code 'import webview, PyInstaller')) {
    $PyCmd = 'py'
    $PyPre = @('-3.13')
    if (-not (Test-PyImport -Exe 'py' -PreArgs @('-3.13') -Code 'import webview')) {
        throw "pywebview ausente no py -3.13: rode os passos da Task 0 (pip install pywebview pythonnet pyinstaller)"
    }
    & $PyCmd ($PyPre + @('-m', 'pip', 'install', '--quiet', 'pyinstaller'))
    if ($LASTEXITCODE -ne 0) { throw "falha ao instalar pyinstaller no 3.13 (pip exit $LASTEXITCODE)" }
}

$icon = Join-Path $Root 'gui\Aegis.ico'
$iconArgs = @()
if (Test-Path $icon) { $iconArgs = @('--icon', $icon) }

Write-Host "`n[1/2] Aegis.exe (GUI + motor, sem console)" -ForegroundColor Cyan
$guiArgs = $PyPre + @(
    '-m', 'PyInstaller', '--noconfirm', '--clean',
    '--onefile', '--windowed', '--name', 'Aegis',
    '--distpath', $OutDir, '--workpath', $Work, '--specpath', $Work,
    '--paths', (Join-Path $Root 'src'), '--paths', (Join-Path $Root 'gui'),
    '--add-data', ((Join-Path $Root 'gui\web') + ';web'),
    '--collect-all', 'webview',
    '--collect-submodules', 'aegis',
    '--hidden-import', 'comtypes', '--hidden-import', 'comtypes.client', '--hidden-import', 'aegis_app'
) + $iconArgs + @((Join-Path $Root 'scripts\aegis_exe.py'))
& $PyCmd $guiArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou no Aegis.exe" }

Write-Host "`n[2/2] AegisApply.exe (helper elevado pontual, sem console)" -ForegroundColor Cyan
$applyArgs = $PyPre + @(
    '-m', 'PyInstaller', '--noconfirm', '--clean',
    '--onefile', '--windowed', '--name', 'AegisApply',
    '--distpath', $OutDir, '--workpath', $Work, '--specpath', $Work,
    '--paths', (Join-Path $Root 'src'),
    '--hidden-import', 'comtypes', '--hidden-import', 'comtypes.client'
) + $iconArgs + @((Join-Path $Root 'scripts\aegis_apply.py'))
& $PyCmd $applyArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou no AegisApply.exe" }

# Smoke do binario offline (nao toca o sistema): precisa dos fakes dentro do
# exe? NAO -- --offline e so para o fonte. No binario, validamos que ele abre
# e responde ao CLI de leitura; escrito fica para o E2E real da Task 8.
# O Aegis.exe e --windowed, entao o bootloader descarta stdout quando ele e um
# console interativo: redirectamos a saida para um arquivo (Start-Process) para
# PODER VER o JSON do status real e conferir o exit code. Leitura pura, sem UAC.
Write-Host "`nSmoke: dist\Aegis.exe --cli status (leitura real, sem elevacao)" -ForegroundColor Cyan
$exe = Join-Path $OutDir 'Aegis.exe'
$smokeOut = Join-Path $env:TEMP "aegis_smoke_$PID.json"
if (Test-Path $smokeOut) { Remove-Item $smokeOut -Force }
# Start-Process -Wait nao aceita teto de tempo; PassThru + WaitForExit(ms) da o
# timeout de seguranca e so DEPOIS lemos ExitCode. Nome com $PID evita
# choque/lixo entre execucoes concorrentes.
#
# Nuance PS 5.1: sem -Wait, o Process de -PassThru so popula .ExitCode se
# EnableRaisingEvents ligar ANTES do termino (sem isso .ExitCode e $null e
# `$null -ne 0` da False -- a assercao de exit code viraria decorativa). Por
# isso ligamos na sequencia e guardamos contra $null explicito.
$p = Start-Process -FilePath $exe -ArgumentList '--cli', 'status' `
    -NoNewWindow -PassThru -RedirectStandardOutput $smokeOut
$p.EnableRaisingEvents = $true
if (-not $p.WaitForExit(120000)) { $p.Kill(); throw "smoke do Aegis.exe excedeu 120s" }
if ($null -eq $p.ExitCode) { throw "smoke do Aegis.exe sem ExitCode legivel" }
if ($p.ExitCode -ne 0) { throw "Aegis.exe nao respondeu ao smoke de leitura (exit $($p.ExitCode))" }
if (-not (Test-Path $smokeOut) -or (Get-Item $smokeOut).Length -eq 0) { throw "Aegis.exe nao imprimiu status no smoke" }
Get-Content $smokeOut
Remove-Item $smokeOut -ErrorAction SilentlyContinue
Write-Host "`nOK: dist\Aegis.exe + dist\AegisApply.exe" -ForegroundColor Green

