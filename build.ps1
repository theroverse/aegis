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
$PyCmd = 'python'
$PyPre = @()
& python -c "import webview, PyInstaller" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    $PyCmd = 'py'
    $PyPre = @('-3.13')
    & py -3.13 -c "import webview" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pywebview ausente no py -3.13: rode os passos da Task 0 (pip install pywebview pythonnet pyinstaller)" }
    & $PyCmd ($PyPre + @('-m', 'pip', 'install', '--quiet', 'pyinstaller'))
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
$smokeOut = Join-Path $env:TEMP 'aegis_smoke_status.json'
if (Test-Path $smokeOut) { Remove-Item $smokeOut -Force }
$proc = Start-Process -FilePath $exe -ArgumentList '--cli', 'status' `
    -NoNewWindow -Wait -PassThru -RedirectStandardOutput $smokeOut
if ($proc.ExitCode -ne 0) { throw "Aegis.exe nao respondeu ao smoke de leitura (exit $($proc.ExitCode))" }
if (-not (Test-Path $smokeOut) -or (Get-Item $smokeOut).Length -eq 0) { throw "Aegis.exe nao imprimiu status no smoke" }
Get-Content $smokeOut
Write-Host "`nOK: dist\Aegis.exe + dist\AegisApply.exe" -ForegroundColor Green

