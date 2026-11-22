# Copies the app into Hallow Remote's source (src\web\auth), which embeds it in HallowRemote.exe. Run after changing the app, then build Remote.
param([string]$Remote = (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'HallowRemote'))
$ErrorActionPreference = 'Stop'
$src = Join-Path (Split-Path $PSScriptRoot) 'app'; $dst = Join-Path $Remote 'src\web\auth'
New-Item -ItemType Directory -Force $dst | Out-Null
Get-ChildItem $dst -File | Where-Object Name -ne 'VERSION.txt' | Remove-Item
Copy-Item "$src\*" $dst
$v = ([regex]::Match((Get-Content "$src\sw.js" -Raw), "VERSION = '([0-9.]+)'")).Groups[1].Value
"copied Hallow Authenticator $v into $dst"
