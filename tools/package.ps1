# Makes the release zip: the app files (what Hallow Remote serves) plus README - dist\Hallow.Authenticator.zip
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot; $dist = Join-Path $root 'dist'; $stg = Join-Path $dist 'Hallow Authenticator'
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force "$stg\app" | Out-Null
Copy-Item "$root\app\*" "$stg\app"; Copy-Item "$root\README.md" $stg
Compress-Archive -Path $stg -DestinationPath "$dist\Hallow.Authenticator.zip"; Remove-Item $stg -Recurse -Force
"zip: $dist\Hallow.Authenticator.zip  sha256 " + (Get-FileHash "$dist\Hallow.Authenticator.zip").Hash.ToLower()
