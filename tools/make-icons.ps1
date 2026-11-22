# Draws the app icons (PNG) with System.Drawing - the Hallow style: a shield (orange -> lilac) with a countdown ring and a code.
# Run once after changing the art; the PNGs are committed. No downloads.
Add-Type -AssemblyName System.Drawing
$out = Join-Path (Split-Path $PSScriptRoot) 'app'
function RoundRect($x, $y, $w, $h, $r) { $p = New-Object Drawing.Drawing2D.GraphicsPath; $d = $r * 2; $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90); $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90); $p.CloseFigure(); $p }
function Icon([int]$n, [bool]$mask, [string]$file) {
    $bmp = New-Object Drawing.Bitmap $n, $n, ([Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([Drawing.Color]::Transparent)
    $s = $n / 256.0
    $bgr = if ($mask) { New-Object Drawing.RectangleF 0, 0, $n, $n } else { New-Object Drawing.RectangleF (8 * $s), (8 * $s), (240 * $s), (240 * $s) }
    $bg = New-Object Drawing.Drawing2D.LinearGradientBrush ([Drawing.PointF]::new(0, $bgr.Top)), ([Drawing.PointF]::new(0, $bgr.Bottom + 1)), ([Drawing.Color]::FromArgb(0x2a, 0x22, 0x38)), ([Drawing.Color]::FromArgb(0x16, 0x12, 0x1c))
    if ($mask) { $g.FillRectangle($bg, $bgr) } else { $p = RoundRect $bgr.X $bgr.Y $bgr.Width $bgr.Height (48 * $s); $g.FillPath($bg, $p) }
    $k = if ($mask) { 0.78 } else { 1.0 }
    function X([double]$v) { $n / 2.0 + ($v - 128) * $s * $k }
    # shield
    $sh = New-Object Drawing.Drawing2D.GraphicsPath
    $pts = @([Drawing.PointF]::new((X 128), (X 36)), [Drawing.PointF]::new((X 204), (X 64)), [Drawing.PointF]::new((X 200), (X 140)), [Drawing.PointF]::new((X 128), (X 222)), [Drawing.PointF]::new((X 56), (X 140)), [Drawing.PointF]::new((X 52), (X 64)))
    $sh.AddCurve($pts, 0.35); $sh.CloseFigure()
    $sr = $sh.GetBounds()
    $fill = New-Object Drawing.Drawing2D.LinearGradientBrush $sr, ([Drawing.Color]::FromArgb(0xff, 0x9a, 0x45)), ([Drawing.Color]::FromArgb(0xb4, 0x8b, 0xf0)), 60.0
    $g.FillPath($fill, $sh)
    # dark face with a ring
    $r = 56 * $s * $k; $cx = X 128; $cy = X 124
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(0x14, 0x10, 0x1b))), $cx - $r, $cy - $r, 2 * $r, 2 * $r)
    $rr = 42 * $s * $k
    $pen = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(0x3a, 0x32, 0x48)), (9 * $s * $k); $g.DrawEllipse($pen, $cx - $rr, $cy - $rr, 2 * $rr, 2 * $rr)
    $pen2 = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(0x6e, 0xd2, 0x8c)), (9 * $s * $k); $pen2.StartCap = 'Round'; $pen2.EndCap = 'Round'
    $g.DrawArc($pen2, $cx - $rr, $cy - $rr, 2 * $rr, 2 * $rr, -90, 250)
    # three code dots
    $dot = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(0xec, 0xe8, 0xf4)); $dr = 7 * $s * $k
    foreach ($i in -1, 0, 1) { $g.FillEllipse($dot, $cx + $i * 20 * $s * $k - $dr, $cy - $dr, 2 * $dr, 2 * $dr) }
    $g.Dispose(); $bmp.Save((Join-Path $out $file), [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
}
Icon 192 $false 'icon-192.png'; Icon 512 $false 'icon-512.png'; Icon 512 $true 'icon-mask-512.png'; Icon 180 $true 'apple-touch-icon.png'
'icons written to ' + $out
