function Extract-CreoThumbnail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path
    )

    process {
        foreach ($p in $Path) {
            $resolved = Resolve-Path -Path $p -ErrorAction Stop
            foreach ($item in $resolved) {
                $File = $item.Path
                $baseName = [IO.Path]::GetFileName($File)
                $Out  = Join-Path (Split-Path $File) ("{0}_thumbnail.jpg" -f $baseName)

                $Bytes = [System.IO.File]::ReadAllBytes($File)
                $TagBytes = [System.Text.Encoding]::ASCII.GetBytes('THMB_IMG_MAIN')

                $TagOffset = -1
                for ($i = 0; $i -le $Bytes.Length - $TagBytes.Length; $i++) {
                    $match = $true
                    for ($j = 0; $j -lt $TagBytes.Length; $j++) {
                        if ($Bytes[$i + $j] -ne $TagBytes[$j]) { $match = $false; break }
                    }
                    if ($match) { $TagOffset = $i; break }
                }
                if ($TagOffset -lt 0) {
                    throw "THMB_IMG_MAIN tag not found in $File"
                }

                $JpegStart = -1
                for ($i = $TagOffset + $TagBytes.Length; $i -lt [Math]::Min($TagOffset + 32, $Bytes.Length - 1); $i++) {
                    if ($Bytes[$i] -eq 0xFF -and $Bytes[$i + 1] -eq 0xD8) {
                        $JpegStart = $i
                        break
                    }
                }
                if ($JpegStart -lt 0) {
                    throw "JPEG SOI FF D8 not found after THMB_IMG_MAIN in $File"
                }

                $JpegEnd = -1
                for ($i = $JpegStart + 2; $i -lt $Bytes.Length - 1; $i++) {
                    if ($Bytes[$i] -eq 0xFF -and $Bytes[$i + 1] -eq 0xD9) {
                        $JpegEnd = $i + 1
                        break
                    }
                }
                if ($JpegEnd -lt 0) {
                    throw "JPEG EOI FF D9 not found in $File"
                }

                $Length = $JpegEnd - $JpegStart + 1
                $Jpeg = New-Object byte[] $Length
                [Array]::Copy($Bytes, $JpegStart, $Jpeg, 0, $Length)
                [System.IO.File]::WriteAllBytes($Out, $Jpeg)

                [PSCustomObject]@{
                    File      = $File
                    Output    = $Out
                    TagOffset = ('0x{0:X}' -f $TagOffset)
                    JpegStart = ('0x{0:X}' -f $JpegStart)
                    JpegEnd   = ('0x{0:X}' -f $JpegEnd)
                    Length    = $Length
                }
            }
        }
    }
}
