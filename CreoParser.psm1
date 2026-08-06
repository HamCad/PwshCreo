function Get-DataMapStrings {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    $sb = New-Object System.Text.StringBuilder
    $tokens = New-Object System.Collections.Generic.List[string]

    foreach ($b in $Bytes) {
        if ($b -ge 32 -and $b -le 126) {
            [void]$sb.Append([char]$b)
        }
        else {
            if ($sb.Length -ge 4) {
                $tokens.Add($sb.ToString())
            }
            $sb.Clear() | Out-Null
        }
    }

    if ($sb.Length -ge 4) {
        $tokens.Add($sb.ToString())
    }

    return $tokens | Where-Object {
        $_ -match '^[a-zA-Z_][a-zA-Z0-9_#]+$' -and $_.Length -gt 3
    }
}

function Get-CreoDataMaps {
    param(
        [Parameter(Mandatory)]
        [string]$File
    )

    if (-not (Test-Path $File)) {
        throw "File not found: $File"
    }

    [byte[]]$Bytes = [System.IO.File]::ReadAllBytes(
        (Resolve-Path $File)
    )

    Write-Host "Loaded $($Bytes.Length) bytes"

    $strings = Get-PrintableStrings -Data $Bytes -MinLen 6

    $parsed = Parse-TocEntries `
        -Strings $strings `
        -MinFields 8

    Write-Host "TOC entries: $($parsed.Entries.Count)"

    $rows = Resolve-StreamRanges `
        -Entries $parsed.Entries `
        -Data $Bytes


    foreach ($row in $rows) {

        if (-not $row.OverheadMatches) {
            continue
        }

        $start = $row.PayloadStart
        $length = $row.PayloadLength

        if (($start + $length) -gt $Bytes.Length) {
            continue
        }

        $payload = $Bytes[$start..($start + $length - 1)]

        $maps = Get-DataMapStrings -Bytes $payload

        if ($maps.Count -gt 0) {

            [PSCustomObject]@{
                Stream = $row.Name
                Offset = $row.PayloadStartHex
                Size   = $row.PayloadLength
                Maps   = $maps
            }
        }
    }
}


# =========================================================================
# FUNCTION: Get-PrintableStrings
#   Extracts runs of printable ASCII with their file offsets. Same approach
#   as the marker analyzer - a run ends at any byte outside 0x20-0x7E (and
#   tab), which is what turns each fixed-width TOC record into its own
#   string (the record delimiter, e.g. \n, is non-printable).
# =========================================================================
function Get-PrintableStrings {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [int]$MinLen = 6
    )

    $results = New-Object System.Collections.Generic.List[object]
    $sb = New-Object System.Text.StringBuilder
    $startOffset = -1

    for ($i = 0; $i -lt $Data.Length; $i++) {
        $b = $Data[$i]
        if (($b -ge 0x20 -and $b -le 0x7E) -or $b -eq 0x09) {
            if ($startOffset -lt 0) { $startOffset = $i }
            [void]$sb.Append([char]$b)
        }
        else {
            if ($sb.Length -ge $MinLen) {
                $results.Add([PSCustomObject]@{ Offset = $startOffset; Value = $sb.ToString() })
            }
            $sb.Clear() | Out-Null
            $startOffset = -1
        }
    }
    if ($sb.Length -ge $MinLen) {
        $results.Add([PSCustomObject]@{ Offset = $startOffset; Value = $sb.ToString() })
    }
    return $results
}

# =========================================================================
# FUNCTION: Parse-TocEntries
#   Classifies each extracted string as: TOC record, TOC page header,
#   ND echo tag, end-of-UGC marker, or "other" (ignored for TOC purposes).
# =========================================================================
function Parse-TocEntries {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Strings,
        [int]$MinFields = 8
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $pages   = New-Object System.Collections.Generic.List[object]
    $echoes  = New-Object System.Collections.Generic.List[object]
    $endMarkers = New-Object System.Collections.Generic.List[object]

    # Trailing '#' padding is stripped before tokenizing.
    foreach ($s in $Strings) {
        $val = $s.Value.TrimEnd('#').TrimEnd()

        if ($val -match '^#UGC_TOC\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)') {
            $pages.Add([PSCustomObject]@{
                Offset = $s.Offset
                Field1 = $matches[1]; Field2 = $matches[2]
                Field3 = $matches[3]; Field4 = $matches[4]
                Raw    = $val
            })
            continue
        }

        if ($val -match '^#END_OF_UGC') {
            $endMarkers.Add([PSCustomObject]@{ Offset = $s.Offset; Raw = $val })
            continue
        }

        if ($val -match '^#ND:(\d+):(.+):(-?\d+)$') {
            $echoes.Add([PSCustomObject]@{
                Offset  = $s.Offset
                NdIndex = $matches[1]
                Name    = $matches[2]
                Tail    = $matches[3]
                Raw     = $val
            })
            continue
        }

        # Skip the plaintext UGC header block lines (#UGC:, #- VERS, #- HOST, etc.)
        if ($val -match '^#') { continue }

        # TOC record grammar: Name field1 field2 ... fieldN (all remaining fields
        # hex/numeric-looking; Name itself must not contain whitespace)
        $tokens = $val -split '\s+'
        if ($tokens.Count -lt ($MinFields + 1)) { continue }

        $name = $tokens[0]
        $fields = $tokens[1..($tokens.Count - 1)]

        # Every field after the name must look like hex/decimal (optionally signed)
        $allNumeric = $true
        foreach ($f in $fields) {
            if ($f -notmatch '^-?[0-9a-fA-F]+$') { $allNumeric = $false; break }
        }
        if (-not $allNumeric) { continue }
        if ($name -notmatch '^[A-Za-z_#][A-Za-z0-9_#:\-]*$') { continue }
        if ($fields.Count -lt $MinFields) { continue }

        function _Hex($t) {
            try { return [Convert]::ToInt64($t, 16) } catch { return $null }
        }

        $entries.Add([PSCustomObject]@{
            RecordOffset = $s.Offset          # where this TOC text record lives in the file
            Name         = $name
            OffsetHex    = $fields[0]
            OffsetVal    = _Hex $fields[0]
            Size1Hex     = $fields[1]
            Size1Val     = _Hex $fields[1]
            Size2Hex     = $fields[2]
            Size2Val     = _Hex $fields[2]
            ClassId      = $fields[3]
            Val5         = $fields[4]
            Sign6        = $fields[5]
            Hash1        = $fields[6]
            Hash2        = $fields[7]
            Raw          = $val
        })
    }

    [PSCustomObject]@{
        Entries     = $entries
        Pages       = $pages
        EchoTags    = $echoes
        EndMarkers  = $endMarkers
    }
}

# =========================================================================
# FUNCTION: Get-Entropy  (small helper reused for stream previews)
# =========================================================================
function Get-Entropy {
    param([Parameter(Mandatory)][byte[]]$Data)
    if ($Data.Length -eq 0) { return 0.0 }
    $freq = New-Object 'int[]' 256
    foreach ($b in $Data) { $freq[$b]++ }
    $ent = 0.0
    foreach ($c in $freq) {
        if ($c -gt 0) {
            $p = $c / [double]$Data.Length
            $ent -= $p * [Math]::Log($p, 2)
        }
    }
    return [Math]::Round($ent, 3)
}

# =========================================================================
# FUNCTION: Format-HexWindow  (same as marker analyzer, kept local/standalone)
# =========================================================================
function Format-HexWindow {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$StartOffset,
        [int]$Length = 64
    )
    if ($StartOffset -lt 0 -or $StartOffset -ge $Data.Length) { return "  (offset out of file bounds)`r`n" }
    $end = [Math]::Min($StartOffset + $Length, $Data.Length) - 1
    $sb = New-Object System.Text.StringBuilder
    for ($row = $StartOffset; $row -le $end; $row += 16) {
        $rowEnd = [Math]::Min($row + 15, $end)
        $hexParts = New-Object System.Collections.Generic.List[string]
        $asciiParts = New-Object System.Text.StringBuilder
        for ($i = $row; $i -le $rowEnd; $i++) {
            $b = $Data[$i]
            [void]$hexParts.Add('{0:X2}' -f $b)
            if ($b -ge 0x20 -and $b -le 0x7E) { [void]$asciiParts.Append([char]$b) } else { [void]$asciiParts.Append('.') }
        }
        $hexStr = ($hexParts -join ' ').PadRight(16 * 3)
        [void]$sb.AppendLine(('{0:X8}  {1} {2}' -f $row, $hexStr, $asciiParts.ToString()))
    }
    return $sb.ToString()
}

# =========================================================================
# FUNCTION: Resolve-StreamRanges
#   Sorts entries by resolved OffsetVal, computes per-entry entropy of the
#   resolved [Offset, Offset+Size1) range (clamped to file bounds), and
#   flags gaps / overlaps between consecutive resolved ranges.
# =========================================================================
function Resolve-StreamRanges {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Entries,
        [Parameter(Mandatory)][byte[]]$Data
    )

    $valid = $Entries | Where-Object { $_.OffsetVal -ne $null -and $_.OffsetVal -ge 0 -and $_.OffsetVal -lt $Data.Length }
    $sorted = $valid | Sort-Object -Property OffsetVal

    $prevEnd = $null
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in $sorted) {
        $len = if ($e.Size1Val -and $e.Size1Val -gt 0) { $e.Size1Val } else { 0 }
        $endOff = $e.OffsetVal + $len
        $clampedEnd = [Math]::Min($endOff, $Data.Length)
        $sliceLen = [Math]::Max(0, $clampedEnd - $e.OffsetVal)
        $entropy = if ($sliceLen -gt 0) { Get-Entropy -Data $Data[$e.OffsetVal..($e.OffsetVal + $sliceLen - 1)] } else { 0.0 }

        $gapFromPrev = if ($prevEnd -ne $null) { $e.OffsetVal - $prevEnd } else { $null }

        # PayloadStart/PayloadLength: empirically, Size1 - Size2 == len(Name) + 2
        # across ~90 streams with zero exceptions (the "#ND:0:<Name>:<n>"-style
        # echo/tag header that precedes the real payload). This lets us strip
        # that header mechanically, no format-specific hardcoding required.
        # >>> MODIFY HERE if you find a stream where this formula breaks - the
        #     fallback below just uses OffsetVal/Size1 unsplit. <<<
        $expectedOverhead = $e.Name.Length + 2
        $actualOverhead   = $len - $e.Size2Val
        $overheadMatches  = ($e.Size2Val -gt 0) -and ($actualOverhead -eq $expectedOverhead)
        $payloadStart     = if ($overheadMatches) { $e.OffsetVal + $actualOverhead } else { $e.OffsetVal }
        $payloadLength    = if ($overheadMatches) { $e.Size2Val } else { $len }

        $rows.Add([PSCustomObject]@{
            Name             = $e.Name
            OffsetHex        = ('0x{0:X8}' -f $e.OffsetVal)
            OffsetVal        = $e.OffsetVal
            Size1            = $len
            Size2            = $e.Size2Val
            ClassId          = $e.ClassId
            Hash1            = $e.Hash1
            Hash2            = $e.Hash2
            EndOffset        = $endOff
            Entropy          = $entropy
            GapFromPrev      = $gapFromPrev
            RecordOffset     = ('0x{0:X8}' -f $e.RecordOffset)
            OverheadMatches  = $overheadMatches
            HeaderLength     = $actualOverhead
            PayloadStart     = $payloadStart
            PayloadStartHex  = ('0x{0:X8}' -f $payloadStart)
            PayloadLength    = $payloadLength
        })
        $prevEnd = [Math]::Max($prevEnd, $endOff)
    }
    return $rows
}

function Search-CreoBinaryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [int]$A = 0,

        [int]$B = 0,

        [int]$C = 0,

        [switch]$CaseSensitive,

        [switch]$Context
    )

    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $File)) {
        throw "File not found: $File"
    }


    [byte[]]$Data = [System.IO.File]::ReadAllBytes(
        (Resolve-Path $File)
    )


    #
    # Resolve UGC streams
    #
    $strings = Get-PrintableStrings -Data $Data -MinLen 6

    $parsed = Parse-TocEntries `
        -Strings $strings `
        -MinFields 8

    $streams = Resolve-StreamRanges `
        -Entries $parsed.Entries `
        -Data $Data


    if ($B -gt 0) {
        $A = $B
        $C = $B
    }


    function Convert-BytesToHex {
        param([byte[]]$Bytes)

        if (-not $Bytes -or $Bytes.Length -eq 0) {
            return ""
        }

        return (($Bytes | ForEach-Object {
            '{0:X2}' -f $_
        }) -join ' ')
    }


    function Convert-BytesToAscii {
        param([byte[]]$Bytes)

        if (-not $Bytes -or $Bytes.Length -eq 0) {
            return ""
        }

        return (($Bytes | ForEach-Object {
            if ($_ -ge 32 -and $_ -le 126) {
                [char]$_
            }
            else {
                '.'
            }
        }) -join '')
    }


    $needle = [System.Text.Encoding]::ASCII.GetBytes($Pattern)


    foreach ($stream in $streams) {

        if ($stream.PayloadLength -le 0) {
            continue
        }


        $start = $stream.PayloadStart
        $length = $stream.PayloadLength


        if (($start + $length) -gt $Data.Length) {
            continue
        }


        [byte[]]$payload = $Data[
            $start..($start + $length - 1)
        ]


        for ($i = 0; $i -le ($payload.Length - $needle.Length); $i++) {

            $found = $true


            for ($j = 0; $j -lt $needle.Length; $j++) {

                $aByte = $payload[$i + $j]
                $bByte = $needle[$j]


                if (-not $CaseSensitive) {

                    if ($aByte -ge 65 -and $aByte -le 90) {
                        $aByte += 32
                    }

                    if ($bByte -ge 65 -and $bByte -le 90) {
                        $bByte += 32
                    }
                }


                if ($aByte -ne $bByte) {
                    $found = $false
                    break
                }
            }


            if (-not $found) {
                continue
            }


            $absolute = $start + $i


            #
            # Simple output mode
            #
            if (($A -eq 0) -and ($B -eq 0) -and ($C -eq 0) -and (-not $Context)) {

                [PSCustomObject]@{
                    Block  = $stream.Name
                    Offset = ('0x{0:X8}' -f $absolute)
                }

                continue
            }


            #
            # Context window
            #
            $beforeStart = [Math]::Max(
                0,
                $i - $A
            )

            $beforeLength = $i - $beforeStart


            $afterStart = $i + $needle.Length

            $afterLength = [Math]::Min(
                $C,
                $payload.Length - $afterStart
            )


            [byte[]]$before = @()

            if ($beforeLength -gt 0) {
                $before = $payload[
                    $beforeStart..($i-1)
                ]
            }


            [byte[]]$matchBytes = $payload[
                $i..($i+$needle.Length-1)
            ]


            [byte[]]$after = @()

            if ($afterLength -gt 0) {
                $after = $payload[
                    $afterStart..($afterStart+$afterLength-1)
                ]
            }


            [byte[]]$window = @(
                $before
                $matchBytes
                $after
            )


            [PSCustomObject]@{
                Block          = $stream.Name
                Type           = "Payload"
                Offset         = ('0x{0:X8}' -f $absolute)
                RelativeOffset = ('0x{0:X8}' -f $i)

                BeforeBytes    = $before.Length
                AfterBytes     = $after.Length

                Entropy        = Get-Entropy -Data $window

                BeforeHex      = Convert-BytesToHex $before
                MatchHex       = Convert-BytesToHex $matchBytes
                AfterHex       = Convert-BytesToHex $after

                ASCII          = Convert-BytesToAscii $window
            }
        }
    }
}


# =========================================================================
# ---------------------------------------------------------------------
#  STATISTICAL FILE STRUCTURE DISCOVERY (phase 2)
#
#  Everything below builds on Get-PrintableStrings / Parse-TocEntries /
#  Resolve-StreamRanges above. Nothing here assigns meaning to a byte or
#  byte sequence - these cmdlets only count, measure spacing, and compute
#  entropy so that recurring structural patterns can be spotted empirically
#  before anyone commits to "this byte means X".
# ---------------------------------------------------------------------
# =========================================================================

# Candidate markers called out in the handoff doc. Pass -Markers to any of
# the cmdlets below to override/extend this set - nothing is hard-coded
# into the analysis logic itself, this is just a convenient starting list.
$script:DefaultCreoMarkers = @(
    @{ Name = 'E1';     Bytes = [byte[]](0xE1) }
    @{ Name = 'E2';     Bytes = [byte[]](0xE2) }
    @{ Name = 'E3';     Bytes = [byte[]](0xE3) }
    @{ Name = 'E4';     Bytes = [byte[]](0xE4) }
    @{ Name = 'F6';     Bytes = [byte[]](0xF6) }
    @{ Name = 'FF';     Bytes = [byte[]](0xFF) }
    @{ Name = '00';     Bytes = [byte[]](0x00) }
    @{ Name = '80';     Bytes = [byte[]](0x80) }
    @{ Name = '80DB';   Bytes = [byte[]](0x80,0xDB) }
    @{ Name = '809D';   Bytes = [byte[]](0x80,0x9D) }
    @{ Name = 'F6F6E3'; Bytes = [byte[]](0xF6,0xF6,0xE3) }
)

# =========================================================================
# FUNCTION: ConvertTo-HexString / ConvertTo-AsciiString
#   Module-scope versions of the byte-formatting helpers (Search-CreoBinaryString
#   keeps its own private copies so it stays standalone; these are shared by
#   the new statistical cmdlets so the logic only lives in one place).
# =========================================================================
function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    return (($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
}

function ConvertTo-AsciiString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    return (($Bytes | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
    }) -join '')
}

# =========================================================================
# FUNCTION: Resolve-CreoFileStreams
#   Shared "load file -> resolve streams" step so every statistical cmdlet
#   below runs the exact same pipeline as Get-CreoDataMaps instead of each
#   re-implementing it slightly differently.
# =========================================================================
function Resolve-CreoFileStreams {
    param([Parameter(Mandatory)][string]$File)

    if (-not (Test-Path -LiteralPath $File)) {
        throw "File not found: $File"
    }

    [byte[]]$Data = [System.IO.File]::ReadAllBytes((Resolve-Path $File))
    $strings = Get-PrintableStrings -Data $Data -MinLen 6
    $parsed  = Parse-TocEntries -Strings $strings -MinFields 8
    $streams = Resolve-StreamRanges -Entries $parsed.Entries -Data $Data

    # Only streams whose payload range actually resolves inside the file
    # are useful for byte-level statistics.
    $usable = $streams | Where-Object {
        $_.PayloadLength -gt 0 -and ($_.PayloadStart + $_.PayloadLength) -le $Data.Length
    }

    [PSCustomObject]@{
        Data    = $Data
        Strings = $strings
        Parsed  = $parsed
        Streams = $usable
    }
}

# Private: every offset (relative to $Payload) where $Needle occurs.
function Find-BytePatternOffsets {
    param([byte[]]$Payload, [byte[]]$Needle)

    $offsets = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -le ($Payload.Length - $Needle.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Payload[$i + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { $offsets.Add($i) }
    }
    return $offsets
}

# =========================================================================
# FUNCTION: Get-CreoMarkerStatistics
#   For each candidate marker: total occurrences, how many distinct streams
#   it appears in, and average local entropy around each occurrence.
# =========================================================================
function Get-CreoMarkerStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [object[]]$Markers = $script:DefaultCreoMarkers,
        [int]$EntropyWindow = 16
    )

    $resolved = Resolve-CreoFileStreams -File $File
    $Data = $resolved.Data
    $streams = $resolved.Streams

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($m in $Markers) {
        $needle = [byte[]]$m.Bytes
        $totalCount = 0
        $distinctStreams = New-Object System.Collections.Generic.HashSet[string]
        $entropies = New-Object System.Collections.Generic.List[double]

        foreach ($stream in $streams) {
            [byte[]]$payload = $Data[$stream.PayloadStart..($stream.PayloadStart + $stream.PayloadLength - 1)]
            $offsets = Find-BytePatternOffsets -Payload $payload -Needle $needle

            foreach ($off in $offsets) {
                $totalCount++
                [void]$distinctStreams.Add($stream.Name)

                $wStart = [Math]::Max(0, $off - $EntropyWindow)
                $wEnd = [Math]::Min($payload.Length - 1, $off + $needle.Length - 1 + $EntropyWindow)
                if ($wEnd -ge $wStart) {
                    $entropies.Add((Get-Entropy -Data $payload[$wStart..$wEnd]))
                }
            }
        }

        $avgEntropy = if ($entropies.Count -gt 0) { [Math]::Round(($entropies | Measure-Object -Average).Average, 3) } else { 0.0 }

        $results.Add([PSCustomObject]@{
            Marker          = $m.Name
            Pattern         = ConvertTo-HexString $needle
            Count           = $totalCount
            DistinctStreams = $distinctStreams.Count
            AvgEntropy      = $avgEntropy
        })
    }

    return $results | Sort-Object -Property Count -Descending
}

# =========================================================================
# FUNCTION: Find-CreoMarkerSequence
#   Raw byte-pattern search over resolved streams (parallel to
#   Search-CreoBinaryString, but for arbitrary byte sequences rather than
#   ASCII text), reporting local context and nearby printable strings.
# =========================================================================
function Find-CreoMarkerSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][byte[]]$Pattern,
        [int]$Context = 12,
        [int]$NearbyStringRadius = 64
    )

    $resolved = Resolve-CreoFileStreams -File $File
    $Data = $resolved.Data
    $streams = $resolved.Streams
    $allStrings = $resolved.Strings

    $needle = [byte[]]$Pattern
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($stream in $streams) {
        $start = $stream.PayloadStart
        [byte[]]$payload = $Data[$start..($start + $stream.PayloadLength - 1)]
        $offsets = Find-BytePatternOffsets -Payload $payload -Needle $needle

        foreach ($i in $offsets) {
            $absolute = $start + $i

            $beforeStart = [Math]::Max(0, $i - $Context)
            $before = if ($i -gt $beforeStart) { $payload[$beforeStart..($i - 1)] } else { @() }

            $afterStart = $i + $needle.Length
            $afterEnd = [Math]::Min($payload.Length - 1, $afterStart + $Context - 1)
            $after = if ($afterEnd -ge $afterStart) { $payload[$afterStart..$afterEnd] } else { @() }

            $matchBytes = $payload[$i..($i + $needle.Length - 1)]
            $window = @($before) + @($matchBytes) + @($after)

            $nearby = $allStrings |
                Where-Object { [Math]::Abs($_.Offset - $absolute) -le $NearbyStringRadius } |
                Select-Object -First 5 |
                ForEach-Object { $_.Value }

            $results.Add([PSCustomObject]@{
                Stream         = $stream.Name
                Offset         = ('0x{0:X8}' -f $absolute)
                RelativeOffset = ('0x{0:X8}' -f $i)
                BeforeBytes    = ConvertTo-HexString $before
                AfterBytes     = ConvertTo-HexString $after
                Entropy        = Get-Entropy -Data $window
                Hex            = ConvertTo-HexString $matchBytes
                NearbyStrings  = ($nearby -join ' | ')
            })
        }
    }

    return $results
}

# =========================================================================
# FUNCTION: Measure-CreoFieldBoundaries
#   For every printable token found inside a resolved stream, measures the
#   distance to the nearest preceding/following occurrence of each
#   candidate marker, then aggregates those distances into average spacing
#   per marker. Purely a spacing/correlation report - draws no conclusions
#   about what a marker "is".
# =========================================================================
function Measure-CreoFieldBoundaries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [object[]]$Markers = $script:DefaultCreoMarkers,
        [int]$MinTokenLen = 4
    )

    $resolved = Resolve-CreoFileStreams -File $File
    $Data = $resolved.Data
    $streams = $resolved.Streams

    $stats = @{}
    foreach ($m in $Markers) {
        $stats[$m.Name] = [PSCustomObject]@{
            BeforeDistances = New-Object System.Collections.Generic.List[int]
            AfterDistances  = New-Object System.Collections.Generic.List[int]
        }
    }

    foreach ($stream in $streams) {
        $start = $stream.PayloadStart
        [byte[]]$payload = $Data[$start..($start + $stream.PayloadLength - 1)]

        # Marker offsets within this stream's payload, computed once per marker.
        $markerOffsets = @{}
        foreach ($m in $Markers) {
            $markerOffsets[$m.Name] = Find-BytePatternOffsets -Payload $payload -Needle ([byte[]]$m.Bytes)
        }

        $tokens = Get-PrintableStrings -Data $payload -MinLen $MinTokenLen

        foreach ($tok in $tokens) {
            $tokStart = $tok.Offset
            $tokEnd = $tok.Offset + $tok.Value.Length - 1

            foreach ($m in $Markers) {
                $offsets = $markerOffsets[$m.Name]
                if ($offsets.Count -eq 0) { continue }

                $prevOffset = $null
                $nextOffset = $null
                foreach ($off in $offsets) {
                    if ($off -lt $tokStart -and ($prevOffset -eq $null -or $off -gt $prevOffset)) { $prevOffset = $off }
                    if ($off -gt $tokEnd -and ($nextOffset -eq $null -or $off -lt $nextOffset)) { $nextOffset = $off }
                }

                if ($prevOffset -ne $null) {
                    $stats[$m.Name].BeforeDistances.Add($tokStart - $prevOffset)
                }
                if ($nextOffset -ne $null) {
                    $stats[$m.Name].AfterDistances.Add($nextOffset - $tokEnd)
                }
            }
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Markers) {
        $b = $stats[$m.Name].BeforeDistances
        $a = $stats[$m.Name].AfterDistances

        $results.Add([PSCustomObject]@{
            Marker              = $m.Name
            TokensWithPrevMatch = $b.Count
            AvgDistanceBefore   = if ($b.Count -gt 0) { [Math]::Round(($b | Measure-Object -Average).Average, 2) } else { $null }
            MedianDistanceBefore= if ($b.Count -gt 0) { ($b | Sort-Object)[[int]([Math]::Floor(($b.Count-1)/2))] } else { $null }
            TokensWithNextMatch = $a.Count
            AvgDistanceAfter    = if ($a.Count -gt 0) { [Math]::Round(($a | Measure-Object -Average).Average, 2) } else { $null }
            MedianDistanceAfter = if ($a.Count -gt 0) { ($a | Sort-Object)[[int]([Math]::Floor(($a.Count-1)/2))] } else { $null }
        })
    }

    return $results | Sort-Object -Property TokensWithPrevMatch -Descending
}

# =========================================================================
# FUNCTION: Compare-CreoStreams
#   Builds a structural fingerprint (entropy, printable/null density, marker
#   counts, avg string spacing) per resolved stream, per file, so
#   fingerprints can be diffed across a collection to spot stable stream
#   signatures, template differences, or abnormal files.
# =========================================================================
function Compare-CreoStreams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [object[]]$Markers = $script:DefaultCreoMarkers
    )

    $resolvedPaths = $Files | Get-ChildItem | Select-Object -ExpandProperty FullName -Unique
    $allFingerprints = New-Object System.Collections.Generic.List[object]

    foreach ($file in $resolvedPaths) {
        $resolved = Resolve-CreoFileStreams -File $file
        $Data = $resolved.Data

        foreach ($stream in $resolved.Streams) {
            $start = $stream.PayloadStart
            [byte[]]$payload = $Data[$start..($start + $stream.PayloadLength - 1)]

            $entropy = Get-Entropy -Data $payload
            $printableCount = ($payload | Where-Object { $_ -ge 0x20 -and $_ -le 0x7E }).Count
            $nullCount = ($payload | Where-Object { $_ -eq 0x00 }).Count
            $printableDensity = if ($payload.Length -gt 0) { [Math]::Round(100.0 * $printableCount / $payload.Length, 1) } else { 0 }
            $nullDensity = if ($payload.Length -gt 0) { [Math]::Round(100.0 * $nullCount / $payload.Length, 1) } else { 0 }

            $tokens = Get-PrintableStrings -Data $payload -MinLen 4
            $avgSpacing = $null
            if ($tokens.Count -gt 1) {
                $spacings = New-Object System.Collections.Generic.List[int]
                for ($i = 1; $i -lt $tokens.Count; $i++) {
                    $spacings.Add($tokens[$i].Offset - ($tokens[$i-1].Offset + $tokens[$i-1].Value.Length))
                }
                $avgSpacing = [Math]::Round(($spacings | Measure-Object -Average).Average, 2)
            }

            $fp = [ordered]@{
                File             = Split-Path -Leaf $file
                Stream           = $stream.Name
                PayloadLength    = $stream.PayloadLength
                Entropy          = $entropy
                PrintableDensity = $printableDensity
                NullDensity      = $nullDensity
                AvgStringSpacing = $avgSpacing
            }

            foreach ($m in $Markers) {
                $count = (Find-BytePatternOffsets -Payload $payload -Needle ([byte[]]$m.Bytes)).Count
                $fp["$($m.Name)Count"] = $count
            }

            $allFingerprints.Add([PSCustomObject]$fp)
        }
    }

    return $allFingerprints
}

# =========================================================================
# FUNCTION: Get-CreoByteNgramStats
#   Byte-frequency / bigram / trigram analysis across resolved streams -
#   the "most common sequences" technique from the handoff doc. Useful as
#   an unbiased starting point for picking new candidate markers, rather
#   than only testing the ones someone already guessed at.
# =========================================================================
function Get-CreoByteNgramStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [ValidateSet(1,2,3)][int]$N = 2,
        [int]$Top = 25,
        [string[]]$StreamNames
    )

    $resolved = Resolve-CreoFileStreams -File $File
    $Data = $resolved.Data
    $streams = $resolved.Streams
    if ($StreamNames) {
        $streams = $streams | Where-Object { $_.Name -in $StreamNames }
    }

    $counts = @{}

    foreach ($stream in $streams) {
        $start = $stream.PayloadStart
        [byte[]]$payload = $Data[$start..($start + $stream.PayloadLength - 1)]

        for ($i = 0; $i -le ($payload.Length - $N); $i++) {
            $key = ($payload[$i..($i + $N - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
            if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        }
    }

    return $counts.GetEnumerator() |
        Sort-Object -Property Value -Descending |
        Select-Object -First $Top |
        ForEach-Object { [PSCustomObject]@{ Sequence = $_.Key; Count = $_.Value } }
}


# --- new gradient and clustering cmdlets ---
function Get-CreoByteTransitionStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter(Mandatory)]
        [byte]$Marker
    )

    $bytes = [System.IO.File]::ReadAllBytes($File)
    $transitions = @{}

    for ($i = 1; $i -lt ($bytes.Count - 1); $i++) {
        if ($bytes[$i] -eq $Marker) {
            $before = $bytes[$i - 1].ToString("X2")
            $after = $bytes[$i + 1].ToString("X2")
            $key = "${before}-${after}"
            
            if (-not $transitions.ContainsKey($key)) {
                $transitions[$key] = [PSCustomObject]@{
                    Before = $before
                    Marker = $Marker.ToString("X2")
                    After = $after
                    Count = 0
                }
            }
            $transitions[$key].Count++
        }
    }

    $transitions.Values | Sort-Object Count -Descending
}

function Find-CreoStructuralRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter(Mandatory)]
        [string]$HexPattern 
        # Example pattern: "E3(..){3}E1" for E3 xx xx xx E1
    )

    $bytes = [System.IO.File]::ReadAllBytes($File)
    $hexString = [System.BitConverter]::ToString($bytes) -replace "-"
    
    $matches = [regex]::Matches($hexString, $HexPattern)
    
    $results = foreach ($m in $matches) {
        [PSCustomObject]@{
            OffsetHex = "0x" + ($m.Index / 2).ToString("X8")
            Length = $m.Length / 2
            MatchValue = $m.Value
        }
    }
    
    $results | Group-Object MatchValue | Select-Object Count, Name | Sort-Object Count -Descending
}

function Measure-CreoEntropyRegions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter()]
        [int]$WindowSize = 256,
        [Parameter()]
        [int]$Step = 64
    )

    $bytes = [System.IO.File]::ReadAllBytes($File)
    
    for ($i = 0; $i -lt ($bytes.Count - $WindowSize); $i += $Step) {
        $window = $bytes[$i..($i + $WindowSize - 1)]
        $counts = @{}
        foreach ($b in $window) { $counts[$b]++ }
        
        $entropy = 0.0
        foreach ($count in $counts.Values) {
            $p = $count / $WindowSize
            if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
        }
        
        [PSCustomObject]@{
            Offset = "0x" + $i.ToString("X8")
            Entropy = [Math]::Round($entropy, 2)
        }
    }
}

function Find-CreoMarkerClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter(Mandatory)]
        [byte]$Marker,
        [Parameter()]
        [int]$Tolerance = 5 
    )

    $bytes = [System.IO.File]::ReadAllBytes($File)
    $positions = @()
    
    for ($i = 0; $i -lt $bytes.Count; $i++) {
        if ($bytes[$i] -eq $Marker) { $positions += $i }
    }

    if ($positions.Count -lt 2) { return }

    $clusters = @{}
    for ($i = 0; $i -lt ($positions.Count - 1); $i++) {
        $spacing = $positions[$i+1] - $positions[$i]
        
        # Group spacings within the tolerance window
        $clusterKey = [Math]::Round($spacing / $Tolerance) * $Tolerance
        
        if (-not $clusters.ContainsKey($clusterKey)) {
            $clusters[$clusterKey] = @{ Count = 0; StartsAt = $positions[$i] }
        }
        $clusters[$clusterKey].Count++
    }

    $clusters.GetEnumerator() | Sort-Object {$_.Value.Count} -Descending | Select-Object @{Name="MedianSpacing";Expression={$_.Name}}, @{Name="StartOffset";Expression={"0x" + $_.Value.StartsAt.ToString("X8")}}, @{Name="ClusterSize";Expression={$_.Value.Count}}
}

function Get-CreoCandidateMarkers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File
    )

    $bytes = [System.IO.File]::ReadAllBytes($File)
    $byteCounts = @{}
    
    # Fast count
    foreach ($b in $bytes) { $byteCounts[$b]++ }

    $candidates = @()
    foreach ($key in $byteCounts.Keys) {
        # Filter noise: 00, FF, and ASCII (0x20 to 0x7E)
        if ($key -eq 0x00 -or $key -eq 0xFF -or ($key -ge 0x20 -and $key -le 0x7E)) { continue }

        $freq = $byteCounts[$key]
        if ($freq -lt 10) { continue } # Minimum threshold

        # Simplified Heuristic Score = (Frequency * Arbitrary Weighting) 
        # Note: You can expand this to include entropy neighborhood checks
        $score = $freq * 1.5 

        $candidates += [PSCustomObject]@{
            HexMarker = $key.ToString("X2")
            Frequency = $freq
            Score = $score
        }
    }

    $candidates | Sort-Object Score -Descending | Select-Object -First 15
}

function Get-CreoMarkerPairs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,
        
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$ResolvedStreams
    )

    begin {
        $fileBytes = [System.IO.File]::ReadAllBytes($File)
        $pairStats = @{}
    }

    process {
        foreach ($stream in $ResolvedStreams) {
            # Ensure we only look at the actual payload, ignoring headers/padding
            $start = $stream.PayloadStart
            $length = $stream.PayloadLength
            $end = $start + $length - 1

            # Prevent out-of-bounds reading
            if ($start -lt 0 -or $end -ge $fileBytes.Count -or $length -lt 2) { continue }

            $lastPos = @{}

            for ($i = $start; $i -lt $end; $i++) {
                $b1 = $fileBytes[$i].ToString("X2")
                $b2 = $fileBytes[$i+1].ToString("X2")
                $sequence = "$b1 $b2"

                if (-not $pairStats.ContainsKey($sequence)) {
                    $pairStats[$sequence] = @{
                        Count = 0
                        Streams = @{}
                        TotalSpacing = 0
                        SpacingCount = 0
                    }
                }

                $stat = $pairStats[$sequence]
                $stat.Count++
                $stat.Streams[$stream.StreamName] = $true

                # Calculate spacing if we've seen this pair in this stream before
                if ($lastPos.ContainsKey($sequence)) {
                    $distance = $i - $lastPos[$sequence]
                    $stat.TotalSpacing += $distance
                    $stat.SpacingCount++
                }
                
                $lastPos[$sequence] = $i
            }
        }
    }

    end {
        $results = foreach ($seq in $pairStats.Keys) {
            $data = $pairStats[$seq]
            $avgSpacing = if ($data.SpacingCount -gt 0) { 
                [Math]::Round($data.TotalSpacing / $data.SpacingCount, 2) 
            } else { 0 }

            [PSCustomObject]@{
                Sequence   = $seq
                Count      = $data.Count
                Streams    = $data.Streams.Count
                AvgSpacing = $avgSpacing
            }
        }

        # Filter out 00 00 noise or extremely low-frequency hits before returning
        $results | Where-Object { $_.Sequence -ne "00 00" -and $_.Count -gt 10 } | 
                   Sort-Object Count -Descending
    }
}

function Resolve-CreoStreamsNormalized {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter()]
        $ResolvedStreams
    )

    if ($null -ne $ResolvedStreams) {

        if ($ResolvedStreams.PSObject.Properties['Streams']) {
            return @($ResolvedStreams.Streams)
        }

        if ($ResolvedStreams -is [System.Array]) {
            $first = $ResolvedStreams | Select-Object -First 1

            if ($first -and $first.PSObject.Properties['Streams']) {
                return @($first.Streams)
            }

            return @($ResolvedStreams)
        }

        return @($ResolvedStreams)
    }

    $resolved = Resolve-CreoFileStreams -File $File

    if ($null -eq $resolved) {
        return @()
    }

    if ($resolved.PSObject.Properties['Streams']) {
        return @($resolved.Streams)
    }

    return @($resolved)
}


function Test-CreoStreamRange {
    param(
        [Parameter(Mandatory)]
        $Stream,

        [Parameter(Mandatory)]
        [int]$FileLength
    )

    if ($null -eq $Stream) {
        return $false
    }

    if (-not ($Stream.PSObject.Properties['PayloadStart'])) {
        return $false
    }

    if (-not ($Stream.PSObject.Properties['PayloadLength'])) {
        return $false
    }

    $start = [int]$Stream.PayloadStart
    $length = [int]$Stream.PayloadLength

    if ($start -lt 0) {
        return $false
    }

    if ($length -le 0) {
        return $false
    }

    if (($start + $length) -gt $FileLength) {
        return $false
    }

    return $true
}


function Get-CreoEntropy {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    if ($Bytes.Count -eq 0) {
        return 0
    }

    $counts = @{}

    foreach ($b in $Bytes) {
        if ($counts.ContainsKey($b)) {
            $counts[$b]++
        }
        else {
            $counts[$b] = 1
        }
    }

    $entropy = 0.0

    foreach ($count in $counts.Values) {
        $p = $count / $Bytes.Count
        $entropy -= $p * [Math]::Log($p,2)
    }

    return $entropy
}

function Get-CreoByteTransitionStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter(Mandatory)]
        [byte]$Marker,

        [Parameter()]
        $ResolvedStreams
    )

    $streams = Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes = [System.IO.File]::ReadAllBytes($File)

    $stats = @{}

    foreach ($stream in $streams) {

        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        for ($i=$start+1; $i -lt $end; $i++) {

            if ($bytes[$i] -ne $Marker) {
                continue
            }

            $key = "{0:X2}-{1:X2}" -f $bytes[$i-1],$bytes[$i+1]

            if (-not $stats.ContainsKey($key)) {

                $stats[$key] = @{
                    Before = $bytes[$i-1].ToString("X2")
                    After = $bytes[$i+1].ToString("X2")
                    Count = 0
                    Streams = [System.Collections.Generic.HashSet[string]]::new()
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }

            $s = $stats[$key]

            $s.Count++
            [void]$s.Streams.Add($stream.Name)

            if ($s.Examples.Count -lt 3) {
                $s.Examples.Add(("0x{0:X8}" -f $i))
            }
        }
    }


    foreach ($s in $stats.Values) {

        [PSCustomObject]@{
            Marker = $Marker.ToString("X2")
            BeforeByte = $s.Before
            AfterByte = $s.After
            Count = $s.Count
            DistinctStreams = $s.Streams.Count
            ExampleOffsets = ($s.Examples -join ", ")
        }
    }
    | Sort-Object Count -Descending
}

function Find-CreoStructuralRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [Parameter()]
        $ResolvedStreams
    )

    $streams = Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes = [System.IO.File]::ReadAllBytes($File)

    $cleanPattern = $Pattern.ToUpper().Replace(" ","")

    if ($cleanPattern.Length % 2 -ne 0) {
        throw "Pattern must contain complete bytes."
    }

    $pattern = @()

    for ($i=0;$i -lt $cleanPattern.Length;$i+=2) {

        $pair = $cleanPattern.Substring($i,2)

        if ($pair -eq "??") {
            $pattern += $null
        }
        else {
            $pattern += [Convert]::ToByte($pair,16)
        }
    }


    $results = [System.Collections.Generic.List[object]]::new()


    foreach ($stream in $streams) {

        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - $pattern.Count


        for ($offset=$start;$offset -le $end;$offset++) {

            $match=$true

            for ($j=0;$j -lt $pattern.Count;$j++) {

                if ($null -ne $pattern[$j] -and
                    $bytes[$offset+$j] -ne $pattern[$j]) {

                    $match=$false
                    break
                }
            }


            if ($match) {

                $slice=$bytes[$offset..($offset+$pattern.Count-1)]

                $results.Add([PSCustomObject]@{
                    Stream=$stream.Name
                    AbsoluteOffset=("0x{0:X8}" -f $offset)
                    RelativeOffset=("0x{0:X8}" -f ($offset-$start))
                    Length=$pattern.Count
                    MatchedBytes=([BitConverter]::ToString($slice) -replace "-"," ")
                })
            }
        }
    }

    $results
}

function Measure-CreoEntropyRegions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter()]
        [int]$WindowSize = 256,

        [Parameter()]
        [int]$Step = 64,

        [Parameter()]
        $ResolvedStreams
    )

    $streams = Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes = [System.IO.File]::ReadAllBytes($File)

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($stream in $streams) {

        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }

        $start = [int]$stream.PayloadStart
        $length = [int]$stream.PayloadLength

        if ($length -lt $WindowSize) {
            continue
        }


        $previous = $null

        for ($offset=0; $offset -le ($length-$WindowSize); $offset += $Step) {

            $absolute = $start + $offset

            $window = $bytes[$absolute..($absolute+$WindowSize-1)]

            $entropy = [Math]::Round(
                (Get-CreoEntropy -Bytes $window),
                4
            )


            $delta = 0

            if ($null -ne $previous) {
                $delta = [Math]::Round(
                    ($entropy-$previous),
                    4
                )
            }


            $results.Add([PSCustomObject]@{
                Stream=$stream.Name
                AbsoluteOffset=("0x{0:X8}" -f $absolute)
                RelativeOffset=("0x{0:X8}" -f $offset)
                Entropy=$entropy
                EntropyDelta=$delta
                WindowSize=$WindowSize
            })


            $previous=$entropy
        }
    }


    $results
}

function Find-CreoMarkerClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter(Mandatory)]
        [byte]$Marker,

        [Parameter()]
        [int]$MaxGap = 64,

        [Parameter()]
        $ResolvedStreams
    )


    $streams = Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes = [System.IO.File]::ReadAllBytes($File)

    $results = [System.Collections.Generic.List[object]]::new()


    foreach ($stream in $streams) {

        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }

        $start=[int]$stream.PayloadStart
        $end=$start+[int]$stream.PayloadLength-1


        $positions=[System.Collections.Generic.List[int]]::new()


        for ($i=$start;$i -le $end;$i++) {

            if ($bytes[$i] -eq $Marker) {
                $positions.Add($i)
            }
        }


        if ($positions.Count -lt 2) {
            continue
        }


        $cluster=[System.Collections.Generic.List[int]]::new()


        for ($i=0;$i -lt $positions.Count;$i++) {

            if ($cluster.Count -eq 0) {
                $cluster.Add($positions[$i])
                continue
            }


            $gap=$positions[$i]-$cluster[$cluster.Count-1]


            if ($gap -le $MaxGap) {
                $cluster.Add($positions[$i])
            }
            else {

                if ($cluster.Count -gt 1) {

                    $spacing=@()

                    for ($j=0;$j -lt ($cluster.Count-1);$j++) {
                        $spacing += $cluster[$j+1]-$cluster[$j]
                    }


                    $results.Add([PSCustomObject]@{
                        Marker=$Marker.ToString("X2")
                        Stream=$stream.Name
                        StartOffset=("0x{0:X8}" -f $cluster[0])
                        EndOffset=("0x{0:X8}" -f $cluster[$cluster.Count-1])
                        Occurrences=$cluster.Count
                        AverageSpacing=[Math]::Round(
                            (($spacing | Measure-Object -Average).Average),
                            2
                        )
                        MedianSpacing=(
                            $spacing | Sort-Object
                        )[[Math]::Floor($spacing.Count/2)]
                    })
                }

                $cluster=[System.Collections.Generic.List[int]]::new()
                $cluster.Add($positions[$i])
            }
        }


        if ($cluster.Count -gt 1) {

            $spacing=@()

            for ($j=0;$j -lt ($cluster.Count-1);$j++) {
                $spacing += $cluster[$j+1]-$cluster[$j]
            }


            $results.Add([PSCustomObject]@{
                Marker=$Marker.ToString("X2")
                Stream=$stream.Name
                StartOffset=("0x{0:X8}" -f $cluster[0])
                EndOffset=("0x{0:X8}" -f $cluster[$cluster.Count-1])
                Occurrences=$cluster.Count
                AverageSpacing=[Math]::Round(
                    (($spacing | Measure-Object -Average).Average),
                    2
                )
                MedianSpacing=(
                    $spacing | Sort-Object
                )[[Math]::Floor($spacing.Count/2)]
            })
        }
    }


    $results
}

function Get-CreoCandidateMarkers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter()]
        [int]$Top = 50,

        [Parameter()]
        $ResolvedStreams
    )


    $streams = Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes=[System.IO.File]::ReadAllBytes($File)


    $streamCount=[Math]::Max(@($streams).Count,1)

    $stats=@{}


    foreach ($stream in $streams) {

        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }


        $start=$stream.PayloadStart
        $end=$start+$stream.PayloadLength-1


        for ($i=$start+1;$i -lt $end;$i++) {

            $b=$bytes[$i]


            if (-not $stats.ContainsKey($b)) {

                $stats[$b]=@{
                    Count=0
                    Streams=[System.Collections.Generic.HashSet[string]]::new()
                    Prev=[System.Collections.Generic.HashSet[byte]]::new()
                    Next=[System.Collections.Generic.HashSet[byte]]::new()
                }
            }


            $s=$stats[$b]

            $s.Count++
            [void]$s.Streams.Add($stream.Name)
            [void]$s.Prev.Add($bytes[$i-1])
            [void]$s.Next.Add($bytes[$i+1])
        }
    }


    $results=@()


    foreach ($b in $stats.Keys) {


        if (
            $b -eq 0x00 -or
            $b -eq 0xFF -or
            ($b -ge 0x20 -and $b -le 0x7E)
        ) {
            continue
        }


        $s=$stats[$b]


        if ($s.Count -lt 5) {
            continue
        }


        $coverage=$s.Streams.Count/$streamCount

        $neighborPenalty=
            [Math]::Max(
                ($s.Prev.Count+$s.Next.Count),
                1
            )


        $score=[
            Math]::Round(
                ($s.Count*$coverage*100)/$neighborPenalty,
                2
            )


        $results += [PSCustomObject]@{
            Marker=("{0:X2}" -f $b)
            Frequency=$s.Count
            StreamCount=$s.Streams.Count
            StreamCoveragePct=[Math]::Round($coverage*100,2)
            UniquePreviousBytes=$s.Prev.Count
            UniqueNextBytes=$s.Next.Count
            Score=$score
        }
    }


    $results |
        Sort-Object Score -Descending |
        Select-Object -First $Top
}

function Get-CreoMarkerPairs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$File,

        [Parameter()]
        [int]$MinCount = 5,

        [Parameter()]
        [int]$MaxResults = 50,

        [Parameter()]
        $ResolvedStreams
    )


    $streams=Resolve-CreoStreamsNormalized -File $File -ResolvedStreams $ResolvedStreams
    $bytes=[System.IO.File]::ReadAllBytes($File)

    $pairs=@{}


    foreach ($stream in $streams) {


        if (-not (Test-CreoStreamRange $stream $bytes.Length)) {
            continue
        }


        $start=$stream.PayloadStart
        $end=$start+$stream.PayloadLength-2


        $last=@{}


        for ($i=$start;$i -le $end;$i++) {


            $a=$bytes[$i]
            $b=$bytes[$i+1]


            if (
                ($a -ge 0x20 -and $a -le 0x7E) -and
                ($b -ge 0x20 -and $b -le 0x7E)
            ) {
                continue
            }


            if ($a -eq 0 -and $b -eq 0) {
                continue
            }


            $key="{0:X2} {1:X2}" -f $a,$b


            if (-not $pairs.ContainsKey($key)) {

                $pairs[$key]=@{
                    Count=0
                    Streams=[System.Collections.Generic.HashSet[string]]::new()
                    Spacing=[System.Collections.Generic.List[int]]::new()
                    Examples=[System.Collections.Generic.List[string]]::new()
                }
            }


            $p=$pairs[$key]

            $p.Count++
            [void]$p.Streams.Add($stream.Name)


            if ($p.Examples.Count -lt 3) {
                $p.Examples.Add(
                    ("0x{0:X8}" -f $i)
                )
            }


            if ($last.ContainsKey($key)) {

                $p.Spacing.Add(
                    $i-$last[$key]
                )
            }


            $last[$key]=$i
        }
    }



    $results=@()


    foreach ($key in $pairs.Keys) {

        $p=$pairs[$key]


        if ($p.Count -lt $MinCount) {
            continue
        }


        $avg=0
        $median=0


        if ($p.Spacing.Count) {

            $sorted=$p.Spacing | Sort-Object

            $avg=[Math]::Round(
                (($sorted | Measure-Object -Average).Average),
                2
            )

            $median=$sorted[
                [Math]::Floor($sorted.Count/2)
            ]
        }


        $results += [PSCustomObject]@{
            Sequence=$key
            Count=$p.Count
            DistinctStreams=$p.Streams.Count
            AvgSpacing=$avg
            MedianSpacing=$median
            ExampleOffsets=($p.Examples -join ", ")
        }
    }


    $results |
        Sort-Object Count -Descending |
        Select-Object -First $MaxResults
}

Export-ModuleMember -Function `
    Get-CreoDataMaps, `
    Search-CreoBinaryString, `
    Get-CreoMarkerStatistics, `
    Find-CreoMarkerSequence, `
    Measure-CreoFieldBoundaries, `
    Compare-CreoStreams, `
    Get-CreoByteNgramStats, `
    Get-CreoByteTransitionStats, `
    Find-CreoStructuralRuns, `
    Measure-CreoEntropyRegions, `
    Find-CreoMarkerClusters, `
    Get-CreoCandidateMarkers, `
    Get-CreoMarkerPairs


    
