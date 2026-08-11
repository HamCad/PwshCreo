# =========================================================================
# C# ACCELERATION ENGINE (CreoNative)
#   Opt-in, with automatic PowerShell fallback everywhere it's used - see
#   $script:UseCSharpEngine below and Find-BytePatternOffsets. PS 5.1-safe
#   deliberately: plain byte[] indexing only, no Span<T>/stackalloc/Math.Log2
#   (those require .NET 5+ and will not compile under Windows PowerShell's
#   .NET Framework host).
#
#   ExtractParameters ports the E1 E1 [00|01] E3 <name>\0 E2 <typeByte>
#   parameter-frame signature and the E232/E233/E234/E235 = Real/String/
#   Integer/Boolean type-code mapping from creo-pwsh.psm1's ExtractParameters,
#   independently confirmed via real Get-CreoParameters output (CAD_SYSTEM,
#   CODE_MATURITY_STATE, TITLE_1, etc. all resolved correctly). Integer/Real
#   payload decoding is intentionally left unresolved ("not decoded") rather
#   than guessed - same honest limitation as the source it's ported from.
#   Domain-specific noise filtering (PTC_ prefix, noise lists) stays in
#   PowerShell, not in this C# layer, so it's easy to see/edit.
# =========================================================================
if (-not ("CreoNative" -as [type])) {
    $creoNativeSource = @"
using System;
using System.Text;
using System.Collections.Generic;

public class CreoParameterHit {
    public string ParameterName;
    public string ParameterValue;
    public string TypeName;
}

public class PrintableRun {
    public int Offset;
    public string Value;
}

public static class CreoNative {
    public static int[] FindBytePattern(byte[] source, byte[] pattern, bool ignoreCase) {
        var offsets = new List<int>();
        if (source == null || pattern == null || pattern.Length == 0 || source.Length < pattern.Length)
            return offsets.ToArray();

        int limit = source.Length - pattern.Length;
        for (int i = 0; i <= limit; i++) {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++) {
                byte s = source[i + j];
                byte p = pattern[j];
                if (ignoreCase) {
                    if (s >= 0x61 && s <= 0x7A) s -= 0x20;
                    if (p >= 0x61 && p <= 0x7A) p -= 0x20;
                }
                if (s != p) { match = false; break; }
            }
            if (match) offsets.Add(i);
        }
        return offsets.ToArray();
    }

    // Wildcard search: pattern entries with HasValue == false match any byte.
    public static int[] FindWildcardPattern(byte[] source, byte?[] pattern) {
        var offsets = new List<int>();
        if (source == null || pattern == null || pattern.Length == 0 || source.Length < pattern.Length)
            return offsets.ToArray();

        int limit = source.Length - pattern.Length;
        for (int i = 0; i <= limit; i++) {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++) {
                if (pattern[j].HasValue && source[i + j] != pattern[j].Value) { match = false; break; }
            }
            if (match) offsets.Add(i);
        }
        return offsets.ToArray();
    }

    // Exact port of Get-PrintableStrings: a run ends at any byte outside
    // 0x20-0x7E (and tab 0x09); MinLen semantics identical.
    public static PrintableRun[] ExtractPrintableRuns(byte[] data, int minLen) {
        var results = new List<PrintableRun>();
        var sb = new StringBuilder();
        int startOffset = -1;

        for (int i = 0; i < data.Length; i++) {
            byte b = data[i];
            if ((b >= 0x20 && b <= 0x7E) || b == 0x09) {
                if (startOffset < 0) startOffset = i;
                sb.Append((char)b);
            }
            else {
                if (sb.Length >= minLen) {
                    results.Add(new PrintableRun { Offset = startOffset, Value = sb.ToString() });
                }
                sb.Clear();
                startOffset = -1;
            }
        }
        if (sb.Length >= minLen) {
            results.Add(new PrintableRun { Offset = startOffset, Value = sb.ToString() });
        }
        return results.ToArray();
    }

    // Bounded single-byte scan within [start, end) - the common case for
    // marker-occurrence counting across a stream's byte range, without
    // needing to slice the array first.
    public static int[] FindByteOccurrences(byte[] data, int start, int end, byte target) {
        var results = new List<int>();
        if (data == null) return results.ToArray();
        start = Math.Max(0, start);
        end = Math.Min(data.Length, end);
        for (int i = start; i < end; i++) {
            if (data[i] == target) results.Add(i);
        }
        return results.ToArray();
    }

    public static double ComputeEntropy(byte[] data, int offset, int length) {
        if (data == null || length <= 0) return 0.0;
        var counts = new int[256];
        int end = offset + length;
        for (int i = offset; i < end; i++) counts[data[i]]++;

        double entropy = 0.0;
        for (int c = 0; c < 256; c++) {
            if (counts[c] == 0) continue;
            double p = (double)counts[c] / length;
            entropy -= p * Math.Log(p, 2);
        }
        return Math.Round(entropy, 3);
    }

    public static string GenerateHexDump(byte[] bytes, int start, int end) {
        start = Math.Max(0, start);
        end = Math.Min(bytes.Length, end);
        int length = end - start;
        if (length <= 0) return string.Empty;

        var sb = new StringBuilder();
        int lineStart = start;
        var hexLine = new StringBuilder();
        var ascLine = new StringBuilder();

        for (int k = start; k < end; k++) {
            byte b = bytes[k];
            hexLine.AppendFormat("{0:X2} ", b);
            ascLine.Append((b >= 32 && b <= 126) ? (char)b : '.');

            if ((k - start + 1) % 16 == 0 || k == end - 1) {
                sb.AppendLine(string.Format("{0:X8}  {1} |{2}|", lineStart, hexLine.ToString().PadRight(48), ascLine.ToString()));
                hexLine.Clear();
                ascLine.Clear();
                lineStart = k + 1;
            }
        }
        return sb.ToString();
    }

    // Validated marker: E1 E1 [00|01] E3 <name>\0 E2 <typeByte> ...
    // Confirmed live against real files - not a hypothesis.
    public static CreoParameterHit[] ExtractParameters(byte[] bytes) {
        var results = new List<CreoParameterHit>();
        int scanLimit = bytes.Length - 12;

        for (int i = 0; i < scanLimit; i++) {
            if (bytes[i] != 0xE1 || bytes[i + 1] != 0xE1) continue;

            bool isPart = bytes[i + 2] == 0x00 && bytes[i + 3] == 0xE3;
            bool isAsm  = bytes[i + 2] == 0x01 && bytes[i + 3] == 0xE3;
            if (!isPart && !isAsm) continue;

            int nameStart = i + 4;
            int nameEnd = Array.IndexOf(bytes, (byte)0, nameStart);
            if (nameEnd <= nameStart) continue;

            string name = Encoding.ASCII.GetString(bytes, nameStart, nameEnd - nameStart);
            bool validName = name.Length > 2;
            if (validName) {
                for (int c = 0; c < name.Length; c++) {
                    char ch = name[c];
                    if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')) { validName = false; break; }
                }
            }
            if (!validName) continue;

            int typeMarkerStart = nameEnd + 1;
            if (typeMarkerStart + 1 >= bytes.Length) continue;
            int typeHex = (bytes[typeMarkerStart] << 8) | bytes[typeMarkerStart + 1];

            string typeName = "Unknown";
            switch (typeHex) {
                case 0xE232: typeName = "Real"; break;
                case 0xE233: typeName = "String"; break;
                case 0xE234: typeName = "Integer"; break;
                case 0xE235: typeName = "Boolean"; break;
            }

            int valueStart = typeMarkerStart + 2;
            string value = null;
            int jumpIndex = valueStart;

            // NOTE: previously this scanned up to 16 bytes forward for "the
            // first printable byte" before extracting anything. That broke
            // empty String values: a 0x00 immediately at valueStart IS a
            // valid empty string, but the old scan walked past it, through
            // the next parameter frame's own header bytes, and landed on
            // the NEXT parameter's name - reporting it as this parameter's
            // value. Confirmed via REFERENCE_3..REFERENCE_6 in
            // start-assembly.asm.1 (all empty; old code reported REFERENCE_3's
            // value as "REFERENCE_4", REFERENCE_5's as "REFERENCE_6", etc).
            // Each type now reads its own value directly from valueStart.
            if (valueStart < bytes.Length) {
                switch (typeName) {
                    case "Boolean":
                        if (valueStart + 3 < bytes.Length) {
                            value = bytes[valueStart] == 0x01 ? "YES" : "NO";
                            jumpIndex = valueStart + 4;
                        }
                        break;
                    case "Integer":
                        if (valueStart + 7 < bytes.Length) {
                            value = "(Integer - raw payload not decoded)";
                            jumpIndex = valueStart + 8;
                        }
                        break;
                    case "Real":
                        if (valueStart + 7 < bytes.Length) {
                            value = "(Real - raw payload not decoded)";
                            jumpIndex = valueStart + 8;
                        }
                        break;
                    case "String":
                        if (bytes[valueStart] == 0x00) {
                            value = "";
                            jumpIndex = valueStart + 1;
                        }
                        else {
                            int valueEnd = Array.IndexOf(bytes, (byte)0, valueStart);
                            if (valueEnd > valueStart) {
                                value = Encoding.ASCII.GetString(bytes, valueStart, valueEnd - valueStart);
                                jumpIndex = valueEnd;
                            }
                        }
                        break;
                }
            }

            if (value != null) {
                results.Add(new CreoParameterHit { ParameterName = name, ParameterValue = value, TypeName = typeName });
            }
            i = Math.Max(i, jumpIndex);
        }
        return results.ToArray();
    }
}
"@
    try {
        Add-Type -TypeDefinition $creoNativeSource -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Warning "CreoNative C# engine failed to compile - falling back to pure PowerShell. Error: $($_.Exception.Message)"
    }
}
$script:UseCSharpEngine = ("CreoNative" -as [type]) -ne $null

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
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    [byte[]]$Bytes = [System.IO.File]::ReadAllBytes(
        (Resolve-Path $Path)
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

    if ($script:UseCSharpEngine) {
        $runs = [CreoNative]::ExtractPrintableRuns($Data, $MinLen)
        $results = New-Object System.Collections.Generic.List[object]
        foreach ($r in $runs) {
            $results.Add([PSCustomObject]@{ Offset = $r.Offset; Value = $r.Value })
        }
        return $results
    }

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

    if ($script:UseCSharpEngine) {
        return [CreoNative]::ComputeEntropy($Data, 0, $Data.Length)
    }

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
        [System.Collections.Generic.List[object]]$Entries = (New-Object System.Collections.Generic.List[object]),
        [Parameter(Mandatory)][byte[]]$Data
    )

    $rows = New-Object System.Collections.Generic.List[object]

    if ($null -eq $Entries -or $Entries.Count -eq 0) {
        return $rows
    }

    $valid = $Entries | Where-Object { $_.OffsetVal -ne $null -and $_.OffsetVal -ge 0 -and $_.OffsetVal -lt $Data.Length }
    $sorted = $valid | Sort-Object -Property OffsetVal

    $prevEnd = $null
    foreach ($e in $sorted) {
        $len = if ($e.Size1Val -and $e.Size1Val -gt 0) { $e.Size1Val } else { 0 }
        $endOff = $e.OffsetVal + $len
        $clampedEnd = [Math]::Min($endOff, $Data.Length)
        $sliceLen = [Math]::Max(0, $clampedEnd - $e.OffsetVal)
        $entropy = if ($sliceLen -gt 0) {
            if ($script:UseCSharpEngine) { [CreoNative]::ComputeEntropy($Data, $e.OffsetVal, $sliceLen) }
            else { Get-Entropy -Data $Data[$e.OffsetVal..($e.OffsetVal + $sliceLen - 1)] }
        } else { 0.0 }

        $gapFromPrev = if ($prevEnd -ne $null) { $e.OffsetVal - $prevEnd } else { $null }

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
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Pattern,
        [int]$A = 0,
        [int]$B = 0,
        [int]$C = 0,
        [switch]$CaseSensitive,
        [switch]$Context
    )

    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

    [byte[]]$Data = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))

    $strings = Get-PrintableStrings -Data $Data -MinLen 6
    $parsed = Parse-TocEntries -Strings $strings -MinFields 8
    $streams = Resolve-StreamRanges -Entries $parsed.Entries -Data $Data

    if ($B -gt 0) { $A = $B; $C = $B }

    function Convert-BytesToHex {
        param([byte[]]$Bytes)
        if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
        return (($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
    }

    function Convert-BytesToAscii {
        param([byte[]]$Bytes)
        if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
        return (($Bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join '')
    }

    $needle = [System.Text.Encoding]::ASCII.GetBytes($Pattern)

    foreach ($stream in $streams) {
        if ($stream.PayloadLength -le 0) { continue }
        $start = $stream.PayloadStart
        $length = $stream.PayloadLength
        if (($start + $length) -gt $Data.Length) { continue }

        [byte[]]$payload = $Data[$start..($start + $length - 1)]

        for ($i = 0; $i -le ($payload.Length - $needle.Length); $i++) {
            $found = $true
            for ($j = 0; $j -lt $needle.Length; $j++) {
                $aByte = $payload[$i + $j]
                $bByte = $needle[$j]
                if (-not $CaseSensitive) {
                    if ($aByte -ge 65 -and $aByte -le 90) { $aByte += 32 }
                    if ($bByte -ge 65 -and $bByte -le 90) { $bByte += 32 }
                }
                if ($aByte -ne $bByte) { $found = $false; break }
            }
            if (-not $found) { continue }

            $absolute = $start + $i

            if (($A -eq 0) -and ($B -eq 0) -and ($C -eq 0) -and (-not $Context)) {
                [PSCustomObject]@{ Block = $stream.Name; Offset = ('0x{0:X8}' -f $absolute) }
                continue
            }

            $beforeStart = [Math]::Max(0, $i - $A)
            $beforeLength = $i - $beforeStart
            $afterStart = $i + $needle.Length
            $afterLength = [Math]::Min($C, $payload.Length - $afterStart)

            [byte[]]$before = @()
            if ($beforeLength -gt 0) { $before = $payload[$beforeStart..($i-1)] }

            [byte[]]$matchBytes = $payload[$i..($i+$needle.Length-1)]

            [byte[]]$after = @()
            if ($afterLength -gt 0) { $after = $payload[$afterStart..($afterStart+$afterLength-1)] }

            [byte[]]$window = @($before; $matchBytes; $after)

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

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    return (($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
}

function ConvertTo-AsciiString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    return (($Bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join '')
}

function Resolve-CreoFileStreams {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

    [byte[]]$Data = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))
    $strings = Get-PrintableStrings -Data $Data -MinLen 6
    $parsed  = Parse-TocEntries -Strings $strings -MinFields 8
    $streams = Resolve-StreamRanges -Entries $parsed.Entries -Data $Data

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

function Find-BytePatternOffsets {
    param([byte[]]$Payload, [byte[]]$Needle)

    if ($script:UseCSharpEngine) {
        return [CreoNative]::FindBytePattern($Payload, $Needle, $false)
    }

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

function Get-CreoMarkerStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [object[]]$Markers = $script:DefaultCreoMarkers,
        [int]$EntropyWindow = 16
    )

    $resolved = Resolve-CreoFileStreams -Path $Path
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

function Find-CreoMarkerSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Pattern,
        [int]$Context = 12,
        [int]$NearbyStringRadius = 64
    )

    $resolved = Resolve-CreoFileStreams -Path $Path
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

function Measure-CreoFieldBoundaries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [object[]]$Markers = $script:DefaultCreoMarkers,
        [int]$MinTokenLen = 4
    )

    $resolved = Resolve-CreoFileStreams -Path $Path
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

                if ($prevOffset -ne $null) { $stats[$m.Name].BeforeDistances.Add($tokStart - $prevOffset) }
                if ($nextOffset -ne $null) { $stats[$m.Name].AfterDistances.Add($nextOffset - $tokEnd) }
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

function Compare-CreoStreams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [object[]]$Markers = $script:DefaultCreoMarkers
    )

    $resolvedPaths = $Files | Get-ChildItem | Select-Object -ExpandProperty FullName -Unique
    $allFingerprints = New-Object System.Collections.Generic.List[object]

    foreach ($file in $resolvedPaths) {
        $resolved = Resolve-CreoFileStreams -Path $file
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

function Get-CreoByteNgramStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet(1,2,3)][int]$N = 2,
        [int]$Top = 25,
        [string[]]$StreamNames
    )

    $resolved = Resolve-CreoFileStreams -Path $Path
    $Data = $resolved.Data
    $streams = $resolved.Streams
    if ($StreamNames) { $streams = $streams | Where-Object { $_.Name -in $StreamNames } }

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

function Test-CreoStreamRange {
    param(
        [Parameter(Mandatory)]$Stream,
        [Parameter(Mandatory)][int]$FileLength
    )

    if ($null -eq $Stream) { return $false }
    if (-not $Stream.PSObject.Properties['PayloadStart']) { return $false }
    if (-not $Stream.PSObject.Properties['PayloadLength']) { return $false }

    $start = [int]$Stream.PayloadStart
    $length = [int]$Stream.PayloadLength

    if ($start -lt 0) { return $false }
    if ($length -le 0) { return $false }
    if (($start + $length) -gt $FileLength) { return $false }

    return $true
}

function Resolve-CreoStreamsNormalized {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()]$ResolvedStreams
    )

    if ($null -ne $ResolvedStreams) {
        return $ResolvedStreams
    }

    return Resolve-CreoFileStreams -Path $Path
}

function Get-CreoByteTransitionStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte]$Marker,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $stats = @{}

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        $positions = if ($script:UseCSharpEngine) {
            [CreoNative]::FindByteOccurrences($bytes, $start + 1, $end, $Marker)
        }
        else {
            $p = New-Object System.Collections.Generic.List[int]
            for ($i = $start + 1; $i -lt $end; $i++) { if ($bytes[$i] -eq $Marker) { $p.Add($i) } }
            $p
        }

        foreach ($i in $positions) {
            $key = "{0:X2}-{1:X2}" -f $bytes[$i-1], $bytes[$i+1]

            if (-not $stats.ContainsKey($key)) {
                $stats[$key] = @{
                    Before  = $bytes[$i-1].ToString("X2")
                    After   = $bytes[$i+1].ToString("X2")
                    Count   = 0
                    Streams = [System.Collections.Generic.HashSet[string]]::new()
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }

            $s = $stats[$key]
            $s.Count++
            [void]$s.Streams.Add($stream.Name)
            if ($s.Examples.Count -lt 3) { $s.Examples.Add(("0x{0:X8}" -f $i)) }
        }
    }

    $output = foreach ($s in $stats.Values) {
        [PSCustomObject]@{
            Marker          = $Marker.ToString("X2")
            BeforeByte      = $s.Before
            AfterByte       = $s.After
            Count           = $s.Count
            DistinctStreams = $s.Streams.Count
            ExampleOffsets  = ($s.Examples -join ", ")
        }
    }

    return $output | Sort-Object -Property Count -Descending
}

function Find-CreoStructuralRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $cleanPattern = $Pattern.ToUpper().Replace(" ", "")
    if ($cleanPattern.Length % 2 -ne 0) { throw "Pattern must contain complete bytes." }

    $patternBytes = @()
    for ($i = 0; $i -lt $cleanPattern.Length; $i += 2) {
        $pair = $cleanPattern.Substring($i, 2)
        if ($pair -eq "??") { $patternBytes += $null }
        else { $patternBytes += [Convert]::ToByte($pair, 16) }
    }

    if ($patternBytes.Count -eq 0) { throw "Empty pattern after parsing." }

    Write-Verbose ("Searching bytes: {0}" -f (
        ($patternBytes | ForEach-Object { if ($null -eq $_) { "??" } else { "{0:X2}" -f $_ } }) -join " "
    ))

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - $patternBytes.Count

        for ($offset = $start; $offset -le $end; $offset++) {
            $match = $true
            for ($j = 0; $j -lt $patternBytes.Count; $j++) {
                if ($null -ne $patternBytes[$j] -and $bytes[$offset + $j] -ne $patternBytes[$j]) { $match = $false; break }
            }

            if ($match) {
                $slice = $bytes[$offset..($offset + $patternBytes.Count - 1)]
                $results.Add([PSCustomObject]@{
                    Stream         = $stream.Name
                    AbsoluteOffset = ("0x{0:X8}" -f $offset)
                    RelativeOffset = ("0x{0:X8}" -f ($offset - $start))
                    Length         = $patternBytes.Count
                    MatchedBytes   = ([BitConverter]::ToString($slice) -replace "-", " ")
                })
            }
        }
    }

    return $results
}

function Measure-CreoEntropyRegions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$WindowSize = 256,
        [int]$Step = 64,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $length = [int]$stream.PayloadLength
        if ($length -lt $WindowSize) { continue }

        $previous = $null

        for ($offset = 0; $offset -le ($length - $WindowSize); $offset += $Step) {
            $absolute = $start + $offset
            $window = $bytes[$absolute..($absolute + $WindowSize - 1)]
            $entropy = [Math]::Round((Get-Entropy -Data $window), 4)

            $delta = 0
            if ($null -ne $previous) { $delta = [Math]::Round(($entropy - $previous), 4) }

            $results.Add([PSCustomObject]@{
                Stream         = $stream.Name
                AbsoluteOffset = ("0x{0:X8}" -f $absolute)
                RelativeOffset = ("0x{0:X8}" -f $offset)
                Entropy        = $entropy
                EntropyDelta   = $delta
                WindowSize     = $WindowSize
            })

            $previous = $entropy
        }
    }

    return $results
}

function Find-CreoMarkerClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte]$Marker,
        [int]$MaxGap = 64,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $results = [System.Collections.Generic.List[object]]::new()

    function _EmitCluster($cluster, $marker, $streamName) {
        if ($cluster.Count -le 1) { return }

        $spacing = @()
        for ($j = 0; $j -lt ($cluster.Count - 1); $j++) { $spacing += $cluster[$j+1] - $cluster[$j] }
        $sortedSpacing = $spacing | Sort-Object

        [PSCustomObject]@{
            Marker         = $marker.ToString("X2")
            Stream         = $streamName
            StartOffset    = ("0x{0:X8}" -f $cluster[0])
            EndOffset      = ("0x{0:X8}" -f $cluster[$cluster.Count - 1])
            Occurrences    = $cluster.Count
            AverageSpacing = [Math]::Round((($spacing | Measure-Object -Average).Average), 2)
            MedianSpacing  = $sortedSpacing[[Math]::Floor($spacing.Count / 2)]
        }
    }

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        $positions = [System.Collections.Generic.List[int]]::new()
        if ($script:UseCSharpEngine) {
            $positions.AddRange([int[]][CreoNative]::FindByteOccurrences($bytes, $start, $end + 1, $Marker))
        }
        else {
            for ($i = $start; $i -le $end; $i++) { if ($bytes[$i] -eq $Marker) { $positions.Add($i) } }
        }
        if ($positions.Count -lt 2) { continue }

        $cluster = [System.Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $positions.Count; $i++) {
            if ($cluster.Count -eq 0) { $cluster.Add($positions[$i]); continue }

            $gap = $positions[$i] - $cluster[$cluster.Count - 1]
            if ($gap -le $MaxGap) { $cluster.Add($positions[$i]) }
            else {
                $emitted = _EmitCluster $cluster $Marker $stream.Name
                if ($emitted) { $results.Add($emitted) }
                $cluster = [System.Collections.Generic.List[int]]::new()
                $cluster.Add($positions[$i])
            }
        }

        $emitted = _EmitCluster $cluster $Marker $stream.Name
        if ($emitted) { $results.Add($emitted) }
    }

    return $results
}

function Get-CreoCandidateMarkers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Top = 50,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $streamCount = [Math]::Max(@($streams).Count, 1)
    $stats = @{}

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = $stream.PayloadStart
        $end = $start + $stream.PayloadLength - 1

        for ($i = $start + 1; $i -lt $end; $i++) {
            $b = $bytes[$i]

            if (-not $stats.ContainsKey($b)) {
                $stats[$b] = @{
                    Count   = 0
                    Streams = [System.Collections.Generic.HashSet[string]]::new()
                    Prev    = [System.Collections.Generic.HashSet[byte]]::new()
                    Next    = [System.Collections.Generic.HashSet[byte]]::new()
                }
            }

            $s = $stats[$b]
            $s.Count++
            [void]$s.Streams.Add($stream.Name)
            [void]$s.Prev.Add($bytes[$i-1])
            [void]$s.Next.Add($bytes[$i+1])
        }
    }

    $results = @()
    foreach ($b in $stats.Keys) {
        if ($b -eq 0x00 -or $b -eq 0xFF -or ($b -ge 0x20 -and $b -le 0x7E)) { continue }

        $s = $stats[$b]
        if ($s.Count -lt 5) { continue }

        $coverage = $s.Streams.Count / $streamCount
        $neighborPenalty = [Math]::Max(($s.Prev.Count + $s.Next.Count), 1)
        $score = [Math]::Round((($s.Count * $coverage * 100) / $neighborPenalty), 2)

        $results += [PSCustomObject]@{
            Marker              = ("{0:X2}" -f $b)
            Frequency           = $s.Count
            StreamCount         = $s.Streams.Count
            StreamCoveragePct   = [Math]::Round($coverage * 100, 2)
            UniquePreviousBytes = $s.Prev.Count
            UniqueNextBytes     = $s.Next.Count
            Score               = $score
        }
    }

    return $results | Sort-Object -Property Score -Descending | Select-Object -First $Top
}

function Get-CreoMarkerPairs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinCount = 5,
        [int]$MaxResults = 50,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $pairs = @{}

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = $stream.PayloadStart
        $end = $start + $stream.PayloadLength - 2

        $last = @{}

        for ($i = $start; $i -le $end; $i++) {
            $a = $bytes[$i]
            $b = $bytes[$i+1]

            if (($a -ge 0x20 -and $a -le 0x7E) -and ($b -ge 0x20 -and $b -le 0x7E)) { continue }
            if ($a -eq 0 -and $b -eq 0) { continue }

            $key = "{0:X2} {1:X2}" -f $a, $b

            if (-not $pairs.ContainsKey($key)) {
                $pairs[$key] = @{
                    Count    = 0
                    Streams  = [System.Collections.Generic.HashSet[string]]::new()
                    Spacing  = [System.Collections.Generic.List[int]]::new()
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }

            $p = $pairs[$key]
            $p.Count++
            [void]$p.Streams.Add($stream.Name)
            if ($p.Examples.Count -lt 3) { $p.Examples.Add(("0x{0:X8}" -f $i)) }

            if ($last.ContainsKey($key)) { $p.Spacing.Add($i - $last[$key]) }
            $last[$key] = $i
        }
    }

    $results = @()
    foreach ($key in $pairs.Keys) {
        $p = $pairs[$key]
        if ($p.Count -lt $MinCount) { continue }

        $avg = 0
        $median = 0
        if ($p.Spacing.Count -gt 0) {
            $sorted = $p.Spacing | Sort-Object
            $avg = [Math]::Round((($sorted | Measure-Object -Average).Average), 2)
            $median = $sorted[[Math]::Floor($sorted.Count / 2)]
        }

        $results += [PSCustomObject]@{
            Sequence        = $key
            Count           = $p.Count
            DistinctStreams = $p.Streams.Count
            AvgSpacing      = $avg
            MedianSpacing   = $median
            ExampleOffsets  = ($p.Examples -join ", ")
        }
    }

    return $results | Sort-Object -Property Count -Descending | Select-Object -First $MaxResults
}

function Test-CreoTlvHypothesis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte]$Marker,
        [ValidateSet(1,2,4)][int]$LengthBytes = 1,
        [ValidateSet('LE','BE')][string]$Endian = 'LE',
        [int]$HeaderOffset = 0,
        [int]$Tolerance = 0,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $samples = New-Object System.Collections.Generic.List[object]

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        $positions = New-Object System.Collections.Generic.List[int]
        if ($script:UseCSharpEngine) {
            $positions.AddRange([int[]][CreoNative]::FindByteOccurrences($bytes, $start, $end + 1, $Marker))
        }
        else {
            for ($i = $start; $i -le $end; $i++) { if ($bytes[$i] -eq $Marker) { $positions.Add($i) } }
        }
        if ($positions.Count -lt 2) { continue }

        for ($k = 0; $k -lt ($positions.Count - 1); $k++) {
            $markerOffset = $positions[$k]
            $lenStart = $markerOffset + 1 + $HeaderOffset

            if (($lenStart + $LengthBytes - 1) -gt $end) { continue }

            $lenBytes = $bytes[$lenStart..($lenStart + $LengthBytes - 1)]
            if ($Endian -eq 'BE') { [array]::Reverse($lenBytes) }

            $candidateLength = switch ($LengthBytes) {
                1 { [int]$lenBytes[0] }
                2 { [BitConverter]::ToUInt16($lenBytes, 0) }
                4 { [BitConverter]::ToUInt32($lenBytes, 0) }
            }

            $valueStart = $lenStart + $LengthBytes
            $actualGap = $positions[$k + 1] - $valueStart

            $samples.Add([PSCustomObject]@{
                Stream          = $stream.Name
                MarkerOffset    = ("0x{0:X8}" -f $markerOffset)
                CandidateLength = $candidateLength
                ActualGap       = $actualGap
                AbsError        = [Math]::Abs($candidateLength - $actualGap)
                Match           = ([Math]::Abs($candidateLength - $actualGap) -le $Tolerance)
            })
        }
    }

    $matchCount = ($samples | Where-Object { $_.Match }).Count
    $total = $samples.Count
    $matchRate = if ($total -gt 0) { [Math]::Round(100.0 * $matchCount / $total, 1) } else { 0.0 }
    $avgAbsError = if ($total -gt 0) { [Math]::Round((($samples | Measure-Object -Property AbsError -Average).Average), 2) } else { $null }

    [PSCustomObject]@{
        Marker          = $Marker.ToString("X2")
        LengthBytes     = $LengthBytes
        Endian          = $Endian
        HeaderOffset    = $HeaderOffset
        SampleCount     = $total
        MatchCount      = $matchCount
        MatchRatePct    = $matchRate
        AvgAbsError     = $avgAbsError
        Samples         = $samples
    }
}

function Get-CreoStringContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$SearchText,
        [int]$ContextBytes = 24,
        [switch]$CaseSensitive,
        [object[]]$KnownMarkers = $script:DefaultCreoMarkers,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($text in $SearchText) {
        $needle = [System.Text.Encoding]::ASCII.GetBytes($text)

        foreach ($stream in $streams) {
            if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

            $start = [int]$stream.PayloadStart
            [byte[]]$payload = $bytes[$start..($start + [int]$stream.PayloadLength - 1)]

            for ($i = 0; $i -le ($payload.Length - $needle.Length); $i++) {
                $match = $true
                for ($j = 0; $j -lt $needle.Length; $j++) {
                    $a = $payload[$i + $j]
                    $b = $needle[$j]
                    if (-not $CaseSensitive) {
                        if ($a -ge 65 -and $a -le 90) { $a += 32 }
                        if ($b -ge 65 -and $b -le 90) { $b += 32 }
                    }
                    if ($a -ne $b) { $match = $false; break }
                }
                if (-not $match) { continue }

                $beforeStart = [Math]::Max(0, $i - $ContextBytes)
                $before = if ($i -gt $beforeStart) { $payload[$beforeStart..($i - 1)] } else { @() }
                $matchBytes = $payload[$i..($i + $needle.Length - 1)]
                $afterStart = $i + $needle.Length
                $afterEnd = [Math]::Min($payload.Length - 1, $afterStart + $ContextBytes - 1)
                $after = if ($afterEnd -ge $afterStart) { $payload[$afterStart..$afterEnd] } else { @() }

                $markersFound = New-Object System.Collections.Generic.List[string]
                $windowStart = $beforeStart
                $window = @($before) + @($matchBytes) + @($after)
                foreach ($m in $KnownMarkers) {
                    $mNeedle = [byte[]]$m.Bytes
                    $offsets = Find-BytePatternOffsets -Payload $window -Needle $mNeedle
                    foreach ($off in $offsets) {
                        $relToMatch = ($windowStart + $off) - $i
                        $markersFound.Add("$($m.Name)@$relToMatch")
                    }
                }

                $results.Add([PSCustomObject]@{
                    Stream         = $stream.Name
                    Offset         = ("0x{0:X8}" -f ($start + $i))
                    RelativeOffset = ("0x{0:X8}" -f $i)
                    MatchedText    = $text
                    BeforeHex      = ConvertTo-HexString $before
                    MatchHex       = ConvertTo-HexString $matchBytes
                    AfterHex       = ConvertTo-HexString $after
                    FullAscii      = ConvertTo-AsciiString $window
                    MarkersFound   = ($markersFound -join ", ")
                })
            }
        }
    }

    return $results
}

function Get-CreoMarkerValueDistribution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte]$Marker,
        [int]$ValueBytes = 1,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $counts = @{}
    $total = 0

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        for ($i = $start; $i -le $end; $i++) {
            if ($bytes[$i] -ne $Marker) { continue }
            if (($i + $ValueBytes) -gt $end) { continue }

            $valueBytesSlice = $bytes[($i + 1)..($i + $ValueBytes)]
            $key = ConvertTo-HexString $valueBytesSlice

            if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
            $counts[$key]++
            $total++
        }
    }

    $distinctCount = $counts.Keys.Count

    $counts.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
        [PSCustomObject]@{
            Marker          = $Marker.ToString("X2")
            FollowingValue  = $_.Key
            Count           = $_.Value
            PctOfOccurrences = if ($total -gt 0) { [Math]::Round(100.0 * $_.Value / $total, 1) } else { 0 }
            DistinctValues  = $distinctCount
            TotalOccurrences = $total
        }
    }
}

function Find-CreoMarkerMotifs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [byte[]]$MarkerBytes = @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF),
        [int]$MaxGap = 3,
        [int]$MinMotifLength = 2,
        [int]$MaxMotifLength = 4,
        [int]$Top = 30,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    $bytes = $context.Data

    $markerSet = New-Object 'System.Collections.Generic.HashSet[byte]'
    foreach ($m in $MarkerBytes) { [void]$markerSet.Add([byte]$m) }

    $motifs = @{}

    function _AddMotif {
        param([byte[]]$Seq, [string]$StreamName, [int]$Offset)

        $key = ConvertTo-HexString $Seq
        if (-not $motifs.ContainsKey($key)) {
            $motifs[$key] = @{
                Count    = 0
                Streams  = [System.Collections.Generic.HashSet[string]]::new()
                Examples = [System.Collections.Generic.List[string]]::new()
            }
        }
        $motifs[$key].Count++
        [void]$motifs[$key].Streams.Add($StreamName)
        if ($motifs[$key].Examples.Count -lt 3) { $motifs[$key].Examples.Add(("0x{0:X8}" -f $Offset)) }
    }

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $start = [int]$stream.PayloadStart
        $end = $start + [int]$stream.PayloadLength - 1

        $events = New-Object System.Collections.Generic.List[int]
        for ($i = $start; $i -le $end; $i++) { if ($markerSet.Contains($bytes[$i])) { $events.Add($i) } }
        if ($events.Count -lt $MinMotifLength) { continue }

        $runStart = 0
        for ($idx = 1; $idx -le $events.Count; $idx++) {
            $isLast = ($idx -eq $events.Count)
            $gapExceeded = $false
            if (-not $isLast) { $gapExceeded = ($events[$idx] - $events[$idx - 1]) -gt $MaxGap }

            if ($isLast -or $gapExceeded) {
                $runEvents = $events.GetRange($runStart, $idx - $runStart)

                if ($runEvents.Count -ge $MinMotifLength) {
                    $maxWin = [Math]::Min($MaxMotifLength, $runEvents.Count)
                    for ($winLen = $MinMotifLength; $winLen -le $maxWin; $winLen++) {
                        for ($w = 0; $w -le ($runEvents.Count - $winLen); $w++) {
                            $seqOffsets = $runEvents.GetRange($w, $winLen)
                            $seqBytes = [byte[]]::new($winLen)
                            for ($z = 0; $z -lt $winLen; $z++) { $seqBytes[$z] = $bytes[$seqOffsets[$z]] }
                            _AddMotif -Seq $seqBytes -StreamName $stream.Name -Offset $seqOffsets[0]
                        }
                    }
                }

                $runStart = $idx
            }
        }
    }

    $results = foreach ($key in $motifs.Keys) {
        $m = $motifs[$key]
        [PSCustomObject]@{
            Motif           = $key
            Count           = $m.Count
            DistinctStreams = $m.Streams.Count
            ExampleOffsets  = ($m.Examples -join ", ")
        }
    }

    return $results | Sort-Object -Property Count -Descending | Select-Object -First $Top
}

function Get-CreoStreamSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$ResolvedStream,
        [Parameter(Mandatory)][byte[]]$FileBytes
    )

    if (-not (Test-CreoStreamRange $ResolvedStream $FileBytes.Length)) { return @() }

    $streamStart = [int]$ResolvedStream.PayloadStart
    $streamBytes = $FileBytes[$streamStart..($streamStart + [int]$ResolvedStream.PayloadLength - 1)]
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $i = 0
    while ($i -lt ($streamBytes.Length - 2)) {
        if ($streamBytes[$i] -eq 0xE0) {
            $typeByte = $streamBytes[$i + 1]
            $stringStart = $i + 2

            $nullIdx = $stringStart
            while ($nullIdx -lt $streamBytes.Length -and $streamBytes[$nullIdx] -ne 0x00) { $nullIdx++ }

            if ($nullIdx -lt $streamBytes.Length -and $nullIdx -gt $stringStart) {
                $propName = [System.Text.Encoding]::ASCII.GetString($streamBytes[$stringStart..($nullIdx - 1)])

                if ($propName -match '^[A-Za-z0-9_#-]+$') {
                    $results.Add([PSCustomObject]@{
                        Stream         = $ResolvedStream.Name
                        AbsoluteOffset = $streamStart + $i
                        OpcodeType     = "0xE0 {0:X2}" -f $typeByte
                        PropertyName   = $propName
                        ValueOffset    = $streamStart + $nullIdx + 1
                    })
                }
                $i = $nullIdx
            }
            else { $i++ }
        }
        else { $i++ }
    }

    return $results
}

function Get-CreoStreamName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'File')]
        [string[]]$Path
    )

    process {
        foreach ($file in $Path) {
            if (-not (Test-Path -LiteralPath $file)) {
                Write-Warning "File not found: $file"
                continue
            }

            $resolved = Resolve-CreoFileStreams -Path $file
            if ($resolved -and $resolved.Streams) {
                foreach ($stream in $resolved.Streams) {
                    [PSCustomObject]@{ File = $file; StreamName = $stream.Name }
                }
            }
        }
    }
}

function Get-CreoModelStreamSchema {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Path = ".\models",
        [string]$Filter = "*.prt.*,*.asm.*",
        [string]$OutputFile = ".\CreoAnalysisResults\AllStreams_Schema.csv",
        [switch]$SummaryOnly
    )

    process {
        $allResults = [System.Collections.Generic.List[object]]::new()

        foreach ($searchPath in $Path) {
            $targetPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($searchPath)

            if (Test-Path -Path $targetPath -PathType Container) {
                $filters = $Filter -split ','
                $files = foreach ($f in $filters) { Get-ChildItem -Path $targetPath -File -Filter $f.Trim() }
                $files = $files | Sort-Object FullName -Unique
            }
            elseif (Test-Path -Path $targetPath -PathType Leaf) { $files = Get-Item -Path $targetPath }
            else { Write-Warning "Path not found: $targetPath"; continue }

            foreach ($file in $files) {
                Write-Host "Processing file: $($file.Name)" -ForegroundColor Cyan
                $resolved = Resolve-CreoFileStreams -Path $file.FullName

                if (-not ($resolved -and $resolved.Streams)) { continue }

                foreach ($stream in $resolved.Streams) {
                    $schema = Get-CreoStreamSchema -ResolvedStream $stream -FileBytes $resolved.Data
                    if (-not $schema) { continue }

                    if ($SummaryOnly) {
                        $allResults.Add([PSCustomObject]@{ File = $file.Name; StreamName = $stream.Name; TokenCount = @($schema).Count })
                    }
                    else {
                        foreach ($item in $schema) {
                            $allResults.Add([PSCustomObject]@{
                                File           = $file.Name
                                StreamName     = $item.Stream
                                AbsoluteOffset = $item.AbsoluteOffset
                                OpcodeType     = $item.OpcodeType
                                PropertyName   = $item.PropertyName
                                ValueOffset    = $item.ValueOffset
                            })
                        }
                    }
                }
            }
        }

        if ($allResults.Count -gt 0) {
            $outputDir = Split-Path -Parent $OutputFile
            if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
            $allResults | Export-Csv -Path $OutputFile -NoTypeInformation
            Write-Host "Schema extraction complete. $($allResults.Count) rows saved to: $OutputFile" -ForegroundColor Green
        }
        else { Write-Warning "No schema records extracted from the specified path." }

        return $allResults
    }
}

function Measure-CreoValueWidth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [byte[]]$TypeBytes,
        [string[]]$StreamNames,
        [Parameter()]$ResolvedStreams
    )

    $context = Resolve-CreoStreamsNormalized -Path $Path -ResolvedStreams $ResolvedStreams
    $streams = @($context.Streams)
    if ($StreamNames) { $streams = $streams | Where-Object { $_.Name -in $StreamNames } }
    $bytes = $context.Data

    $widthsByType = @{}
    $samplesByType = @{}

    foreach ($stream in $streams) {
        if (-not (Test-CreoStreamRange $stream $bytes.Length)) { continue }

        $streamStart = [int]$stream.PayloadStart
        $streamEnd = $streamStart + [int]$stream.PayloadLength - 1

        $schema = Get-CreoStreamSchema -ResolvedStream $stream -FileBytes $bytes
        if (-not $schema -or $schema.Count -eq 0) { continue }

        $e0Offsets = New-Object System.Collections.Generic.List[int]
        if ($script:UseCSharpEngine) {
            $e0Offsets.AddRange([int[]][CreoNative]::FindByteOccurrences($bytes, $streamStart, $streamEnd + 1, 0xE0))
        }
        else {
            for ($p = $streamStart; $p -le $streamEnd; $p++) { if ($bytes[$p] -eq 0xE0) { $e0Offsets.Add($p) } }
        }

        $e0Idx = 0
        foreach ($entry in $schema) {
            $typeHex = ($entry.OpcodeType -split ' ')[1]
            if ($TypeBytes -and ([Convert]::ToByte($typeHex, 16) -notin $TypeBytes)) { continue }

            $valueStart = [int]$entry.ValueOffset
            while ($e0Idx -lt $e0Offsets.Count -and $e0Offsets[$e0Idx] -le $valueStart) { $e0Idx++ }
            $nextE0 = if ($e0Idx -lt $e0Offsets.Count) { $e0Offsets[$e0Idx] } else { $null }
            $width = if ($nextE0) { $nextE0 - $valueStart } else { $streamEnd - $valueStart + 1 }

            if (-not $widthsByType.ContainsKey($typeHex)) {
                $widthsByType[$typeHex] = New-Object System.Collections.Generic.List[int]
                $samplesByType[$typeHex] = New-Object System.Collections.Generic.List[string]
            }
            $widthsByType[$typeHex].Add($width)
            if ($samplesByType[$typeHex].Count -lt 3) { $samplesByType[$typeHex].Add("$($entry.Stream):$($entry.PropertyName)") }
        }
    }

    $results = foreach ($key in $widthsByType.Keys) {
        $vals = $widthsByType[$key]
        $sorted = $vals | Sort-Object
        $mean = ($vals | Measure-Object -Average).Average
        $variance = if ($vals.Count -gt 1) { (($vals | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum) / ($vals.Count - 1) } else { 0 }
        $modeGroup = $vals | Group-Object | Sort-Object Count -Descending | Select-Object -First 1

        [PSCustomObject]@{
            TypeByte      = $key
            SampleCount   = $vals.Count
            MinWidth      = $sorted[0]
            MaxWidth      = $sorted[-1]
            AvgWidth      = [Math]::Round($mean, 2)
            MedianWidth   = $sorted[[Math]::Floor(($sorted.Count - 1) / 2)]
            StdDev        = [Math]::Round([Math]::Sqrt($variance), 2)
            ModeWidth     = $modeGroup.Name
            ModePct       = [Math]::Round(100.0 * $modeGroup.Count / $vals.Count, 1)
            ExampleFields = ($samplesByType[$key] -join ", ")
        }
    }

    return $results | Sort-Object -Property SampleCount -Descending
}

function Find-CreoString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Pattern,
        [Alias("B")][int]$BeforeContext = 32,
        [Alias("A")][int]$AfterContext = 64,
        [Alias("C")][int]$Context = -1,
        [Alias("Quiet")][switch]$AddressOnly,
        [switch]$Raw,
        [switch]$IgnoreCase
    )

    begin {
        $bytesBefore = if ($Context -ge 0) { $Context } else { $BeforeContext }
        $bytesAfter  = if ($Context -ge 0) { $Context } else { $AfterContext }
        $forceRaw = $Raw.IsPresent -or $PSBoundParameters.ContainsKey('Context') -or
                    $PSBoundParameters.ContainsKey('BeforeContext') -or $PSBoundParameters.ContainsKey('AfterContext')
        $seenPaths = New-Object System.Collections.Generic.HashSet[string]
    }

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                if (-not $seenPaths.Add($rp.Path)) { continue }

                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $bytes = $resolved.Data
                $fileMatches = New-Object System.Collections.Generic.List[object]

                $sortedStreams = @($resolved.Streams | Sort-Object PayloadStart)
                $streamCount = $sortedStreams.Count
                $needHexDump = $forceRaw -and (-not $AddressOnly.IsPresent)

                foreach ($term in $Pattern) {
                    if ([string]::IsNullOrEmpty($term)) { continue }
                    $needle = [System.Text.Encoding]::ASCII.GetBytes($term)

                    $offsets = if ($script:UseCSharpEngine) {
                        [CreoNative]::FindBytePattern($bytes, $needle, $IgnoreCase.IsPresent)
                    }
                    else { Find-BytePatternOffsets -Payload $bytes -Needle $needle }

                    $streamIdx = 0
                    foreach ($i in $offsets) {
                        while ($streamIdx -lt $streamCount -and
                               ($sortedStreams[$streamIdx].PayloadStart + $sortedStreams[$streamIdx].PayloadLength) -le $i) {
                            $streamIdx++
                        }

                        $streamName = "UNRESOLVED_REGION"
                        if ($streamIdx -lt $streamCount -and
                            $sortedStreams[$streamIdx].PayloadStart -le $i -and
                            $i -lt ($sortedStreams[$streamIdx].PayloadStart + $sortedStreams[$streamIdx].PayloadLength)) {
                            $streamName = $sortedStreams[$streamIdx].Name
                        }

                        $hexDump = $null
                        if ($needHexDump) {
                            $start = [Math]::Max(0, $i - $bytesBefore)
                            $end = [Math]::Min($bytes.Length, $i + $term.Length + $bytesAfter)
                            $hexDump = if ($script:UseCSharpEngine) { [CreoNative]::GenerateHexDump($bytes, $start, $end) }
                            else { Format-HexWindow -Data $bytes -StartOffset $start -Length ($end - $start) }
                        }

                        $fileMatches.Add([PSCustomObject]@{
                            FileName   = $fileInfo.Name
                            SearchTerm = $term
                            Stream     = $streamName
                            OffsetHex  = ("0x{0:X8}" -f $i)
                            OffsetDec  = $i
                            HexDump    = $hexDump
                        })
                    }
                }

                if ($fileMatches.Count -eq 0) { continue }

                if ($forceRaw) { $fileMatches | ForEach-Object { $_ } }
                else {
                    $fileMatches | Group-Object SearchTerm, Stream | ForEach-Object {
                        [PSCustomObject]@{
                            FileName   = $fileInfo.Name
                            SearchTerm = $_.Group[0].SearchTerm
                            Stream     = $_.Group[0].Stream
                            HitCount   = $_.Count
                            Offsets    = (($_.Group | Select-Object -ExpandProperty OffsetHex) -join ", ")
                        }
                    }
                }
            }
        }
    }
}

function Get-CreoParametersFromPayloadPS {
    param([byte[]]$Payload)

    $results = New-Object System.Collections.Generic.List[object]
    $scanLimit = $Payload.Length - 12

    for ($i = 0; $i -lt $scanLimit; $i++) {
        if ($Payload[$i] -ne 0xE1 -or $Payload[$i + 1] -ne 0xE1) { continue }

        $isPart = $Payload[$i + 2] -eq 0x00 -and $Payload[$i + 3] -eq 0xE3
        $isAsm  = $Payload[$i + 2] -eq 0x01 -and $Payload[$i + 3] -eq 0xE3
        if (-not $isPart -and -not $isAsm) { continue }

        $nameStart = $i + 4
        $nameEnd = -1
        for ($z = $nameStart; $z -lt $Payload.Length; $z++) { if ($Payload[$z] -eq 0) { $nameEnd = $z; break } }
        if ($nameEnd -le $nameStart) { continue }

        $name = [System.Text.Encoding]::ASCII.GetString($Payload[$nameStart..($nameEnd - 1)])
        $validName = $name.Length -gt 2
        if ($validName) {
            foreach ($ch in $name.ToCharArray()) {
                if (-not (($ch -ge 'A' -and $ch -le 'Z') -or ($ch -ge '0' -and $ch -le '9') -or $ch -eq '_')) { $validName = $false; break }
            }
        }
        if (-not $validName) { continue }

        $typeMarkerStart = $nameEnd + 1
        if (($typeMarkerStart + 1) -ge $Payload.Length) { continue }

        $typeHex = ([int]$Payload[$typeMarkerStart] -shl 8) -bor [int]$Payload[$typeMarkerStart + 1]
        $typeName = switch ($typeHex) {
            0xE232 { "Real" }
            0xE233 { "String" }
            0xE234 { "Integer" }
            0xE235 { "Boolean" }
            default { "Unknown" }
        }

        $valueStart = $typeMarkerStart + 2
        $value = $null
        $jumpIndex = $valueStart

        # NOTE: previously this scanned up to 16 bytes forward for "the
        # first printable byte" before extracting anything. That broke
        # empty String values: a 0x00 immediately at valueStart IS a valid
        # empty string, but the old scan walked past it, through the next
        # parameter frame's own header bytes, and landed on the NEXT
        # parameter's name - reporting it as this parameter's value.
        # Confirmed via REFERENCE_3..REFERENCE_6 in start-assembly.asm.1 (all
        # empty; old code reported REFERENCE_3's value as "REFERENCE_4",
        # REFERENCE_5's as "REFERENCE_6", etc). Mirrors the C# fix exactly.
        if ($valueStart -lt $Payload.Length) {
            switch ($typeName) {
                "Boolean" {
                    if (($valueStart + 3) -lt $Payload.Length) {
                        $value = if ($Payload[$valueStart] -eq 0x01) { "YES" } else { "NO" }
                        $jumpIndex = $valueStart + 4
                    }
                }
                "Integer" {
                    if (($valueStart + 7) -lt $Payload.Length) {
                        $value = "(Integer - raw payload not decoded)"
                        $jumpIndex = $valueStart + 8
                    }
                }
                "Real" {
                    if (($valueStart + 7) -lt $Payload.Length) {
                        $value = "(Real - raw payload not decoded)"
                        $jumpIndex = $valueStart + 8
                    }
                }
                "String" {
                    if ($Payload[$valueStart] -eq 0x00) {
                        $value = ""
                        $jumpIndex = $valueStart + 1
                    }
                    else {
                        $valueEnd = -1
                        for ($z = $valueStart; $z -lt $Payload.Length; $z++) { if ($Payload[$z] -eq 0) { $valueEnd = $z; break } }
                        if ($valueEnd -gt $valueStart) {
                            $value = [System.Text.Encoding]::ASCII.GetString($Payload[$valueStart..($valueEnd - 1)])
                            $jumpIndex = $valueEnd
                        }
                    }
                }
            }
        }

        if ($null -ne $value) { $results.Add([PSCustomObject]@{ ParameterName = $name; ParameterValue = $value; TypeName = $typeName }) }
        $i = [Math]::Max($i, $jumpIndex)
    }

    return $results
}

function Get-CreoParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string[]]$StreamNames = @("NeuPrtSld", "NeuAsmSld", "LargeText", "FullMData", "MdlStatus", "MdlRefInfo"),
        [string[]]$NoiseList = @(
            "ConfigName", "PITCH", "THREADS_PER_INCH", "THREAD_SERIES", "SCREW_SIZE", "CSINK_DIAMETER",
            "CSINK_ANGLE", "DRILL_DIAMETER", "THREAD_DIAMETER", "CLASS", "METRIC", "BOTCSINK_DIAM",
            "BOTCSINK_ANGLE", "NEUT_SPEC_ATTR_SOLID_STATE"
        ),
        [string[]]$PtcExceptions = @("PTC_MASTER_MATERIAL", "PTC_COMMON_NAME"),
        [switch]$IncludeNoise
    )

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $streams = $resolved.Streams | Where-Object { $_.Name -in $StreamNames }

                foreach ($stream in $streams) {
                    $payload = $resolved.Data[$stream.PayloadStart..($stream.PayloadStart + $stream.PayloadLength - 1)]

                    $hits = if ($script:UseCSharpEngine) { [CreoNative]::ExtractParameters($payload) }
                    else { Get-CreoParametersFromPayloadPS -Payload $payload }

                    foreach ($p in $hits) {
                        $isPtc = $p.ParameterName.StartsWith("PTC_") -and ($p.ParameterName -notin $PtcExceptions)
                        $isNoise = $isPtc -or ($p.ParameterName -in $NoiseList)
                        if ($isNoise -and -not $IncludeNoise.IsPresent) { continue }

                        [PSCustomObject]@{
                            File           = $fileInfo.Name
                            Stream         = $stream.Name
                            ParameterName  = $p.ParameterName
                            ParameterValue = $p.ParameterValue
                            TypeName       = $p.TypeName
                            IsNoise        = $isNoise
                        }
                    }
                }
            }
        }
    }
}

Export-ModuleMember -Function `
    Get-CreoDataMaps, `
    Search-CreoBinaryString, `
    Resolve-CreoFileStreams, `
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
    Get-CreoMarkerPairs, `
    Test-CreoTlvHypothesis, `
    Get-CreoStringContext, `
    Get-CreoMarkerValueDistribution, `
    Find-CreoMarkerMotifs, `
    Get-CreoStreamSchema, `
    Get-CreoStreamName, `
    Get-CreoModelStreamSchema, `
    Measure-CreoValueWidth, `
    Find-CreoString, `
    Get-CreoParameter
