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

public class CreoNamedFrameHit {
    public string Name;
    public string Value;
    public string TypeName;
    public int Offset;
}

public class CreoInstanceHit {
    public string RawName;
    public string MarkerType;
    public int Offset;
}

public class CreoNullTerminatedString {
    public string Text;
    public int EndByteIndex;
}

public class PrintableRun {
    public int Offset;
    public string Value;
}

public static class CreoNative {
    // Ported for Get-CreoInstanceBOM.
    // Finds E3 7B E2 and literal "name\\0" instance markers and returns
    // the raw extracted name, marker type, and marker offset.
    public static CreoInstanceHit[] ExtractInstanceMarkers(byte[] bytes) {
        var results = new List<CreoInstanceHit>();
        byte[] markerA = { 0xE3, 0x7B, 0xE2 };
        byte[] markerB = { 0x6E, 0x61, 0x6D, 0x65, 0x00 }; // "name\\0"
        int scanLimit = bytes.Length - 10;

        for (int i = 0; i < scanLimit; i++) {
            bool isA = true;
            for (int j = 0; j < markerA.Length; j++) {
                if (bytes[i + j] != markerA[j]) { isA = false; break; }
            }

            bool isB = false;
            if (!isA) {
                isB = true;
                for (int j = 0; j < markerB.Length; j++) {
                    if (bytes[i + j] != markerB[j]) { isB = false; break; }
                }
                if (isB && i > 0 && bytes[i - 1] == 0x5F) { isB = false; }
            }

            if (!isA && !isB) continue;

            int offsetShift = isA ? 4 : markerB.Length;
            int stringStart = i + offsetShift;
            int stringEnd = Array.IndexOf(bytes, (byte)0, stringStart);

            if (stringEnd > stringStart) {
                string rawString = Encoding.ASCII.GetString(bytes, stringStart, stringEnd - stringStart);
                string cleanName = rawString.Split('#')[0];

                var sb = new StringBuilder();
                bool inTag = false;
                for (int s = 0; s < cleanName.Length; s++) {
                    char ch = cleanName[s];
                    if (ch == '<') { inTag = true; continue; }
                    if (ch == '>') { inTag = false; continue; }
                    if (!inTag) sb.Append(ch);
                }

                string cleanNameStr = sb.ToString().Trim();

                bool isValid = cleanNameStr.Length > 5;
                if (isValid) {
                    for (int c = 0; c < cleanNameStr.Length; c++) {
                        char ch = cleanNameStr[c];
                        if (!((ch >= 'A' && ch <= 'Z') ||
                              (ch >= 'a' && ch <= 'z') ||
                              (ch >= '0' && ch <= '9') ||
                              ch == '_' || ch == '-')) {
                            isValid = false;
                            break;
                        }
                    }
                }

                if (isValid) {
                    results.Add(new CreoInstanceHit {
                        RawName = cleanNameStr,
                        MarkerType = isA ? "E3_7B_E2" : "name_literal",
                        Offset = i
                    });
                }

                i = stringEnd;
            }
        }

        return results.ToArray();
    }

    // Ported for Get-CreoVersionHistory.
    // Matches the PowerShell Get-CreoNullTerminatedStringsFromPayloadPS
    // behavior exactly: printable ASCII runs are retained only when
    // terminated by 0x00; any other non-printable byte clears the run.
    // EndByteIndex is the null terminator's index, which the PowerShell
    // timestamp logic uses directly.
    public static CreoNullTerminatedString[] ExtractNullTerminatedStrings(byte[] data, int minLen) {
        var results = new List<CreoNullTerminatedString>();
        var current = new List<byte>();

        for (int i = 0; i < data.Length; i++) {
            byte b = data[i];

            if (b >= 32 && b <= 126) {
                current.Add(b);
            }
            else if (b == 0x00 && current.Count >= minLen) {
                results.Add(new CreoNullTerminatedString {
                    Text = Encoding.ASCII.GetString(current.ToArray(), 0, current.Count),
                    EndByteIndex = i
                });
                current.Clear();
            }
            else {
                current.Clear();
            }
        }

        return results.ToArray();
    }

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
            // company_start_asm.asm.1 (all empty; old code reported REFERENCE_3's
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
    // Same E1 E1 [00|01] E3 <name>\0 E2 <typeByte> ... frame as
    // ExtractParameters above, but matched against a caller-supplied set
    // of exact names instead of the ALL-CAPS-only validName filter.
    // Needed for internal Creo fields like "ConfigName" that are
    // mixed-case and silently fail that filter - not an error, just
    // never a hit. Built for BOM extraction: enclosure.asm.5 showed
    // "ConfigName" repeating once per component instance, String value =
    // component name. See the validation-status note above this file
    // before trusting Quantity on files you haven't checked by hand.
    public static CreoNamedFrameHit[] ExtractNamedFrames(byte[] bytes, string[] targetNames) {
        var results = new List<CreoNamedFrameHit>();
        var targets = new HashSet<string>(targetNames, StringComparer.Ordinal);
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
            if (!targets.Contains(name)) continue;

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

            // Same empty-string-safe extraction as ExtractParameters -
            // see the NOTE above ExtractParameters for why this matters
            // (REFERENCE_3..REFERENCE_6 empty-value bug).
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
                results.Add(new CreoNamedFrameHit { Name = name, Value = value, TypeName = typeName, Offset = i });
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
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Strings,

        [int]$MinFields = 8
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $pages   = New-Object System.Collections.Generic.List[object]
    $echoes  = New-Object System.Collections.Generic.List[object]
    $endMarkers = New-Object System.Collections.Generic.List[object]

    # Trailing '#' padding is stripped before tokenizing.
    foreach ($s in $Strings) {
        if ($null -eq $s) {
            continue
        }

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

# function ConvertTo-HexString {
#     [CmdletBinding()]
#     param(
#         [AllowNull()]
#         [byte[]]$Bytes
#     )
# 
#     if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
#         return ''
#     }
# 
#     return (($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
# }


function ConvertFrom-HexString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$HexString
    )

    # Allows spaces, commas, colons, hyphens, and 0x prefixes.
    $normalized = $HexString -replace '(?i)0x', ''
    $normalized = $normalized -replace '[^0-9A-Fa-f]', ''

    if ($normalized.Length -eq 0) {
        throw "No hexadecimal bytes were found in '$HexString'."
    }

    if (($normalized.Length % 2) -ne 0) {
        throw "Hexadecimal input must contain complete byte pairs. Received '$HexString'."
    }

    [byte[]]$bytes = for ($i = 0; $i -lt $normalized.Length; $i += 2) {
        try {
            [Convert]::ToByte($normalized.Substring($i, 2), 16)
        }
        catch {
            throw "Invalid hex byte at position $i in '$HexString': $($_.Exception.Message)"
        }
    }

    return $bytes
}

function ConvertTo-AsciiString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    return (($Bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join '')
}

# function Resolve-CreoFileStreams {
#     param([Parameter(Mandatory)][string]$Path)
# 
#     if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
# 
#     [byte[]]$Data = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))
#     $strings = Get-PrintableStrings -Data $Data -MinLen 6
#     $parsed  = Parse-TocEntries -Strings $strings -MinFields 8
#     $streams = Resolve-StreamRanges -Entries $parsed.Entries -Data $Data
# 
#     $usable = $streams | Where-Object {
#         $_.PayloadLength -gt 0 -and ($_.PayloadStart + $_.PayloadLength) -le $Data.Length
#     }
# 
#     [PSCustomObject]@{
#         Data    = $Data
#         Strings = $strings
#         Parsed  = $parsed
#         Streams = $usable
#     }
# }

function Resolve-CreoFileStreams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path not found: $Path"
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop

    # When a directory is passed, process every file beneath it recursively.
    if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force |
            ForEach-Object {
                Resolve-CreoFileStreams -Path $_.FullName
            }

        return
    }

    # Original single-file behavior.
    [byte[]]$Data = [System.IO.File]::ReadAllBytes($item.FullName)

    $strings = @(Get-PrintableStrings -Data $Data -MinLen 6)
    $parsed  = Parse-TocEntries -Strings $strings -MinFields 8
    $streams = Resolve-StreamRanges -Entries $parsed.Entries -Data $Data

    $usable = $streams | Where-Object {
        $_.PayloadLength -gt 0 -and
        ($_.PayloadStart + $_.PayloadLength) -le $Data.Length
    }

    [PSCustomObject]@{
        Path    = $item.FullName
        Data    = $Data
        Strings = $strings
        Parsed  = $parsed
        Streams = $usable
    }
}

function Find-BytePatternOffsets {
    param(
        [byte[]]$Payload,

        [Parameter(Mandatory)]
        [object]$Needle
    )

    [byte[]]$Needle = ConvertTo-CreoByteArray -InputObject $Needle

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
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        # Supports strings, byte arrays, or marker objects with Name + Bytes.
        [object[]]$Markers = $script:DefaultCreoMarkers,

        [ValidateRange(0, [int]::MaxValue)]
        [int]$EntropyWindow = 16
    )

    $resolved = Resolve-CreoFileStreams -Path $Path
    $Data = $resolved.Data
    $streams = $resolved.Streams

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($marker in $Markers) {
        if ($null -eq $marker) {
            Write-Warning 'Skipping a null marker.'
            continue
        }

        # Normalize every supported marker form to:
        # $markerName = display label
        # $needle     = byte[] pattern
        if ($marker -is [string]) {
            $markerName = $marker
            [byte[]]$needle = ConvertFrom-HexString -HexString $marker
        }
        elseif ($marker -is [byte[]]) {
            [byte[]]$needle = $marker
            $markerName = ConvertTo-HexString -Bytes $needle
        }
        elseif ($null -ne $marker.PSObject.Properties['Bytes']) {
            [byte[]]$needle = $marker.Bytes

            if ([string]::IsNullOrWhiteSpace([string]$marker.Name)) {
                $markerName = ConvertTo-HexString -Bytes $needle
            }
            else {
                $markerName = [string]$marker.Name
            }
        }
        else {
            throw (
                "Unsupported marker type '$($marker.GetType().FullName)'. " +
                "Use a hexadecimal string, [byte[]], or an object with a Bytes property."
            )
        }

        if ($null -eq $needle -or $needle.Length -eq 0) {
            throw "Marker '$markerName' resolved to an empty byte pattern."
        }

        $totalCount = 0
        $distinctStreams = [System.Collections.Generic.HashSet[string]]::new()
        $entropies = [System.Collections.Generic.List[double]]::new()

        foreach ($stream in $streams) {
            if ($stream.PayloadLength -le 0) {
                continue
            }

            $payloadStart = [int]$stream.PayloadStart
            $payloadLength = [int]$stream.PayloadLength
            $payloadEnd = $payloadStart + $payloadLength - 1

            # Avoid invalid array ranges when a malformed stream points outside Data.
            if ($payloadStart -lt 0 -or $payloadEnd -ge $Data.Length) {
                Write-Warning (
                    "Skipping stream '$($stream.Name)': payload range " +
                    "$payloadStart..$payloadEnd is outside the data buffer."
                )
                continue
            }

            [byte[]]$payload = $Data[$payloadStart..$payloadEnd]

            if ($payload.Length -lt $needle.Length) {
                continue
            }

            $offsets = Find-BytePatternOffsets -Payload $payload -Needle $needle

            foreach ($off in $offsets) {
                $totalCount++
                [void]$distinctStreams.Add([string]$stream.Name)

                $wStart = [Math]::Max(0, $off - $EntropyWindow)
                $wEnd = [Math]::Min(
                    $payload.Length - 1,
                    $off + $needle.Length - 1 + $EntropyWindow
                )

                if ($wEnd -ge $wStart) {
                    [byte[]]$entropyData = $payload[$wStart..$wEnd]
                    $entropies.Add((Get-Entropy -Data $entropyData))
                }
            }
        }

        $avgEntropy = if ($entropies.Count -gt 0) {
            [Math]::Round(
                ($entropies | Measure-Object -Average).Average,
                3
            )
        }
        else {
            0.0
        }

        $results.Add([PSCustomObject]@{
            Marker          = $markerName
            Pattern         = ConvertTo-HexString -Bytes $needle
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
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$Pattern,

        [int]$Context = 12,
        [int]$NearbyStringRadius = 64
    )

    [byte[]]$Pattern = ConvertTo-CreoByteArray -InputObject $Pattern

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
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [object]$Marker,

        [Parameter()]$ResolvedStreams
    )
    [byte[]]$markerBytes = ConvertTo-CreoByteArray -InputObject $Marker

    if ($markerBytes.Length -ne 1) {
        throw "-Marker must be exactly one byte, for example E3 or 0xE3."
    }

    [byte]$Marker = $markerBytes[0]


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


# Example:
# Get-ChildItem .\models\prt0001* | ForEach-Object {
#     Find-CreoMarkerClusters -Path $_.FullName -Marker E9
# }

function Find-CreoMarkerClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [object]$Marker,
        
        [int]$MaxGap = 64,
        [Parameter()]$ResolvedStreams
    )
    [byte[]]$markerBytes = ConvertTo-CreoByteArray -InputObject $Marker

    if ($markerBytes.Length -ne 1) {
        throw "-Marker must be exactly one byte, for example E3 or 0xE3."
    }

    [byte]$Marker = $markerBytes[0]


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
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$Marker,

        [ValidateSet(1,2,4)]
        [int]$LengthBytes = 1,
        
        [ValidateSet('LE','BE')]
        [string]$Endian = 'LE',
        
        [int]$HeaderOffset = 0,
        
        [int]$Tolerance = 0,
        
        [Parameter()]$ResolvedStreams
    )
    [byte[]]$markerBytes = ConvertTo-CreoByteArray -InputObject $Marker

    if ($markerBytes.Length -ne 1) {
        throw "-Marker must be exactly one byte, for example E3 or 0xE3."
    }

    [byte]$Marker = $markerBytes[0]


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
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$Marker,

        [int]$ValueBytes = 1,

        [Parameter()]$ResolvedStreams
    )
    [byte[]]$markerBytes = ConvertTo-CreoByteArray -InputObject $Marker

    if ($markerBytes.Length -ne 1) {
        throw "-Marker must be exactly one byte, for example E3 or 0xE3."
    }

    [byte]$Marker = $markerBytes[0]


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
        [object]$MarkerBytes = @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF),
        [int]$MaxGap = 3,
        [int]$MinMotifLength = 2,
        [int]$MaxMotifLength = 4,
        [int]$Top = 30,
        [Parameter()]$ResolvedStreams
    )
    [byte[]]$MarkerBytes = ConvertTo-CreoByteArray -InputObject $MarkerBytes

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
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [object]$TypeBytes,

        [string[]]$StreamNames,
        [Parameter()]$ResolvedStreams
    )

    if ($null -ne $TypeBytes) {
        [byte[]]$TypeBytes = ConvertTo-CreoByteArray -InputObject $TypeBytes
    }

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
        [switch]$IgnoreCase,
        [switch]$Color
    )

    begin {
        $bytesBefore = if ($Context -ge 0) { $Context } else { $BeforeContext }
        $bytesAfter  = if ($Context -ge 0) { $Context } else { $AfterContext }
        $forceRaw = $Raw.IsPresent -or $Color.IsPresent -or $PSBoundParameters.ContainsKey('Context') -or
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

                            if ($Color.IsPresent) {
                                Write-Host ""
                                Write-Host "--- $($fileInfo.Name) : $streamName : '$term' @ 0x$($i.ToString('X8')) ---" -ForegroundColor DarkGray
                                Write-CreoColorHexRows -Data $bytes[$start..($end - 1)] -BaseOffset $start
                            }
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
        # Confirmed via REFERENCE_3..REFERENCE_6 in company_start_asm.asm.1 (all
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

# =========================================================================
# FUNCTION: Compare-CreoStreamBytes
#   Byte-level diff of ONE named stream between two files (typically a
#   resave pair - same file before/after a specific edit). Finds the first
#   offset where the two payloads diverge and shows raw hex/ASCII on both
#   sides from that point. Built specifically for the resave-pair workflow:
#   Compare-CreoStreams tells you WHICH stream changed and by how much;
#   this tells you WHAT changed, byte for byte.
# =========================================================================
function Compare-CreoStreamBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Before,
        [Parameter(Mandatory)][string]$After,
        [Parameter(Mandatory)][string]$StreamName,
        [int]$ContextBytes = 32,
        [int]$ShowBytes = 96
    )

    $rBefore = Resolve-CreoFileStreams -Path $Before
    $rAfter  = Resolve-CreoFileStreams -Path $After

    $sBefore = $rBefore.Streams | Where-Object { $_.Name -eq $StreamName } | Select-Object -First 1
    $sAfter  = $rAfter.Streams  | Where-Object { $_.Name -eq $StreamName } | Select-Object -First 1

    if (-not $sBefore -or -not $sAfter) {
        throw "Stream '$StreamName' not found in one or both files (Before: $([bool]$sBefore), After: $([bool]$sAfter)). Run Get-CreoStreamName to check the exact name."
    }

    $bytesBefore = $rBefore.Data[$sBefore.PayloadStart..($sBefore.PayloadStart + $sBefore.PayloadLength - 1)]
    $bytesAfter  = $rAfter.Data[$sAfter.PayloadStart..($sAfter.PayloadStart + $sAfter.PayloadLength - 1)]

    $minLen = [Math]::Min($bytesBefore.Length, $bytesAfter.Length)
    $divergeAt = $minLen
    for ($i = 0; $i -lt $minLen; $i++) {
        if ($bytesBefore[$i] -ne $bytesAfter[$i]) { $divergeAt = $i; break }
    }

    if ($divergeAt -eq $minLen -and $bytesBefore.Length -eq $bytesAfter.Length) {
        return [PSCustomObject]@{
            StreamName   = $StreamName
            Identical    = $true
            LengthBefore = $bytesBefore.Length
            LengthAfter  = $bytesAfter.Length
            Detail       = "Byte-for-byte identical - no change in this stream between these two files."
        }
    }

    $ctxStart = [Math]::Max(0, $divergeAt - $ContextBytes)
    $commonTail = if ($divergeAt -gt $ctxStart) { $bytesBefore[$ctxStart..($divergeAt - 1)] } else { @() }

    $newInBefore = if ($divergeAt -lt $bytesBefore.Length) {
        $endIdx = [Math]::Min($bytesBefore.Length, $divergeAt + $ShowBytes) - 1
        $bytesBefore[$divergeAt..$endIdx]
    } else { @() }

    $newInAfter = if ($divergeAt -lt $bytesAfter.Length) {
        $endIdx = [Math]::Min($bytesAfter.Length, $divergeAt + $ShowBytes) - 1
        $bytesAfter[$divergeAt..$endIdx]
    } else { @() }

    [PSCustomObject]@{
        StreamName       = $StreamName
        Identical        = $false
        LengthBefore     = $bytesBefore.Length
        LengthAfter      = $bytesAfter.Length
        LengthDelta      = $bytesAfter.Length - $bytesBefore.Length
        DivergesAt       = ("0x{0:X8}" -f $divergeAt)
        DivergesAtAbsBefore = ("0x{0:X8}" -f ($sBefore.PayloadStart + $divergeAt))
        DivergesAtAbsAfter  = ("0x{0:X8}" -f ($sAfter.PayloadStart + $divergeAt))
        CommonContext    = ConvertTo-HexString $commonTail
        BeforeHex        = ConvertTo-HexString $newInBefore
        BeforeAscii      = ConvertTo-AsciiString $newInBefore
        AfterHex         = ConvertTo-HexString $newInAfter
        AfterAscii       = ConvertTo-AsciiString $newInAfter
    }
}

# =========================================================================
# FUNCTION: Write-CreoColorHexRows (private)
#   Shared coloring logic behind Show-CreoHexDump and Find-CreoString's
#   -Color switch, so both stay in sync automatically instead of carrying
#   two copies of the same byte-classification rules.
# =========================================================================
function Write-CreoColorHexRows {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Data,

        [Parameter(Mandatory)]
        [int]$BaseOffset,

        [object]$MarkerBytes = @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF)
    )

    [byte[]]$MarkerBytes = ConvertTo-CreoByteArray -InputObject $MarkerBytes

    $markerSet = New-Object 'System.Collections.Generic.HashSet[byte]'
    foreach ($m in $MarkerBytes) { [void]$markerSet.Add([byte]$m) }

    for ($row = 0; $row -lt $Data.Length; $row += 16) {
        $rowEnd = [Math]::Min($row + 15, $Data.Length - 1)
        Write-Host ("{0:X8}  " -f ($BaseOffset + $row)) -NoNewline -ForegroundColor DarkGray

        for ($i = $row; $i -le ($row + 15); $i++) {
            if ($i -gt $rowEnd) { Write-Host "   " -NoNewline; continue }
            $b = $Data[$i]
            $color = if ($markerSet.Contains($b)) { "Yellow" }
                     elseif ($b -eq 0x00) { "DarkGray" }
                     elseif ($b -ge 0x20 -and $b -le 0x7E) { "Gray" }
                     else { "White" }
            Write-Host ("{0:X2} " -f $b) -NoNewline -ForegroundColor $color
        }

        Write-Host " |" -NoNewline
        for ($i = $row; $i -le $rowEnd; $i++) {
            $b = $Data[$i]
            $color = if ($markerSet.Contains($b)) { "Yellow" }
                     elseif ($b -eq 0x00) { "DarkGray" }
                     elseif ($b -ge 0x20 -and $b -le 0x7E) { "Gray" }
                     else { "White" }
            $ch = if ($b -ge 0x20 -and $b -le 0x7E) { [char]$b } else { '.' }
            Write-Host $ch -NoNewline -ForegroundColor $color
        }
        Write-Host "|"
    }
}

# =========================================================================
# FUNCTION: Show-CreoHexDump
#   Console-only (Write-Host, not pipeline output) colorized hex dump.
#   Yellow = candidate marker byte (E0-E7/F6-FF family), Green = printable
#   ASCII, DarkGray = null, White = everything else.
#   -Offset is ALWAYS an absolute file offset - the same kind of value
#   every other command in this module reports (AbsoluteOffset, OffsetHex,
#   DivergesAtAbsBefore/After, etc). Paste any of those straight in here,
#   no relative-vs-absolute conversion needed. -StreamName is purely a
#   convenience: if you omit -Offset, it starts you at the beginning of
#   that stream instead of byte 0 of the file.
# =========================================================================
function Show-CreoHexDump {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]$Path,

        [Parameter(ParameterSetName = 'File')]
        [string]$StreamName,

        [Parameter(ParameterSetName = 'File')]
        [int]$Offset = 0,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]]$Bytes,

        [Parameter(ParameterSetName = 'Bytes')]
        [int]$BaseOffset = 0,

        [int]$Length = 256,
        [object]$MarkerBytes = @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF)
    )
    [byte[]]$MarkerBytes = ConvertTo-CreoByteArray -InputObject $MarkerBytes

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
        $all = [System.IO.File]::ReadAllBytes((Resolve-Path $Path))

        $start = $Offset
        if (-not $PSBoundParameters.ContainsKey('Offset') -and $StreamName) {
            $resolved = Resolve-CreoFileStreams -Path $Path
            $stream = $resolved.Streams | Where-Object { $_.Name -eq $StreamName } | Select-Object -First 1
            if (-not $stream) { throw "Stream '$StreamName' not found. Run Get-CreoStreamName -Path '$Path' to see what's available." }
            $start = [int]$stream.PayloadStart
        }

        $start = [Math]::Max(0, $start)
        $end = [Math]::Min($all.Length, $start + $Length)
        if ($start -ge $end) { throw "Offset 0x$($start.ToString('X8')) is outside the file (file is $($all.Length) bytes)." }
        $data = $all[$start..($end - 1)]
        $base = $start
    }
    else {
        $data = $Bytes
        $base = $BaseOffset
    }

    Write-Host ""
    Write-Host "Marker" -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "Printable" -ForegroundColor Green -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "Null" -ForegroundColor DarkGray -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "Other" -ForegroundColor White
    Write-Host ""

    Write-CreoColorHexRows -Data $data -BaseOffset $base -MarkerBytes $MarkerBytes

    Write-Host ""
}

# =========================================================================
# FUNCTION: Export-CreoThumbnail
#   Extracts the embedded JPEG thumbnail from THMB_IMG_MAIN. Locates the
#   JPEG SOI/EOI markers (FF D8 / FF D9) inside the stream rather than
#   assuming a fixed offset, so this works on any file regardless of how
#   much header overhead precedes the actual image bytes - generalizes the
#   approach the user found by hand on prt0001.prt.1.
#   NOTE: searches the stream's full RAW TOC-declared range (OffsetVal to
#   EndOffset), not the overhead-stripped PayloadStart/PayloadLength. The
#   overhead-stripping formula this module uses elsewhere assumes the
#   "#ND:0:<Name>:<n>" echo-tag pattern, tuned for name/value dictionary
#   streams - it doesn't reliably apply to an embedded binary image, and
#   was clipping into the actual JPEG bytes on real files.
# =========================================================================
function Export-CreoThumbnail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,

        [string]$OutputDirectory,
        [switch]$PassThru
    )

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $stream = $resolved.Streams | Where-Object { $_.Name -eq "THMB_IMG_MAIN" } | Select-Object -First 1

                if (-not $stream) {
                    Write-Warning "$($fileInfo.Name): no THMB_IMG_MAIN stream found."
                    continue
                }

                $rawStart = [int]$stream.OffsetVal
                $rawEnd = [int]$stream.EndOffset
                if ($rawEnd -gt $resolved.Data.Length) { $rawEnd = $resolved.Data.Length }
                if ($rawStart -ge $rawEnd) {
                    Write-Warning "$($fileInfo.Name): THMB_IMG_MAIN has no usable byte range."
                    continue
                }
                $payload = $resolved.Data[$rawStart..($rawEnd - 1)]

                $soiOffsets = Find-BytePatternOffsets -Payload $payload -Needle ([byte[]](0xFF, 0xD8))
                if ($soiOffsets.Count -eq 0) {
                    Write-Warning "$($fileInfo.Name): THMB_IMG_MAIN found but no JPEG SOI (FF D8) inside it - may not have a cached thumbnail, or uses a different image format."
                    continue
                }

                # Try each SOI candidate in order until one has a matching EOI -
                # guards against a coincidental FF D8 in header bytes that
                # isn't the real image start.
                $jpegStart = $null
                $eoiOffset = -1
                foreach ($candidateStart in $soiOffsets) {
                    for ($i = $candidateStart + 2; $i -lt ($payload.Length - 1); $i++) {
                        if ($payload[$i] -eq 0xFF -and $payload[$i + 1] -eq 0xD9) {
                            $jpegStart = $candidateStart
                            $eoiOffset = $i + 1
                            break
                        }
                    }
                    if ($eoiOffset -ge 0) { break }
                }

                if ($null -eq $jpegStart) {
                    Write-Warning "$($fileInfo.Name): found $($soiOffsets.Count) JPEG SOI candidate(s) in THMB_IMG_MAIN but none had a matching EOI (FF D9) - possibly truncated, or not actually a JPEG."
                    continue
                }

                $jpegBytes = $payload[$jpegStart..$eoiOffset]

                $outDir = if ($OutputDirectory) { $OutputDirectory } else { $fileInfo.DirectoryName }
                if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
                $outPath = Join-Path $outDir "$($fileInfo.Name)_thumbnail.jpg"

                [System.IO.File]::WriteAllBytes($outPath, $jpegBytes)

                $result = [PSCustomObject]@{
                    File         = $fileInfo.Name
                    OutputPath   = $outPath
                    JpegStartAbs = ("0x{0:X8}" -f ($rawStart + $jpegStart))
                    JpegEndAbs   = ("0x{0:X8}" -f ($rawStart + $eoiOffset))
                    Length       = $jpegBytes.Length
                }
                if ($PassThru) { $result } else { Write-Host "Saved: $outPath ($($jpegBytes.Length) bytes)" -ForegroundColor Green }
            }
        }
    }
}

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



# =========================================================================
# FUNCTION: ConvertTo-CreoByteArray:
#   One reusable converter function, then have every public function accept
#   marker/search-byte input as [object] rather than [byte[]]
#   
#   " E3F74133 "
#   "E3 F7 41 33"
#   "E3, F7, 41, 33"
#   "0xE3 0xF7 0x41 0x33"
#   [byte[]](0xE3, 0xF7, 0x41, 0x33)
#   @(0xE3, 0xF7, 0x41, 0x33)
# =========================================================================
function ConvertTo-CreoByteArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        throw "Byte input cannot be null."
    }

    # Already exactly what we need.
    if ($InputObject -is [byte[]]) {
        return $InputObject
    }

    # A hex string, such as:
    # E3F74133
    # E3 F7 41 33
    # E3, F7, 41, 33
    # 0xE3 0xF7 0x41 0x33
    if ($InputObject -is [string]) {
        $text = $InputObject.Trim()

        if ([string]::IsNullOrWhiteSpace($text)) {
            throw "Byte input cannot be empty."
        }

        # One uninterrupted hex string: E3F74133
        if ($text -match '^[0-9A-Fa-f]+$') {
            if (($text.Length % 2) -ne 0) {
                throw (
                    "Hex input must contain complete byte pairs. " +
                    "Received $($text.Length) hex characters: '$InputObject'."
                )
            }

            $bytes = New-Object byte[] ($text.Length / 2)

            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $pair = $text.Substring($i * 2, 2)
                $bytes[$i] = [Convert]::ToByte($pair, 16)
            }

            return $bytes
        }

        # Delimited byte values: E3 F7 41 33, 0xE3,0xF7, etc.
        $tokens = $text -split '[\s,;:\-]+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        if ($tokens.Count -eq 0) {
            throw "No byte values were found in '$InputObject'."
        }

        $bytes = New-Object System.Collections.Generic.List[byte]

        foreach ($token in $tokens) {
            $hex = $token -replace '^(?i:0x)', ''

            if ($hex -notmatch '^[0-9A-Fa-f]{2}$') {
                throw (
                    "Invalid byte token '$token'. Expected exactly two hex digits, " +
                    "such as E3 or 0xE3."
                )
            }

            $bytes.Add([Convert]::ToByte($hex, 16))
        }

        return $bytes.ToArray()
    }

    # Handles normal numeric arrays, such as @(0xE3, 0xF7, 0x41, 0x33).
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $bytes = New-Object System.Collections.Generic.List[byte]

        foreach ($value in $InputObject) {
            if ($null -eq $value) {
                throw "Byte input contains a null value."
            }

            try {
                $bytes.Add([Convert]::ToByte($value))
            }
            catch {
                throw "Cannot convert '$value' to a byte. Valid decimal values are 0 through 255."
            }
        }

        if ($bytes.Count -eq 0) {
            throw "Byte input cannot be empty."
        }

        return $bytes.ToArray()
    }

    # Supports a single numeric byte-like value.
    try {
        return [byte[]]@([Convert]::ToByte($InputObject))
    }
    catch {
        throw "Cannot convert '$InputObject' to a byte array."
    }
}



# =========================================================================
# FUNCTION: Search-CreoBinary:
#   It uses Parameter Sets to automatically adapt to what you hand it, 
#   eliminating the need to remember different cmdlet names. It integrates
#   stream-aware relative offsets, entropy calculation, and the colorized
#   hex dump into a single, foolproof output.
# =========================================================================

function Search-CreoBinary {
    <#
    .SYNOPSIS
        A unified utility for exploring binary file structures, mapping stream boundaries, 
        and visually inspecting marker patterns.
    .DESCRIPTION
        This script compresses files from a local source folder and uploads 
        the resulting zip archive to a backup server, keeping a local log entry.
    .PARAMETER SourcePath
        The directory on the local machine that you want to back up.
    .EXAMPLE
        Search-CreoBinary -Path .\models\*.prt.1 -Pattern "rev_string" -Context 60

        Search for text (Automatically sizes the window and highlights default markers)
    .EXAMPLE
        $myMarker = [byte[]](0x0A, 0x72, 0x65, 0x76, 0x5F)
        Search-CreoBinary -Path .\models\company_start_prt.prt.1 -SearchBytes $myMarker

        Search for exact bytes (Automatically switches to byte-matching mode)
    .EXAMPLE
        Search-CreoBinary -Path .\models\company_start_prt.prt.1 -StreamName "FeatDefs" -Offset 0xB1

        Jump to a specific address/stream (Replaces `Show-CreoHexDump`)   
    .EXAMPLE
        Search-CreoBinary -Path .\file.prt.1 -Pattern "PTC_" -MarkerBytes @(0xAA, 0xBB, 0xCC)

        Supply custom marker bytes for syntax highlighting
        By default, it highlights `0xE0-E7` and `0xF6-FF` in yellow. If you discover a new proprietary marker table you want to trace visually, just pass it    
    #>
    [CmdletBinding(DefaultParameterSetName = 'SearchString')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,

        [Parameter(Mandatory, ParameterSetName = 'SearchString', Position = 0)]
        [string[]]$Pattern,

        [Parameter(Mandatory, ParameterSetName = 'SearchBytes')]
        [object]$SearchBytes,

        [Parameter(Mandatory, ParameterSetName = 'DirectOffset')]
        [int]$Offset,

        [Parameter(ParameterSetName = 'DirectOffset')]
        [string]$StreamName,

        [Alias("B")][int]$BeforeContext = 32,
        [Alias("A")][int]$AfterContext = 64,
        [Alias("C")][int]$Context = -1,

        [switch]$IgnoreCase,
        [switch]$Quiet,    # Suppress visual hex dump, return objects only
        [switch]$Raw,      # Output plain objects without grouping
        
        [object]$MarkerBytes = @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF)

    )
    begin {
        [byte[]]$MarkerBytes = ConvertTo-CreoByteArray -InputObject $MarkerBytes

        if ($PSCmdlet.ParameterSetName -eq 'SearchBytes') {
            [byte[]]$SearchBytes = ConvertTo-CreoByteArray -InputObject $SearchBytes
        }

        $bytesBefore = if ($Context -ge 0) { $Context } else { $BeforeContext }
        $bytesAfter  = if ($Context -ge 0) { $Context } else { $AfterContext }
        $seenPaths = [System.Collections.Generic.HashSet[string]]::new()

        # Embedded helper for colorized terminal output
        function Write-ColorDump([byte[]]$Data, [int]$BaseOffset, [byte[]]$Markers) {
            $markerSet = [System.Collections.Generic.HashSet[byte]]::new()
            foreach ($m in $Markers) { [void]$markerSet.Add([byte]$m) }

            for ($row = 0; $row -lt $Data.Length; $row += 16) {
                $rowEnd = [Math]::Min($row + 15, $Data.Length - 1)
                Write-Host ("{0:X8}  " -f ($BaseOffset + $row)) -NoNewline -ForegroundColor DarkGray

                # Hex side
                for ($i = $row; $i -le ($row + 15); $i++) {
                    if ($i -gt $rowEnd) { Write-Host "   " -NoNewline; continue }
                    $b = $Data[$i]
                    $color = if ($markerSet.Contains($b)) { "Yellow" }
                             elseif ($b -eq 0x00) { "DarkGray" }
                             elseif ($b -ge 0x20 -and $b -le 0x7E) { "Green" }
                             else { "White" }
                    Write-Host ("{0:X2} " -f $b) -NoNewline -ForegroundColor $color
                }

                Write-Host " |" -NoNewline
                
                # ASCII side
                for ($i = $row; $i -le $rowEnd; $i++) {
                    $b = $Data[$i]
                    $color = if ($markerSet.Contains($b)) { "Yellow" }
                             elseif ($b -eq 0x00) { "DarkGray" }
                             elseif ($b -ge 0x20 -and $b -le 0x7E) { "Green" }
                             else { "White" }
                    $ch = if ($b -ge 0x20 -and $b -le 0x7E) { [char]$b } else { '.' }
                    Write-Host $ch -NoNewline -ForegroundColor $color
                }
                Write-Host "|"
            }
        }
    }

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                if (-not $seenPaths.Add($rp.Path)) { continue }

                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                # Assumes your Resolve-CreoFileStreams and Get-Entropy functions are in scope
                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $bytes = $resolved.Data
                $sortedStreams = @($resolved.Streams | Sort-Object PayloadStart)
                
                $targetOffsets = [System.Collections.Generic.List[int]]::new()
                $searchTerms = @()
                $matchLengths = @{}

                # Determine target offsets based on the parameter set used
                if ($PSCmdlet.ParameterSetName -eq 'DirectOffset') {
                    $start = $Offset
                    if ($StreamName) {
                        $stream = $sortedStreams | Where-Object { $_.Name -eq $StreamName } | Select-Object -First 1
                        if ($stream) { $start = [int]$stream.PayloadStart + $Offset }
                    }
                    $targetOffsets.Add([Math]::Max(0, $start))
                    $searchTerms = @("Direct Address: 0x$($start.ToString('X8'))")
                }
                elseif ($PSCmdlet.ParameterSetName -eq 'SearchBytes') {
                    $searchTerms = @("Byte Pattern")
                    if ($script:UseCSharpEngine) {
                        $targetOffsets.AddRange([CreoNative]::FindBytePattern($bytes, $SearchBytes, $false))
                    } else {
                        $targetOffsets.AddRange((Find-BytePatternOffsets -Payload $bytes -Needle $SearchBytes))
                    }
                }
                else {
                    foreach ($term in $Pattern) {
                        if ([string]::IsNullOrEmpty($term)) { continue }
                        $needle = [System.Text.Encoding]::ASCII.GetBytes($term)
                        $searchTerms += $term
                    
                        $hits = if ($script:UseCSharpEngine) {
                            [CreoNative]::FindBytePattern($bytes, $needle, $IgnoreCase.IsPresent)
                        } else {
                            Find-BytePatternOffsets -Payload $bytes -Needle $needle
                        }
                    
                        foreach ($h in $hits) {
                            $targetOffsets.Add($h)
                            $matchLengths[$h] = $needle.Length   # remember which term matched here
                        }
                    }
                }

                $targetOffsets = $targetOffsets | Sort-Object -Unique

                foreach ($hit in $targetOffsets) {
                    # Resolve which stream this offset belongs to
                    $streamName = "UNRESOLVED_REGION"
                    $relativeOffset = $hit
                    
                    foreach ($s in $sortedStreams) {
                        if ($s.PayloadStart -le $hit -and $hit -lt ($s.PayloadStart + $s.PayloadLength)) {
                            $streamName = $s.Name
                            $relativeOffset = $hit - $s.PayloadStart
                            break
                        }
                    }

                    # Calculate display window bounds
                    $start = [Math]::Max(0, $hit - $bytesBefore)
                    $end = [Math]::Min($bytes.Length, $hit + 1 + $bytesAfter) # +1 acts as dummy length for direct offsets
                    if ($PSCmdlet.ParameterSetName -eq 'SearchBytes') { $end = [Math]::Min($bytes.Length, $hit + $SearchBytes.Length + $bytesAfter) }
                    elseif ($PSCmdlet.ParameterSetName -eq 'SearchString') {
                        $len = if ($matchLengths.ContainsKey($hit)) { $matchLengths[$hit] } else { 1 }
                        $end = [Math]::Min($bytes.Length, $hit + $len + $bytesAfter)
                    }
                    
                    $windowBytes = $bytes[$start..($end - 1)]

                    # Visual Output
                    if (-not $Quiet) {
                        Write-Host "`n=====================================================================" -ForegroundColor Cyan
                        Write-Host " FILE    : " -NoNewline; Write-Host $fileInfo.Name -ForegroundColor White
                        Write-Host " STREAM  : " -NoNewline; Write-Host $streamName -ForegroundColor White
                        Write-Host " OFFSET  : " -NoNewline; Write-Host ("0x{0:X8} (Absolute) | 0x{1:X8} (Relative)" -f $hit, $relativeOffset) -ForegroundColor White
                        
                        # Only calculate entropy if the helper is loaded
                        if (Get-Command Get-Entropy -ErrorAction SilentlyContinue) {
                            $entropy = Get-Entropy -Data $windowBytes
                            Write-Host " ENTROPY : " -NoNewline; Write-Host ("{0:N3}" -f $entropy) -ForegroundColor White
                        }
                        
                        Write-Host "=====================================================================" -ForegroundColor Cyan
                        Write-ColorDump -Data $windowBytes -BaseOffset $start -Markers $MarkerBytes
                    }

                    # Pipeline Output
                    if ($Raw -or $Quiet) {
                        [PSCustomObject]@{
                            FileName       = $fileInfo.Name
                            Stream         = $streamName
                            AbsoluteOffset = ("0x{0:X8}" -f $hit)
                            RelativeOffset = ("0x{0:X8}" -f $relativeOffset)
                            WindowBytes    = $windowBytes.Count
                        }
                    }
                }
            }
        }
    }
}

# =========================================================================
# FUNCTION: Invoke-CreoRegionAnalysis:
#   This command will accept the object output from Search-CreoBinary 
#   (which outputs Block, RelativeOffset, and absolute Offset) directly
#   via the pipeline. It will then act as an orchestrator, calling your 
#   existing, more granular functions (Get-CreoStreamSchema, 
#   Show-CreoHexDump, etc.) to generate a unified, comprehensive snapshot
#   of that specific memory region.
# =========================================================================

function Invoke-CreoRegionAnalysis {
    <#
    .SYNOPSIS
        Performs deep, localized analysis on a specific byte offset within a Creo binary file stream.

    .DESCRIPTION
        Invoke-CreoRegionAnalysis acts as an orchestrator for various Creo exploratory functions. 
        It is designed to accept pipeline input directly from search cmdlets (like Search-CreoBinaryString) 
        and automatically generate a contextual report of the surrounding bytes. It aggregates colorized hex dumps, 
        nearby E0 schema extractions, and E1/E3 parameter decodings to help identify structural motifs without 
        running slow, full-file analysis.

    .EXAMPLE
        Search-CreoBinaryString -Path .\models\company_start_prt.prt.1 -Pattern "gcd_uid" | Invoke-CreoRegionAnalysis -Path .\models\company_start_prt.prt.1

        Searches for the string "gcd_uid" and pipes the resulting hit objects directly into the analyzer. 
        The analyzer outputs a contextual hex dump and nearby data structures for every match.

    .EXAMPLE
        [PSCustomObject]@{ Stream = "MdlStatus"; Offset = "0x0001ACFF" } | Invoke-CreoRegionAnalysis -Path .\models\company_start_prt.prt.1 -ContextWindow 256

        Manually specifies a known stream and hex offset to analyze, expanding the hex dump and schema search radius to 256 bytes.    
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Block')]
        [string]$Stream,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Offset, 

        [int]$ContextWindow = 128
    )

    process {
        # 1. Convert the Hex string offset back to an integer
        $absOffset = [Convert]::ToInt32($Offset, 16)
        
        Write-Host "`n=====================================================================" -ForegroundColor Cyan
        Write-Host " CREO REGION ANALYSIS: $Stream @ $Offset" -ForegroundColor Cyan
        Write-Host "=====================================================================" -ForegroundColor Cyan

        # 2. Resolve the file and isolate the stream
        $resolved = Resolve-CreoFileStreams -Path $Path
        $targetStream = $resolved.Streams | Where-Object { $_.Name -eq $Stream } | Select-Object -First 1

        if (-not $targetStream) {
            Write-Warning "Could not resolve stream $Stream in $Path"
            return
        }

        # 3. Output a colorized Hex Dump of the immediate area
        $dumpStart = [Math]::Max([int]$targetStream.PayloadStart, $absOffset - ($ContextWindow / 2))
        
        # Calculate the safe end of the slice to prevent out-of-bounds errors at the EOF
        $sliceEnd = [Math]::Min($dumpStart + $ContextWindow - 1, $resolved.Data.Length - 1)
        
        # Strictly slice the byte array so the hex dumper cannot read past the context window
        $windowBytes = $resolved.Data[$dumpStart..$sliceEnd]

        Write-Host "`n[+] Colorized Hex Dump (-$($ContextWindow/2) to +$($ContextWindow/2) bytes)" -ForegroundColor Yellow
        
        # Pass only the sliced bytes. BaseOffset is kept so your UI prints the correct memory addresses on the left.
        Show-CreoHexDump -Bytes $windowBytes -BaseOffset $dumpStart

        # 4. Check for nearby structural schemas (E0 markers)
        $schema = Get-CreoStreamSchema -ResolvedStream $targetStream -FileBytes $resolved.Data
        $nearbySchema = $schema | Where-Object { 
            $_.AbsoluteOffset -ge $dumpStart -and 
            $_.AbsoluteOffset -le ($dumpStart + $ContextWindow) 
        }

        if ($nearbySchema) {
            Write-Host "`n[+] Nearby Parsed Schema Properties (E0 Type Encodings)" -ForegroundColor Yellow
            $nearbySchema | Format-Table AbsoluteOffset, OpcodeType, PropertyName -AutoSize | Out-String | Write-Host
        } else {
            Write-Host "`n[-] No E0 Schema properties found in this immediate window." -ForegroundColor DarkGray
        }

        # 5. Check for extracted parameters in the payload
        $streamStart = [int]$targetStream.PayloadStart
        $streamLen = [int]$targetStream.PayloadLength
        $payload = $resolved.Data[$streamStart..($streamStart + $streamLen - 1)]
        
        $params = Get-CreoParametersFromPayloadPS -Payload $payload
        if ($params) {
            Write-Host "`n[+] E1/E3 Parameters Found in Stream (Top 5)" -ForegroundColor Yellow
            $params | Select-Object -First 5 | Format-Table ParameterName, TypeName, ParameterValue -AutoSize | Out-String | Write-Host
        }

        Write-Host "=====================================================================`n" -ForegroundColor Cyan
    }
}


# =========================================================================
# FUNCTION: Export-CreoRegionBlob (The Carver):
#   Once Invoke-CreoRegionAnalysis flags a highly volatile or high-entropy
#   region (like the SolidPersistTable block), you don't want to keep 
#   analyzing it in the context of the entire multi-megabyte .prt file. 
#   You need to carve out that exact chunk of raw bytes.
# =========================================================================
function Export-CreoRegionBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [int]$Padding = 32
    )

    process {
        $path = if ($InputObject.PSObject.Properties['FilePath']) {
            [string]$InputObject.FilePath
        }
        else {
            # FileName alone is unsafe unless it is resolvable from CWD.
            [string]$InputObject.FileName
        }

        # Search-CreoBinary currently emits a formatted hex string.
        $offsetText = [string]$InputObject.AbsoluteOffset
        $offset = if ($offsetText -match '^0x[0-9A-Fa-f]+$') {
            [Convert]::ToInt64($offsetText.Substring(2), 16)
        }
        else {
            [Convert]::ToInt64($offsetText)
        }

        $matchLength = if ($InputObject.PSObject.Properties['MatchLength']) {
            [int]$InputObject.MatchLength
        }
        elseif ($InputObject.PSObject.Properties['WindowBytes']) {
            [int]$InputObject.WindowBytes
        }
        else {
            64
        }

        $startOffset = [Math]::Max(0L, $offset - $Padding)
        $extractLength = $matchLength + (2 * $Padding)

        $resolved = Resolve-CreoFileStreams -Path $path
        $targetStream = $resolved.Streams |
            Where-Object {
                $offset -ge $_.PayloadStart -and
                $offset -lt ($_.PayloadStart + $_.PayloadLength)
            } |
            Select-Object -First 1

        $streamName = if ($targetStream) { $targetStream.Name } else { 'UnknownStream' }

        $allBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $path))
        $available = [Math]::Min($extractLength, $allBytes.Length - $startOffset)

        if ($available -le 0) {
            throw "Offset 0x{0:X8} is outside '$path'." -f $offset
        }

        $buffer = $allBytes[$startOffset..($startOffset + $available - 1)]

        $null = New-Item -ItemType Directory -Path $DestinationPath -Force
        $safeStreamName = $streamName -replace '[\\/:*?"<>|]', '_'
        $outFile = Join-Path $DestinationPath (
            '{0}_{1:X8}_len{2}.bin' -f $safeStreamName, $offset, $available
        )

        [System.IO.File]::WriteAllBytes($outFile, [byte[]]$buffer)

        [PSCustomObject]@{
            ExtractedFile  = $outFile
            OriginalOffset = $offset
            StartOffset    = $startOffset
            BytesWritten   = $available
            StreamName     = $streamName
        }
    }
}



# =========================================================================
# FUNCTION: Trace-CreoPointerReference (The XREF Tracker): 
#   Since we now know that the E0 markers are dynamically assigning 4-byte
#   IDs (like E3 F7 41 33), finding the declaration is only half the battle. 
#   You need a cmdlet that takes the ID found in the snapshot and sweeps the
#   rest of the parsed file streams to build a cross-reference (XREF) map 
#   of everywhere that specific ID is invoked.
# =========================================================================
function Trace-CreoPointerReference {
    <#
    .SYNOPSIS
        Finds repetitions of a selected fixed-width binary token.

    .DESCRIPTION
        This is a bounded candidate-token tracer, not proof that a token is
        a Creo pointer or object ID.

        For every pipeline input, it:
          1. Parses its absolute offset.
          2. Reads TokenLength bytes at that offset.
          3. Converts those bytes to the hex-string grammar accepted by
             Find-CreoStructuralRuns.
          4. Searches parsed streams for identical occurrences.
          5. Emits typed objects for the results.

        Identical tokens are scanned only once per invocation, even if the
        pipeline contains many hits that begin with the same bytes.

    .EXAMPLE
        # Manually trace one known token occurrence.
        Search-CreoBinary -Path .\models\prt0001.prt.8 `
            -Offset 0x4F9A -Quiet |
            Trace-CreoPointerReference -TokenLength 4 `
                -IncludeColorDump

    .EXAMPLE
        # Trace a limited number of E3 F7 search hits.
        $hits = Search-CreoBinary -Path .\models\prt0001.prt.8 `
            -SearchBytes 'E3 F7' -Quiet

        $hits | Trace-CreoPointerReference `
            -TokenLength 4 `
            -MaxInputHits 10 `
            -MaxReferencesPerToken 50

    .NOTES
        Search-CreoBinary currently emits AbsoluteOffset as a formatted
        string such as 0x00004F9A, so this function parses it explicitly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        # Override FileName/FilePath in the pipeline object when needed.
        [string]$Path,

        [ValidateRange(2, 32)]
        [int]$TokenLength = 4,

        # Prevent accidental full-file rescans for thousands of generic hits.
        [ValidateRange(1, 100000)]
        [int]$MaxInputHits = 25,

        # Prevent overwhelming output for common tokens.
        [ValidateRange(1, 100000)]
        [int]$MaxReferencesPerToken = 100,

        # Do not emit the location from which the token was read.
        [switch]$ExcludeSelf,

        # Display a 64-byte hex dump for each emitted reference.
        [switch]$IncludeColorDump,

        # Passed to Show-CreoHexDump when -IncludeColorDump is used.
        [ValidateRange(1, 65536)]
        [int]$DumpLength = 64
    )

    begin {
        $processedInputHits = 0

        # Keyed as: fullPath|E3 F7 1E 25
        # A repeated token gets scanned once, not once per matching seed.
        $seenTokens = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        function ConvertFrom-CreoOffset {
            param(
                [Parameter(Mandatory)]
                [object]$Value
            )

            if ($Value -is [byte] -or
                $Value -is [int16] -or
                $Value -is [int32] -or
                $Value -is [int64] -or
                $Value -is [uint16] -or
                $Value -is [uint32] -or
                $Value -is [uint64]) {
                return [Int64]$Value
            }

            $text = ([string]$Value).Trim()

            if ($text -match '^(?i:0x)([0-9a-f]+)$') {
                return [Convert]::ToInt64($matches[1], 16)
            }

            try {
                return [Convert]::ToInt64(
                    $text,
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
            }
            catch {
                throw "Cannot interpret '$Value' as an absolute file offset."
            }
        }

        function ConvertTo-CreoHexPattern {
            param(
                [Parameter(Mandatory)]
                [byte[]]$Bytes
            )

            return (($Bytes | ForEach-Object {
                $_.ToString('X2')
            }) -join ' ')
        }

        function Resolve-CreoTracePath {
            param(
                [Parameter(Mandatory)]
                [object]$InputObject,

                [string]$PathOverride
            )

            if (-not [string]::IsNullOrWhiteSpace($PathOverride)) {
                return (Resolve-Path -LiteralPath $PathOverride -ErrorAction Stop).Path
            }

            if ($InputObject.PSObject.Properties['FilePath'] -and
                -not [string]::IsNullOrWhiteSpace([string]$InputObject.FilePath)) {
                return (Resolve-Path -LiteralPath ([string]$InputObject.FilePath) `
                    -ErrorAction Stop).Path
            }

            if ($InputObject.PSObject.Properties['FileName'] -and
                -not [string]::IsNullOrWhiteSpace([string]$InputObject.FileName)) {
                return (Resolve-Path -LiteralPath ([string]$InputObject.FileName) `
                    -ErrorAction Stop).Path
            }

            throw (
                "Input object has neither a usable FilePath nor FileName. " +
                "Supply -Path explicitly or update Search-CreoBinary to emit FilePath."
            )
        }
    }

    process {
        if ($processedInputHits -ge $MaxInputHits) {
            Write-Warning (
                "MaxInputHits ($MaxInputHits) reached. " +
                "Remaining pipeline inputs were skipped."
            )
            return
        }

        if (-not $InputObject.PSObject.Properties['AbsoluteOffset'] -and
            -not $InputObject.PSObject.Properties['Offset']) {
            throw (
                "Input object must expose AbsoluteOffset or Offset. " +
                "Received: $($InputObject.PSObject.TypeNames[0])"
            )
        }

        $offsetValue = if ($InputObject.PSObject.Properties['AbsoluteOffset']) {
            $InputObject.AbsoluteOffset
        }
        else {
            $InputObject.Offset
        }

        [Int64]$sourceOffset = ConvertFrom-CreoOffset -Value $offsetValue
        if ($sourceOffset -lt 0) {
            throw "Negative offsets are invalid: $sourceOffset"
        }

        $resolvedPath = Resolve-CreoTracePath `
            -InputObject $InputObject `
            -PathOverride $Path

        $fileInfo = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        if ($fileInfo.PSIsContainer) {
            throw "Trace-CreoPointerReference requires a file, not a directory: $resolvedPath"
        }

        if (($sourceOffset + $TokenLength) -gt $fileInfo.Length) {
            Write-Warning (
                "Skipping 0x{0:X8}: a {1}-byte token would extend past " +
                "the end of '{2}'." -f $sourceOffset, $TokenLength, $fileInfo.Name
            )
            return
        }

        [byte[]]$idBuffer = New-Object byte[] $TokenLength

        $fileStream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )

        try {
            [void]$fileStream.Seek($sourceOffset, [System.IO.SeekOrigin]::Begin)

            $totalRead = 0
            while ($totalRead -lt $TokenLength) {
                $read = $fileStream.Read(
                    $idBuffer,
                    $totalRead,
                    $TokenLength - $totalRead
                )

                if ($read -le 0) { break }
                $totalRead += $read
            }

            if ($totalRead -ne $TokenLength) {
                throw (
                    "Only read $totalRead of $TokenLength bytes at " +
                    "0x$($sourceOffset.ToString('X8'))."
                )
            }
        }
        finally {
            $fileStream.Dispose()
        }

        $pattern = ConvertTo-CreoHexPattern -Bytes $idBuffer
        $tokenKey = '{0}|{1}' -f $resolvedPath, $pattern

        $processedInputHits++

        if (-not $seenTokens.Add($tokenKey)) {
            Write-Verbose (
                "Skipping duplicate candidate token '$pattern' from " +
                "0x$($sourceOffset.ToString('X8'))."
            )
            return
        }

        Write-Verbose (
            "Tracing candidate token '$pattern' from " +
            "0x$($sourceOffset.ToString('X8')) in '$($fileInfo.Name)'."
        )

        # Find-CreoStructuralRuns expects a hex-pattern string, not [byte[]].
        $rawXrefs = @(
            Find-CreoStructuralRuns -Path $resolvedPath -Pattern $pattern
        )

        # A malformed stream map could make the same absolute location appear
        # through more than one stream range. Deduplicate by numeric offset.
        $uniqueXrefs = [System.Collections.Generic.List[object]]::new()
        $seenReferenceOffsets = [System.Collections.Generic.HashSet[Int64]]::new()

        foreach ($ref in $rawXrefs) {
            if ($null -eq $ref) { continue }

            [Int64]$referenceOffset = ConvertFrom-CreoOffset `
                -Value $ref.AbsoluteOffset

            if ($ExcludeSelf -and $referenceOffset -eq $sourceOffset) {
                continue
            }

            if ($seenReferenceOffsets.Add($referenceOffset)) {
                $uniqueXrefs.Add($ref)
            }
        }

        $emitted = 0
        foreach ($ref in $uniqueXrefs) {
            if ($emitted -ge $MaxReferencesPerToken) {
                Write-Warning (
                    "Token '$pattern' had more than $MaxReferencesPerToken " +
                    "unique references. Output was truncated."
                )
                break
            }

            [Int64]$referenceOffset = ConvertFrom-CreoOffset `
                -Value $ref.AbsoluteOffset

            [Int64]$relativeOffset = if (
                $ref.PSObject.Properties['RelativeOffset']
            ) {
                ConvertFrom-CreoOffset -Value $ref.RelativeOffset
            }
            else {
                -1
            }

            $result = [PSCustomObject]@{
                FilePath             = $resolvedPath
                FileName             = $fileInfo.Name
                CandidateToken       = $pattern
                TokenLength          = $TokenLength

                SourceOffset         = $sourceOffset
                SourceOffsetHex      = ('0x{0:X8}' -f $sourceOffset)

                TargetStream         = [string]$ref.Stream
                TargetOffset         = $referenceOffset
                TargetOffsetHex      = ('0x{0:X8}' -f $referenceOffset)

                TargetRelativeOffset = $relativeOffset
                TargetRelativeHex    = if ($relativeOffset -ge 0) {
                    '0x{0:X8}' -f $relativeOffset
                }
                else {
                    $null
                }

                MatchedBytes         = [string]$ref.MatchedBytes
                IsSourceLocation     = ($referenceOffset -eq $sourceOffset)
            }

            if ($IncludeColorDump) {
                Show-CreoHexDump `
                    -Path $resolvedPath `
                    -Offset $referenceOffset `
                    -Length $DumpLength
            }

            Write-Output $result
            $emitted++
        }
    }
}


function Get-CreoStreamFingerprints {
    <#
    .SYNOPSIS
        Produces SHA-256 fingerprints for every resolved Creo stream payload.

    .DESCRIPTION
        Accepts individual files, wildcard paths, and directories.

        Uses [System.Security.Cryptography.SHA256]::Create().ComputeHash()
        instead of [SHA256]::HashData(), making it compatible with Windows
        PowerShell 5.1 / .NET Framework as well as PowerShell 7+.

    .EXAMPLE
        Get-CreoStreamFingerprints -Path .\models\prt0001.prt.4

    .EXAMPLE
        Get-CreoStreamFingerprints -Path '.\models\prt0001.prt.*' |
            Sort-Object FileName, StreamName |
            Format-Table -AutoSize

    .EXAMPLE
        # Include files inside subdirectories.
        Get-CreoStreamFingerprints -Path .\models -Recurse |
            Export-Csv .\stream_hashes.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [switch]$Recurse
    )

    begin {
        $seenFiles = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        function Get-CreoFingerprintFiles {
            param(
                [Parameter(Mandatory)]
                [string[]]$InputPaths,

                [switch]$IncludeRecurse
            )

            foreach ($inputPath in $InputPaths) {
                $resolvedItems = @(
                    Resolve-Path -Path $inputPath -ErrorAction Stop
                )

                foreach ($resolvedItem in $resolvedItems) {
                    $item = Get-Item -LiteralPath $resolvedItem.Path `
                        -Force `
                        -ErrorAction Stop

                    if ($item.PSIsContainer) {
                        Get-ChildItem `
                            -LiteralPath $item.FullName `
                            -File `
                            -Force `
                            -Recurse:$IncludeRecurse
                    }
                    else {
                        $item
                    }
                }
            }
        }
    }

    process {
        $files = @(
            Get-CreoFingerprintFiles `
                -InputPaths $Path `
                -IncludeRecurse:$Recurse
        )

        foreach ($file in $files) {
            if (-not $seenFiles.Add($file.FullName)) {
                continue
            }

            $resolved = Resolve-CreoFileStreams -Path $file.FullName

            if ($null -eq $resolved -or $null -eq $resolved.Data) {
                Write-Warning "Could not resolve streams for '$($file.FullName)'."
                continue
            }

            [byte[]]$data = $resolved.Data
            $streams = @($resolved.Streams)

            foreach ($stream in $streams) {
                if (-not (Test-CreoStreamRange `
                    -Stream $stream `
                    -FileLength $data.Length)) {
                    Write-Verbose (
                        "Skipping invalid stream range '$($stream.Name)' " +
                        "in '$($file.Name)'."
                    )
                    continue
                }

                [Int64]$payloadStart = [Int64]$stream.PayloadStart
                [Int64]$payloadLength = [Int64]$stream.PayloadLength

                # ComputeHash overloads use Int32 offsets/counts.
                # The current resolver also stores offsets as [int].
                if ($payloadStart -gt [Int32]::MaxValue -or
                    $payloadLength -gt [Int32]::MaxValue) {
                    Write-Warning (
                        "Skipping '$($stream.Name)' in '$($file.Name)': " +
                        "payload range exceeds .NET Int32 hashing overload limits."
                    )
                    continue
                }

                $sha256 = [System.Security.Cryptography.SHA256]::Create()

                try {
                    # Hashes the exact region without copying it into a
                    # separate $payload array.
                    [byte[]]$hashBytes = $sha256.ComputeHash(
                        $data,
                        [int]$payloadStart,
                        [int]$payloadLength
                    )

                    $hashHex = ([System.BitConverter]::ToString($hashBytes)) `
                        -replace '-', ''
                }
                finally {
                    if ($null -ne $sha256) {
                        $sha256.Dispose()
                    }
                }

                [PSCustomObject]@{
                    FilePath       = $file.FullName
                    FileName       = $file.Name

                    StreamName     = [string]$stream.Name
                    PayloadStart   = $payloadStart
                    PayloadStartHex = ('0x{0:X8}' -f $payloadStart)

                    PayloadLength  = $payloadLength
                    PayloadEnd     = $payloadStart + $payloadLength
                    PayloadEndHex  = (
                        '0x{0:X8}' -f ($payloadStart + $payloadLength)
                    )

                    SHA256         = $hashHex

                    # Useful context retained from Resolve-StreamRanges.
                    Size1          = $stream.Size1
                    Size2          = $stream.Size2
                    Entropy        = $stream.Entropy
                    OverheadMatches = $stream.OverheadMatches
                }
            }
        }
    }
}


function Compare-CreoStreamBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReferencePath,

        [Parameter(Mandatory)]
        [string]$DifferencePath,

        [Parameter(Mandatory)]
        [string]$StreamName,

        [ValidateRange(0, 4096)]
        [int]$Context = 32
    )

    function Get-TargetStream {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [string]$Name
        )

        $resolved = Resolve-CreoFileStreams -Path $Path

        $stream = @(
            $resolved.Streams |
                Where-Object Name -eq $Name |
                Select-Object -First 1
        )

        if ($stream.Count -eq 0) {
            throw "Stream '$Name' was not found in '$Path'."
        }

        $s = $stream[0]
        [int]$start = $s.PayloadStart
        [int]$length = $s.PayloadLength

        if ($start -lt 0 -or $length -lt 0 -or
            ($start + $length) -gt $resolved.Data.Length) {
            throw "Invalid range for stream '$Name' in '$Path'."
        }

        [PSCustomObject]@{
            Path          = (Resolve-Path -LiteralPath $Path).Path
            FileName      = (Split-Path -Leaf $Path)
            Stream        = $s
            Payload       = [byte[]]$resolved.Data[$start..($start + $length - 1)]
            PayloadStart  = $start
            PayloadLength = $length
        }
    }

    $left = Get-TargetStream -Path $ReferencePath -Name $StreamName
    $right = Get-TargetStream -Path $DifferencePath -Name $StreamName

    $maxLength = [Math]::Max($left.PayloadLength, $right.PayloadLength)
    $ranges = [System.Collections.Generic.List[object]]::new()

    $inRange = $false
    $rangeStart = 0

    for ($i = 0; $i -lt $maxLength; $i++) {
        $leftExists = $i -lt $left.PayloadLength
        $rightExists = $i -lt $right.PayloadLength

        $same = $leftExists -and $rightExists -and
            ($left.Payload[$i] -eq $right.Payload[$i])

        if (-not $same -and -not $inRange) {
            $rangeStart = $i
            $inRange = $true
        }
        elseif ($same -and $inRange) {
            $ranges.Add([PSCustomObject]@{
                RelativeStart    = $rangeStart
                RelativeEnd      = $i - 1
                Length           = $i - $rangeStart
            })

            $inRange = $false
        }
    }

    if ($inRange) {
        $ranges.Add([PSCustomObject]@{
            RelativeStart = $rangeStart
            RelativeEnd   = $maxLength - 1
            Length        = $maxLength - $rangeStart
        })
    }

    foreach ($range in $ranges) {
        $leftStart = [Math]::Max(0, $range.RelativeStart - $Context)
        $rightStart = [Math]::Max(0, $range.RelativeStart - $Context)

        $leftEnd = [Math]::Min(
            $left.PayloadLength,
            $range.RelativeEnd + 1 + $Context
        )

        $rightEnd = [Math]::Min(
            $right.PayloadLength,
            $range.RelativeEnd + 1 + $Context
        )

        [PSCustomObject]@{
            StreamName          = $StreamName

            ReferenceFile       = $left.FileName
            DifferenceFile      = $right.FileName

            RelativeStart       = $range.RelativeStart
            RelativeStartHex    = ('0x{0:X8}' -f $range.RelativeStart)

            ReferenceAbsolute   = $left.PayloadStart + $range.RelativeStart
            ReferenceAbsoluteHex = (
                '0x{0:X8}' -f ($left.PayloadStart + $range.RelativeStart)
            )

            DifferenceAbsolute  = $right.PayloadStart + $range.RelativeStart
            DifferenceAbsoluteHex = (
                '0x{0:X8}' -f ($right.PayloadStart + $range.RelativeStart)
            )

            DifferenceLength    = $range.Length

            ReferenceContextStart = $left.PayloadStart + $leftStart
            ReferenceBytes      = if ($leftStart -lt $leftEnd) {
                [byte[]]$left.Payload[$leftStart..($leftEnd - 1)]
            }
            else {
                [byte[]]@()
            }

            DifferenceContextStart = $right.PayloadStart + $rightStart
            DifferenceBytes     = if ($rightStart -lt $rightEnd) {
                [byte[]]$right.Payload[$rightStart..($rightEnd - 1)]
            }
            else {
                [byte[]]@()
            }
        }
    }
}




# =========================================================================
# FUNCTION: Show-CreoStreamHashMatrix:
# .EXAMPLE
# Show-CreoStreamHashMatrix -Path '.\models\prt0001.prt.*'
# 
# Full matrix
# 
# 
# .EXAMPLE
# Show-CreoStreamHashMatrix `
#     -Path '.\models\prt0001.prt.*' `
#     -ChangedOnly
# 
# Only changed streams
# This will be your most useful command while running the test matrix:
# 
# 
# .EXAMPLE
# Show-CreoStreamHashMatrix `
#     -Path '.\models\prt0001.prt.[7-8]' `
#     -BaselinePath '.\models\prt0001.prt.7' `
#     -StreamName 'LargeText', 'NeuPrtSld', 'FeatDefs',
#                 'FeatRefData', 'FeatDefsIndex', 'MdlStatus'
# 
# Parameter experiment
# Use `.7` as the baseline and focus on currently relevant streams:
# 
# .EXAMPLE
# Show-CreoStreamHashMatrix `
#     -Path '.\models\prt0001.prt.[2-3]' `
#     -BaselinePath '.\models\prt0001.prt.2' `
#     -StreamName 'AllFeatur', 'FeatDefs', 'FeatRefData',
#                 'FeatDefsIndex', 'SolidPersistTable',
#                 'SolidPrimdata', 'NeuPrtSld',
#                 'BasFullData', 'FullMData'
# 
# Geometry experiment
# For `.2` vs `.3`, initially examine these candidates:
# 
# 
# 
# 
# .EXAMPLE
# $comparison = Show-CreoStreamHashMatrix `
#     -Path '.\models\prt0001.prt.*' `
#     -ChangedOnly `
#     -PassThru
# 
# $comparison |
#     Select-Object StreamName, Status, PresentFiles, MissingFiles,
#                   DistinctHashes, BaselineFile, BaselineLength |
#     Export-Csv .\prt0001_stream_hash_comparison.csv -NoTypeInformation
# 
# Export results
# The display is for people; `-PassThru` makes the same comparison available as objects:
# 
# =========================================================================

function Show-CreoStreamHashMatrix {
    <#
    .SYNOPSIS
        Displays a color-coded stream-hash comparison matrix for Creo files.

    .DESCRIPTION
        Calls Get-CreoStreamFingerprints for files matched by -Path, then
        compares every stream's SHA-256 to one baseline file.

        Default baseline:
          The earliest numeric final extension when filenames end in .N.
          Example: prt0001.prt.1 is selected before prt0001.prt.10.

        Status legend:
          =  Green       Stream exists and hash equals the baseline hash.
          X  Red         Stream exists but its hash differs from baseline.
          -  Yellow      Stream does not exist in this file revision.
          ?  DarkYellow  Baseline does not contain this stream.

        This is a raw persistence-state tool. A red X means only that the
        serialized stream changed; it does not by itself prove geometry,
        parameter, annotation, or product-definition change.

    .EXAMPLE
        Show-CreoStreamHashMatrix -Path '.\models\prt0001.prt.*'

    .EXAMPLE
        # Show only streams that differ from the baseline or are missing.
        Show-CreoStreamHashMatrix `
            -Path '.\models\prt0001.prt.*' `
            -ChangedOnly

    .EXAMPLE
        # Use revision .7 as the comparison baseline.
        Show-CreoStreamHashMatrix `
            -Path '.\models\prt0001.prt.*' `
            -BaselinePath '.\models\prt0001.prt.7'

    .EXAMPLE
        # Focus on streams that currently look relevant to model definition.
        Show-CreoStreamHashMatrix `
            -Path '.\models\prt0001.prt.*' `
            -StreamName 'FeatDefs', 'AllFeatur', 'NeuPrtSld',
                        'SolidPersistTable', 'SolidPrimdata',
                        'FeatRefData', 'FeatDefsIndex'

    .EXAMPLE
        # Capture the typed summary objects for export or later filtering.
        $comparison = Show-CreoStreamHashMatrix `
            -Path '.\models\prt0001.prt.*' `
            -ChangedOnly `
            -PassThru

        $comparison | Export-Csv .\stream_comparison.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string[]]$StreamName = '*',

        [switch]$ChangedOnly,

        [switch]$SameOnly,

        [switch]$PassThru,

        [switch]$NoColor
    )

    begin {
        if ($ChangedOnly -and $SameOnly) {
            throw 'Use either -ChangedOnly or -SameOnly, not both.'
        }

        function Get-CreoNaturalRevisionInfo {
            param(
                [Parameter(Mandatory)]
                [string]$FileName
            )

            # Handles Creo-style versioned file names:
            # prt0001.prt.1
            # prt0001.prt.10
            #
            # Numeric sort matters because lexical sorting puts .10 before .2.
            if ($FileName -match '\.(\d+)$') {
                return [PSCustomObject]@{
                    HasNumericRevision = $true
                    Revision           = [Int64]$matches[1]
                    SortName           = $FileName
                }
            }

            return [PSCustomObject]@{
                HasNumericRevision = $false
                Revision           = [Int64]::MaxValue
                SortName           = $FileName
            }
        }

        function Get-CreoShortLabel {
            param(
                [Parameter(Mandatory)]
                [string]$FileName
            )

            # Prefer a compact ".7" style column heading for Creo revisions.
            if ($FileName -match '\.(\d+)$') {
                return ".{0}" -f $matches[1]
            }

            # Fall back to a trimmed filename for non-versioned files.
            if ($FileName.Length -gt 12) {
                return $FileName.Substring(0, 12)
            }

            return $FileName
        }

        function Write-CreoMatrixText {
            param(
                [Parameter(Mandatory)]
                [string]$Text,

                [ConsoleColor]$Color = [ConsoleColor]::Gray,

                [switch]$NoNewline,

                [switch]$DisableColor
            )

            if ($DisableColor) {
                Write-Host $Text -NoNewline:$NoNewline
            }
            else {
                Write-Host $Text `
                    -ForegroundColor $Color `
                    -NoNewline:$NoNewline
            }
        }
    }

    process {
        # Get-CreoStreamFingerprints supports files, directories, and wildcards.
        $fingerprints = @(
            Get-CreoStreamFingerprints -Path $Path
        )

        if ($fingerprints.Count -eq 0) {
            throw 'No stream fingerprints were produced for the supplied path(s).'
        }

        # Get a distinct, naturally sorted list of input files.
        $files = @(
            $fingerprints |
                Group-Object FilePath |
                ForEach-Object {
                    $first = $_.Group | Select-Object -First 1
                    $sort = Get-CreoNaturalRevisionInfo -FileName $first.FileName

                    [PSCustomObject]@{
                        FilePath       = $first.FilePath
                        FileName       = $first.FileName
                        Revision       = $sort.Revision
                        HasRevision    = $sort.HasNumericRevision
                        SortName       = $sort.SortName
                        Label          = Get-CreoShortLabel -FileName $first.FileName
                    }
                } |
                Sort-Object `
                    @{ Expression = { -not $_.HasRevision } },
                    @{ Expression = { $_.Revision } },
                    @{ Expression = { $_.SortName } }
        )

        if ($files.Count -lt 2) {
            throw (
                'At least two files are required for a comparison. ' +
                "Found $($files.Count)."
            )
        }

        # Use a caller-specified baseline if supplied; otherwise use the
        # earliest naturally sorted revision.
        $baselineFile = $null

        if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
            $baselineMatches = @(
                Resolve-Path -Path $BaselinePath -ErrorAction Stop
            )

            if ($baselineMatches.Count -ne 1) {
                throw (
                    "-BaselinePath must resolve to exactly one file. " +
                    "It resolved to $($baselineMatches.Count) item(s)."
                )
            }

            $baselineResolvedPath = $baselineMatches[0].Path

            $baselineFile = @(
                $files | Where-Object {
                    $_.FilePath -eq $baselineResolvedPath
                }
            ) | Select-Object -First 1

            if ($null -eq $baselineFile) {
                throw (
                    "Baseline '$baselineResolvedPath' is not included in " +
                    'the files matched by -Path.'
                )
            }
        }
        else {
            $baselineFile = $files | Select-Object -First 1
        }

        # Build a fast lookup:
        #   <full file path>|<stream name> => fingerprint object
        $lookup = @{}

        foreach ($row in $fingerprints) {
            $key = '{0}|{1}' -f $row.FilePath, $row.StreamName

            # If the resolver somehow produces duplicate same-name streams
            # for one file, retain the first and make it visible with Verbose.
            if ($lookup.ContainsKey($key)) {
                Write-Verbose (
                    "Duplicate stream '$($row.StreamName)' in " +
                    "'$($row.FileName)'; retaining first fingerprint."
                )
                continue
            }

            $lookup[$key] = $row
        }

        # Build the union of stream names across every selected file.
        $streamNames = @(
            $fingerprints |
                Select-Object -ExpandProperty StreamName -Unique |
                Where-Object {
                    $candidate = $_

                    foreach ($pattern in $StreamName) {
                        if ($candidate -like $pattern) {
                            return $true
                        }
                    }

                    return $false
                } |
                Sort-Object
        )

        if ($streamNames.Count -eq 0) {
            throw 'No streams matched the supplied -StreamName filter.'
        }

        $summaries = [System.Collections.Generic.List[object]]::new()

        foreach ($stream in $streamNames) {
            $baselineKey = '{0}|{1}' -f $baselineFile.FilePath, $stream
            $baselineRow = $lookup[$baselineKey]

            $presentCount = 0
            $sameCount = 0
            $differentCount = 0
            $missingCount = 0
            $hashes = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )

            $perFile = @{}

            foreach ($file in $files) {
                $key = '{0}|{1}' -f $file.FilePath, $stream
                $row = $lookup[$key]

                if ($null -eq $row) {
                    $missingCount++

                    $perFile[$file.FilePath] = [PSCustomObject]@{
                        Status = 'Missing'
                        Symbol = '-'
                        Color  = [ConsoleColor]::Yellow
                        Row    = $null
                    }

                    continue
                }

                $presentCount++
                [void]$hashes.Add([string]$row.SHA256)

                if ($null -eq $baselineRow) {
                    $perFile[$file.FilePath] = [PSCustomObject]@{
                        Status = 'NoBaseline'
                        Symbol = '?'
                        Color  = [ConsoleColor]::DarkYellow
                        Row    = $row
                    }

                    continue
                }

                if ($row.SHA256 -eq $baselineRow.SHA256) {
                    $sameCount++

                    $perFile[$file.FilePath] = [PSCustomObject]@{
                        Status = 'Same'
                        Symbol = '='
                        Color  = [ConsoleColor]::Green
                        Row    = $row
                    }
                }
                else {
                    $differentCount++

                    $perFile[$file.FilePath] = [PSCustomObject]@{
                        Status = 'Different'
                        Symbol = 'X'
                        Color  = [ConsoleColor]::Red
                        Row    = $row
                    }
                }
            }

            $status = if ($null -eq $baselineRow) {
                'NoBaselineStream'
            }
            elseif ($missingCount -gt 0) {
                'MissingInSomeFiles'
            }
            elseif ($differentCount -eq 0) {
                'SameAcrossAllFiles'
            }
            else {
                'ChangedFromBaseline'
            }

            $summary = [ordered]@{
                StreamName        = $stream
                Status            = $status
                PresentFiles      = $presentCount
                TotalFiles        = $files.Count
                MissingFiles      = $missingCount
                DistinctHashes    = $hashes.Count
                BaselineFile      = $baselineFile.FileName
                BaselineLength    = if ($baselineRow) {
                    $baselineRow.PayloadLength
                }
                else {
                    $null
                }
                BaselineSHA256    = if ($baselineRow) {
                    $baselineRow.SHA256
                }
                else {
                    $null
                }
            }

            foreach ($file in $files) {
                $cell = $perFile[$file.FilePath]

                # Dynamic per-file properties make -PassThru exportable.
                $summary["$($file.Label)_Status"] = $cell.Status
                $summary["$($file.Label)_Length"] = if ($cell.Row) {
                    $cell.Row.PayloadLength
                }
                else {
                    $null
                }
                $summary["$($file.Label)_SHA256"] = if ($cell.Row) {
                    $cell.Row.SHA256
                }
                else {
                    $null
                }
            }

            $summaries.Add([PSCustomObject]$summary)
        }

        $displayRows = @(
            foreach ($summary in $summaries) {
                if ($ChangedOnly -and
                    $summary.Status -eq 'SameAcrossAllFiles') {
                    continue
                }

                if ($SameOnly -and
                    $summary.Status -ne 'SameAcrossAllFiles') {
                    continue
                }

                $summary
            }
        )

        $sameStreams = @(
            $summaries | Where-Object {
                $_.Status -eq 'SameAcrossAllFiles'
            }
        ).Count

        $changedStreams = @(
            $summaries | Where-Object {
                $_.Status -eq 'ChangedFromBaseline'
            }
        ).Count

        $missingStreams = @(
            $summaries | Where-Object {
                $_.Status -eq 'MissingInSomeFiles' -or
                $_.Status -eq 'NoBaselineStream'
            }
        ).Count

        # -------------------------
        # Console visualization
        # -------------------------
        Write-Host ''
        Write-CreoMatrixText `
            -Text '=== Creo Stream Hash Matrix ===' `
            -Color Cyan `
            -DisableColor:$NoColor

        Write-Host ''

        Write-CreoMatrixText `
            -Text 'Baseline : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $baselineFile.FileName `
            -Color White `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'Files    : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $files.Count `
            -Color White `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'Streams  : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $summaries.Count `
            -Color White `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'Same     : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $sameStreams `
            -Color Green `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'Changed  : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $changedStreams `
            -Color Red `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'Missing  : ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text $missingStreams `
            -Color Yellow `
            -DisableColor:$NoColor

        Write-Host ''
        Write-Host ''

        Write-CreoMatrixText `
            -Text 'Legend: ' `
            -Color DarkGray `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text '= same  ' `
            -Color Green `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text 'X changed  ' `
            -Color Red `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text '- missing  ' `
            -Color Yellow `
            -NoNewline `
            -DisableColor:$NoColor

        Write-CreoMatrixText `
            -Text '? no baseline stream' `
            -Color DarkYellow `
            -DisableColor:$NoColor

        Write-Host ''
        Write-Host ''

        # Calculate widths. Limit stream-name width to keep the matrix readable.
        $streamColumnWidth = [Math]::Max(
            24,
            [Math]::Min(
                34,
                (($displayRows | ForEach-Object {
                    $_.StreamName.Length
                } | Measure-Object -Maximum).Maximum)
            )
        )

        $fileColumnWidth = 8

        # Header row.
        $streamHeaderFormat = '{0,-' + $streamColumnWidth + '}  '
        $streamHeaderText = $streamHeaderFormat -f 'StreamName'

        Write-CreoMatrixText `
            -Text $streamHeaderText `
            -Color Cyan `
            -NoNewline `
            -DisableColor:$NoColor

        foreach ($file in $files) {
            $header = $file.Label

            if ($header.Length -gt $fileColumnWidth) {
                $header = $header.Substring(0, $fileColumnWidth)
            }

            $fileHeaderFormat = '{0,' + $fileColumnWidth + '} '
            $fileHeaderText = $fileHeaderFormat -f $header

            Write-CreoMatrixText `
                -Text $fileHeaderText `
                -Color Cyan `
                -NoNewline `
                -DisableColor:$NoColor
        }

        Write-CreoMatrixText `
            -Text '  Distinct  Status' `
            -Color Cyan `
            -DisableColor:$NoColor

        # Separator row.
        $separatorLength = $streamColumnWidth + 2 +
            (($fileColumnWidth + 1) * $files.Count) + 22

        Write-CreoMatrixText `
            -Text ('-' * $separatorLength) `
            -Color DarkGray `
            -DisableColor:$NoColor

        foreach ($summary in $displayRows) {
            $displayName = $summary.StreamName

            if ($displayName.Length -gt $streamColumnWidth) {
                $displayName = $displayName.Substring(
                    0,
                    $streamColumnWidth - 1
                ) + '…'
            }

            $nameColor = switch ($summary.Status) {
                'SameAcrossAllFiles' { [ConsoleColor]::Green }
                'ChangedFromBaseline' { [ConsoleColor]::Red }
                default { [ConsoleColor]::Yellow }
            }

            $streamNameFormat = '{0,-' + $streamColumnWidth + '}  '
            $streamNameText = $streamNameFormat -f $displayName

            Write-CreoMatrixText `
                -Text $streamNameText `
                -Color $nameColor `
                -NoNewline `
                -DisableColor:$NoColor

            foreach ($file in $files) {
                $statusProperty = '{0}_Status' -f $file.Label
                $cellStatus = $summary.$statusProperty

                $symbol = switch ($cellStatus) {
                    'Same'       { '=' }
                    'Different'  { 'X' }
                    'Missing'    { '-' }
                    'NoBaseline' { '?' }
                    default      { '?' }
                }

                $color = switch ($cellStatus) {
                    'Same'       { [ConsoleColor]::Green }
                    'Different'  { [ConsoleColor]::Red }
                    'Missing'    { [ConsoleColor]::Yellow }
                    'NoBaseline' { [ConsoleColor]::DarkYellow }
                    default      { [ConsoleColor]::Gray }
                }

                $statusSymbolFormat = '{0,' + $fileColumnWidth + '} '
                $statusSymbolText = $statusSymbolFormat -f $symbol

                Write-CreoMatrixText `
                    -Text $statusSymbolText `
                    -Color $color `
                    -NoNewline `
                    -DisableColor:$NoColor
            }

            $statusText = switch ($summary.Status) {
                'SameAcrossAllFiles' {
                    'SAME'
                }
                'ChangedFromBaseline' {
                    'CHANGED'
                }
                'MissingInSomeFiles' {
                    'MISSING'
                }
                'NoBaselineStream' {
                    'NO BASELINE'
                }
                default {
                    $summary.Status
                }
            }

            $statusColor = switch ($summary.Status) {
                'SameAcrossAllFiles'  { [ConsoleColor]::Green }
                'ChangedFromBaseline' { [ConsoleColor]::Red }
                default               { [ConsoleColor]::Yellow }
            }

            $distinctHashText = '  {0,8}  ' -f $summary.DistinctHashes
                    
            Write-CreoMatrixText `
                -Text $distinctHashText `
                -Color DarkGray `
                -NoNewline `
                -DisableColor:$NoColor

            Write-CreoMatrixText `
                -Text $statusText `
                -Color $statusColor `
                -DisableColor:$NoColor
        }

        Write-Host ''
        Write-CreoMatrixText `
            -Text (
                'Displayed {0} of {1} stream(s).' -f
                $displayRows.Count,
                $summaries.Count
            ) `
            -Color DarkGray `
            -DisableColor:$NoColor

        Write-Host ''

        if ($PassThru) {
            Write-Output $displayRows
        }
    }
}


function Get-CreoCandidatePlmHashes {
    <#
    .SYNOPSIS
        Produces provisional PLM-oriented composite hashes for Creo files.

    .DESCRIPTION
        IMPORTANT:
        Every profile in this function is deliberately named "Candidate".
        These profiles are based on controlled tests of prt0001.prt.1-.10,
        not on an official Creo binary-file specification.

        The profiles are intended to be revised as you run more experiments,
        validate behavior with assemblies, and identify semantic record
        formats.

        Current candidate evidence:

        CandidateGeometryStreamName:
          - AllFeatur
          - BasicText
          - NeuAsmSld
          - VisibGeom

        These streams were selected because they:
          - Stayed unchanged for the .7 -> .8 parameter string change.
          - Changed for the .8 -> .9 revolve-cut addition.
          - Returned to the .8 hash in .10 after deleting that cut.

        CandidateParameterPersistenceStreamName:
          - ActEntity
          - FeatDefs
          - FeatDefsIndex
          - FeatRefData
          - NeuPrtSld

        These streams changed during .7 -> .8, where the only intended
        change was PARAMETER_3:
          "This Is My String" -> "This Is NOT My String"

        This is NOT YET a semantic parameter hash. It is a conservative
        parameter-persistence candidate and can change for unrelated
        serialized-state changes.

        CandidateAnnotationStreamName:
          Empty by default, because annotations have not yet been validated
          with controlled note/dimension/symbol experiments.

    .EXAMPLE
        Get-CreoCandidatePlmHashes -Path '.\models\prt0001.prt.*' |
            Format-Table FileName,
                         CandidateGeometryHash,
                         CandidateParameterPersistenceHash,
                         CandidateNativeDefinitionHash -AutoSize

    .EXAMPLE
        # Compare only revisions .8, .9, and .10.
        Get-CreoCandidatePlmHashes `
            -Path '.\models\prt0001.prt.8',
                  '.\models\prt0001.prt.9',
                  '.\models\prt0001.prt.10' |
            Format-Table FileName,
                         CandidateGeometryHash,
                         CandidateParameterPersistenceHash,
                         CandidateNativeDefinitionHash -AutoSize

    .EXAMPLE
        # Later, after annotation testing, supply a provisional profile.
        Get-CreoCandidatePlmHashes `
            -Path '.\models\prt0001.prt.*' `
            -CandidateAnnotationStreamName 'Notes', 'DwgData'

    .EXAMPLE
        # Test an alternative geometry profile without changing the function.
        Get-CreoCandidatePlmHashes `
            -Path '.\models\prt0001.prt.*' `
            -CandidateGeometryStreamName 'AllFeatur',
                                         'BasicText',
                                         'NeuAsmSld',
                                         'VisibGeom',
                                         'ModelView#9'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        # -----------------------------------------------------------------
        # Candidate Geometry Profile
        #
        # Current test evidence:
        # .7 -> .8 parameter edit: same
        # .8 -> .9 revolve cut:     changed
        # .9 -> .10 cut deletion:   returned to .8 hash
        #
        # Continue validating this profile using:
        # - save-only tests
        # - datum visibility tests
        # - parameter add/edit tests
        # - annotation tests
        # - controlled geometry changes
        # - assembly model tests
        # -----------------------------------------------------------------
        [string[]]$CandidateGeometryStreamName = @(
            'AllFeatur',
            'BasicText',
            'NeuAsmSld',
            'VisibGeom'
        ),

        # -----------------------------------------------------------------
        # Candidate Parameter Persistence Profile
        #
        # Current test evidence:
        # .7 -> .8 parameter string edit changed all of these streams.
        #
        # This profile is intentionally conservative and may include
        # non-parameter persistence. Replace it eventually with a semantic
        # PARAMETER_* record extractor and normalized parameter hash.
        # -----------------------------------------------------------------
        [string[]]$CandidateParameterPersistenceStreamName = @(
            'ActEntity',
            'FeatDefs',
            'FeatDefsIndex',
            'FeatRefData',
            'NeuPrtSld'
        ),

        # -----------------------------------------------------------------
        # Candidate Annotation Profile
        #
        # Leave empty until controlled tests establish which streams change
        # only for annotation/note/dimension/symbol edits.
        #
        # Example future candidate:
        # -CandidateAnnotationStreamName 'Notes', 'DwgData'
        # -----------------------------------------------------------------
        [string[]]$CandidateAnnotationStreamName = @(),

        # Include per-profile stream components in the output object.
        # Useful for SQL ingestion or diagnosing profile differences.
        [switch]$IncludeCandidateComponents
    )

    begin {
        function Get-CreoCandidateSha256 {
            param(
                [Parameter(Mandatory)]
                [string]$CandidateText
            )

            [byte[]]$candidateBytes =
                [System.Text.Encoding]::UTF8.GetBytes($CandidateText)

            $candidateSha256 =
                [System.Security.Cryptography.SHA256]::Create()

            try {
                [byte[]]$candidateHashBytes =
                    $candidateSha256.ComputeHash($candidateBytes)

                return (
                    [System.BitConverter]::ToString($candidateHashBytes) `
                        -replace '-', ''
                )
            }
            finally {
                if ($null -ne $candidateSha256) {
                    $candidateSha256.Dispose()
                }
            }
        }

        function New-CreoCandidateProfile {
            param(
                [Parameter(Mandatory)]
                [string]$CandidateProfileName,

                [Parameter()]
                [AllowEmptyCollection()]
                [string[]]$CandidateStreamNames,

                [Parameter(Mandatory)]
                [object[]]$CandidateFileFingerprintRows
            )

            # No candidate stream profile means no hash should be claimed.
            if ($null -eq $CandidateStreamNames -or
                $CandidateStreamNames.Count -eq 0) {
                return [PSCustomObject]@{
                    CandidateProfileName          = $CandidateProfileName
                    CandidateProfileConfigured    = $false
                    CandidateProfileComplete      = $false
                    CandidateHash                 = $null
                    CandidateIncludedStreamCount  = 0
                    CandidateMissingStreamCount   = 0
                    CandidateMissingStreams       = @()
                    CandidateComponents           = @()
                }
            }

            # Make the profile deterministic:
            # no duplicate names, case-insensitive sort.
            $candidateExpectedStreams = @(
                $CandidateStreamNames |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            )

            # Map this file's stream names to fingerprints.
            $candidateStreamLookup = @{}

            foreach ($candidateRow in $CandidateFileFingerprintRows) {
                if (-not $candidateStreamLookup.ContainsKey(
                    [string]$candidateRow.StreamName
                )) {
                    $candidateStreamLookup[
                        [string]$candidateRow.StreamName
                    ] = $candidateRow
                }
            }

            $candidateCanonicalLines =
                [System.Collections.Generic.List[string]]::new()

            $candidateComponents =
                [System.Collections.Generic.List[object]]::new()

            $candidateMissingStreams =
                [System.Collections.Generic.List[string]]::new()

            foreach ($candidateStreamName in $candidateExpectedStreams) {
                if ($candidateStreamLookup.ContainsKey(
                    $candidateStreamName
                )) {
                    $candidateRow =
                        $candidateStreamLookup[$candidateStreamName]

                    # Canonical input contains only stable stream identity,
                    # payload size, and raw stream hash.
                    #
                    # Do NOT include offsets: stream offsets can move due to
                    # unrelated persistence changes.
                    $candidateCanonicalLine = (
                        'STREAM|{0}|{1}|{2}' -f
                        $candidateRow.StreamName,
                        $candidateRow.PayloadLength,
                        $candidateRow.SHA256
                    )

                    $candidateCanonicalLines.Add($candidateCanonicalLine)

                    $candidateComponents.Add([PSCustomObject]@{
                        StreamName    = $candidateRow.StreamName
                        PayloadLength = $candidateRow.PayloadLength
                        SHA256        = $candidateRow.SHA256
                        Present       = $true
                    })
                }
                else {
                    # Include an explicit missing marker in the canonical
                    # input, so an absent stream changes the profile hash.
                    $candidateCanonicalLines.Add(
                        'MISSING|{0}' -f $candidateStreamName
                    )

                    $candidateMissingStreams.Add($candidateStreamName)

                    $candidateComponents.Add([PSCustomObject]@{
                        StreamName    = $candidateStreamName
                        PayloadLength = $null
                        SHA256        = $null
                        Present       = $false
                    })
                }
            }

            $candidateCanonicalText = @(
                'PROFILE|{0}' -f $CandidateProfileName
                'PROFILE_VERSION|1'
                $candidateCanonicalLines
            ) -join "`n"

            return [PSCustomObject]@{
                CandidateProfileName         = $CandidateProfileName
                CandidateProfileConfigured   = $true
                CandidateProfileComplete     = (
                    $candidateMissingStreams.Count -eq 0
                )
                CandidateHash                = Get-CreoCandidateSha256 `
                    -CandidateText $candidateCanonicalText
                CandidateIncludedStreamCount = (
                    $candidateExpectedStreams.Count -
                    $candidateMissingStreams.Count
                )
                CandidateMissingStreamCount  = $candidateMissingStreams.Count
                CandidateMissingStreams      = $candidateMissingStreams.ToArray()
                CandidateComponents          = $candidateComponents.ToArray()
            }
        }
    }

    process {
        # Uses your existing wildcard-aware fingerprint function.
        $candidateFingerprintRows = @(
            Get-CreoStreamFingerprints -Path $Path
        )

        if ($candidateFingerprintRows.Count -eq 0) {
            throw 'No Creo stream fingerprints were produced.'
        }

        $candidateFiles = @(
            $candidateFingerprintRows |
                Group-Object FilePath |
                ForEach-Object {
                    $_.Group | Select-Object -First 1
                } |
                Sort-Object FileName
        )

        foreach ($candidateFile in $candidateFiles) {
            $candidateFileRows = @(
                $candidateFingerprintRows |
                    Where-Object {
                        $_.FilePath -eq $candidateFile.FilePath
                    }
            )

            # Exact artifact hash: useful for audit and deduplication.
            $candidateFileHash =
                Get-FileHash `
                    -LiteralPath $candidateFile.FilePath `
                    -Algorithm SHA256

            $candidateGeometryProfile = New-CreoCandidateProfile `
                -CandidateProfileName 'CandidateGeometryProfileV1' `
                -CandidateStreamNames $CandidateGeometryStreamName `
                -CandidateFileFingerprintRows $candidateFileRows

            $candidateParameterProfile = New-CreoCandidateProfile `
                -CandidateProfileName 'CandidateParameterPersistenceProfileV1' `
                -CandidateStreamNames `
                    $CandidateParameterPersistenceStreamName `
                -CandidateFileFingerprintRows $candidateFileRows

            # The candidate native-definition profile intentionally includes
            # both geometry-sensitive and parameter-sensitive candidate
            # streams. It is useful when configuration control cares about
            # either geometry OR parameter persistence changes.
            $candidateNativeDefinitionStreamNames = @(
                $CandidateGeometryStreamName +
                $CandidateParameterPersistenceStreamName |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            )

            $candidateNativeDefinitionProfile = New-CreoCandidateProfile `
                -CandidateProfileName 'CandidateNativeDefinitionProfileV1' `
                -CandidateStreamNames `
                    $candidateNativeDefinitionStreamNames `
                -CandidateFileFingerprintRows $candidateFileRows

            $candidateAnnotationProfile = New-CreoCandidateProfile `
                -CandidateProfileName 'CandidateAnnotationProfileV1' `
                -CandidateStreamNames $CandidateAnnotationStreamName `
                -CandidateFileFingerprintRows $candidateFileRows

            $candidateResult = [ordered]@{
                FilePath  = $candidateFile.FilePath
                FileName  = $candidateFile.FileName
                FileSHA256 = $candidateFileHash.Hash

                # Candidate geometry-equivalence profile.
                CandidateGeometryHash = $candidateGeometryProfile.CandidateHash
                CandidateGeometryProfileConfigured =
                    $candidateGeometryProfile.CandidateProfileConfigured
                CandidateGeometryProfileComplete =
                    $candidateGeometryProfile.CandidateProfileComplete
                CandidateGeometryMissingStreams =
                    $candidateGeometryProfile.CandidateMissingStreams -join ', '

                # Candidate parameter-persistence profile.
                CandidateParameterPersistenceHash =
                    $candidateParameterProfile.CandidateHash
                CandidateParameterProfileConfigured =
                    $candidateParameterProfile.CandidateProfileConfigured
                CandidateParameterProfileComplete =
                    $candidateParameterProfile.CandidateProfileComplete
                CandidateParameterMissingStreams =
                    $candidateParameterProfile.CandidateMissingStreams -join ', '

                # Candidate union profile: geometry + parameter persistence.
                CandidateNativeDefinitionHash =
                    $candidateNativeDefinitionProfile.CandidateHash
                CandidateNativeDefinitionProfileComplete =
                    $candidateNativeDefinitionProfile.CandidateProfileComplete
                CandidateNativeDefinitionMissingStreams =
                    $candidateNativeDefinitionProfile.CandidateMissingStreams -join ', '

                # Intentionally unconfigured until annotation testing exists.
                CandidateAnnotationHash =
                    $candidateAnnotationProfile.CandidateHash
                CandidateAnnotationProfileConfigured =
                    $candidateAnnotationProfile.CandidateProfileConfigured
                CandidateAnnotationProfileComplete =
                    $candidateAnnotationProfile.CandidateProfileComplete
                CandidateAnnotationMissingStreams =
                    $candidateAnnotationProfile.CandidateMissingStreams -join ', '
            }

            if ($IncludeCandidateComponents) {
                $candidateResult['CandidateGeometryComponents'] =
                    $candidateGeometryProfile.CandidateComponents

                $candidateResult['CandidateParameterComponents'] =
                    $candidateParameterProfile.CandidateComponents

                $candidateResult['CandidateNativeDefinitionComponents'] =
                    $candidateNativeDefinitionProfile.CandidateComponents

                $candidateResult['CandidateAnnotationComponents'] =
                    $candidateAnnotationProfile.CandidateComponents
            }

            [PSCustomObject]$candidateResult
        }
    }
}

function Get-CreoInitialInventory {
    <#
    .SYNOPSIS
        Performs the initial file-level inventory crawl for Creo files.

    .DESCRIPTION
        Produces one normalized record per physical Creo file. This is the
        primary "Files" dataset for an initial SQL import.

        It intentionally does NOT decide:
          - Which duplicate is the master
          - Which same-name model is the correct model
          - Whether a candidate geometry match is release-equivalent
          - Whether a file should be deleted

        It records evidence so that those decisions can be made later.

    .NOTES
        Candidate hash profiles are provisional and must remain versioned.

        Do not use CandidateGeometryHash to deduplicate files when
        CandidateGeometryProfileComplete is False. A False value means one
        or more expected profile streams were absent from that Creo file.

        Assembly files may require a different candidate profile from parts.
        The output includes CreoObjectType so that SQL can separate profiles
        by PRT / ASM / DRW during validation.

    .EXAMPLE
        $crawlRunId = [guid]::NewGuid().ToString()

        Get-CreoInitialInventory `
            -Path '\\EngineeringShare\Creo' `
            -RootPath '\\EngineeringShare\Creo' `
            -CrawlRunId $crawlRunId |
            Export-Csv '.\initial_creo_file_inventory.csv' -NoTypeInformation

    .EXAMPLE
        Get-CreoInitialInventory `
            -Path '\\EngineeringShare\Creo' `
            -RootPath '\\EngineeringShare\Creo' `
            -CreoObjectType prt, asm |
            Format-Table FileName, CreoObjectType, CreoVersion,
                         FileSHA256, CandidateGeometryHash -AutoSize

    .EXAMPLE
        # Inventory a specific known model history.
        Get-CreoInitialInventory `
            -Path '.\models\prt0001.prt.*' `
            -RootPath '.\models'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        # Use the engineering-share root here. It allows the output to retain
        # a stable RelativePath even when files are deeply nested.
        [string]$RootPath,

        # Persist this exact ID in SQL to associate every row with one crawl.
        [string]$CrawlRunId = ([guid]::NewGuid().ToString()),

        # Core Creo model/document types for the initial pass.
        [ValidateSet('prt', 'asm', 'drw')]
        [string[]]$CreoObjectType = @('prt', 'asm', 'drw'),

        # Recurse is enabled by default because this is intended for shared
        # drive inventory. Set -Recurse:$false for a single folder only.
        [bool]$Recurse = $true,

        # Include filesystem hidden/system files if the current account can
        # access them.
        [switch]$IncludeHidden,

        # Stop immediately on a parser/hash error instead of emitting a row
        # with InventoryStatus = Error.
        [switch]$StopOnError,

        # -----------------------------------------------------------------
        # Candidate Geometry Profile
        #
        # Current part-file test evidence:
        # .7 -> .8 parameter string edit: unchanged
        # .8 -> .9 revolve cut:           changed
        # .9 -> .10 delete cut:            returned to .8 hash
        #
        # Validate further before treating as a production GeometryHash.
        # -----------------------------------------------------------------
        [string[]]$CandidateGeometryStreamName = @(
            'AllFeatur',
            'BasicText',
            'NeuAsmSld',
            'VisibGeom'
        ),

        # -----------------------------------------------------------------
        # Candidate Parameter Persistence Profile
        #
        # Current part-file test evidence:
        # .7 -> .8 PARAMETER_3 string edit changed these streams.
        #
        # This is NOT a normalized semantic parameter hash. It is a
        # conservative candidate until your parameter extractor becomes the
        # authoritative parameter-signature source.
        # -----------------------------------------------------------------
        [string[]]$CandidateParameterPersistenceStreamName = @(
            'ActEntity',
            'FeatDefs',
            'FeatDefsIndex',
            'FeatRefData',
            'NeuPrtSld'
        ),

        # Leave empty until annotation-specific testing proves a profile.
        [string[]]$CandidateAnnotationStreamName = @()
    )

    begin {
        function Get-CreoRelativePath {
            param(
                [Parameter(Mandatory)]
                [string]$FullPath,

                [string]$ResolvedRootPath
            )

            if ([string]::IsNullOrWhiteSpace($ResolvedRootPath)) {
                return [System.IO.Path]::GetFileName($FullPath)
            }

            $root = $ResolvedRootPath.TrimEnd('\', '/')
            $comparison = [System.StringComparison]::OrdinalIgnoreCase

            if ($FullPath.StartsWith($root, $comparison)) {
                $relative = $FullPath.Substring($root.Length).TrimStart('\', '/')

                if (-not [string]::IsNullOrWhiteSpace($relative)) {
                    return $relative
                }
            }

            # The file was not under RootPath. Preserve its full path rather
            # than silently generating an incorrect relative path.
            return $FullPath
        }

        function Get-CreoFileIdentity {
            param(
                [Parameter(Mandatory)]
                [System.IO.FileInfo]$FileInfo
            )

            # Examples:
            # prt0001.prt.8
            # company_start_asm.asm.1
            # some_drawing.drw.3
            #
            # BaseModelName is a grouping/search key only. It is NOT a unique
            # model identity: multiple contractors can use the same names.
            $pattern = (
                '^(?<BaseName>.+?)\.' +
                '(?<CreoType>prt|asm|drw)' +
                '(?:\.(?<Version>\d+))?$'
            )

            if ($FileInfo.Name -match $pattern) {
                $version = if ([string]::IsNullOrWhiteSpace($matches.Version)) {
                    $null
                }
                else {
                    [Int64]$matches.Version
                }

                return [PSCustomObject]@{
                    IsCreoCandidate = $true
                    BaseModelName   = $matches.BaseName
                    CreoObjectType  = $matches.CreoType.ToLowerInvariant()
                    CreoVersion     = $version

                    # This is deliberately only a candidate grouping key.
                    # It helps identify likely version families but cannot
                    # distinguish same-named contractor/customer models.
                    CandidateModelNameKey = (
                        '{0}|{1}' -f
                        $matches.BaseName.ToUpperInvariant(),
                        $matches.CreoType.ToUpperInvariant()
                    )
                }
            }

            return [PSCustomObject]@{
                IsCreoCandidate      = $false
                BaseModelName        = $null
                CreoObjectType       = $null
                CreoVersion          = $null
                CandidateModelNameKey = $null
            }
        }

        function Get-CreoInventoryFiles {
            param(
                [Parameter(Mandatory)]
                [string[]]$InputPath,

                [bool]$DoRecurse,

                [switch]$IncludeHiddenItems
            )

            foreach ($inputItemPath in $InputPath) {
                $resolvedItems = @(
                    Resolve-Path -Path $inputItemPath -ErrorAction Stop
                )

                foreach ($resolvedItem in $resolvedItems) {
                    $item = Get-Item `
                        -LiteralPath $resolvedItem.Path `
                        -Force `
                        -ErrorAction Stop

                    if ($item.PSIsContainer) {
                        Get-ChildItem `
                            -LiteralPath $item.FullName `
                            -File `
                            -Force:$IncludeHiddenItems `
                            -Recurse:$DoRecurse
                    }
                    else {
                        $item
                    }
                }
            }
        }

        $resolvedRootPath = $null

        if (-not [string]::IsNullOrWhiteSpace($RootPath)) {
            $resolvedRootPath = (
                Resolve-Path -LiteralPath $RootPath -ErrorAction Stop
            ).Path
        }

        $seenInventoryFiles = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        $inventoryTimestampUtc = [datetime]::UtcNow
    }

    process {
        $inventoryFiles = @(
            Get-CreoInventoryFiles `
                -InputPath $Path `
                -DoRecurse $Recurse `
                -IncludeHiddenItems:$IncludeHidden
        )

        foreach ($inventoryFile in $inventoryFiles) {
            if (-not $seenInventoryFiles.Add($inventoryFile.FullName)) {
                continue
            }

            $candidateIdentity = Get-CreoFileIdentity -FileInfo $inventoryFile

            if (-not $candidateIdentity.IsCreoCandidate) {
                continue
            }

            if ($candidateIdentity.CreoObjectType -notin $CreoObjectType) {
                continue
            }

            $candidateRelativePath = Get-CreoRelativePath `
                -FullPath $inventoryFile.FullName `
                -ResolvedRootPath $resolvedRootPath

            # These fields are always collected, even if Creo parsing fails.
            $candidateBaseRecord = [ordered]@{
                CrawlRunId               = $CrawlRunId
                CrawlTimestampUtc        = $inventoryTimestampUtc.ToString('o')

                SourceRootPath           = $resolvedRootPath
                FilePath                 = $inventoryFile.FullName
                RelativePath             = $candidateRelativePath
                ParentDirectory          = $inventoryFile.DirectoryName

                FileName                 = $inventoryFile.Name
                BaseModelName            = $candidateIdentity.BaseModelName
                CandidateModelNameKey    = $candidateIdentity.CandidateModelNameKey

                CreoObjectType           = $candidateIdentity.CreoObjectType
                CreoVersion              = $candidateIdentity.CreoVersion

                FileSizeBytes            = [Int64]$inventoryFile.Length
                FileCreatedUtc           = $inventoryFile.CreationTimeUtc.ToString('o')
                FileLastWriteUtc         = $inventoryFile.LastWriteTimeUtc.ToString('o')
                FileAttributes           = [string]$inventoryFile.Attributes

                # This identifies byte-for-byte duplicate physical files.
                FileSHA256               = $null

                # Candidate composite hashes.
                CandidateGeometryHash                     = $null
                CandidateGeometryProfileConfigured        = $false
                CandidateGeometryProfileComplete          = $false
                CandidateGeometryMissingStreams           = $null

                CandidateParameterPersistenceHash         = $null
                CandidateParameterProfileConfigured       = $false
                CandidateParameterProfileComplete         = $false
                CandidateParameterMissingStreams          = $null

                CandidateNativeDefinitionHash             = $null
                CandidateNativeDefinitionProfileComplete  = $false
                CandidateNativeDefinitionMissingStreams   = $null

                CandidateAnnotationHash                   = $null
                CandidateAnnotationProfileConfigured      = $false
                CandidateAnnotationProfileComplete        = $false
                CandidateAnnotationMissingStreams         = $null

                # Preserve profile identity in SQL. Do not overwrite a hash
                # later without knowing which candidate rule produced it.
                CandidateGeometryProfileVersion           = 'CandidateGeometryProfileV1'
                CandidateParameterProfileVersion          = 'CandidateParameterPersistenceProfileV1'
                CandidateNativeDefinitionProfileVersion   = 'CandidateNativeDefinitionProfileV1'
                CandidateAnnotationProfileVersion         = 'CandidateAnnotationProfileV1'

                InventoryStatus         = 'Pending'
                InventoryError          = $null
            }

            try {
                $candidateFileHash = Get-FileHash `
                    -LiteralPath $inventoryFile.FullName `
                    -Algorithm SHA256 `
                    -ErrorAction Stop

                $candidateBaseRecord.FileSHA256 =
                    $candidateFileHash.Hash

                # This runs the candidate PLM profiles.
                #
                # The existing function returns one record because this call
                # provides exactly one physical file.
                $candidatePlmHash = @(
                    Get-CreoCandidatePlmHashes `
                        -Path $inventoryFile.FullName `
                        -CandidateGeometryStreamName `
                            $CandidateGeometryStreamName `
                        -CandidateParameterPersistenceStreamName `
                            $CandidateParameterPersistenceStreamName `
                        -CandidateAnnotationStreamName `
                            $CandidateAnnotationStreamName `
                        -ErrorAction Stop
                ) | Select-Object -First 1

                if ($null -eq $candidatePlmHash) {
                    throw (
                        'Get-CreoCandidatePlmHashes returned no result for ' +
                        "'$($inventoryFile.FullName)'."
                    )
                }

                $candidateBaseRecord.CandidateGeometryHash =
                    $candidatePlmHash.CandidateGeometryHash

                $candidateBaseRecord.CandidateGeometryProfileConfigured =
                    $candidatePlmHash.CandidateGeometryProfileConfigured

                $candidateBaseRecord.CandidateGeometryProfileComplete =
                    $candidatePlmHash.CandidateGeometryProfileComplete

                $candidateBaseRecord.CandidateGeometryMissingStreams =
                    $candidatePlmHash.CandidateGeometryMissingStreams

                $candidateBaseRecord.CandidateParameterPersistenceHash =
                    $candidatePlmHash.CandidateParameterPersistenceHash

                $candidateBaseRecord.CandidateParameterProfileConfigured =
                    $candidatePlmHash.CandidateParameterProfileConfigured

                $candidateBaseRecord.CandidateParameterProfileComplete =
                    $candidatePlmHash.CandidateParameterProfileComplete

                $candidateBaseRecord.CandidateParameterMissingStreams =
                    $candidatePlmHash.CandidateParameterMissingStreams

                $candidateBaseRecord.CandidateNativeDefinitionHash =
                    $candidatePlmHash.CandidateNativeDefinitionHash

                $candidateBaseRecord.CandidateNativeDefinitionProfileComplete =
                    $candidatePlmHash.CandidateNativeDefinitionProfileComplete

                $candidateBaseRecord.CandidateNativeDefinitionMissingStreams =
                    $candidatePlmHash.CandidateNativeDefinitionMissingStreams

                $candidateBaseRecord.CandidateAnnotationHash =
                    $candidatePlmHash.CandidateAnnotationHash

                $candidateBaseRecord.CandidateAnnotationProfileConfigured =
                    $candidatePlmHash.CandidateAnnotationProfileConfigured

                $candidateBaseRecord.CandidateAnnotationProfileComplete =
                    $candidatePlmHash.CandidateAnnotationProfileComplete

                $candidateBaseRecord.CandidateAnnotationMissingStreams =
                    $candidatePlmHash.CandidateAnnotationMissingStreams

                $candidateBaseRecord.InventoryStatus = 'Succeeded'
            }
            catch {
                $candidateBaseRecord.InventoryStatus = 'Error'
                $candidateBaseRecord.InventoryError = $_.Exception.Message

                if ($StopOnError) {
                    throw
                }
            }

            [PSCustomObject]$candidateBaseRecord
        }
    }
}

function Get-CreoInitialStreamInventory {
    <#
    .SYNOPSIS
        Produces one record per resolved stream per Creo file.

    .DESCRIPTION
        This is the child dataset for Get-CreoInitialInventory.

        Suggested SQL relationship:
            CreoFileInventory.CrawlRunId + CreoFileInventory.FilePath
                ->
            CreoStreamInventory.CrawlRunId + CreoStreamInventory.FilePath

        Use this table to:
          - Find streams that are identical across all versions
          - Identify save-sensitive streams
          - Compare PRT and ASM stream behavior
          - Build/refine candidate profile versions
          - Investigate candidate duplicate groups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [Parameter(Mandatory)]
        [string]$CrawlRunId
    )

    process {
        Get-CreoStreamFingerprints -Path $Path |
            ForEach-Object {
                [PSCustomObject]@{
                    CrawlRunId      = $CrawlRunId
                    FilePath        = $_.FilePath
                    FileName        = $_.FileName

                    StreamName      = $_.StreamName
                    PayloadStart    = $_.PayloadStart
                    PayloadStartHex = $_.PayloadStartHex
                    PayloadLength   = $_.PayloadLength
                    PayloadEnd      = $_.PayloadEnd
                    PayloadEndHex   = $_.PayloadEndHex

                    StreamSHA256    = $_.SHA256
                    Entropy         = $_.Entropy
                    Size1           = $_.Size1
                    Size2           = $_.Size2
                    OverheadMatches = $_.OverheadMatches
                }
            }
    }
}

function Test-CreoInitialInventory {
    <#
    .SYNOPSIS
        Read-only dry run for Get-CreoInitialInventory.

    .DESCRIPTION
        This function intentionally runs the SAME inventory pipeline used by
        Get-CreoInitialInventory. It does not independently inspect parser
        internals or duplicate stream-resolution logic.

        Therefore:

            Test-CreoInitialInventory says Ready
                <=> Get-CreoInitialInventory succeeded for that file

        It does not write files, modify Creo data, create folders, export CSV,
        or insert anything into SQL. It reads files, computes hashes, and
        returns diagnostic objects only.

    .NOTES
        CandidateAnnotationProfileConfigured is expected to be False until an
        annotation profile is validated. That does NOT make a file non-ready.

    .EXAMPLE
        Test-CreoInitialInventory -Path .\models -RootPath .\models -ShowAll

    .EXAMPLE
        $preflight = Test-CreoInitialInventory `
            -Path '\\EngineeringShare\Creo' `
            -RootPath '\\EngineeringShare\Creo' `
            -ShowAll

        $preflight |
            Where-Object PreflightStatus -ne 'Ready' |
            Format-List *

    .EXAMPLE
        # Only display warning/error conditions.
        Test-CreoInitialInventory `
            -Path .\models `
            -RootPath .\models `
            -ErrorsOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [string]$RootPath,

        [ValidateSet('prt', 'asm', 'drw')]
        [string[]]$CreoObjectType = @('prt', 'asm', 'drw'),

        [bool]$Recurse = $true,

        [switch]$IncludeHidden,

        # Print all successful and failed files.
        [switch]$ShowAll,

        # Print only CandidateProfileIncomplete and Error files.
        [switch]$ErrorsOnly,

        # -----------------------------------------------------------------
        # Preserve these candidate profile parameters so preflight validates
        # the same profile that your production crawl will use.
        # -----------------------------------------------------------------
        [string[]]$CandidateGeometryStreamName = @(
            'AllFeatur',
            'BasicText',
            'NeuAsmSld',
            'VisibGeom'
        ),

        [string[]]$CandidateParameterPersistenceStreamName = @(
            'ActEntity',
            'FeatDefs',
            'FeatDefsIndex',
            'FeatRefData',
            'NeuPrtSld'
        ),

        [string[]]$CandidateAnnotationStreamName = @()
    )

    begin {
        if ($ShowAll -and $ErrorsOnly) {
            throw 'Use either -ShowAll or -ErrorsOnly, not both.'
        }

        function Get-CreoPreflightFiles {
            param(
                [Parameter(Mandatory)]
                [string[]]$InputPath,

                [bool]$DoRecurse,

                [switch]$IncludeHiddenItems
            )

            foreach ($inputItemPath in $InputPath) {
                $resolvedItems = @(
                    Resolve-Path -Path $inputItemPath -ErrorAction Stop
                )

                foreach ($resolvedItem in $resolvedItems) {
                    $item = Get-Item `
                        -LiteralPath $resolvedItem.Path `
                        -Force `
                        -ErrorAction Stop

                    if ($item.PSIsContainer) {
                        Get-ChildItem `
                            -LiteralPath $item.FullName `
                            -File `
                            -Force:$IncludeHiddenItems `
                            -Recurse:$DoRecurse
                    }
                    else {
                        $item
                    }
                }
            }
        }

        function Write-CreoPreflightStatus {
            param(
                [Parameter(Mandatory)]
                [string]$Status,

                [Parameter(Mandatory)]
                [string]$FileName,

                [string]$Detail
            )

            $color = switch ($Status) {
                'Ready' {
                    [ConsoleColor]::Green
                }

                'CandidateProfileIncomplete' {
                    [ConsoleColor]::Yellow
                }

                'Error' {
                    [ConsoleColor]::Red
                }

                default {
                    [ConsoleColor]::Gray
                }
            }

            $lineFormat = '{0,-30} {1,-38} {2}'
            $line = $lineFormat -f $Status, $FileName, $Detail

            Write-Host $line -ForegroundColor $color
        }

        $resolvedRootPath = $null

        if (-not [string]::IsNullOrWhiteSpace($RootPath)) {
            $resolvedRootPath = (
                Resolve-Path -LiteralPath $RootPath -ErrorAction Stop
            ).Path
        }

        $escapedCreoTypes = @(
            $CreoObjectType |
                ForEach-Object {
                    [regex]::Escape($_)
                }
        ) -join '|'

        $creoNamePattern = (
            '(?i)\.(?:' + $escapedCreoTypes + ')(?:\.\d+)?$'
        )

        $seenPreflightFiles =
            [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )

        Write-Host ''
        Write-Host '=== Creo Initial Inventory Preflight ===' `
            -ForegroundColor Cyan

        Write-Host (
            'Running the same read-only hash and candidate-profile path ' +
            'used by Get-CreoInitialInventory.'
        ) -ForegroundColor DarkGray

        Write-Host ''
        $headerFormat = '{0,-30} {1,-38} {2}'
        $header = $headerFormat -f 'Status', 'File', 'Detail'

        Write-Host $header -ForegroundColor Cyan
        Write-Host ('-' * 100) -ForegroundColor DarkGray
    }

    process {
        $preflightFiles = @(
            Get-CreoPreflightFiles `
                -InputPath $Path `
                -DoRecurse $Recurse `
                -IncludeHiddenItems:$IncludeHidden
        )

        foreach ($preflightFile in $preflightFiles) {
            if (-not $seenPreflightFiles.Add($preflightFile.FullName)) {
                continue
            }

            if ($preflightFile.Name -notmatch $creoNamePattern) {
                continue
            }

            try {
                # ---------------------------------------------------------
                # This is the key design correction:
                #
                # Do NOT call Resolve-CreoFileStreams separately and then
                # attempt to inspect its internals.
                #
                # Instead, call the exact real inventory function used for
                # production records. A physical file is passed directly, so
                # this creates one read-only inventory result.
                # ---------------------------------------------------------
                $inventoryResult = @(
                    Get-CreoInitialInventory `
                        -Path $preflightFile.FullName `
                        -RootPath $resolvedRootPath `
                        -CreoObjectType $CreoObjectType `
                        -Recurse:$false `
                        -CandidateGeometryStreamName `
                            $CandidateGeometryStreamName `
                        -CandidateParameterPersistenceStreamName `
                            $CandidateParameterPersistenceStreamName `
                        -CandidateAnnotationStreamName `
                            $CandidateAnnotationStreamName
                ) | Select-Object -First 1

                if ($null -eq $inventoryResult) {
                    throw (
                        'Get-CreoInitialInventory returned no inventory ' +
                        "record for '$($preflightFile.FullName)'."
                    )
                }

                $preflightStatus = if (
                    $inventoryResult.InventoryStatus -ne 'Succeeded'
                ) {
                    'Error'
                }
                elseif (
                    -not $inventoryResult.CandidateGeometryProfileComplete -or
                    -not $inventoryResult.CandidateParameterProfileComplete -or
                    -not $inventoryResult.CandidateNativeDefinitionProfileComplete
                ) {
                    # Parsing and inventory succeeded. The candidate profile
                    # simply needs more validation or a file-type-specific
                    # stream profile.
                    'CandidateProfileIncomplete'
                }
                else {
                    'Ready'
                }

                $preflightErrorMessage = if (
                    $preflightStatus -eq 'Error'
                ) {
                    $inventoryResult.InventoryError
                }
                else {
                    $null
                }

                $preflightRecord = [PSCustomObject]@{
                    FilePath       = $inventoryResult.FilePath
                    RelativePath   = $inventoryResult.RelativePath
                    FileName       = $inventoryResult.FileName

                    CreoObjectType = $inventoryResult.CreoObjectType
                    CreoVersion    = $inventoryResult.CreoVersion
                    FileSizeBytes  = $inventoryResult.FileSizeBytes

                    PreflightStatus = $preflightStatus
                    ErrorStage      = if (
                        $preflightStatus -eq 'Error'
                    ) {
                        'Get-CreoInitialInventory'
                    }
                    else {
                        $null
                    }

                    ErrorMessage = $preflightErrorMessage

                    FileSHA256 = $inventoryResult.FileSHA256

                    CandidateGeometryHash = (
                        $inventoryResult.CandidateGeometryHash
                    )

                    CandidateGeometryComplete = (
                        $inventoryResult.CandidateGeometryProfileComplete
                    )

                    CandidateGeometryMissingStreams = (
                        $inventoryResult.CandidateGeometryMissingStreams
                    )

                    CandidateParameterPersistenceHash = (
                        $inventoryResult.CandidateParameterPersistenceHash
                    )

                    CandidateParameterComplete = (
                        $inventoryResult.CandidateParameterProfileComplete
                    )

                    CandidateParameterMissingStreams = (
                        $inventoryResult.CandidateParameterMissingStreams
                    )

                    CandidateNativeDefinitionHash = (
                        $inventoryResult.CandidateNativeDefinitionHash
                    )

                    CandidateNativeComplete = (
                        $inventoryResult.CandidateNativeDefinitionProfileComplete
                    )

                    CandidateNativeMissingStreams = (
                        $inventoryResult.CandidateNativeDefinitionMissingStreams
                    )

                    CandidateAnnotationConfigured = (
                        $inventoryResult.CandidateAnnotationProfileConfigured
                    )

                    CandidateAnnotationComplete = (
                        $inventoryResult.CandidateAnnotationProfileComplete
                    )
                }
            }
            catch {
                $preflightRecord = [PSCustomObject]@{
                    FilePath       = $preflightFile.FullName
                    RelativePath   = $preflightFile.Name
                    FileName       = $preflightFile.Name

                    CreoObjectType = $null
                    CreoVersion    = $null
                    FileSizeBytes  = [Int64]$preflightFile.Length

                    PreflightStatus = 'Error'
                    ErrorStage      = 'Test-CreoInitialInventory'
                    ErrorMessage    = $_.Exception.Message

                    FileSHA256      = $null

                    CandidateGeometryHash = $null
                    CandidateGeometryComplete = $false
                    CandidateGeometryMissingStreams = $null

                    CandidateParameterPersistenceHash = $null
                    CandidateParameterComplete = $false
                    CandidateParameterMissingStreams = $null

                    CandidateNativeDefinitionHash = $null
                    CandidateNativeComplete = $false
                    CandidateNativeMissingStreams = $null

                    CandidateAnnotationConfigured = $false
                    CandidateAnnotationComplete = $false
                }
            }

            $showThisRecord = if ($ErrorsOnly) {
                $preflightRecord.PreflightStatus -ne 'Ready'
            }
            elseif ($ShowAll) {
                $true
            }
            else {
                # Default behavior: show only warning/error conditions.
                $preflightRecord.PreflightStatus -ne 'Ready'
            }

            if ($showThisRecord) {
                $detail = switch ($preflightRecord.PreflightStatus) {
                    'Ready' {
                        'Inventory and candidate profiles succeeded'
                    }

                    'CandidateProfileIncomplete' {
                        'Inventory succeeded; profile missing: {0}' -f (
                            $preflightRecord.CandidateNativeMissingStreams
                        )
                    }

                    'Error' {
                        '{0}: {1}' -f `
                            $preflightRecord.ErrorStage,
                            $preflightRecord.ErrorMessage
                    }

                    default {
                        'Unknown preflight state'
                    }
                }

                Write-CreoPreflightStatus `
                    -Status $preflightRecord.PreflightStatus `
                    -FileName $preflightRecord.FileName `
                    -Detail $detail
            }

            Write-Output $preflightRecord
        }
    }
}

function Show-CreoHexDumpEx {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(ParameterSetName = 'File')]
        [string]$StreamName,

        # Absolute file offset. Cannot be combined with -RelativeOffset.
        [Parameter(ParameterSetName = 'File')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset,

        # Offset from the beginning of -StreamName's payload.
        [Parameter(ParameterSetName = 'File')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$RelativeOffset,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(ParameterSetName = 'Bytes')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$BaseOffset = 0,

        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length = 256,

        [object]$MarkerBytes = @(
            0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
            0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
        ),

        [ValidateRange(1, 64)]
        [int]$BytesPerRow = 16,

        [switch]$NoColor
    )

    begin {
        [byte[]]$markerArray = ConvertTo-CreoByteArray -InputObject $MarkerBytes
        $markerSet = [System.Collections.Generic.HashSet[byte]]::new()

        foreach ($marker in $markerArray) {
            [void]$markerSet.Add([byte]$marker)
        }

        function Write-HexCell {
            param(
                [Parameter(Mandatory)]
                [byte]$Byte,

                [Parameter(Mandatory)]
                [System.Collections.Generic.HashSet[byte]]$MarkerSet,

                [switch]$DisableColor
            )

            $hex = '{0:X2}' -f $Byte

            if ($DisableColor) {
                Write-Host $hex -NoNewline
            }
            elseif ($MarkerSet.Contains($Byte)) {
                Write-Host $hex -ForegroundColor Yellow -NoNewline
            }
            elseif ($Byte -eq 0x00) {
                Write-Host $hex -ForegroundColor DarkGray -NoNewline
            }
            elseif ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                Write-Host $hex -ForegroundColor Green -NoNewline
            }
            else {
                Write-Host $hex -ForegroundColor White -NoNewline
            }
        }

        function Write-AsciiCell {
            param(
                [Parameter(Mandatory)]
                [byte]$Byte,

                [Parameter(Mandatory)]
                [System.Collections.Generic.HashSet[byte]]$MarkerSet,

                [switch]$DisableColor
            )

            $character = if ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                [char]$Byte
            }
            else {
                '.'
            }

            if ($DisableColor) {
                Write-Host $character -NoNewline
            }
            elseif ($MarkerSet.Contains($Byte)) {
                Write-Host $character -ForegroundColor Yellow -NoNewline
            }
            elseif ($Byte -eq 0x00) {
                Write-Host $character -ForegroundColor DarkGray -NoNewline
            }
            elseif ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                Write-Host $character -ForegroundColor Green -NoNewline
            }
            else {
                Write-Host $character -ForegroundColor White -NoNewline
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
            [byte[]]$data = $Bytes
            [int]$displayBase = $BaseOffset
        }
        else {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                throw "File not found: $Path"
            }

            $resolved = Resolve-CreoFileStreams -Path $Path
            [byte[]]$fileData = $resolved.Data

            $hasAbsoluteOffset = $PSBoundParameters.ContainsKey('Offset')
            $hasRelativeOffset = $PSBoundParameters.ContainsKey('RelativeOffset')

            if ($hasAbsoluteOffset -and $hasRelativeOffset) {
                throw 'Specify either -Offset (absolute) or -RelativeOffset (stream-relative), not both.'
            }

            $stream = $null
            if (-not [string]::IsNullOrWhiteSpace($StreamName)) {
                $stream = $resolved.Streams |
                    Where-Object { $_.Name -eq $StreamName } |
                    Select-Object -First 1

                if ($null -eq $stream) {
                    throw "Stream '$StreamName' was not found."
                }
            }

            if ($hasRelativeOffset) {
                if ($null -eq $stream) {
                    throw '-RelativeOffset requires -StreamName.'
                }

                [int]$payloadStart = $stream.PayloadStart
                [int]$payloadLength = $stream.PayloadLength
                [int]$payloadEndExclusive = $payloadStart + $payloadLength

                if ($RelativeOffset -ge $payloadLength) {
                    throw (
                        "Relative offset 0x$($RelativeOffset.ToString('X')) exceeds " +
                        "stream '$StreamName' length 0x$($payloadLength.ToString('X'))."
                    )
                }

                [int]$start = $payloadStart + $RelativeOffset
                [int]$endExclusive = [Math]::Min(
                    $payloadEndExclusive,
                    $start + $Length
                )
            }
            elseif ($hasAbsoluteOffset) {
                [int]$start = $Offset

                if ($start -ge $fileData.Length) {
                    throw (
                        "Absolute offset 0x$($start.ToString('X8')) is outside " +
                        "the file length 0x$($fileData.Length.ToString('X8'))."
                    )
                }

                # If a stream was specified, constrain output to its payload.
                if ($null -ne $stream) {
                    [int]$payloadStart = $stream.PayloadStart
                    [int]$payloadEndExclusive = $payloadStart + [int]$stream.PayloadLength

                    if ($start -lt $payloadStart -or $start -ge $payloadEndExclusive) {
                        throw (
                            "Absolute offset 0x$($start.ToString('X8')) is outside " +
                            "stream '$StreamName' payload range " +
                            "0x$($payloadStart.ToString('X8'))..0x$(($payloadEndExclusive - 1).ToString('X8'))."
                        )
                    }

                    [int]$endExclusive = [Math]::Min(
                        $payloadEndExclusive,
                        $start + $Length
                    )
                }
                else {
                    [int]$endExclusive = [Math]::Min(
                        $fileData.Length,
                        $start + $Length
                    )
                }
            }
            elseif ($null -ne $stream) {
                [int]$start = $stream.PayloadStart
                [int]$payloadEndExclusive = $start + [int]$stream.PayloadLength
                [int]$endExclusive = [Math]::Min(
                    $payloadEndExclusive,
                    $start + $Length
                )
            }
            else {
                [int]$start = 0
                [int]$endExclusive = [Math]::Min($fileData.Length, $Length)
            }

            if ($endExclusive -le $start) {
                throw 'The requested hex-dump window is empty.'
            }

            [byte[]]$data = $fileData[$start..($endExclusive - 1)]
            [int]$displayBase = $start
        }

        Write-Host ''
        Write-Host 'Legend: ' -NoNewline
        Write-Host 'Marker' -ForegroundColor Yellow -NoNewline
        Write-Host '  ' -NoNewline
        Write-Host 'Printable ASCII' -ForegroundColor Green -NoNewline
        Write-Host '  ' -NoNewline
        Write-Host '00 / Null' -ForegroundColor DarkGray -NoNewline
        Write-Host '  Other' -ForegroundColor White
        Write-Host ''

        for ($rowStart = 0; $rowStart -lt $data.Length; $rowStart += $BytesPerRow) {
            $rowLength = [Math]::Min($BytesPerRow, $data.Length - $rowStart)

            Write-Host ('{0:X8}  ' -f ($displayBase + $rowStart)) -ForegroundColor DarkCyan -NoNewline

            for ($column = 0; $column -lt $BytesPerRow; $column++) {
                if ($column -lt $rowLength) {
                    Write-HexCell -Byte $data[$rowStart + $column] `
                        -MarkerSet $markerSet `
                        -DisableColor:$NoColor
                    Write-Host ' ' -NoNewline
                }
                else {
                    Write-Host '   ' -NoNewline
                }
            }

            Write-Host ' |' -NoNewline

            for ($column = 0; $column -lt $rowLength; $column++) {
                Write-AsciiCell -Byte $data[$rowStart + $column] `
                    -MarkerSet $markerSet `
                    -DisableColor:$NoColor
            }

            Write-Host '|'
        }

        Write-Host ''
    }
}

function Show-CreoHexDumpPatternEx {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(ParameterSetName = 'File')]
        [string]$StreamName,

        [Parameter(ParameterSetName = 'File')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset,

        [Parameter(ParameterSetName = 'File')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$RelativeOffset,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(ParameterSetName = 'Bytes')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$BaseOffset = 0,

        [Parameter(Mandatory)]
        [object]$Pattern,

        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length = 256,

        [ValidateRange(1, 64)]
        [int]$BytesPerRow = 16,

        [switch]$NoOverlap,

        [switch]$NoColor
    )

    begin {
        [byte[]]$needle = ConvertTo-CreoByteArray -InputObject $Pattern

        if ($needle.Length -eq 0) {
            throw '-Pattern cannot resolve to an empty byte sequence.'
        }

        function Get-PatternByteIndexes {
            param(
                [Parameter(Mandatory)]
                [byte[]]$Data,

                [Parameter(Mandatory)]
                [byte[]]$Needle,

                [switch]$DisableOverlap
            )

            $indexes = [System.Collections.Generic.HashSet[int]]::new()

            if ($Data.Length -lt $Needle.Length) {
                return $indexes
            }

            for ($i = 0; $i -le ($Data.Length - $Needle.Length); $i++) {
                $match = $true

                for ($j = 0; $j -lt $Needle.Length; $j++) {
                    if ($Data[$i + $j] -ne $Needle[$j]) {
                        $match = $false
                        break
                    }
                }

                if ($match) {
                    for ($j = 0; $j -lt $Needle.Length; $j++) {
                        [void]$indexes.Add($i + $j)
                    }

                    if ($DisableOverlap) {
                        $i += $Needle.Length - 1
                    }
                }
            }

            return $indexes
        }

        function Write-PatternHexCell {
            param(
                [Parameter(Mandatory)]
                [byte]$Byte,

                [Parameter(Mandatory)]
                [bool]$IsPatternByte,

                [switch]$DisableColor
            )

            $hex = '{0:X2}' -f $Byte

            if ($DisableColor) {
                Write-Host $hex -NoNewline
            }
            elseif ($IsPatternByte) {
                Write-Host $hex -ForegroundColor Magenta -BackgroundColor DarkMagenta -NoNewline
            }
            elseif ($Byte -eq 0x00) {
                Write-Host $hex -ForegroundColor DarkGray -NoNewline
            }
            elseif ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                Write-Host $hex -ForegroundColor Green -NoNewline
            }
            else {
                Write-Host $hex -ForegroundColor White -NoNewline
            }
        }

        function Write-PatternAsciiCell {
            param(
                [Parameter(Mandatory)]
                [byte]$Byte,

                [Parameter(Mandatory)]
                [bool]$IsPatternByte,

                [switch]$DisableColor
            )

            $character = if ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                [char]$Byte
            }
            else {
                '.'
            }

            if ($DisableColor) {
                Write-Host $character -NoNewline
            }
            elseif ($IsPatternByte) {
                Write-Host $character -ForegroundColor Magenta -BackgroundColor DarkMagenta -NoNewline
            }
            elseif ($Byte -eq 0x00) {
                Write-Host $character -ForegroundColor DarkGray -NoNewline
            }
            elseif ($Byte -ge 0x20 -and $Byte -le 0x7E) {
                Write-Host $character -ForegroundColor Green -NoNewline
            }
            else {
                Write-Host $character -ForegroundColor White -NoNewline
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
            [byte[]]$data = $Bytes
            [int]$displayBase = $BaseOffset
        }
        else {
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                throw "File not found: $Path"
            }

            $resolved = Resolve-CreoFileStreams -Path $Path
            [byte[]]$fileData = $resolved.Data

            $hasAbsoluteOffset = $PSBoundParameters.ContainsKey('Offset')
            $hasRelativeOffset = $PSBoundParameters.ContainsKey('RelativeOffset')

            if ($hasAbsoluteOffset -and $hasRelativeOffset) {
                throw 'Specify either -Offset or -RelativeOffset, not both.'
            }

            $stream = $null
            if (-not [string]::IsNullOrWhiteSpace($StreamName)) {
                $stream = $resolved.Streams |
                    Where-Object { $_.Name -eq $StreamName } |
                    Select-Object -First 1

                if ($null -eq $stream) {
                    throw "Stream '$StreamName' was not found."
                }
            }

            if ($hasRelativeOffset) {
                if ($null -eq $stream) {
                    throw '-RelativeOffset requires -StreamName.'
                }

                [int]$streamStart = $stream.PayloadStart
                [int]$streamLength = $stream.PayloadLength

                if ($RelativeOffset -ge $streamLength) {
                    throw "Relative offset 0x$($RelativeOffset.ToString('X')) is outside stream '$StreamName'."
                }

                [int]$start = $streamStart + $RelativeOffset
                [int]$endExclusive = [Math]::Min(
                    $streamStart + $streamLength,
                    $start + $Length
                )
            }
            elseif ($hasAbsoluteOffset) {
                [int]$start = $Offset

                if ($start -ge $fileData.Length) {
                    throw "Absolute offset 0x$($start.ToString('X8')) is outside the file."
                }

                if ($null -ne $stream) {
                    [int]$streamStart = $stream.PayloadStart
                    [int]$streamEndExclusive = $streamStart + [int]$stream.PayloadLength

                    if ($start -lt $streamStart -or $start -ge $streamEndExclusive) {
                        throw "Absolute offset 0x$($start.ToString('X8')) is outside stream '$StreamName'."
                    }

                    [int]$endExclusive = [Math]::Min(
                        $streamEndExclusive,
                        $start + $Length
                    )
                }
                else {
                    [int]$endExclusive = [Math]::Min(
                        $fileData.Length,
                        $start + $Length
                    )
                }
            }
            elseif ($null -ne $stream) {
                [int]$start = $stream.PayloadStart
                [int]$endExclusive = [Math]::Min(
                    $start + [int]$stream.PayloadLength,
                    $start + $Length
                )
            }
            else {
                [int]$start = 0
                [int]$endExclusive = [Math]::Min($fileData.Length, $Length)
            }

            if ($endExclusive -le $start) {
                throw 'The requested dump range is empty.'
            }

            [byte[]]$data = $fileData[$start..($endExclusive - 1)]
            [int]$displayBase = $start
        }

        $patternIndexes = Get-PatternByteIndexes `
            -Data $data `
            -Needle $needle `
            -DisableOverlap:$NoOverlap

        Write-Host ''
        Write-Host 'Legend: ' -NoNewline
        Write-Host ('Exact pattern: {0}' -f (ConvertTo-HexString $needle)) `
            -ForegroundColor Magenta -NoNewline
        Write-Host '  Printable ASCII' -ForegroundColor Green -NoNewline
        Write-Host '  00 / Null' -ForegroundColor DarkGray
        Write-Host ''

        for ($rowStart = 0; $rowStart -lt $data.Length; $rowStart += $BytesPerRow) {
            $rowLength = [Math]::Min($BytesPerRow, $data.Length - $rowStart)

            Write-Host ('{0:X8}  ' -f ($displayBase + $rowStart)) -ForegroundColor DarkCyan -NoNewline

            for ($column = 0; $column -lt $BytesPerRow; $column++) {
                if ($column -lt $rowLength) {
                    $index = $rowStart + $column

                    Write-PatternHexCell `
                        -Byte $data[$index] `
                        -IsPatternByte $patternIndexes.Contains($index) `
                        -DisableColor:$NoColor

                    Write-Host ' ' -NoNewline
                }
                else {
                    Write-Host '   ' -NoNewline
                }
            }

            Write-Host ' |' -NoNewline

            for ($column = 0; $column -lt $rowLength; $column++) {
                $index = $rowStart + $column

                Write-PatternAsciiCell `
                    -Byte $data[$index] `
                    -IsPatternByte $patternIndexes.Contains($index) `
                    -DisableColor:$NoColor
            }

            Write-Host '|'
        }

        Write-Host ''
    }
}

function Find-CreoBytePatternOffsetsEx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Payload,

        [Parameter(Mandatory)]
        [object]$Pattern,

        [switch]$NoOverlap
    )

    [byte[]]$needle = ConvertTo-CreoByteArray -InputObject $Pattern

    if ($null -eq $Payload -or $Payload.Length -eq 0) {
        return [int[]]@()
    }

    if ($needle.Length -eq 0) {
        throw '-Pattern resolved to an empty byte sequence.'
    }

    if ($needle.Length -gt $Payload.Length) {
        return [int[]]@()
    }

    $offsets = [System.Collections.Generic.List[int]]::new()

    for ($i = 0; $i -le ($Payload.Length - $needle.Length); $i++) {
        $match = $true

        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($Payload[$i + $j] -ne $needle[$j]) {
                $match = $false
                break
            }
        }

        if ($match) {
            $offsets.Add($i)

            if ($NoOverlap) {
                $i += $needle.Length - 1
            }
        }
    }

    return $offsets.ToArray()
}

function Invoke-CreoRegionAnalysisEx {
    [CmdletBinding(DefaultParameterSetName = 'Absolute')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Block', 'StreamName')]
        [string]$Stream,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Absolute',
            ValueFromPipelineByPropertyName
        )]
        [Alias('AbsoluteOffset')]
        [object]$Offset,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Relative',
            ValueFromPipelineByPropertyName
        )]
        [object]$RelativeOffset,

        [ValidateRange(16, 65536)]
        [int]$ContextWindow = 256,

        [object]$HighlightPattern = '00 E1 E1 E1 E1 E1 00',

        [switch]$NoColor
    )

    begin {
        function ConvertTo-OffsetInteger {
            param(
                [Parameter(Mandatory)]
                [object]$Value,

                [Parameter(Mandatory)]
                [string]$ParameterName
            )

            if ($Value -is [int]) {
                return [int]$Value
            }

            if ($Value -is [long]) {
                if ($Value -gt [int]::MaxValue -or $Value -lt 0) {
                    throw "$ParameterName '$Value' is outside supported 32-bit offset range."
                }

                return [int]$Value
            }

            $text = [string]$Value

            if ([string]::IsNullOrWhiteSpace($text)) {
                throw "$ParameterName cannot be empty."
            }

            $text = $text.Trim()

            if ($text -match '^0x[0-9A-Fa-f]+$') {
                return [Convert]::ToInt32($text.Substring(2), 16)
            }

            if ($text -match '^[0-9A-Fa-f]+$' -and $text -match '[A-Fa-f]') {
                return [Convert]::ToInt32($text, 16)
            }

            try {
                return [Convert]::ToInt32($text, 10)
            }
            catch {
                throw "Cannot convert $ParameterName '$Value' to an integer offset."
            }
        }
    }

    process {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "File not found: $Path"
        }

        $resolved = Resolve-CreoFileStreams -Path $Path

        $targetStream = $resolved.Streams |
            Where-Object { $_.Name -eq $Stream } |
            Select-Object -First 1

        if ($null -eq $targetStream) {
            throw "Stream '$Stream' was not found in '$Path'."
        }

        [int]$streamStart = $targetStream.PayloadStart
        [int]$streamLength = $targetStream.PayloadLength
        [int]$streamEndExclusive = $streamStart + $streamLength

        if ($PSCmdlet.ParameterSetName -eq 'Relative') {
            [int]$relative = ConvertTo-OffsetInteger `
                -Value $RelativeOffset `
                -ParameterName 'RelativeOffset'

            if ($relative -lt 0 -or $relative -ge $streamLength) {
                throw (
                    "Relative offset 0x$($relative.ToString('X')) is outside stream '$Stream' " +
                    "(payload length 0x$($streamLength.ToString('X'))."
                )
            }

            [int]$absolute = $streamStart + $relative
        }
        else {
            [int]$absolute = ConvertTo-OffsetInteger `
                -Value $Offset `
                -ParameterName 'Offset'

            if ($absolute -lt $streamStart -or $absolute -ge $streamEndExclusive) {
                throw (
                    "Absolute offset 0x$($absolute.ToString('X8')) is outside stream '$Stream' " +
                    "(range 0x$($streamStart.ToString('X8'))..0x$(($streamEndExclusive - 1).ToString('X8')))."
                )
            }

            [int]$relative = $absolute - $streamStart
        }

        [int]$before = [Math]::Floor($ContextWindow / 2)
        [int]$after = $ContextWindow - $before

        [int]$dumpStart = [Math]::Max($streamStart, $absolute - $before)
        [int]$dumpEndExclusive = [Math]::Min(
            $streamEndExclusive,
            $absolute + $after
        )

        [int]$dumpLength = $dumpEndExclusive - $dumpStart

        Write-Host ''
        Write-Host '=====================================================================' -ForegroundColor Cyan
        Write-Host (
            ' CREO REGION ANALYSIS: {0} | Absolute 0x{1:X8} | Relative 0x{2:X8}' -f
            $Stream, $absolute, $relative
        ) -ForegroundColor Cyan
        Write-Host '=====================================================================' -ForegroundColor Cyan

        Write-Host (
            "`n[+] Hex window: absolute 0x{0:X8}..0x{1:X8} ({2} bytes)" -f
            $dumpStart,
            ($dumpEndExclusive - 1),
            $dumpLength
        ) -ForegroundColor Yellow

        Show-CreoHexDumpPatternEx `
            -Path $Path `
            -StreamName $Stream `
            -Offset $dumpStart `
            -Length $dumpLength `
            -Pattern $HighlightPattern `
            -NoColor:$NoColor

        $schema = @(Get-CreoStreamSchema `
            -ResolvedStream $targetStream `
            -FileBytes $resolved.Data)

        $nearbySchema = $schema | Where-Object {
            $_.AbsoluteOffset -ge $dumpStart -and
            $_.AbsoluteOffset -lt $dumpEndExclusive
        }

        if (@($nearbySchema).Count -gt 0) {
            Write-Host '[+] Nearby Parsed Schema Properties' -ForegroundColor Yellow

            $nearbySchema |
                Select-Object AbsoluteOffset, OpcodeType, PropertyName, ValueOffset |
                Format-Table -AutoSize |
                Out-String |
                Write-Host
        }
        else {
            Write-Host '[-] No E0 schema properties begin inside this window.' -ForegroundColor DarkGray
        }

        # Optional: retain the module's existing parameter extraction,
        # but do not fail the region analyzer if that helper is unavailable.
        $parameterExtractor = Get-Command -Name Get-CreoParametersFromPayloadPS -ErrorAction SilentlyContinue

        if ($null -ne $parameterExtractor) {
            [byte[]]$payload = $resolved.Data[$streamStart..($streamEndExclusive - 1)]
            $parameters = @(Get-CreoParametersFromPayloadPS -Payload $payload)

            if ($parameters.Count -gt 0) {
                Write-Host '[+] E1/E3 Parameters Found in Stream (Top 5)' -ForegroundColor Yellow

                $parameters |
                    Select-Object -First 5 |
                    Format-Table ParameterName, TypeName, ParameterValue -AutoSize |
                    Out-String |
                    Write-Host
            }
        }

        Write-Host '=====================================================================' -ForegroundColor Cyan
        Write-Host ''
    }
}



# -------------------------------------------------------------------------
#    POWERSHELL - PS fallback function. Paste as a new top-level function,
#    next to Get-CreoParametersFromPayloadPS (same section of the module).
#    Not exported - internal helper, same as Get-CreoParametersFromPayloadPS.
# -------------------------------------------------------------------------
function Get-CreoNamedFramesFromPayloadPS {
    param(
        [byte[]]$Payload,
        [string[]]$TargetNames
    )

    $results = New-Object System.Collections.Generic.List[object]
    $scanLimit = $Payload.Length - 12
    $targetSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$TargetNames, [System.StringComparer]::Ordinal)

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
        if (-not $targetSet.Contains($name)) { continue }

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

        # Mirrors the C# fix exactly - see ExtractNamedFrames/ExtractParameters
        # NOTE for why a 0x00 immediately at valueStart must be read as a
        # valid empty string, not skipped past.
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

        if ($null -ne $value) {
            $results.Add([PSCustomObject]@{ Name = $name; Value = $value; TypeName = $typeName; Offset = $i })
        }
        $i = [Math]::Max($i, $jumpIndex)
    }

    return $results
}

# =========================================================================
# Get-CreoBOM additions for CreoParser.psm1
#
# PURE ADDITIONS. Nothing existing was modified - no changes to
# ExtractParameters, Get-CreoParametersFromPayloadPS, Get-CreoParameter,
# Resolve-CreoFileStreams, or anything else. Five things to paste in,
# each marked below with exactly where it goes. Built against the
# 2530-line copy you originally sent me, so verify the anchor functions
# (ExtractParameters, Get-CreoParametersFromPayloadPS, Get-CreoParameter,
# Export-ModuleMember) still exist under those names in your current file
# before pasting - if you renamed any of them, adjust the anchor, the new
# code doesn't care what's around it.
#
# WHY A SEPARATE SCANNER INSTEAD OF FILTERING Get-CreoParameter's OUTPUT:
# "ConfigName" is mixed-case. ExtractParameters' name-validity filter only
# accepts A-Z/0-9/_ and silently drops anything else - no error, just no
# hit. That's why "ConfigName" already sits in Get-CreoParameter's
# NoiseList: it was inert, filtering a hit that could never occur. Rather
# than loosen the filter on the parameter extractor everyone else depends
# on (risk to already-tested behavior), this adds a second method that
# shares the identical frame signature and value-extraction logic, but
# matches names exactly against a caller-supplied set instead of the
# uppercase filter. ExtractParameters is untouched.
#
# VALIDATION STATUS - read before trusting Quantity at scale:
# Confirmed: the E1E1[00|01]E3 frame signature is real (same one
# Get-CreoParameter already relies on). In the enclosure.asm.5 excerpt,
# "ConfigName" repeats scale with what look like real quantities
# (LOWER_BACK x2, UPPER_BACK x2).
# NOT yet confirmed:
#   1. That raw repeat count always equals true physical instance count,
#      as opposed to e.g. one instance being recorded twice across two
#      related structural entries.
#   2. That ConfigName captures every BOM member. In that same excerpt,
#      TITLE_BLOCK arrives via a DIFFERENT parameter - PTC_SYMBOL_NAME,
#      not ConfigName - right next to the ConfigName run. That's plausibly
#      a drawing-format/title-block symbol rather than a physical part,
#      which might be correct to exclude from a physical BOM - but that's
#      an assumption, not something either of us has verified yet.
# Before trusting Quantity against real data: pick one assembly with a
# BOM you already know (or can export from Creo) and diff this output
# against it, the same way the prt0001 sequence validated PDMTrail_L03.
# =========================================================================

function Get-CreoBOM {
    <#
    .SYNOPSIS
        Extracts a Bill of Materials (component name + quantity) from a
        Creo assembly file via repeated 'ConfigName' parameter frames.
    .DESCRIPTION
        Scans the given stream(s) - NeuAsmSld by default, the only one
        confirmed so far - for the validated E1 E1 [00|01] E3 <name>\0
        E2 <typeByte> parameter-frame signature, filtered to frames named
        "ConfigName". That name is mixed-case, which is exactly why
        Get-CreoParameter's ALL-CAPS-only filter drops it silently (it's
        sat inert in Get-CreoParameter's default NoiseList for that
        reason). Each ConfigName frame's String value is a component
        name; grouping by value and counting repeats gives
        (ComponentName, Quantity).

        VALIDATION STATUS - not yet fully confirmed, read before trusting
        Quantity at scale. Confirmed: the frame signature is real and
        repeat count tracked plausible quantities in the one example
        checked (enclosure.asm.5: LOWER_BACK x2, UPPER_BACK x2). NOT
        confirmed: that raw repeat count always equals true physical
        quantity, or that ConfigName captures every BOM member - the same
        excerpt shows TITLE_BLOCK arriving via a different parameter
        (PTC_SYMBOL_NAME), not ConfigName, plausibly because it's a
        drawing-format symbol rather than a physical part. Validate
        against an assembly with a known BOM before trusting this on
        files you haven't checked by hand.
    .PARAMETER Path
        Path to one or more Creo assembly files. Accepts pipeline input.
    .PARAMETER StreamNames
        Streams to scan for ConfigName frames. Defaults to NeuAsmSld, the
        only stream confirmed so far - widen if you find it elsewhere.
    .PARAMETER TargetNames
        Frame name(s) to match. Defaults to "ConfigName". Exposed as a
        parameter (rather than hardcoded) since the underlying scanner
        is general-purpose - useful later for other mixed-case system
        fields that ExtractParameters can't reach.
    .EXAMPLE
        Get-CreoBOM -Path .\enclosure.asm.5 | Format-Table -AutoSize
    .EXAMPLE
        Get-ChildItem -Filter "*.asm*" | Get-CreoBOM | Export-Csv bom.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string[]]$StreamNames = @("NeuAsmSld"),
        [string[]]$TargetNames = @("ConfigName")
    )

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $streams = $resolved.Streams | Where-Object { $_.Name -in $StreamNames }

                if (-not $streams) {
                    Write-Warning "$($fileInfo.Name): none of the target streams ($($StreamNames -join ', ')) were found - not an assembly, or ConfigName lives somewhere else in this file."
                    continue
                }

                $allHits = New-Object System.Collections.Generic.List[object]
                foreach ($stream in $streams) {
                    $payload = $resolved.Data[$stream.PayloadStart..($stream.PayloadStart + $stream.PayloadLength - 1)]

                    $hits = if ($script:UseCSharpEngine) { [CreoNative]::ExtractNamedFrames($payload, $TargetNames) }
                    else { Get-CreoNamedFramesFromPayloadPS -Payload $payload -TargetNames $TargetNames }

                    foreach ($h in $hits) {
                        [void]$allHits.Add([PSCustomObject]@{
                            Stream = $stream.Name
                            Name   = $h.Name
                            Value  = $h.Value
                            Offset = $stream.PayloadStart + $h.Offset   # absolute file offset, not payload-relative
                        })
                    }
                }

                if ($allHits.Count -eq 0) {
                    Write-Warning "$($fileInfo.Name): no ConfigName frames found in $($StreamNames -join ', ')."
                    continue
                }

                $parentAssembly = ($fileInfo.Name -replace '(?i)\.(asm|prt)(\.\d+)?$', '')

                $grouped = $allHits | Where-Object { $_.Value } | Group-Object Value
                foreach ($g in $grouped) {
                    [PSCustomObject]@{
                        ParentAssembly = $parentAssembly
                        ComponentName  = $g.Name
                        Quantity       = $g.Count
                        SourceFile     = $fileInfo.Name
                        FirstOffset    = ("0x{0:X8}" -f ($g.Group[0].Offset))
                    }
                }
            }
        }
    }
}

# =========================================================================
# Get-CreoInstanceBOM + Get-CreoVersionHistory additions for CreoParser.psm1
#
# PURE ADDITIONS - nothing existing touched, including the Get-CreoBOM /
# ExtractNamedFrames patch from before. Four things to paste in, anchored
# to function/class names, not line numbers.
#
# WHAT THIS IS AND ISN'T:
# Both of these are ports of a DIFFERENT module's logic, adapted to this
# module's architecture (C# for the raw byte scan, PowerShell for
# interpretation) - they are NOT independently re-derived from this
# module's own byte-level evidence the way E1E1[00|01]E3 was. Treat them
# as second opinions to cross-check against what you already have
# (Get-CreoBOM for BOM, the rev_string/PDMTrail_L03 thread for history),
# not replacements. Ported faithfully where the original logic was
# preserved - noted inline anywhere behavior was intentionally changed.
# =========================================================================

function Get-CreoInstanceMarkersFromPayloadPS {
    param([byte[]]$Payload)

    $results = New-Object System.Collections.Generic.List[object]
    $markerA = [byte[]]@(0xE3, 0x7B, 0xE2)
    $markerB = [byte[]]@(0x6E, 0x61, 0x6D, 0x65, 0x00)  # "name\0"
    $scanLimit = $Payload.Length - 10

    for ($i = 0; $i -lt $scanLimit; $i++) {
        $isA = $true
        for ($j = 0; $j -lt $markerA.Length; $j++) { if ($Payload[$i + $j] -ne $markerA[$j]) { $isA = $false; break } }

        $isB = $false
        if (-not $isA) {
            $isB = $true
            for ($j = 0; $j -lt $markerB.Length; $j++) { if ($Payload[$i + $j] -ne $markerB[$j]) { $isB = $false; break } }
            if ($isB -and $i -gt 0 -and $Payload[$i - 1] -eq 0x5F) { $isB = $false }
        }

        if (-not $isA -and -not $isB) { continue }

        $offsetShift = if ($isA) { 4 } else { $markerB.Length }
        $stringStart = $i + $offsetShift
        $stringEnd = -1
        for ($z = $stringStart; $z -lt $Payload.Length; $z++) { if ($Payload[$z] -eq 0) { $stringEnd = $z; break } }

        if ($stringEnd -gt $stringStart) {
            $rawString = [System.Text.Encoding]::ASCII.GetString($Payload[$stringStart..($stringEnd - 1)])
            $cleanName = $rawString.Split('#')[0]

            $sb = New-Object System.Text.StringBuilder
            $inTag = $false
            foreach ($ch in $cleanName.ToCharArray()) {
                if ($ch -eq '<') { $inTag = $true; continue }
                if ($ch -eq '>') { $inTag = $false; continue }
                if (-not $inTag) { [void]$sb.Append($ch) }
            }
            $cleanNameStr = $sb.ToString().Trim()

            $isValid = $cleanNameStr.Length -gt 5
            if ($isValid) {
                foreach ($ch in $cleanNameStr.ToCharArray()) {
                    if (-not (($ch -ge 'A' -and $ch -le 'Z') -or ($ch -ge 'a' -and $ch -le 'z') -or ($ch -ge '0' -and $ch -le '9') -or $ch -eq '_' -or $ch -eq '-')) {
                        $isValid = $false; break
                    }
                }
            }

            if ($isValid) {
                $results.Add([PSCustomObject]@{
                    RawName    = $cleanNameStr
                    MarkerType = if ($isA) { "E3_7B_E2" } else { "name_literal" }
                    Offset     = $i
                })
            }
            $i = $stringEnd
        }
    }

    return $results
}

function Get-CreoNullTerminatedStringsFromPayloadPS {
    param([byte[]]$Payload, [int]$MinLen = 2)

    $results = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[byte]

    for ($i = 0; $i -lt $Payload.Length; $i++) {
        $b = $Payload[$i]
        if ($b -ge 32 -and $b -le 126) {
            [void]$current.Add($b)
        }
        elseif ($b -eq 0 -and $current.Count -ge $MinLen) {
            $results.Add([PSCustomObject]@{
                Text          = [System.Text.Encoding]::ASCII.GetString($current.ToArray())
                EndByteIndex  = $i
            })
            $current.Clear()
        }
        else {
            $current.Clear()
        }
    }

    return $results
}

function Get-CreoInstanceBOM {
    <#
    .SYNOPSIS
        Extracts a Bill of Materials via the E3 7B E2 / literal "name\0"
        instance markers - a second, independent BOM signal alongside
        Get-CreoBOM's ConfigName-frame approach, ported from an earlier
        module of yours.
    .DESCRIPTION
        Two-pass extraction, same shape as the module this was ported
        from. Pass 1 builds a dictionary of full candidate names by
        loosely regex-scanning $DictionaryBlocks (default FeatDefsCmp,
        NeuAsmSld, MdlRefInfo) for part-number-shaped tokens (8+ chars,
        at least one letter, one digit, one dash/underscore). Pass 2
        scans $InstanceBlock (default FeatDefsCmp) for the raw
        E3 7B E2 / "name\0" markers, then for each hit checks whether
        the raw name is a truncated PREFIX of a longer Pass-1 dictionary
        entry, substituting the longer name before counting - the
        anti-truncation step.

        VALIDATION STATUS: ported wholesale on the strength of "produced
        good output before," not independently re-derived against this
        module's own byte-level evidence the way ConfigName was. Neither
        marker has a documented structural meaning here. Cross-check
        against Get-CreoBOM's output on the same file rather than
        trusting either alone - on ul7.asm.8, E3 7B E2 hit FeatDefsCmp
        only once, which can't be a complete BOM by itself; run this
        function (it checks "name\0" too) before concluding the marker
        approach doesn't apply to that file.
    .PARAMETER Path
        Path to one or more Creo assembly files. Accepts pipeline input.
    .PARAMETER DictionaryBlocks
        Streams scanned in Pass 1 to build the anti-truncation dictionary.
    .PARAMETER InstanceBlock
        Stream scanned in Pass 2 for the actual instance markers.
    .PARAMETER ExcludeNames
        Cleaned candidate names to always reject, case-insensitive. The
        original hardcoded "Set24" here - moved to a parameter since it
        was presumably noise specific to whatever file it was tuned
        against originally; add to or clear this as your own files show.
    .EXAMPLE
        Get-CreoInstanceBOM -Path .\asm0001.asm.1 | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string[]]$DictionaryBlocks = @("FeatDefsCmp", "NeuAsmSld", "MdlRefInfo"),
        [string]$InstanceBlock = "FeatDefsCmp",
        [string[]]$ExcludeNames = @("Set24")
    )

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $parentAssembly = ($fileInfo.Name -replace '(?i)\.(asm|prt)(\.\d+)?$', '')

                # Pass 1: anti-truncation dictionary.
                $knownNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($blockName in $DictionaryBlocks) {
                    $stream = $resolved.Streams | Where-Object { $_.Name -eq $blockName } | Select-Object -First 1
                    if (-not $stream) { continue }
                    $payload = $resolved.Data[$stream.PayloadStart..($stream.PayloadStart + $stream.PayloadLength - 1)]
                    $ascii = [System.Text.Encoding]::ASCII.GetString($payload)
                    foreach ($m in [regex]::Matches($ascii, '[A-Za-z0-9_\-]{8,}')) {
                        if ($m.Value -match '[A-Za-z]' -and $m.Value -match '[0-9]' -and $m.Value -match '[\-_]') {
                            [void]$knownNames.Add($m.Value)
                        }
                    }
                }
                $sortedKnownNames = @($knownNames | Sort-Object Length -Descending)

                # Pass 2: raw instance markers.
                $instanceStream = $resolved.Streams | Where-Object { $_.Name -eq $InstanceBlock } | Select-Object -First 1
                if (-not $instanceStream) {
                    Write-Warning "$($fileInfo.Name): instance block '$InstanceBlock' not found."
                    continue
                }
                $instancePayload = $resolved.Data[$instanceStream.PayloadStart..($instanceStream.PayloadStart + $instanceStream.PayloadLength - 1)]

                $hits = if ($script:UseCSharpEngine) { [CreoNative]::ExtractInstanceMarkers($instancePayload) }
                else { Get-CreoInstanceMarkersFromPayloadPS -Payload $instancePayload }

                if ($hits.Count -eq 0) {
                    Write-Warning "$($fileInfo.Name): no E3 7B E2 / name-literal markers found in $InstanceBlock."
                    continue
                }

                $resolvedNames = foreach ($h in $hits) {
                    if ($h.RawName -in $ExcludeNames) { continue }

                    $resolvedName = $h.RawName
                    foreach ($kn in $sortedKnownNames) {
                        if ($kn.StartsWith($h.RawName, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $resolvedName = $kn
                            break
                        }
                    }

                    [PSCustomObject]@{
                        RawName      = $h.RawName
                        ResolvedName = $resolvedName
                        MarkerType   = $h.MarkerType
                        Offset       = $instanceStream.PayloadStart + $h.Offset
                    }
                }

                $grouped = $resolvedNames | Where-Object { $_.ResolvedName -ne $parentAssembly } | Group-Object ResolvedName
                foreach ($g in $grouped) {
                    [PSCustomObject]@{
                        ParentAssembly = $parentAssembly
                        ComponentName  = $g.Name
                        Quantity       = $g.Count
                        SourceFile     = $fileInfo.Name
                        FirstOffset    = ("0x{0:X8}" -f (($g.Group | Sort-Object Offset)[0].Offset))
                        MarkerTypes    = (($g.Group.MarkerType | Sort-Object -Unique) -join '; ')
                    }
                }
            }
        }
    }
}

function Get-CreoVersionHistory {
    <#
    .SYNOPSIS
        Extracts save/version-history events (hostname, user, Creo
        version, revision, parent file, and an experimental timestamp
        decode) from a Creo file. Ported from a separate module's
        ParseVersionHistory.
    .DESCRIPTION
        Scans $StreamNames (default MdlStatus - inherited from the
        module this was ported from, not independently re-derived here)
        for null-terminated ASCII strings, then for each string
        beginning with the literal "Hostname: '" prefix, assembles an
        event by looking at nearby strings within fixed windows:
          - CreoVersion: next 1-3 strings, either "Creo <ver>" or a bare
            version-shaped string matching ^\d+\.\d+.
          - Revision / ParentFile: anywhere within +/-15 strings, the
            value immediately following a literal "rev_string" /
            "from_mdl_name" string.
          - UserName: scanning BACKWARD up to 8 strings, the first one
            that isn't in the blacklist below, has no spaces, length>=4,
            and matches [a-zA-Z0-9._-]+.
          - Timestamp (EXPERIMENTAL, NOT confirmed): once a UserName
            candidate is found, checks whether the byte right after its
            null terminator is 0xE2, and if so reads 6 more bytes as a
            packed date: [sec][min][hour][day][month0][year-1900] at
            offsets +2..+7 from that null terminator. This is a
            genuinely DIFFERENT hypothesis than the raw-Unix-epoch guess
            for UserName -> "1517522437C" in HANDOFF.md - different byte
            layout, found via a different scan (proximity to
            "Hostname:", not necessarily the same SolidPersistTable
            field). Test against a file with a known real save date
            (e.g. a prt0001.1-10 resave) before trusting it - and don't
            assume it and the HANDOFF hypothesis are describing the same
            underlying field just because both produce a plausible date.

        Blacklist (excluded from UserName candidates): user_name,
        comment, rel_level, rev_string, time, rec_uobj_id, Proe_version,
        Attributes, from_mdl_name, to_mdl_name.
    .PARAMETER Path
        Path to one or more Creo files. Accepts pipeline input.
    .PARAMETER StreamNames
        Streams to scan for history strings. Defaults to MdlStatus.
    .EXAMPLE
        Get-CreoVersionHistory -Path .\prt0001.prt.5 | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path,
        [string[]]$StreamNames = @("MdlStatus")
    )

    process {
        foreach ($filePath in $Path) {
            $resolvedPaths = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            foreach ($rp in $resolvedPaths) {
                $fileInfo = [System.IO.FileInfo]::new($rp.Path)
                if (-not $fileInfo.Exists) { continue }

                $resolved = Resolve-CreoFileStreams -Path $fileInfo.FullName
                $streams = $resolved.Streams | Where-Object { $_.Name -in $StreamNames }

                if (-not $streams) {
                    Write-Warning "$($fileInfo.Name): none of the target streams ($($StreamNames -join ', ')) were found."
                    continue
                }

                $blacklist = @("user_name", "comment", "rel_level", "rev_string", "time", "rec_uobj_id", "Proe_version", "Attributes", "from_mdl_name", "to_mdl_name")

                foreach ($stream in $streams) {
                    $payload = $resolved.Data[$stream.PayloadStart..($stream.PayloadStart + $stream.PayloadLength - 1)]

                    $strings = if ($script:UseCSharpEngine) { [CreoNative]::ExtractNullTerminatedStrings($payload, 2) }
                    else { Get-CreoNullTerminatedStringsFromPayloadPS -Payload $payload -MinLen 2 }

                    if ($strings.Count -eq 0) { continue }

                    for ($i = 0; $i -lt $strings.Count; $i++) {
                        $current = $strings[$i]
                        if (-not $current.Text.StartsWith("Hostname: '")) { continue }

                        $hostname = $current.Text.Substring(11).TrimEnd("'")
                        $creoVersion = $null
                        $revision = $null
                        $parentFile = $null
                        $userName = $null
                        $timestamp = $null
                        $timestampRawBytes = $null

                        for ($k = $i + 1; $k -le [Math]::Min($i + 3, $strings.Count - 1); $k++) {
                            $next = $strings[$k].Text
                            if ($next.StartsWith("Creo ")) { $creoVersion = $next.Substring(5); break }
                            elseif ($next -match '^\d+\.\d+') { $creoVersion = $next; break }
                        }

                        $windowStart = [Math]::Max(0, $i - 15)
                        $windowEnd = [Math]::Min($strings.Count - 1, $i + 15)
                        for ($k = $windowStart; $k -le $windowEnd; $k++) {
                            if ($strings[$k].Text -eq "rev_string" -and ($k + 1) -lt $strings.Count) { $revision = $strings[$k + 1].Text }
                            if ($strings[$k].Text -eq "from_mdl_name" -and ($k + 1) -lt $strings.Count) { $parentFile = $strings[$k + 1].Text }
                        }

                        $backEnd = [Math]::Max(0, $i - 8)
                        for ($j = ($i - 1); $j -ge $backEnd; $j--) {
                            $prev = $strings[$j].Text
                            if ($prev -notmatch ' ' -and $prev.Length -ge 4 -and $prev -match '^[a-zA-Z0-9\._\-]+$' -and $prev -notin $blacklist) {
                                $userName = $prev

                                # EXPERIMENTAL - see .DESCRIPTION.
                                $nullIndex = $strings[$j].EndByteIndex
                                if (($nullIndex + 7) -lt $payload.Length -and $payload[$nullIndex + 1] -eq 0xE2) {
                                    $sc = [int]$payload[$nullIndex + 2]
                                    $mi = [int]$payload[$nullIndex + 3]
                                    $hr = [int]$payload[$nullIndex + 4]
                                    $dy = [int]$payload[$nullIndex + 5]
                                    $mo = [int]$payload[$nullIndex + 6]
                                    $yr = [int]$payload[$nullIndex + 7]
                                    $timestampRawBytes = "sec={0} min={1} hr={2} day={3} mon0={4} yr-1900={5}" -f $sc, $mi, $hr, $dy, $mo, $yr

                                    if ($yr -ge 0 -and $yr -le 200 -and $mo -ge 0 -and $mo -le 11) {
                                        try { $timestamp = [datetime]::new((1900 + $yr), ($mo + 1), $dy, $hr, $mi, $sc) }
                                        catch { $timestamp = $null }
                                    }
                                }
                                break
                            }
                        }

                        [PSCustomObject]@{
                            File              = $fileInfo.Name
                            Stream            = $stream.Name
                            Hostname          = $hostname
                            UserName          = $userName
                            CreoVersion       = $creoVersion
                            Revision          = $revision
                            ParentFile        = $parentFile
                            Timestamp         = $timestamp
                            TimestampRawBytes = $timestampRawBytes
                            Offset            = ("0x{0:X8}" -f ($stream.PayloadStart + $current.EndByteIndex - $current.Text.Length))
                        }
                    }
                }
            }
        }
    }
}



Export-ModuleMember -Function `
    Export-CreoThumbnail, `
    Extract-CreoThumbnail, `
    Compare-CreoStreamBytes, `
    Show-CreoHexDump, `
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
    Get-CreoParameter,`
    Search-CreoBinary,`
    Invoke-CreoRegionAnalysis, `
    Trace-CreoPointerReference, `
    Export-CreoRegionBlob,
    Get-CreoStreamFingerprints, `
    Show-CreoStreamHashMatrix, `
    Get-CreoCandidatePlmHashes, `
    Get-CreoInitialInventory, `
    Get-CreoInitialStreamInventory, `
    Test-CreoInitialInventory, `
    Show-CreoHexDumpEx, `
    Show-CreoHexDumpPatternEx, `
    Find-CreoBytePatternOffsetsEx, `
    Invoke-CreoRegionAnalysisEx, `
    Get-CreoBOM, `
    Get-CreoInstanceBOM, `
    Get-CreoVersionHistory 
