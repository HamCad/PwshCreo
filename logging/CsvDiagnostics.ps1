#requires -Version 5.1
<#
.SYNOPSIS
  Diagnostics + cleanup helpers for the "comma-delimited but the format
  sucks" .txt exports -- figure out what's actually wrong before writing
  a fix for it.

.DESCRIPTION
  Two very different problems both look like "half the columns are empty":

  (A) $-amounts and thousands-separated numbers are QUOTED in the source
      ("$1,234.56"). This is actually fine -- a real CSV parser (Import-Csv,
      or the C# equivalent, TextFieldParser / a proper CsvHelper-style
      reader) already handles it correctly, because the quotes tell the
      parser that comma isn't a delimiter there. The only work left is
      cleaning the VALUE afterward (strip $ and the commas) -- zero risk,
      because by that point the field is already correctly isolated.

  (B) The same amounts are NOT quoted. Now there's a genuine ambiguity: a
      bare "9,500" in the data is indistinguishable from two adjacent
      fields "9" and "500" without knowing the expected column layout.
      Anything that tries to guess is a heuristic, not a guarantee, and
      needs to be checked, not trusted blindly.

  Test-DelimitedFileShape tells you which one you're actually dealing
  with, per file, without needing to show me the file itself: (A) parses
  clean with a matching field count on every row; (B) shows rows whose
  raw field count doesn't match the header.
#>

function Test-DelimitedFileShape {
    <#
    .SYNOPSIS
      Reports whether a delimited file's rows actually have the number of
      fields the header promises, and how populated each column really is.
      Run this FIRST on any new file before writing a converter for it.

    .PARAMETER SampleMisalignedRows
      How many example bad rows to print (line number + raw text), so you
      can see the actual shape of the problem.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Delimiter = ',',
        [int]$SampleMisalignedRows = 5
    )
    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    if (-not $lines.Count) { throw "No lines read from $Path" }

    $header = $lines[0] -split [regex]::Escape($Delimiter)
    $expected = $header.Count
    Write-Host "Header ($expected columns): $($header -join ' | ')"

    # The direct, reliable signal: a naive split having MORE fields than the
    # header is only harmless if quote characters are actually present to
    # justify it (a legitimately quoted "BOLT WORKS, LLC"). A line with
    # EXTRA fields and NO quote characters anywhere has no such excuse --
    # that comma was never inside quotes, so it's a real, unrepaired
    # delimiter collision. This is a direct test, not an inference from
    # parsed values (which a truncated-but-still-numeric fragment like
    # "$1" from a split "$1,234.56" can slip past).
    $badLines = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $naiveCount = ($lines[$i] -split [regex]::Escape($Delimiter)).Count
        $hasQuotes = $lines[$i].Contains('"')
        if ($naiveCount -gt $expected -and -not $hasQuotes) {
            $badLines.Add([PSCustomObject]@{ LineNumber = $i + 1; FieldCount = $naiveCount; Text = $lines[$i] })
        }
    }

    if ($badLines.Count) {
        $pct = [math]::Round(100.0 * $badLines.Count / ($lines.Count - 1), 1)
        Write-Host "`nDiagnosis: $($badLines.Count) of $($lines.Count - 1) rows ($pct%) have MORE fields than"
        Write-Host "the header with NO quote characters anywhere on the line -- that's an unquoted"
        Write-Host "delimiter collision (case B), not a parsing artifact. Import-Csv will silently"
        Write-Host "shift values into the wrong columns on these rows rather than error. Sample:"
        $badLines | Select-Object -First $SampleMisalignedRows | ForEach-Object {
            Write-Host "  line $($_.LineNumber) ($($_.FieldCount) fields, expected $expected): $($_.Text)"
        }
    }
    else {
        Write-Host "`nDiagnosis: no rows have unexplained extra fields -- any `$/comma-in-number values"
        Write-Host "here are either absent or properly quoted (case A). Import-Csv is parsing this"
        Write-Host "file correctly; run values through ConvertTo-CleanNumericValue and you're done."
    }

    # Per-column populated rate + clean-numeric rate is still worth seeing --
    # useful supporting context, just not the primary signal anymore.
    $parsed = @(Import-Csv -LiteralPath $Path -Delimiter $Delimiter)
    $numericLike = $header | Where-Object { $_ -match '(?i)price|cost|amount|total|qty|quantity|value' }
    Write-Host "`nQuote-aware parse: $($parsed.Count) rows. Per-column populated / clean-numeric rate:"
    foreach ($col in $header) {
        $nonBlank = @($parsed | Where-Object { -not [string]::IsNullOrWhiteSpace($_.$col) })
        $pct2 = if ($parsed.Count) { [math]::Round(100.0 * $nonBlank.Count / $parsed.Count, 1) } else { 0 }
        $sample = ($nonBlank | Select-Object -First 1).$col
        $line = "  {0,-25} {1,6}% populated   e.g. '{2}'" -f $col, $pct2, $sample
        if ($col -in $numericLike -and $nonBlank.Count) {
            $cleanCount = @($nonBlank | Where-Object { $null -ne (ConvertTo-CleanNumericValue -Value $_.$col) }).Count
            $line += ("   |  {0}% clean-numeric" -f [math]::Round(100.0 * $cleanCount / $nonBlank.Count, 1))
        }
        Write-Host $line
    }
}

function ConvertTo-CleanNumericValue {
    <#
    .SYNOPSIS
      Cleans an ALREADY-ISOLATED field value into a plain number string:
      strips $ and thousands commas, treats parenthesized numbers as
      negative ("(1,234.56)" -> "-1234.56", a common accounting-export
      convention), and maps common non-numeric placeholders to $null.
      Safe to use regardless of case (A) or (B) above, since it only runs
      AFTER a field has already been correctly separated from its
      neighbors -- it never looks at delimiters.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $v = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if ($v -in @('N/A', 'NA', 'NULL', '-', '--', '*', 'WITHHELD', 'UNK', 'TBD')) { return $null }

    $negative = $false
    if ($v -match '^\((.+)\)$') { $negative = $true; $v = $Matches[1] }

    $v = $v -replace '[,$%\s]', ''
    if ($v -notmatch '^-?\d+(\.\d+)?$') { return $null }   # still not a clean number -- don't guess

    if ($negative -and -not $v.StartsWith('-')) { $v = '-' + $v }
    return $v
}

function Repair-AmbiguousDelimitedLine {
    <#
    .SYNOPSIS
      FALLBACK for case (B) only -- unquoted thousands-separated numbers
      that are genuinely splitting a line into too many fields. Reconciles
      a too-long raw split back down to the expected column count by
      merging adjacent numeric-looking fragments, but ONLY merges enough
      pairs to reach the expected count, from left to right, and only
      where the merge target actually still looks numeric afterward.

    .DESCRIPTION
      This is a heuristic, not a guarantee -- verify it against the case
      it's least suited to before trusting it: two SEPARATE small numeric
      fields sitting next to each other (e.g. quantity=9 immediately
      followed by a 3-digit field) are structurally indistinguishable from
      one thousands-separated number, and this function does not know the
      difference. Run it with -WhatIf on a sample first and read the
      before/after, especially for files with several adjacent numeric
      columns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][int]$ExpectedFieldCount,
        [string]$Delimiter = ',',
        [switch]$WhatIf
    )
    $fields = [System.Collections.Generic.List[string]]($Line -split [regex]::Escape($Delimiter))
    $originalCount = $fields.Count
    if ($fields.Count -le $ExpectedFieldCount) {
        return $Line   # nothing to repair (or already short -- a different problem, don't touch it)
    }

    $i = 0
    while ($fields.Count -gt $ExpectedFieldCount -and $i -lt $fields.Count - 1) {
        $candidate = ($fields[$i] + ',' + $fields[$i + 1])
        # only merge if the joined text is EXACTLY a thousands-grouped number
        # (optionally $-prefixed) -- i.e. the comma we're re-inserting sits
        # at a real 3-digit group boundary, not just "two numbers next to
        # each other"
        if ($candidate -match '^\$?\d{1,3}(,\d{3})+(\.\d+)?$') {
            $fields[$i] = $candidate -replace '[,$]', ''
            $fields.RemoveAt($i + 1)
        }
        else {
            $i++
        }
    }

    $result = $fields -join $Delimiter
    if ($WhatIf) {
        Write-Host "  [$originalCount -> $($fields.Count) fields, expected $ExpectedFieldCount]"
        Write-Host "  before: $Line"
        Write-Host "  after:  $result"
    }
    return $result
}
