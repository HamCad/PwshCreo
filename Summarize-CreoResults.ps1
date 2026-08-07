<#
.SYNOPSIS
Summarizes the CSV reports produced by Invoke-CreoAnalysisPipeline.ps1.

.DESCRIPTION
The per-file/per-marker CSVs are useful for drilling in, but they're too granular to
eyeball across a whole model collection. This rolls them up into a handful of ranked
summaries: which markers are most frequent and most stream-consistent, which streams
run hottest/coldest on entropy, which byte-pairs show the most regular spacing, and
(if present) how big the structural-pattern hit set was per file/stream.

.PARAMETER ResultsFolder
Folder containing the CSVs from Invoke-CreoAnalysisPipeline.ps1. Default .\CreoAnalysisResults.

.PARAMETER Top
How many rows to show per ranked table. Default 15.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ResultsFolder = ".\CreoAnalysisResults",

    [Parameter()]
    [int]$Top = 15
)

if (-not (Test-Path -LiteralPath $ResultsFolder)) {
    throw "Results folder not found: $ResultsFolder"
}

function Import-CreoCsvSet {
    param([string]$Pattern)
    $files = Get-ChildItem -Path $ResultsFolder -Filter $Pattern -File
    if (-not $files) { return @() }
    $rows = foreach ($f in $files) {
        Import-Csv -Path $f.FullName
    }
    return $rows
}

# =========================================================================
# 1. Bulk stream comparison -> marker totals, entropy extremes
# =========================================================================
$bulkPath = Join-Path $ResultsFolder "Bulk_StreamComparison.csv"
if (Test-Path -LiteralPath $bulkPath) {
    $bulk = Import-Csv -Path $bulkPath

    # Marker columns are everything ending in "Count"
    $markerCols = $bulk[0].PSObject.Properties.Name | Where-Object { $_ -like "*Count" }

    Write-Host "`n=== Marker totals across all streams/files ===" -ForegroundColor Cyan
    $markerTotals = foreach ($col in $markerCols) {
        $sum = ($bulk | Measure-Object -Property $col -Sum).Sum
        $streamsWithHit = ($bulk | Where-Object { [double]$_.$col -gt 0 }).Count
        [PSCustomObject]@{
            Marker           = $col -replace 'Count$', ''
            TotalCount       = $sum
            StreamsWithHit   = $streamsWithHit
            StreamCoveragePct = if ($bulk.Count -gt 0) { [Math]::Round(100.0 * $streamsWithHit / $bulk.Count, 1) } else { 0 }
        }
    }
    $markerTotals | Sort-Object -Property TotalCount -Descending | Select-Object -First $Top | Format-Table -AutoSize

    Write-Host "`n=== Highest-entropy streams (most compressed/random-looking) ===" -ForegroundColor Cyan
    $bulk | Sort-Object { [double]$_.Entropy } -Descending |
        Select-Object -First $Top File, Stream, Entropy, PayloadLength, PrintableDensity, NullDensity |
        Format-Table -AutoSize

    Write-Host "`n=== Lowest-entropy streams (most structured/repetitive) ===" -ForegroundColor Cyan
    $bulk | Where-Object { [double]$_.PayloadLength -gt 0 } | Sort-Object { [double]$_.Entropy } |
        Select-Object -First $Top File, Stream, Entropy, PayloadLength, PrintableDensity, NullDensity |
        Format-Table -AutoSize

    Write-Host "`n=== Same stream name across files: entropy consistency ===" -ForegroundColor Cyan
    Write-Host "(low StdDev = stable structural signature; high StdDev = version drift or abnormal file)"
    $bulk | Group-Object Stream | ForEach-Object {
        $entropies = $_.Group | ForEach-Object { [double]$_.Entropy }
        $mean = ($entropies | Measure-Object -Average).Average
        $variance = if ($entropies.Count -gt 1) {
            (($entropies | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum) / ($entropies.Count - 1)
        } else { 0 }
        [PSCustomObject]@{
            Stream        = $_.Name
            FileCount     = $_.Count
            AvgEntropy    = [Math]::Round($mean, 3)
            StdDevEntropy = [Math]::Round([Math]::Sqrt($variance), 3)
        }
    } | Where-Object { $_.FileCount -gt 1 } | Sort-Object -Property StdDevEntropy -Descending |
        Select-Object -First $Top | Format-Table -AutoSize
}
else {
    Write-Warning "Bulk_StreamComparison.csv not found in $ResultsFolder - skipping marker/entropy summaries."
}

# =========================================================================
# 2. Candidate markers -> which bytes score highest, and how consistently
#    across files (a marker that's top-ranked in every file is a much
#    stronger candidate than one that only shows up once)
# =========================================================================
$candidates = Import-CreoCsvSet -Pattern "*_CandidateMarkers.csv"
if ($candidates.Count -gt 0) {
    Write-Host "`n=== Candidate markers: consistency across files ===" -ForegroundColor Cyan
    $candidates | Group-Object Marker | ForEach-Object {
        $scores = $_.Group | ForEach-Object { [double]$_.Score }
        [PSCustomObject]@{
            Marker      = $_.Name
            FilesSeenIn = $_.Count
            AvgScore    = [Math]::Round((($scores | Measure-Object -Average).Average), 2)
            MaxScore    = [Math]::Round((($scores | Measure-Object -Maximum).Maximum), 2)
        }
    } | Sort-Object -Property FilesSeenIn, AvgScore -Descending | Select-Object -First $Top | Format-Table -AutoSize
}

# =========================================================================
# 3. Byte-pair spacing -> tightest, most consistent spacing = most likely
#    structural (vs incidental) sequences
# =========================================================================
$pairs = Import-CreoCsvSet -Pattern "*_MarkerPairs.csv"
if ($pairs.Count -gt 0) {
    Write-Host "`n=== Most frequent byte-pair sequences (aggregated across files) ===" -ForegroundColor Cyan
    $pairs | Group-Object Sequence | ForEach-Object {
        $counts = $_.Group | ForEach-Object { [double]$_.Count }
        $spacings = $_.Group | ForEach-Object { [double]$_.AvgSpacing } | Where-Object { $_ -gt 0 }
        [PSCustomObject]@{
            Sequence       = $_.Name
            TotalCount     = ($counts | Measure-Object -Sum).Sum
            FilesSeenIn    = $_.Count
            AvgSpacing     = if ($spacings) { [Math]::Round((($spacings | Measure-Object -Average).Average), 2) } else { $null }
        }
    } | Sort-Object -Property TotalCount -Descending | Select-Object -First $Top | Format-Table -AutoSize
}

# =========================================================================
# 4. Marker clusters -> largest/most regular clusters
# =========================================================================
$clusters = Import-CreoCsvSet -Pattern "*_MarkerClusters.csv"
if ($clusters.Count -gt 0) {
    Write-Host "`n=== Largest marker clusters (regular runs of a marker) ===" -ForegroundColor Cyan
    $clusters | Sort-Object { [double]$_.Occurrences } -Descending |
        Select-Object -First $Top Marker, Stream, Occurrences, AverageSpacing, MedianSpacing |
        Format-Table -AutoSize
}

# =========================================================================
# 5. Structural pattern hits (if -StructuralPattern was used in the pipeline)
# =========================================================================
$structuralPath = Join-Path $ResultsFolder "Bulk_StructuralRuns.csv"
if (Test-Path -LiteralPath $structuralPath) {
    $runs = Import-Csv -Path $structuralPath
    Write-Host "`n=== Structural pattern hits by stream ===" -ForegroundColor Cyan
    Write-Host "($($runs.Count) total hits - a huge count usually means the pattern was too short/common; try a longer wildcard pattern)"
    $runs | Group-Object Stream | Sort-Object Count -Descending |
        Select-Object -First $Top Name, Count |
        Format-Table -AutoSize
}

Write-Host "`nDone." -ForegroundColor Cyan
