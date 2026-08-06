<#
.SYNOPSIS
Runs Creo binary analysis cmdlets against all part and assembly files in a specified directory.

.DESCRIPTION
Gathers all *.prt.* and *.asm.* files and utilizes the loaded Creo analysis module
to generate statistical fingerprints, marker data, clustering, and data maps,
exporting the results to CSV.

Per file, streams are resolved once via Resolve-CreoFileStreams and that result is
reused (-ResolvedStreams) across every cmdlet that accepts it, instead of re-reading
and re-parsing the file for each call.

.PARAMETER Directory
Root directory to search (recursively) for *.prt.* / *.asm.* files.

.PARAMETER OutputFolder
Where CSV reports are written. Created if it doesn't exist.

.PARAMETER TopCandidateMarkers
How many auto-discovered candidate markers (from Get-CreoCandidateMarkers) to run
byte-transition and clustering analysis on, per file. Default 5.

.PARAMETER StructuralPattern
Optional wildcard hex pattern (e.g. "E3????E1", "??" = any byte) passed to
Find-CreoStructuralRuns. If omitted, structural-run search is skipped.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Directory,

    [Parameter()]
    [string]$OutputFolder = ".\CreoAnalysisResults",

    [Parameter()]
    [int]$TopCandidateMarkers = 5,

    [Parameter()]
    [string]$StructuralPattern
)

# Ensure the output directory exists
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Recursively gather target files
$targetFiles = Get-ChildItem -Path $Directory -Include "*.prt.*", "*.asm.*" -Recurse -File
$filePaths = $targetFiles.FullName

if (-not $filePaths) {
    Write-Warning "No *.prt.* or *.asm.* files found in $Directory."
    return
}

Write-Host "Found $($filePaths.Count) Creo files. Starting analysis pipeline..." -ForegroundColor Cyan

# ---------------------------------------------------------
# 1. Bulk Comparison
# ---------------------------------------------------------
# Compare-CreoStreams natively accepts an array of files via -Files.
Write-Host "`n[1/3] Running Compare-CreoStreams across all files..."
$bulkComparison = Compare-CreoStreams -Files $filePaths
$bulkComparison | Export-Csv -Path "$OutputFolder\Bulk_StreamComparison.csv" -NoTypeInformation

# ---------------------------------------------------------
# 2. Bulk Structural Run Search (optional)
# ---------------------------------------------------------
if ($StructuralPattern) {
    Write-Host "`n[2/3] Searching for structural pattern '$StructuralPattern' across all files..."
    $bulkStructuralRuns = New-Object System.Collections.Generic.List[object]

    foreach ($file in $filePaths) {
        try {
            $runs = Find-CreoStructuralRuns -File $file -Pattern $StructuralPattern
            foreach ($r in $runs) {
                $r | Add-Member -NotePropertyName File -NotePropertyValue (Split-Path $file -Leaf) -Force
                $bulkStructuralRuns.Add($r)
            }
        }
        catch {
            Write-Warning "  Find-CreoStructuralRuns failed on $(Split-Path $file -Leaf): $($_.Exception.Message)"
        }
    }

    if ($bulkStructuralRuns.Count -gt 0) {
        $bulkStructuralRuns | Export-Csv -Path "$OutputFolder\Bulk_StructuralRuns.csv" -NoTypeInformation
    }
}
else {
    Write-Host "`n[2/3] Skipping structural run search (no -StructuralPattern supplied)."
}

# ---------------------------------------------------------
# 3. Per-File Analysis Loop
# ---------------------------------------------------------
Write-Host "`n[3/3] Running individual file metrics..."

foreach ($file in $filePaths) {
    $fileName = Split-Path $file -Leaf
    Write-Host "  -> Processing: $fileName" -ForegroundColor Green

    try {
        # Resolve streams once; reused below via -ResolvedStreams so the phase-3
        # cmdlets don't each re-read and re-parse the file from scratch.
        $resolved = Resolve-CreoFileStreams -File $file
    }
    catch {
        Write-Warning "  Failed to resolve streams for ${fileName}: $($_.Exception.Message)"
        continue
    }

    # --- Get Data Maps ---
    $dataMaps = Get-CreoDataMaps -File $file
    if ($dataMaps) {
        $dataMaps | Export-Csv -Path "$OutputFolder\${fileName}_DataMaps.csv" -NoTypeInformation
    }

    # --- Get Marker Statistics (fixed candidate list) ---
    $markerStats = Get-CreoMarkerStatistics -File $file
    if ($markerStats) {
        $markerStats | Export-Csv -Path "$OutputFolder\${fileName}_MarkerStats.csv" -NoTypeInformation
    }

    # --- Measure Field Boundaries ---
    $boundaries = Measure-CreoFieldBoundaries -File $file
    if ($boundaries) {
        $boundaries | Export-Csv -Path "$OutputFolder\${fileName}_FieldBoundaries.csv" -NoTypeInformation
    }

    # --- Get Byte Ngram Stats (default N=2) ---
    $ngramStats = Get-CreoByteNgramStats -File $file
    if ($ngramStats) {
        $ngramStats | Export-Csv -Path "$OutputFolder\${fileName}_NgramStats.csv" -NoTypeInformation
    }

    # --- Auto-discover candidate markers (frequency + coverage + neighbor diversity) ---
    $candidates = Get-CreoCandidateMarkers -File $file -ResolvedStreams $resolved -Top $TopCandidateMarkers
    if ($candidates) {
        $candidates | Export-Csv -Path "$OutputFolder\${fileName}_CandidateMarkers.csv" -NoTypeInformation
    }

    # --- Byte-transition stats + marker clustering, for each discovered candidate marker ---
    $transitions = New-Object System.Collections.Generic.List[object]
    $clusters = New-Object System.Collections.Generic.List[object]

    foreach ($candidate in $candidates) {
        $markerByte = [Convert]::ToByte($candidate.Marker, 16)

        $t = Get-CreoByteTransitionStats -File $file -Marker $markerByte -ResolvedStreams $resolved
        foreach ($row in $t) { $transitions.Add($row) }

        $c = Find-CreoMarkerClusters -File $file -Marker $markerByte -ResolvedStreams $resolved
        foreach ($row in $c) { $clusters.Add($row) }
    }

    if ($transitions.Count -gt 0) {
        $transitions | Export-Csv -Path "$OutputFolder\${fileName}_ByteTransitions.csv" -NoTypeInformation
    }
    if ($clusters.Count -gt 0) {
        $clusters | Export-Csv -Path "$OutputFolder\${fileName}_MarkerClusters.csv" -NoTypeInformation
    }

    # --- Marker pair (bigram) stats, scoped to resolved streams ---
    $markerPairs = Get-CreoMarkerPairs -File $file -ResolvedStreams $resolved
    if ($markerPairs) {
        $markerPairs | Export-Csv -Path "$OutputFolder\${fileName}_MarkerPairs.csv" -NoTypeInformation
    }

    # --- Sliding-window entropy regions ---
    $entropyRegions = Measure-CreoEntropyRegions -File $file -ResolvedStreams $resolved
    if ($entropyRegions) {
        $entropyRegions | Export-Csv -Path "$OutputFolder\${fileName}_EntropyRegions.csv" -NoTypeInformation
    }
}

Write-Host "`nAnalysis complete. All reports have been saved to: $OutputFolder" -ForegroundColor Cyan
