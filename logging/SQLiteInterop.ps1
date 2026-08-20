#requires -Version 5.1
<#
.SYNOPSIS
  Minimal SQLite driver for PowerShell built entirely on winsqlite3.dll --
  the SQLite engine that ships inside Windows 10/11 -- via P/Invoke.

.NOTES
  No NuGet package, no PSSQLite module, no installer. Add-Type compiles the
  C# below using the .NET compiler already on the machine; DllImport then
  calls straight into C:\Windows\System32\winsqlite3.dll, which is already
  present. Nothing is downloaded or installed.

  winsqlite3.dll is an internal Windows component: its exact SQLite version
  is not pinned by Microsoft and differs across Windows builds (one publicly
  reported build was 3.23.2, from 2018). This library therefore only uses
  the original SQLite C API (open/prepare/bind/step/column/finalize), which
  has been stable since SQLite's earliest releases -- nothing here depends
  on a specific modern version.

  Run Test-SqliteSetup once on your machine before pointing this at real
  data -- see the bottom of this file.
#>

# Change this only if you intentionally ship your own sqlite3.dll instead of
# using the one built into Windows.
$Script:SqliteDllName = 'winsqlite3.dll'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeSqlite
{
    private const string DLL = "$Script:SqliteDllName";

    public const int SQLITE_OK         = 0;
    public const int SQLITE_ROW        = 100;
    public const int SQLITE_DONE       = 101;
    public const int SQLITE_CONSTRAINT = 19;

    public const int SQLITE_INTEGER = 1;
    public const int SQLITE_FLOAT   = 2;
    public const int SQLITE_TEXT    = 3;
    public const int SQLITE_BLOB    = 4;
    public const int SQLITE_NULL    = 5;

    // Tells SQLite to copy bound text/blob values immediately, so our
    // managed byte[] can be released right after the bind call returns.
    public static readonly IntPtr SQLITE_TRANSIENT = new IntPtr(-1);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_open(byte[] filename, out IntPtr db);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_close_v2(IntPtr db);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_exec(IntPtr db, byte[] sql, IntPtr callback, IntPtr callbackArg, out IntPtr errmsg);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nBytes, out IntPtr stmt, IntPtr tail);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_step(IntPtr stmt);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_finalize(IntPtr stmt);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_reset(IntPtr stmt);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_column_count(IntPtr stmt);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr sqlite3_column_name(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_column_type(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_column_bytes(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long sqlite3_column_int64(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern double sqlite3_column_double(IntPtr stmt, int col);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_bind_null(IntPtr stmt, int index);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_bind_int64(IntPtr stmt, int index, long value);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_bind_double(IntPtr stmt, int index, double value);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_bind_text(IntPtr stmt, int index, byte[] value, int nBytes, IntPtr destructor);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr sqlite3_errmsg(IntPtr db);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_changes(IntPtr db);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr sqlite3_libversion();

    // ---- managed helpers -----------------------------------------------

    public static byte[] StringToUtf8Bytes(string s)
    {
        if (s == null) return null;
        byte[] body = Encoding.UTF8.GetBytes(s);
        byte[] withNull = new byte[body.Length + 1];
        Array.Copy(body, withNull, body.Length);
        withNull[withNull.Length - 1] = 0;
        return withNull;
    }

    // For null-terminated results with no length function (errmsg, libversion).
    public static string Utf8PtrToString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero) return null;
        int len = 0;
        while (Marshal.ReadByte(ptr, len) != 0) len++;
        byte[] buffer = new byte[len];
        if (len > 0) Marshal.Copy(ptr, buffer, 0, len);
        return Encoding.UTF8.GetString(buffer);
    }

    // For column text specifically: SQLite's documented-safe pairing is
    // column_text() called BEFORE column_bytes() for the same column.
    public static string Utf8ColumnText(IntPtr stmt, int col)
    {
        IntPtr textPtr = sqlite3_column_text(stmt, col);
        if (textPtr == IntPtr.Zero) return null;
        int len = sqlite3_column_bytes(stmt, col);
        byte[] buffer = new byte[len];
        if (len > 0) Marshal.Copy(textPtr, buffer, 0, len);
        return Encoding.UTF8.GetString(buffer);
    }
}
"@

function Open-SqliteDb {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [NativeSqlite]::StringToUtf8Bytes($Path)
    $database = [IntPtr]::Zero
    $rc = [NativeSqlite]::sqlite3_open($bytes, [ref]$database)
    if ($rc -ne [NativeSqlite]::SQLITE_OK) {
        throw "sqlite3_open failed for '$Path' (code $rc)"
    }
    # Off by default, per connection -- must be set every time a db is opened.
    Invoke-SqliteExec -Database $database -Sql 'PRAGMA foreign_keys = ON;'
    return $database
}

function Close-SqliteDb {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IntPtr]$Database)
    [NativeSqlite]::sqlite3_close_v2($Database) | Out-Null
}

function Invoke-SqliteExec {
    # For DDL / PRAGMA / multi-statement batches with no parameters and no
    # result rows (sqlite3_exec runs as many ';'-separated statements as
    # you hand it in one call).
    [CmdletBinding()]
    param([Parameter(Mandatory)][IntPtr]$Database, [Parameter(Mandatory)][string]$Sql)
    $sqlBytes = [NativeSqlite]::StringToUtf8Bytes($Sql)
    $errPtr = [IntPtr]::Zero
    $rc = [NativeSqlite]::sqlite3_exec($Database, $sqlBytes, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$errPtr)
    if ($rc -ne [NativeSqlite]::SQLITE_OK) {
        $msg = [NativeSqlite]::Utf8PtrToString($errPtr)
        throw "sqlite3_exec failed (code $rc): $msg"
    }
}

function Bind-SqliteParams {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IntPtr]$Stmt, [object[]]$Params)
    for ($i = 0; $i -lt $Params.Count; $i++) {
        $idx = $i + 1   # sqlite bind indices are 1-based
        $val = $Params[$i]
        if ($null -eq $val -or ($val -is [string] -and $val.Length -eq 0)) {
            [void][NativeSqlite]::sqlite3_bind_null($Stmt, $idx)
        }
        elseif ($val -is [int] -or $val -is [long]) {
            [void][NativeSqlite]::sqlite3_bind_int64($Stmt, $idx, [long]$val)
        }
        elseif ($val -is [double] -or $val -is [decimal] -or $val -is [single]) {
            [void][NativeSqlite]::sqlite3_bind_double($Stmt, $idx, [double]$val)
        }
        else {
            if ($val -is [datetime]) { $s = $val.ToString('yyyy-MM-dd') } else { $s = [string]$val }
            $bytes = [NativeSqlite]::StringToUtf8Bytes($s)
            [void][NativeSqlite]::sqlite3_bind_text($Stmt, $idx, $bytes, ($bytes.Length - 1), [NativeSqlite]::SQLITE_TRANSIENT)
        }
    }
}

function Invoke-SqliteNonQuery {
    # INSERT / UPDATE / DELETE with positional '?' parameters. Returns the
    # number of rows changed (sqlite3_changes).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][string]$Sql,
        [object[]]$Params = @()
    )
    $stmt = [IntPtr]::Zero
    $sqlBytes = [NativeSqlite]::StringToUtf8Bytes($Sql)
    $rc = [NativeSqlite]::sqlite3_prepare_v2($Database, $sqlBytes, -1, [ref]$stmt, [IntPtr]::Zero)
    if ($rc -ne [NativeSqlite]::SQLITE_OK) {
        throw "prepare failed (code $rc): $([NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_errmsg($Database)))"
    }
    try {
        Bind-SqliteParams -Stmt $stmt -Params $Params
        $rc = [NativeSqlite]::sqlite3_step($stmt)
        if ($rc -ne [NativeSqlite]::SQLITE_DONE -and $rc -ne [NativeSqlite]::SQLITE_ROW) {
            throw "step failed (code $rc): $([NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_errmsg($Database)))"
        }
        return [NativeSqlite]::sqlite3_changes($Database)
    }
    finally {
        [NativeSqlite]::sqlite3_finalize($stmt) | Out-Null
    }
}

function Invoke-SqliteQuery {
    # SELECT with positional '?' parameters. Returns an array of PSCustomObject.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][string]$Sql,
        [object[]]$Params = @()
    )
    $stmt = [IntPtr]::Zero
    $sqlBytes = [NativeSqlite]::StringToUtf8Bytes($Sql)
    $rc = [NativeSqlite]::sqlite3_prepare_v2($Database, $sqlBytes, -1, [ref]$stmt, [IntPtr]::Zero)
    if ($rc -ne [NativeSqlite]::SQLITE_OK) {
        throw "prepare failed (code $rc): $([NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_errmsg($Database)))"
    }
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        Bind-SqliteParams -Stmt $stmt -Params $Params
        $colCount = [NativeSqlite]::sqlite3_column_count($stmt)
        $colNames = @(for ($c = 0; $c -lt $colCount; $c++) {
            [NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_column_name($stmt, $c))
        })
        while (([NativeSqlite]::sqlite3_step($stmt)) -eq [NativeSqlite]::SQLITE_ROW) {
            $row = [ordered]@{}
            for ($c = 0; $c -lt $colCount; $c++) {
                $type = [NativeSqlite]::sqlite3_column_type($stmt, $c)
                $value = $null
                switch ($type) {
                    ([NativeSqlite]::SQLITE_INTEGER) { $value = [NativeSqlite]::sqlite3_column_int64($stmt, $c) }
                    ([NativeSqlite]::SQLITE_FLOAT)   { $value = [NativeSqlite]::sqlite3_column_double($stmt, $c) }
                    ([NativeSqlite]::SQLITE_TEXT)    { $value = [NativeSqlite]::Utf8ColumnText($stmt, $c) }
                    ([NativeSqlite]::SQLITE_NULL)    { $value = $null }
                    default                          { $value = [NativeSqlite]::Utf8ColumnText($stmt, $c) }
                }
                $row[$colNames[$c]] = $value
            }
            $results.Add([PSCustomObject]$row)
        }
    }
    finally {
        [NativeSqlite]::sqlite3_finalize($stmt) | Out-Null
    }
    return , $results.ToArray()   # leading comma: never unwrap a 1-row result to a scalar
}

function New-SqliteStatement {
    # Prepares a statement ONCE so it can be reused across many rows via
    # Invoke-SqlitePreparedNonQuery, instead of re-parsing and re-UTF8-
    # encoding the same SQL text on every single row. Caller must
    # eventually call Close-SqliteStatement.
    [CmdletBinding()]
    param([Parameter(Mandatory)][IntPtr]$Database, [Parameter(Mandatory)][string]$Sql)
    $stmt = [IntPtr]::Zero
    $sqlBytes = [NativeSqlite]::StringToUtf8Bytes($Sql)
    $rc = [NativeSqlite]::sqlite3_prepare_v2($Database, $sqlBytes, -1, [ref]$stmt, [IntPtr]::Zero)
    if ($rc -ne [NativeSqlite]::SQLITE_OK) {
        throw "prepare failed (code $rc): $([NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_errmsg($Database))) -- SQL: $Sql"
    }
    return $stmt
}

function Close-SqliteStatement {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IntPtr]$Statement)
    [NativeSqlite]::sqlite3_finalize($Statement) | Out-Null
}

function Invoke-SqlitePreparedNonQuery {
    # Runs an ALREADY-PREPARED statement (from New-SqliteStatement) with
    # fresh parameters, then resets it so the same handle can run again
    # next row. Every parameter position gets rebound every call, so no
    # explicit clear-bindings step is needed. Returns rows changed, or
    # -1 if -IgnoreConstraintViolation was set and this row hit a UNIQUE/
    # constraint conflict (still resets the statement either way).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][IntPtr]$Statement,
        [object[]]$Params = @(),
        [switch]$IgnoreConstraintViolation
    )
    Bind-SqliteParams -Stmt $Statement -Params $Params
    $rc = [NativeSqlite]::sqlite3_step($Statement)
    if ($rc -eq [NativeSqlite]::SQLITE_CONSTRAINT -and $IgnoreConstraintViolation) {
        [NativeSqlite]::sqlite3_reset($Statement) | Out-Null
        return -1
    }
    if ($rc -ne [NativeSqlite]::SQLITE_DONE -and $rc -ne [NativeSqlite]::SQLITE_ROW) {
        [NativeSqlite]::sqlite3_reset($Statement) | Out-Null
        throw "step failed (code $rc): $([NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_errmsg($Database)))"
    }
    $changes = [NativeSqlite]::sqlite3_changes($Database)
    [NativeSqlite]::sqlite3_reset($Statement) | Out-Null
    return $changes
}

function Invoke-SqliteUpsertPrepared {
    # Same UPDATE-then-INSERT-if-nothing-changed logic as Invoke-SqliteUpsert,
    # but against statements prepared once by the caller and reused across
    # every row -- this is the part that actually removes the per-row
    # prepare/finalize + SQL-to-UTF8 cost. UpdateParams must be in
    # "SET col=?, ... WHERE key=?, ..." order (update values then key
    # values); InsertParams must be in the INSERT's own column order (key
    # values then update values -- see Import-CsvToSqliteTable).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][IntPtr]$UpdateStatement,
        [Parameter(Mandatory)][IntPtr]$InsertStatement,
        [Parameter(Mandatory)][AllowNull()][object[]]$UpdateParams,
        [Parameter(Mandatory)][AllowNull()][object[]]$InsertParams,
        [bool]$HasUpdateColumns = $true
    )
    if ($HasUpdateColumns) {
        $changed = Invoke-SqlitePreparedNonQuery -Database $Database -Statement $UpdateStatement -Params $UpdateParams
        if ($changed -gt 0) { return 'updated' }
    }
    else {
        # no mutable columns -- UpdateStatement is a SELECT EXISTS check instead
        Bind-SqliteParams -Stmt $UpdateStatement -Params $UpdateParams
        $exists = ([NativeSqlite]::sqlite3_step($UpdateStatement)) -eq [NativeSqlite]::SQLITE_ROW
        [NativeSqlite]::sqlite3_reset($UpdateStatement) | Out-Null
        if ($exists) { return 'unchanged' }
    }
    Invoke-SqlitePreparedNonQuery -Database $Database -Statement $InsertStatement -Params $InsertParams | Out-Null
    return 'inserted'
}

function Invoke-SqliteUpsert {
    # Update the row if its natural key already exists; insert it if not.
    # Written as UPDATE-then-INSERT-if-nothing-changed rather than SQLite's
    # newer "INSERT ... ON CONFLICT DO UPDATE" syntax (added in 3.24, 2018)
    # -- winsqlite3.dll's version isn't guaranteed (see notes at the top of
    # this file), so this sticks to UPDATE/INSERT, which every version has.
    #
    # KeyColumns identifies "the same row" across repeated pulls (e.g. a
    # solicitation_number, or niin+year+month for a stock snapshot).
    # UpdateColumns are refreshed every time that key is seen again. Any
    # column NOT listed in either (e.g. a first_seen_at with a
    # DEFAULT CURRENT_TIMESTAMP) is left alone after its first insert.
    #
    # Returns 'inserted', 'updated', or 'unchanged' (key existed, nothing
    # in UpdateColumns to write).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$KeyColumns,
        [System.Collections.Specialized.OrderedDictionary]$UpdateColumns = [ordered]@{}
    )
    $keyNames = @($KeyColumns.Keys)

    if ($UpdateColumns.Count -gt 0) {
        $setClause = (($UpdateColumns.Keys) | ForEach-Object { "$_ = ?" }) -join ', '
        $whereClause = ($keyNames | ForEach-Object { "$_ = ?" }) -join ' AND '
        $updateParams = @($UpdateColumns.Keys | ForEach-Object { $UpdateColumns[$_] }) + @($keyNames | ForEach-Object { $KeyColumns[$_] })
        $changed = Invoke-SqliteNonQuery -Database $Database -Sql "UPDATE $Table SET $setClause WHERE $whereClause;" -Params $updateParams
        if ($changed -gt 0) { return 'updated' }
    }
    else {
        $whereClause = ($keyNames | ForEach-Object { "$_ = ?" }) -join ' AND '
        $existsParams = @($keyNames | ForEach-Object { $KeyColumns[$_] })
        $found = Invoke-SqliteQuery -Database $Database -Sql "SELECT 1 FROM $Table WHERE $whereClause LIMIT 1;" -Params $existsParams
        if ($found.Count -gt 0) { return 'unchanged' }
    }

    $allNames = $keyNames + @($UpdateColumns.Keys)
    $placeholders = ($allNames | ForEach-Object { '?' }) -join ', '
    $insertParams = @($keyNames | ForEach-Object { $KeyColumns[$_] }) + @($UpdateColumns.Keys | ForEach-Object { $UpdateColumns[$_] })
    Invoke-SqliteNonQuery -Database $Database -Sql "INSERT INTO $Table ($($allNames -join ', ')) VALUES ($placeholders);" -Params $insertParams | Out-Null
    return 'inserted'
}

function Import-CsvToSqliteTable {
    # CSV loader built for repeated, overlapping pulls: a row already on
    # file gets its UpdateColumns refreshed in place; a row never seen
    # before gets inserted. Nothing is ever deleted, and nothing outside
    # UpdateColumns is ever touched -- a solicitation that stops showing up
    # in a later export simply stays exactly as it was last seen, instead
    # of being silently dropped from your local history.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string[]]$KeyColumns,
        [string[]]$UpdateColumns = @(),
        [switch]$TouchLoadedAt   # also set source_loaded_at = now() on every insert/update
    )
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        Write-Warning "CSV not found, skipping: $CsvPath"
        return [ordered]@{ Inserted = 0; Updated = 0; Unchanged = 0 }
    }
    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -eq 0) {
        Write-Host "  $(Split-Path -Leaf $CsvPath): no rows, skipping"
        return [ordered]@{ Inserted = 0; Updated = 0; Unchanged = 0 }
    }

    $stats = @{ inserted = 0; updated = 0; unchanged = 0 }
    $keyNames = $KeyColumns
    $hasUpdateCols = $UpdateColumns.Count -gt 0 -or $TouchLoadedAt
    $effectiveUpdateColumns = @($UpdateColumns) + @($(if ($TouchLoadedAt) { 'source_loaded_at' }))

    # A brand-new/empty table can never match an UPDATE, so trying one on
    # every row (as the general upsert logic does) is a wasted round trip
    # for exactly the scenario a first-time bulk load is. Detect that case
    # once per file and skip straight to INSERT-only for the whole load --
    # this alone roughly doubled measured throughput on a 50k-row file.
    $countCheck = Invoke-SqliteQuery -Database $Database -Sql "SELECT COUNT(*) AS c FROM $Table;"
    $insertOnly = ([long]$countCheck[0].c -eq 0)

    if (-not $insertOnly) {
        if ($hasUpdateCols) {
            $setClause = ($effectiveUpdateColumns | ForEach-Object { "$_ = ?" }) -join ', '
            $whereClause = ($keyNames | ForEach-Object { "$_ = ?" }) -join ' AND '
            $updateSql = "UPDATE $Table SET $setClause WHERE $whereClause;"
        }
        else {
            $whereClause = ($keyNames | ForEach-Object { "$_ = ?" }) -join ' AND '
            $updateSql = "SELECT 1 FROM $Table WHERE $whereClause LIMIT 1;"
        }
    }
    $allNames = $keyNames + $effectiveUpdateColumns
    $insertSql = "INSERT INTO $Table ($($allNames -join ', ')) VALUES ($(($allNames | ForEach-Object { '?' }) -join ', '));"

    Invoke-SqliteExec -Database $Database -Sql 'BEGIN;'
    $updateStmt = [IntPtr]::Zero
    $insertStmt = [IntPtr]::Zero
    $updateSqlForFallback = $null
    try {
        if (-not $insertOnly) { $updateStmt = New-SqliteStatement -Database $Database -Sql $updateSql }
        else {
            # Needed only if a same-file duplicate key shows up mid-load;
            # built now (once) so it's ready without extra per-row cost.
            if ($hasUpdateCols) {
                $setClause = ($effectiveUpdateColumns | ForEach-Object { "$_ = ?" }) -join ', '
                $whereClause = ($keyNames | ForEach-Object { "$_ = ?" }) -join ' AND '
                $updateSqlForFallback = "UPDATE $Table SET $setClause WHERE $whereClause;"
            }
        }
        $insertStmt = New-SqliteStatement -Database $Database -Sql $insertSql

        foreach ($r in $rows) {
            $keyVals = @(foreach ($col in $KeyColumns) {
                $v = $r.$col
                if ([string]::IsNullOrWhiteSpace($v)) { $null } else { $v }
            })
            $updateVals = @(foreach ($col in $UpdateColumns) {
                $v = $r.$col
                if ([string]::IsNullOrWhiteSpace($v)) { $null } else { $v }
            })
            if ($TouchLoadedAt) { $updateVals += (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
            $insertParams = $keyVals + $updateVals

            if ($insertOnly) {
                $changed = Invoke-SqlitePreparedNonQuery -Database $Database -Statement $insertStmt -Params $insertParams -IgnoreConstraintViolation
                if ($changed -ge 0) {
                    $stats.inserted++
                }
                else {
                    # a duplicate key WITHIN this file, not a pre-existing row
                    # -- fall back to updating it, lazily preparing the
                    # update statement the first time this actually happens
                    if ($updateStmt -eq [IntPtr]::Zero -and $updateSqlForFallback) {
                        $updateStmt = New-SqliteStatement -Database $Database -Sql $updateSqlForFallback
                    }
                    if ($updateStmt -ne [IntPtr]::Zero) {
                        $updateParams = $updateVals + $keyVals
                        Invoke-SqlitePreparedNonQuery -Database $Database -Statement $updateStmt -Params $updateParams | Out-Null
                        $stats.updated++
                    }
                    else {
                        $stats.unchanged++   # no update columns to apply -- key exists, nothing to change
                    }
                }
            }
            else {
                $updateParams = if ($hasUpdateCols) { $updateVals + $keyVals } else { $keyVals }
                $result = Invoke-SqliteUpsertPrepared -Database $Database -UpdateStatement $updateStmt -InsertStatement $insertStmt `
                    -UpdateParams $updateParams -InsertParams $insertParams -HasUpdateColumns $hasUpdateCols
                $stats[$result]++
            }
        }
        Invoke-SqliteExec -Database $Database -Sql 'COMMIT;'
    }
    catch {
        Invoke-SqliteExec -Database $Database -Sql 'ROLLBACK;'
        throw
    }
    finally {
        if ($updateStmt -ne [IntPtr]::Zero) { Close-SqliteStatement -Statement $updateStmt }
        if ($insertStmt -ne [IntPtr]::Zero) { Close-SqliteStatement -Statement $insertStmt }
    }
    Write-Host "  $Table <- $(Split-Path -Leaf $CsvPath): $($stats.inserted) new, $($stats.updated) updated, $($stats.unchanged) unchanged"
    return [ordered]@{ Inserted = $stats.inserted; Updated = $stats.updated; Unchanged = $stats.unchanged }
}

function Import-QualifiedProductSourceCsv {
    # qualified_product_source.qpl_id is a surrogate key -- re-inserting
    # qualified_product_list rows must never change an existing qpl_id
    # (Invoke-SqliteUpsert already guarantees that), and this CSV should
    # never need to know a surrogate id at all. It carries the natural key
    # (qpl_number, gov_spec_number) instead and this function resolves the
    # current qpl_id via lookup at load time.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Database,
        [Parameter(Mandatory)][string]$CsvPath
    )
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        Write-Warning "CSV not found, skipping: $CsvPath"
        return
    }
    $rows = @(Import-Csv -LiteralPath $CsvPath)
    $stats = @{ inserted = 0; updated = 0; unchanged = 0; skipped = 0 }
    Invoke-SqliteExec -Database $Database -Sql 'BEGIN;'
    try {
        foreach ($r in $rows) {
            $qpl = Invoke-SqliteQuery -Database $Database `
                -Sql 'SELECT qpl_id FROM qualified_product_list WHERE qpl_number = ? AND gov_spec_number = ?;' `
                -Params @($r.qpl_number, $r.gov_spec_number)
            if ($qpl.Count -eq 0) {
                Write-Warning "  No qualified_product_list row for qpl_number='$($r.qpl_number)' gov_spec_number='$($r.gov_spec_number)' -- load qualified_product_list.csv first. Skipping row for niin=$($r.niin)."
                $stats.skipped++
                continue
            }
            $keyVals = [ordered]@{ niin = $r.niin; qpl_id = $qpl[0].qpl_id; cage_code = $r.cage_code }
            $updateVals = [ordered]@{
                fsc_code               = $r.fsc_code
                govt_designation       = $r.govt_designation
                mfr_designation        = $r.mfr_designation
                mfr_name               = $r.mfr_name
                test_qualification_ref = $r.test_qualification_ref
                source_loaded_at       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            }
            $result = Invoke-SqliteUpsert -Database $Database -Table 'qualified_product_source' -KeyColumns $keyVals -UpdateColumns $updateVals
            $stats[$result]++
        }
        Invoke-SqliteExec -Database $Database -Sql 'COMMIT;'
    }
    catch {
        Invoke-SqliteExec -Database $Database -Sql 'ROLLBACK;'
        throw
    }
    Write-Host "  qualified_product_source <- $(Split-Path -Leaf $CsvPath): $($stats.inserted) new, $($stats.updated) updated, $($stats.unchanged) unchanged, $($stats.skipped) skipped"
}

function Test-SqliteSetup {
    # Run this first, on your own machine, before loading real data. It
    # confirms winsqlite3.dll is reachable and that a full round trip
    # (create table, parameterized insert, select) actually works.
    [CmdletBinding()]
    param()
    Write-Host "winsqlite3.dll self-test" -ForegroundColor Cyan
    try {
        $ver = [NativeSqlite]::Utf8PtrToString([NativeSqlite]::sqlite3_libversion())
        Write-Host "  Detected SQLite engine version: $ver"
        $database = Open-SqliteDb -Path ':memory:'
        Invoke-SqliteExec -Database $database -Sql 'CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, amount REAL);'
        Invoke-SqliteNonQuery -Database $database -Sql 'INSERT INTO t (name, amount) VALUES (?, ?);' -Params @('widget', 12.5) | Out-Null
        $rows = Invoke-SqliteQuery -Database $database -Sql 'SELECT * FROM t;'
        Close-SqliteDb -Database $database
        if ($rows.Count -eq 1 -and $rows[0].name -eq 'widget' -and [double]$rows[0].amount -eq 12.5) {
            Write-Host "  PASS -- wrote and read back a row correctly." -ForegroundColor Green
            return $true
        }
        Write-Warning "  Round trip returned unexpected data: $($rows | Out-String)"
        return $false
    }
    catch {
        Write-Error "  FAIL: $($_.Exception.Message)"
        Write-Host "  If this mentions the DLL or an entry point, confirm the file exists:"
        Write-Host "    Test-Path C:\Windows\System32\winsqlite3.dll"
        return $false
    }
}
