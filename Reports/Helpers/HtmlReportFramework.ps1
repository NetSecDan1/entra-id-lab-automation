<#
.SYNOPSIS
    Self-contained HTML report renderer for KQL / Graph query results.

.DESCRIPTION
    New-HtmlReport is a single function with zero dependencies on the rest of
    this repo (no Common.ps1, no other helper). That's deliberate: dot-source
    this file when working inside Reports/KQL, but if you're writing a
    one-off script somewhere else entirely, just copy the function body from
    here and paste it at the bottom of that script — it'll work standalone.

    It takes whatever rows your query returned (each query's shape is
    different — that's fine, columns are auto-detected from the first row)
    plus optional KPI "stat tiles", and writes one polished, dark-mode-aware,
    sortable/searchable HTML file. No external CSS/JS — everything is inlined
    so the output is a single file you can email, or open straight from disk.

.EXAMPLE
    $rows = Invoke-LabKqlQuery -WorkspaceId $wsId -Query $kql
    New-HtmlReport -Title "Risky Sign-Ins" -Subtitle "Last 7 days — contoso.onmicrosoft.com" `
        -Rows $rows -OutputPath ".\Reports\Output\RiskySignIns.html" -Open
#>

function New-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Subtitle = "",
        [Parameter(Mandatory)][string]$OutputPath,

        # Row data for the main table(s). Either a single collection, or a hashtable
        # of @{ "Section title" = $rows; "Another section" = $otherRows }.
        [Parameter(Mandatory)]$Rows,

        # Optional KPI tiles: @(@{ Label="Risky sign-ins"; Value=42; Tone="danger" }, ...)
        # Tone: "good" | "warn" | "danger" | "neutral" (default)
        [array]$StatTiles = @(),

        [string]$FooterNote = "",
        [switch]$Open
    )

    # ---- normalize input into named sections -------------------------------
    $sections = [ordered]@{}
    if ($Rows -is [System.Collections.IDictionary]) {
        foreach ($key in $Rows.Keys) { $sections[$key] = @($Rows[$key]) }
    } else {
        $sections["Results"] = @($Rows)
    }

    # ---- column heuristics ---------------------------------------------------
    $badgeColumnNames = @("risklevel", "severity", "status", "result", "state", "outcome", "conditionalaccessstatus")
    $numericTypeNames = @("Int32", "Int64", "Double", "Decimal", "Single", "UInt32", "UInt64")

    function Get-CellTone($value) {
        $v = [string]$value
        switch -Regex ($v) {
            '^(high|critical|failure|failed|block(ed)?|denied|true)$'                  { return "danger" }
            '^(medium|warning|warn|notapplied|skipped)$'                                { return "warn" }
            '^(low|none|success|succeeded|ok|allowed|granted|false|healthy|created)$'   { return "good" }
            default                                                                     { return "" }
        }
    }

    $sectionsHtml = New-Object System.Text.StringBuilder
    $sectionIndex = 0
    foreach ($sectionTitle in $sections.Keys) {
        $sectionIndex++
        $data = @($sections[$sectionTitle])
        $tableId = "tbl$sectionIndex"

        if ($data.Count -eq 0) {
            [void]$sectionsHtml.Append("<section class='card'><h2>$([System.Net.WebUtility]::HtmlEncode($sectionTitle))</h2><p class='empty'>No rows returned.</p></section>")
            continue
        }

        $columns = @($data[0].PSObject.Properties.Name)
        $columnIsNumeric = @{}
        foreach ($col in $columns) {
            $sample = $data | Where-Object { $null -ne $_.$col } | Select-Object -First 1 -ExpandProperty $col -ErrorAction SilentlyContinue
            $columnIsNumeric[$col] = ($null -ne $sample -and $numericTypeNames -contains $sample.GetType().Name)
        }

        $jsonRows = $data | Select-Object $columns | ConvertTo-Json -Depth 6 -Compress
        if ($data.Count -eq 1) { $jsonRows = "[$jsonRows]" }  # ConvertTo-Json unwraps single-element arrays
        $jsonRows = $jsonRows -replace '</', '<\/'  # log data (user agents, app names, ...) could contain </script>; keep it inert inside the inline <script> block

        $badgeCols = @($columns | Where-Object { $badgeColumnNames -contains $_.ToLowerInvariant() })
        $badgeColsJson = ($badgeCols | ConvertTo-Json -Compress)
        if ($badgeCols.Count -eq 0) { $badgeColsJson = "[]" }
        if ($badgeCols.Count -eq 1) { $badgeColsJson = "[$badgeColsJson]" }

        $numericColsJson = ((@($columns | Where-Object { $columnIsNumeric[$_] })) | ConvertTo-Json -Compress)
        if ($numericColsJson -eq $null -or $numericColsJson -eq "") { $numericColsJson = "[]" }
        if (($columns | Where-Object { $columnIsNumeric[$_] }).Count -eq 1) { $numericColsJson = "[$numericColsJson]" }

        $columnsJson = ($columns | ConvertTo-Json -Compress)
        if ($columns.Count -eq 1) { $columnsJson = "[$columnsJson]" }

        [void]$sectionsHtml.Append(@"
<section class="card">
  <div class="card-head">
    <h2>$([System.Net.WebUtility]::HtmlEncode($sectionTitle))</h2>
    <div class="card-tools">
      <span class="row-count" id="$tableId-count"></span>
      <input type="search" class="search" id="$tableId-search" placeholder="Filter rows..." />
    </div>
  </div>
  <div class="table-wrap">
    <table id="$tableId"></table>
  </div>
</section>
<script>
  renderTable("$tableId", $columnsJson, $jsonRows, $badgeColsJson, $numericColsJson);
</script>
"@)
    }

    $tilesHtml = ""
    if (@($StatTiles).Count -gt 0) {
        $tileBlocks = foreach ($tile in $StatTiles) {
            $tone = if ($tile.Tone) { [string]$tile.Tone } else { "neutral" }
            "<div class='tile tile-$tone'><div class='tile-value'>$([System.Net.WebUtility]::HtmlEncode([string]$tile.Value))</div><div class='tile-label'>$([System.Net.WebUtility]::HtmlEncode([string]$tile.Label))</div></div>"
        }
        $tilesHtml = "<div class='tiles'>$($tileBlocks -join '')</div>"
    }

    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$([System.Net.WebUtility]::HtmlEncode($Title))</title>
<style>
  :root {
    --bg: #f5f6f8; --card: #ffffff; --text: #1a1d24; --muted: #6b7280;
    --border: #e5e7eb; --accent: #4f46e5; --good: #059669; --warn: #d97706; --danger: #dc2626;
    --good-bg: #ecfdf5; --warn-bg: #fffbeb; --danger-bg: #fef2f2; --neutral-bg: #eef2ff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1115; --card: #171a21; --text: #e5e7eb; --muted: #9ca3af;
      --border: #2a2e37; --accent: #818cf8; --good: #34d399; --warn: #fbbf24; --danger: #f87171;
      --good-bg: #052e21; --warn-bg: #3a2a05; --danger-bg: #3a0d0d; --neutral-bg: #1e2140;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; background: var(--bg); color: var(--text); font: 14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
  header { margin-bottom: 20px; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  .subtitle { color: var(--muted); font-size: 13px; }
  .generated { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .tiles { display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }
  .tile { flex: 1 1 160px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .tile-value { font-size: 26px; font-weight: 700; }
  .tile-label { color: var(--muted); font-size: 12px; margin-top: 2px; }
  .tile-good .tile-value { color: var(--good); }
  .tile-warn .tile-value { color: var(--warn); }
  .tile-danger .tile-value { color: var(--danger); }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 18px; }
  .card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
  .card-head h2 { margin: 0; font-size: 15px; }
  .card-tools { display: flex; align-items: center; gap: 10px; }
  .row-count { color: var(--muted); font-size: 12px; white-space: nowrap; }
  .search { border: 1px solid var(--border); background: var(--bg); color: var(--text); border-radius: 6px; padding: 6px 10px; font-size: 13px; min-width: 160px; }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th { color: var(--muted); font-weight: 600; cursor: pointer; user-select: none; position: sticky; top: 0; background: var(--card); }
  th:hover { color: var(--text); }
  th .arrow { opacity: 0.4; margin-left: 4px; }
  tr:hover td { background: rgba(127,127,127,0.06); }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge-good { background: var(--good-bg); color: var(--good); }
  .badge-warn { background: var(--warn-bg); color: var(--warn); }
  .badge-danger { background: var(--danger-bg); color: var(--danger); }
  .badge-neutral { background: var(--neutral-bg); color: var(--accent); }
  .empty { color: var(--muted); font-style: italic; }
  footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<header>
  <h1>$([System.Net.WebUtility]::HtmlEncode($Title))</h1>
  <div class="subtitle">$([System.Net.WebUtility]::HtmlEncode($Subtitle))</div>
  <div class="generated">Generated $generatedAt</div>
</header>
$tilesHtml
$($sectionsHtml.ToString())
<footer>$([System.Net.WebUtility]::HtmlEncode($FooterNote))</footer>
<script>
function toneClass(v) {
  const s = String(v).toLowerCase();
  if (/^(high|critical|failure|failed|block(ed)?|denied|true)$/.test(s)) return "badge-danger";
  if (/^(medium|warning|warn|notapplied|skipped)$/.test(s)) return "badge-warn";
  if (/^(low|none|success|succeeded|ok|allowed|granted|false|healthy|created)$/.test(s)) return "badge-good";
  return "badge-neutral";
}

function renderTable(id, columns, rows, badgeCols, numericCols) {
  const container = document.getElementById(id);
  const searchBox = document.getElementById(id + "-search");
  const countEl = document.getElementById(id + "-count");
  let sortCol = null, sortDir = 1;

  function cellHtml(col, val) {
    if (val === null || val === undefined) return "";
    if (badgeCols.includes(col)) {
      return '<span class="badge ' + toneClass(val) + '">' + escapeHtml(String(val)) + '</span>';
    }
    return escapeHtml(String(val));
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  function draw() {
    const q = (searchBox.value || "").toLowerCase();
    let data = rows.filter(r => !q || columns.some(c => String(r[c] ?? "").toLowerCase().includes(q)));

    if (sortCol) {
      data = data.slice().sort((a, b) => {
        let av = a[sortCol], bv = b[sortCol];
        if (numericCols.includes(sortCol)) { av = Number(av) || 0; bv = Number(bv) || 0; return (av - bv) * sortDir; }
        av = String(av ?? ""); bv = String(bv ?? "");
        return av.localeCompare(bv) * sortDir;
      });
    }

    let html = "<thead><tr>" + columns.map(c => {
      const arrow = sortCol === c ? (sortDir === 1 ? "&#9650;" : "&#9660;") : "";
      return '<th data-col="' + c + '">' + escapeHtml(c) + ' <span class="arrow">' + arrow + '</span></th>';
    }).join("") + "</tr></thead>";

    html += "<tbody>" + data.map(r =>
      "<tr>" + columns.map(c => {
        const cls = numericCols.includes(c) ? ' class="num"' : "";
        return "<td" + cls + ">" + cellHtml(c, r[c]) + "</td>";
      }).join("") + "</tr>"
    ).join("") + "</tbody>";

    container.innerHTML = html;
    countEl.textContent = "Showing " + data.length + " of " + rows.length + " rows";

    container.querySelectorAll("th").forEach(th => {
      th.addEventListener("click", () => {
        const col = th.getAttribute("data-col");
        if (sortCol === col) { sortDir *= -1; } else { sortCol = col; sortDir = 1; }
        draw();
      });
    });
  }

  searchBox.addEventListener("input", draw);
  draw();
}
</script>
</body>
</html>
"@

    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8

    Write-Host "[+] Report written: $OutputPath" -ForegroundColor Green
    if ($Open) { Start-Process $OutputPath }
    return $OutputPath
}
