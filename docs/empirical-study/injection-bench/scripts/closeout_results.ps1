param([string]$Results = (Join-Path $PSScriptRoot '../results'))
$ErrorActionPreference = 'Stop'
# Aggregate retained metric tables only; no inference, payloads, traces or remote calls.
$primary = @(Import-Csv (Join-Path $Results 'summary.csv'))
$audit = @(Import-Csv (Join-Path $Results 'audit/summary.csv'))
$plans = @(Import-Csv (Join-Path $Results 'planned.csv')) + @(Import-Csv (Join-Path $Results 'frontier-planned.csv'))
$output = foreach ($group in ($plans | Group-Object model,system)) {
    $model = $group.Group[0].model
    $system = $group.Group[0].system
    $saved = @($primary | Where-Object { $_.model -eq $model -and $_.system -eq $system })
    $later = @($audit | Where-Object { $_.model -eq $model -and $_.system -eq $system })
    $complete = $saved.Count -eq 1 -and $saved[0].status -eq 'complete'
    $terminal = if ($complete) { [int]$saved[0].finished } elseif ($later.Count -eq 1) { [int]$later[0].cases_terminal } else { 0 }
    [pscustomobject]@{
        model = $model; system = $system; planned = $group.Count
        terminal = $terminal; pending = $group.Count - $terminal
        status = $(if ($complete) { 'complete' } else { 'incomplete_service_filter_closeout' })
        attack_successes = $(if ($complete) { $saved[0].attack_successes } else { '' })
        attack_n = $(if ($complete) { $saved[0].attack_n } else { '' })
        asr = $(if ($complete) { $saved[0].asr_lower } else { '' })
        clean_successes = $(if ($complete) { $saved[0].clean_successes } else { '' })
        clean_n = $(if ($complete) { $saved[0].clean_n } else { '' })
        clean_utility = $(if ($complete) { $saved[0].clean_utility } else { '' })
        attacked_successes = $(if ($complete) { $saved[0].attacked_successes } else { '' })
        attacked_utility = $(if ($complete) { $saved[0].attacked_utility } else { '' })
        failures = $(if ($complete) { $saved[0].failed } else { '' })
        source = $(if ($complete) { 'summary.csv' } else { 'audit/summary.csv' })
    }
}
$output | Sort-Object model,system | Export-Csv (Join-Path $Results 'closeout.csv') -NoTypeInformation -Encoding UTF8
