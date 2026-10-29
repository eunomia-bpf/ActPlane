# Windows performs only file publication and Git; all analysis runs in the Workspace.
param([switch]$Watch, [switch]$Force)
$ErrorActionPreference='Stop'
$lane=$PSScriptRoot
$repo=(Resolve-Path (Join-Path $lane '../../..')).Path
$gitbash='C:\Program Files\Git\bin\bash.exe'
$wrapper='C:/Users/10678/actplane-tools/ws.sh'
Set-Location $repo
if((& git branch --show-current) -ne 'experiments/mlsys27'){throw 'Unexpected publication branch'}
do {
  try {
    $command=if($Force){'exec bash checkpoint.sh --force #'}else{'exec bash checkpoint.sh #'}
    $output=$command | & $gitbash $wrapper sh benign-utility
    if($LASTEXITCODE -ne 0){throw ($output -join "`n")}
    if(($output -join "`n") -match 'CHECKPOINT_UPDATED') {
      & $gitbash $wrapper pull benign-utility checkpoint/results checkpoint/benchmark/expanded/results
      if($LASTEXITCODE -ne 0){throw 'Result pull failed'}
      $source=Join-Path $lane 'checkpoint'
      foreach($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
        $relative=$file.FullName.Substring($source.Length+1)
        $target=Join-Path $lane $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        [IO.File]::WriteAllBytes($target,[IO.File]::ReadAllBytes($file.FullName))
      }
      $progress=[IO.File]::ReadAllText((Join-Path $lane 'results/expansion-progress.md'))
      foreach($name in @('README.md','SUMMARY.md')) {
        $path=Join-Path $lane $name
        $body=[IO.File]::ReadAllText($path)
        $table=if($name -eq 'SUMMARY.md'){$progress.Substring(0,$progress.IndexOf('Available-condition'))}else{$progress}
        $body=[regex]::Replace($body,'(?s)<!-- expansion-status:start -->.*?<!-- expansion-status:end -->','<!-- expansion-status:start -->'+"`n"+$table+"`n"+'<!-- expansion-status:end -->')
        [IO.File]::WriteAllText($path,$body,[Text.UTF8Encoding]::new($false))
      }
      # The only recursively removed tree is this lane's just-pulled publication copy.
      $resolved=(Resolve-Path -LiteralPath $source).Path
      if($resolved -ne (Join-Path $lane 'checkpoint')){throw 'Unexpected checkpoint path'}
      Remove-Item -LiteralPath $resolved -Recurse -Force
      & git add -- docs/empirical-study/benign-utility
      if($LASTEXITCODE -ne 0){Start-Sleep -Seconds 3; & git add -- docs/empirical-study/benign-utility}
      & git diff --cached --quiet -- docs/empirical-study/benign-utility
      if($LASTEXITCODE -eq 1) {
        & git commit -m 'Checkpoint official expansion outcomes and honest partial report' -- docs/empirical-study/benign-utility
        if($LASTEXITCODE -ne 0){throw 'Checkpoint commit failed'}
      }
      Write-Output ('Published snapshot '+[DateTime]::UtcNow.ToString('o'))
    }
    & git push origin HEAD:refs/heads/experiments/mlsys27
    if($LASTEXITCODE -ne 0){throw 'Branch push failed; next iteration will retry'}
    $Force=$false
  } catch {
    $Force=$true
    Write-Output ('Checkpoint retry: '+$_)
    if(-not $Watch){throw}
  }
  if($Watch){Start-Sleep -Seconds 60}
} while($Watch)
