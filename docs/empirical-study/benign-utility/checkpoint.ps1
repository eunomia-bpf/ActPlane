# Windows performs only file publication and Git; all analysis runs in the Workspace.
param([switch]$Watch, [switch]$Force)
$ErrorActionPreference='Stop'
$lane=$PSScriptRoot
$repo=(Resolve-Path (Join-Path $lane '../../..')).Path
$gitbash='C:\Program Files\Git\bin\bash.exe'
$wrapper='C:/Users/10678/actplane-tools/ws.sh'
$publish=@('docs/empirical-study/benign-utility/README.md','docs/empirical-study/benign-utility/SUMMARY.md','docs/empirical-study/benign-utility/results','docs/empirical-study/benign-utility/benchmark/expanded/results')
Set-Location $repo
if((& git branch --show-current) -ne 'experiments/mlsys27'){throw 'Unexpected publication branch'}
$publishedFingerprint=''
do {
  try {
    $command=if($Force){'exec bash checkpoint.sh --force #'}else{'exec bash checkpoint.sh #'}
    $output=$command | & $gitbash $wrapper sh benign-utility
    if($LASTEXITCODE -ne 0){throw ($output -join "`n")}
    $match=[regex]::Match(($output -join "`n"),'CHECKPOINT_FINGERPRINT ([a-f0-9]{64})')
    if(-not $match.Success){throw 'Remote checkpoint did not identify a complete snapshot'}
    $fingerprint=$match.Groups[1].Value
    if($fingerprint -ne $publishedFingerprint) {
      & $gitbash $wrapper pull benign-utility "checkpoint/$fingerprint/results" "checkpoint/$fingerprint/benchmark/expanded/results"
      if($LASTEXITCODE -ne 0){throw 'Result pull failed'}
      $source=Join-Path (Join-Path $lane 'checkpoint') $fingerprint
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
        $paragraph=Join-Path $lane 'results/paper-paragraph.md'
        if($name -eq 'README.md' -and (Test-Path -LiteralPath $paragraph)) {
          $body=[regex]::Replace($body,'(?s)<!-- paper-paragraph:start -->.*?<!-- paper-paragraph:end -->','<!-- paper-paragraph:start -->'+"`n"+[IO.File]::ReadAllText($paragraph)+"`n"+'<!-- paper-paragraph:end -->')
        }
        [IO.File]::WriteAllText($path,$body,[Text.UTF8Encoding]::new($false))
      }
      # The only recursively removed tree is this lane's just-pulled publication copy.
      $resolved=(Resolve-Path -LiteralPath $source).Path
      if($resolved -ne $source){throw 'Unexpected checkpoint path'}
      Remove-Item -LiteralPath $resolved -Recurse -Force
      & git add -- $publish
      if($LASTEXITCODE -ne 0){Start-Sleep -Seconds 3; & git add -- $publish}
      & git diff --cached --quiet -- $publish
      if($LASTEXITCODE -eq 1) {
        & git commit -m 'Checkpoint official expansion outcomes and honest partial report' -- $publish
        if($LASTEXITCODE -ne 0){throw 'Checkpoint commit failed'}
      }
      $publishedFingerprint=$fingerprint
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
