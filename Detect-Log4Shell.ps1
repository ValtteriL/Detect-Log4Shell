<#

    .SYNOPSIS
    This is a powershell implementation of https://github.com/Neo23x0/log4shell-detector
    Now using more advanced regex from https://github.com/back2root/log4shell-rex

    .DESCRIPTION
    Recursively checks all files in given paths and checks if ${jndi:ldap: is found in a line
    To detect even obfuscated attacks, we are using special regex from https://github.com/back2root/log4shell-rex

    By default will look for files under 25MB that have been modified since the exploit was disclosed (9/12/2021)
    
    .PARAMETER Paths
    Paths to start recursively scanning for files
    WARNING: By default the path is C:\ - This will take a very long time

    .PARAMETER AllSizes
    Check all files regardless of size
    By default will only check files under 25MB

    .EXAMPLE
    PS> .\Detect-Log4Shell -Paths ..\teeest\
    [.] Searching for exploitation attempts recursively from ..\teeest\
    [.] Checking items in ..\teeest\
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\obfu.txt:1: ${${eh:wDUdos:jKY:-j}${xksV:Xgi:-n}${hNdb:SbmXU:goWgvJ:iqAV:Ux:-d}${MXWN:oOi:c:UxXzcI:-i}${DYKgs:tHlY:-:}${d:FHdMm:fw:-l}${Gw:-d}${LebGxe:c:SxLXa:-a}${echyWc:BE:NBO:s:gVbT:-p}${l:QwCL:gzOQm:gqsDS:-:}${qMztLn:e:E:WS:-/}${NUu:S:afVNbT:kyjbiE:-/}${PtGUfI:WcYh:c:-1}${YoSJ:KUV:uySK:crNTm:-2}${EwkY:EsX:S:wk:-7}${HUWOJ:MMIxOn:S:-.}${MHF:s:-0}${obrJVU:RPw:d:A:-.}${E:RgY:j:-0}${MaOtbM:-.}${O:-1}${zzfuGD:YEyvy:mhp:T:-:}${vlaw:WuOBz:-1}${HAjxt:ziBgmc:-0}${UKVBrk:sNAKe:F:qXNetQ:mdIuOW:-9}${geJs:sgYgQW:oOd:qOGf:aYpAkP:-9}${UonINv:-/}${aTygHK:pbQiTB:KkXhKS:-o}${FMRAKM:-b}${wiu:vKIVuh:-j}}
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\obfu2.txt:1: ${jndi:ld${ozI:Kgh:Qn:TXM:-a}p:${DBEau:Y:pLXUu:SfRKk:vWu:-/}${x:UMADq:-/}127${lt:tWd:iEVW:pD:tGCr:-.}${jFpSDW:z:SN:AuqM:C:-0}${dxxilc:HTFa:QLgii:pv:-.}0.${a:l:urnrtk:-1}:1099${zlSEqQ:T:qg:o:-/}ob${E:yJDsbq:-j}}
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\obfu3.txt:1: ${${upper:j}${lower:n}${lower:d}${lower:i}${lower::}${lower:l}${lower:d}${lower:a}${lower:p}${lower::}${lower:/}${lower:/}${lower:1}${lower:2}${lower:7}${lower:.}${lower:0}${lower:.}${lower:0}${lower:.}${lower:1}${lower::}${lower:1}${lower:0}${lower:9}${lower:9}${lower:/}${lower:o}${lower:b}${lower:j}}
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\obfu4.txt:1: ${${upper:j}n${lower:d}${lower:i}:l${lower:d}${lower:a}${lower:p}${lower::}${lower:/}${lower:/}1${lower:2}${lower:7}.0${lower:.}0${lower:.}${lower:1}${lower::}10${lower:9}9${lower:/}o${lower:b}j}
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\obfu5.txt:1: ${jndi:ldap://127.0.0.1:1099/obj}
    [!!] Log4J exploitation attempt found in C:\Users\valtteri\teeest\test.txt:3: ${jndi:LDap:dasdasdasdas${jndi:ldap:4214123

    .EXAMPLE
    PS> Detect-Log4Shell -Paths .\test\ -AllSizes
    [.] Searching for exploitation attempts recursively from .\test\
    [.] Checking items in .\test\

#>


param(
    [String[]] $Paths = 'C:\',
    [switch] $AllSizes = $false
)

Write-Output "[.] Searching for exploitation attempts recursively from $Paths"

# string we are looking for: '${jndi:ldap:' with any characters in-between and without case sensitivity
#$matchRegex = '.*\$.*\{.*j.*n.*d.*i.*\:.*l.*d.*a.*p.*\:.*'
$matchRegex = '(?:\$|%(?:25)*24|\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))'

# file extensions to exclude from scan
$excludeList = @("*.dll","*.js", "*.exe", "*.dll", "*.iso", "*.pdf", "*.msi", "*.pak", "*.manifest", "*.png", "*.jpg")

# Check all files in paths for the regex
foreach ($path in $Paths) {
    Write-Output "[.] Checking items in $path"
    
    Write-Output "[.] Collecting list of files to scan... This might take a while..."

    if ($AllSizes) {
        $files = (Get-ChildItem $path -File -Recurse -ErrorAction SilentlyContinue -Exclude $excludeList | Where-Object {$_.lastwritetime -gt [datetime]::parse("09/12/2021")})
    } else {
        $files = (Get-ChildItem $path -File -Recurse -ErrorAction SilentlyContinue -Exclude $excludeList | Where-Object {$_.length -lt 25mb} | Where-Object {$_.lastwritetime -gt [datetime]::parse("09/12/2021")})
    }

    Write-Output "[.] Found $($files.Length) files to scan"

    $files | ForEach-Object {
        $filename = $_.FullName
        Write-Progress -Activity "[.] Checking $($filename)"
        Get-Content -LiteralPath $_.FullName | Select-String -Pattern $matchRegex -AllMatches | ForEach-Object {
            Write-Output "[!!] Log4J exploitation attempt found in $($filename):$($_.LineNumber): $($_)"
        }
    }
}
