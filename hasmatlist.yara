Rule hasmatlist
{
	Meta:
		Author = “@TheCyberViking”
		Date = “11/01/2020”
`		description = “yara rule for part of surveillance project”
		Reference = “https://twitter.com/TheCyberViking”
		
	Strings:
		$a = “Hazmat” nocase
		$b = “Nuclear” nocase
		$c = “Chemical Spill” nocase
		$d = “Suspicious package” nocase
		$e = “Toxic” nocase
		$f = “Nuclear facility” nocase
		$g = “Nuclear threat” nocase
		$h = “Cloud” nocase
		$i = “Plume” nocase
		$j = “Radiation” nocase
		$k = “Radioactive” nocase
		$l = “Biological infection” nocase
		$m = “Chemical” nocase
		$n = “Biological” nocase
    $o = “Epidemic” nocase
    $p = “Hazardous” nocase
    $q = “Infection” nocase
    $r = “Gas” nocase
    $s = “Spillover” nocase
    $t = “Anthrax” nocase
    $u = “Exposure” nocase
    $v = “Nerve agent” nocase
    $w = “Ricin” nocase
    $x = “Sarin” nocase
    $y = “NK” nocase
    $z = “North Korea” nocase
    
	Conditions:
		any of them
}
