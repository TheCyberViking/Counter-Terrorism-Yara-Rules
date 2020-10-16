hategroups.yara

Rule username_capture
{
	Meta:
hategroups.yara

Rule username_capture
{
	Meta:
	Meta:
		Author = “@TheCyberViking”
		Date = “11/01/2020”
`		description = “yara rule for part of surveillance project”
		Reference = “https://twitter.com/TheCyberViking”
		
	Strings:
		$a = “ACT for America” nocase
		$b = “ACT” nocase
		$c = “Alliance Defending Freedom” nocase
		$d = “America's Promise Ministries” nocase
		$e = “Americas Promise Ministries” nocase
		$f = “American Patrol” nocase
		$g = “American College of Pediatricians” nocase
		$h = “American Family Association” nocase
		$i = “National Liberation Army” nocase
		$j = “American Freedom Party” nocase
		$k = “American Renaissance” nocase
		$l = “Aryan Brotherhood” nocase
		$m = “Aryan Nations” nocase
		$n = “Atomwaffen Division” nocase
    $o = “Blood & Honour” nocase
    $p = “Brotherhood of Klans” nocase
    $q = “Center for Immigration Studies” nocase
    $r = “Fraternal Order of Alt-Knights” nocase
    $s = “Storm Front” nocase
    $t = “Creativity Movement” nocase
    $u = “Dustin Inman Society” nocase
    $v = “FOAK” nocase
    $w = “Imperial Klans of America” nocase
    $y = “Jewish Defense League” nocase
    $z = “KKK” nocase
    $a1 = “Sovereign Citizens” nocase
    $a2 = “Nation of Islam” nocase
    $a3 = “National Alliance” nocase
    $a4 = “National Liberty Alliance” nocase
    $a5 = “National Socialist Movement” nocase
    $a6 = “National Vanguard” nocase
    $a7 = “Blank Panther” nocase
    $a8 = “Oath Keepers” nocase
    $a9 = “Proud Boys” nocase
    $b1 = “United Constitutional Patriots” nocase
    $b2 = “VDARE” nocase
    $b3 = “Vinlanders Social Club” nocase
    $b4 = “Westboro Baptist Church” nocase
    $b5 = “White Lives Matter” nocase
    $b6 = “White Revolution” nocase
    
    
        

	Conditions:
		any of them
}
