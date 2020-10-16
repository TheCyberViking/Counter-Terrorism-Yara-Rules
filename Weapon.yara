Weapon.yara

Rule weapon
{
	Meta:
		Author = “TheCyberViking”
		Date = “11/01/2020”
`		description = “yara rule for part of surveillance project”
		Reference = “https://twitter.com/TheCyberViking”
		
	Strings:
		$a = “knife” nocase
		$b = “knives” nocase
		$c = “weapon” nocase
		$d = “weapons” nocase
		$e = “gun” nocase
		$f = “guns” nocase
		$g = “firearm” nocase
		$h = “firearms” nocase
		$i = “handgun” nocase
		$j = “handguns” nocase
		$k = “shooter” nocase
		$l = “shotgun” nocase
		$m = “shotguns” nocase
		$n = “heater” nocase

	Conditions:
		any of them
}
