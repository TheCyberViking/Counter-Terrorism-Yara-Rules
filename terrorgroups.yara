Rule terrorgroups
{
	Meta:
		Author = “@TheCyberViking”
		Date = “11/01/2020”
`		description = “yara rule for part of surveillance project”
		Reference = “https://twitter.com/TheCyberViking”
		
	Strings:
		$a = “IRA” nocase
		$b = “RIRA” nocase
		$c = “UVA” nocase
		$d = “UVF” nocase
		$e = “ISIS” nocase
		$f = “al-Qaeda” nocase
		$g = “al-Qa'ida” nocase
		$h = “Taliban” nocase
		$i = “National Liberation Army” nocase
		$j = “Jihad” nocase
		$k = “Harakat Sawa’d Misr” nocase
		$l = “HAMAS” nocase
		$m = “Mujahidin” nocase
		$n = “AOI” nocase
    		$o = “PLF” nocase
    		$p = “YPG” nocase
    		$q = “Mujahideen” nocase
    		$r = “Hizballah” nocase
    		$s = “Boko Haram” nocase
    		$t = “Communist Party” nocase
    		$u = “al-Shabaab” nocase
    		$v = “al-Nusrah” nocase
    		$w = “Islamic State” nocase
    		$y = “New Irish Republican Army” nocase
    		$z = “Continuity Irish Republican Army” nocase
    		$a1 = “Irish Republican Army” nocase
    		$a2 = “Kahane Chai” nocase
    		$a3 = “Ulster Voulnteeer Force” nocase
    		$a4 = “Ulster Voulnteer Army” nocase
    		$a5 = “antifa” nocase
    		$a6 = “cartel” nocase
    		$a7 = “mafia” nocase
    		$a8 = “Al-Shabaab” nocase
        

	Conditions:
		any of them
}
