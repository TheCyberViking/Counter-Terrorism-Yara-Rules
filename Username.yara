Username.yara

Rule username_capture
{
	Meta:
		Author = “TheCyberViking”
		Date = “11/01/2020”
`		description = “yara rule for part of surveillance project”
		Reference = “https://twitter.com/TheCyberViking”
		

	Strings:
		$a = “username” nocase
		$b = “uname” nocase
		$c = “user” nocase

	Conditions:
		any of them
}
