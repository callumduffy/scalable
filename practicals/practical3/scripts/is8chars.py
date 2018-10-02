with open("2BillPwords.txt", "r", errors="ignore") as us:
	words=us.readlines()
	eight_char_words = [word for word in words if len(word) == 9]
	with open("8Char2BillPwords.txt","w") as new:
		for word in eight_char_words:
			new.write("%s" % word)