with open("1.6millpwords.txt", "r", errors="ignore") as us:
	words=us.readlines()
	eight_char_words = [word for word in words if len(word) == 6]
	with open("5letter.txt","w") as new:
		for word in eight_char_words:
			new.write("%s" % word)