with open("linuxvoice-word.txt", "r", errors="ignore") as us:
	words=us.readlines()
	four_char_words = [word for word in words if len(word) == 5]
	with open("capitals.txt","w") as new:
		for word in eight_char_words:
			if word[0].isupper():
				new.write("%s" % word)