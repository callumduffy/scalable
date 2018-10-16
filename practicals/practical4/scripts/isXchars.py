with open("duffyc8.hashes", "r", errors="ignore") as us:
	words=us.readlines()
	eight_char_words = [word for word in words if len(word) == 35]
	with open("md5.hashes","w") as new:
		for word in eight_char_words:
			new.write("%s" % word)