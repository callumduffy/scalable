cracked = False

with open("words.txt", "r") as u:
	words=u.readlines()
	words=  [x.strip() for x in words]
	
	with open("8CharWords.txt","a") as new:
		
		for w in words:
			if len(w) == 8:
				w=w+"\n"
				new.write(w)