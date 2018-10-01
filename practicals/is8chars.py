with open("2BillPwords.txt", "r", errors="ignore") as us:
	words=us.readlines()
	words=  [x.strip() for x in words]
	
	with open("8Char2BillPwords.txt","w") as new:
		
		for w in words:
			if len(w) == 8:
				w=w+"\n"
				new.write(w)