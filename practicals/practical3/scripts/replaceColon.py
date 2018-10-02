with open("duffyc8.cracked", "r") as colon:
	lines=colon.readlines()
	print(len(lines))
	
	with open("duffyc8.broken", "a") as final:
		for l in lines:
			l = l.replace(":"," ")
			l = l.replace('\r','')
			final.write(l)