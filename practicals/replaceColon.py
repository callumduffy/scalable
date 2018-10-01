with open("duffyc8.cracked", "r") as colon:
	lines=colon.readlines()
	
	with open("duffyc8.broken", "a") as final:
	
	for l in lines:
		l.replace(";"," ")
		l=l+"\h"
		final.write(l)
		