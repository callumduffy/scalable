with open("rockyou.txt", "r", errors="ignore") as us:
	words=us.readlines()
	words = [word for word in words]
	x=0
	with open("rockyou-small.txt","w") as new:
		while x < 1000000:
			new.write("%s" % words[x])
			x+=1