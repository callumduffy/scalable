cracked = False

with open("desUncracked.hashes", "a") as u:
	with open("results.broken", "r") as cslist:
		cs=cslist.readlines()
		with open("des.hashes", "r") as hslist:
			hs=hslist.readlines()
			hs= [x.strip() for x in hs]
			for h in hs:
				for c in cs:
					if h in c:
						cracked = True
						print("found")
						break
				if cracked:
					print("cracked")
				else:
					h=h+"\n"
					u.writelines(h)
				cracked=False