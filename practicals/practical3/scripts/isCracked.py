cracked = False

with open("des.hashes", "a") as u:
	with open("duffyc8.broken", "r") as cslist:
		cs=cslist.readlines()
		with open("desUncracked.hashes", "r") as hslist:
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