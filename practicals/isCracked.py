cracked = false

with open("uncracked.txt", "a") as uncracked:
	with open("duffyc8.cracked", "r") as cs:
		with open("duffyc8.hashes", "r") as hs:
			for h in hs:
				for c in cs:
					if h in c:
						cracked = true
						break
				if !cracked:
					uncracked.write(h)
				cracked = false