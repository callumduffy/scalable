import string

letters = list(string.ascii_lowercase)
word = ""

with open("4letterWords.txt","w") as new:
		for l1 in letters:
			t1 = l1
			for l2 in letters:
				t2 = t1 + l2
				for l3 in letters:
					t3 = t2 + l3
					for l4 in letters:
						t4 = t3 + l4 + "\n"
						new.write("%s" % t4)