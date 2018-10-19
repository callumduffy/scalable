import sys

if len(sys.argv) < 1:
    print("Specify an input path for the hashes file.")
else:   
    input_path = sys.argv[1]
    with open(input_path, "r", errors="ignore") as hashes_file:
        hashes = hashes_file.readlines()
        md5 = []
        des = []
        sha256 = []
        sha512 = []
        pbkdf2 = []
        argon2 = []
        for hash in hashes:
            if "$1$" in hash and len(hash) == 35:
                md5.append(hash)
            elif "$pbkdf2" in hash and len(hash) == 88:
                pbkdf2.append(hash)
            elif "$argon2i$" in hash and len(hash) == 77:
                argon2.append(hash)
            elif "$5$" in hash and len(hash) > 50:
                sha256.append(hash)
            elif "$6$" in hash and len(hash) > 90:
                sha512.append(hash)
            elif len(hash) == 14:
                des.append(hash)

        hashes_detected = len(md5) + len(des) + len(sha256) + len(sha512) + len(pbkdf2) + len(argon2)
        all_hash_types_detected = len(hashes) == hashes_detected

        if all_hash_types_detected:
            print("All %i hashes were successfully identified by their respective algorithms." % len(hashes))
        else:
            unknown_hashes = len(hashes) - hashes_detected
            print("Could not identify the algorithms of %i hashes." % unknown_hashes)

        print("MD5: %i" % len(md5))
        print("DES: %i" % len(des))
        print("SHA-256: %i" % len(sha256))
        print("SHA-512: %i" % len(sha512))
        print("PBKDF2: %i" % len(pbkdf2))
        print("Argon 2: %i" % len(argon2))

        with open("md5.hashes", "w") as md5_hashes:
            for h in md5:
                md5_hashes.write(h)
        with open("des.hashes", "w") as des_hashes:
            for h in des:
                des_hashes.write(h)
        with open("sha256.hashes", "w") as sha256_hashes:
            for h in sha256:
                sha256_hashes.write(h)
        with open("sha512.hashes", "w") as sha512_hashes:
            for h in sha512:
                sha512_hashes.write(h)
        with open("pbkdf2.hashes", "w") as pbkdf2_hashes:
            for h in pbkdf2:
                pbkdf2_hashes.write(h)
        with open("argon2.hashes", "w") as argon2_hashes:
            for h in argon2:
                argon2_hashes.write(h)