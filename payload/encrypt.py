import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_header):
	key = get_random_bytes(32)
	iv = get_random_bytes(16)
	
	with open(input_file, 'rb') as file:
		data = file.read()

	cipher = AES.new(key, AES.MODE_CBC, iv)
	encrypted_data = cipher.encrypt(pad(data, AES.block_size))

	with open(output_header, 'w') as file:
		file.write("#pragma once\n\n")

		file.write(f"// KEY: {key.hex()}\n")
		file.write("unsigned char raw_key[] = { " + ", ".join([f"0x{b:02X}" for b in key]) + " };\n\n")

		file.write("unsigned char raw_iv[] = { " + ", ".join([f"0x{b:02X}" for b in iv]) + " };\n\n")

		file.write(f"unsigned int payload_len = {len(encrypted_data)};\n\n")
		file.write("unsigned char encrypted_pld[] = {\n\t")
		for i, b in enumerate(encrypted_data):
			file.write(f"0x{b:02X}, ")
			if(i + 1) % 16 == 0:
				file.write("\n\t")
		file.write("\n};\n")

	print(f"Payload is encrypted!")
	print(f"Key: {key.hex()}")
	print(f"File {output_header} is updated.")

file = input("Enter file name: ")
encrypt_file(file, 'payload.h')	

