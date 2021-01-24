#! python3
# Usage: python3 AES-128.py [mode] [file] [passkey]
# Advanced Encryption Standard (128-bit-key)
import copy, sys, os



sbox = {'00': '63', '01': '7c', '02': '77', '03': '7b', '04': 'f2', '05': '6b', '06': '6f', '07': 'c5', '08': '30', '09': '01', '0a': '67', '0b': '2b', '0c': 'fe', '0d': 'd7', '0e': 'ab', '0f': '76', '10': 'ca', '11': '82', '12': 'c9', '13': '7d', '14': 'fa', '15': '59', '16': '47', '17': 'f0', '18': 'ad', '19': 'd4', '1a': 'a2', '1b': 'af', '1c': '9c', '1d': 'a4', '1e': '72', '1f': 'c0', '20': 'b7', '21': 'fd', '22': '93', '23': '26', '24': '36', '25': '3f', '26': 'f7', '27': 'cc', '28': '34', '29': 'a5', '2a': 'e5', '2b': 'f1', '2c': '71', '2d': 'd8', '2e': '31', '2f': '15', '30': '04', '31': 'c7', '32': '23', '33': 'c3', '34': '18', '35': '96', '36': '05', '37': '9a', '38': '07', '39': '12', '3a': '80', '3b': 'e2', '3c': 'eb', '3d': '27', '3e': 'b2', '3f': '75', '40': '09', '41': '83', '42': '2c', '43': '1a', '44': '1b', '45': '6e', '46': '5a', '47': 'a0', '48': '52', '49': '3b', '4a': 'd6', '4b': 'b3', '4c': '29', '4d': 'e3', '4e': '2f', '4f': '84', '50': '53', '51': 'd1', '52': '00', '53': 'ed', '54': '20', '55': 'fc', '56': 'b1', '57': '5b', '58': '6a', '59': 'cb', '5a': 'be', '5b': '39', '5c': '4a', '5d': '4c', '5e': '58', '5f': 'cf', '60': 'd0', '61': 'ef', '62': 'aa', '63': 'fb', '64': '43', '65': '4d', '66': '33', '67': '85', '68': '45', '69': 'f9', '6a': '02', '6b': '7f', '6c': '50', '6d': '3c', '6e': '9f', '6f': 'a8', '70': '51', '71': 'a3', '72': '40', '73': '8f', '74': '92', '75': '9d', '76': '38', '77': 'f5', '78': 'bc', '79': 'b6', '7a': 'da', '7b': '21', '7c': '10', '7d': 'ff', '7e': 'f3', '7f': 'd2', '80': 'cd', '81': '0c', '82': '13', '83': 'ec', '84': '5f', '85': '97', '86': '44', '87': '17', '88': 'c4', '89': 'a7', '8a': '7e', '8b': '3d', '8c': '64', '8d': '5d', '8e': '19', '8f': '73', '90': '60', '91': '81', '92': '4f', '93': 'dc', '94': '22', '95': '2a', '96': '90', '97': '88', '98': '46', '99': 'ee', '9a': 'b8', '9b': '14', '9c': 'de', '9d': '5e', '9e': '0b', '9f': 'db', 'a0': 'e0', 'a1': '32', 'a2': '3a', 'a3': '0a', 'a4': '49', 'a5': '06', 'a6': '24', 'a7': '5c', 'a8': 'c2', 'a9': 'd3', 'aa': 'ac', 'ab': '62', 'ac': '91', 'ad': '95', 'ae': 'e4', 'af': '79', 'b0': 'e7', 'b1': 'c8', 'b2': '37', 'b3': '6d', 'b4': '8d', 'b5': 'd5', 'b6': '4e', 'b7': 'a9', 'b8': '6c', 'b9': '56', 'ba': 'f4', 'bb': 'ea', 'bc': '65', 'bd': '7a', 'be': 'ae', 'bf': '08', 'c0': 'ba', 'c1': '78', 'c2': '25', 'c3': '2e', 'c4': '1c', 'c5': 'a6', 'c6': 'b4', 'c7': 'c6', 'c8': 'e8', 'c9': 'dd', 'ca': '74', 'cb': '1f', 'cc': '4b', 'cd': 'bd', 'ce': '8b', 'cf': '8a', 'd0': '70', 'd1': '3e', 'd2': 'b5', 'd3': '66', 'd4': '48', 'd5': '03', 'd6': 'f6', 'd7': '0e', 'd8': '61', 'd9': '35', 'da': '57', 'db': 'b9', 'dc': '86', 'dd': 'c1', 'de': '1d', 'df': '9e', 'e0': 'e1', 'e1': 'f8', 'e2': '98', 'e3': '11', 'e4': '69', 'e5': 'd9', 'e6': '8e', 'e7': '94', 'e8': '9b', 'e9': '1e', 'ea': '87', 'eb': 'e9', 'ec': 'ce', 'ed': '55', 'ee': '28', 'ef': 'df', 'f0': '8c', 'f1': 'a1', 'f2': '89', 'f3': '0d', 'f4': 'bf', 'f5': 'e6', 'f6': '42', 'f7': '68', 'f8': '41', 'f9': '99', 'fa': '2d', 'fb': '0f', 'fc': 'b0', 'fd': '54', 'fe': 'bb', 'ff': '16'}


rcon = [[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],[10,0,0,0],[20,0,0,0],[40,0,0,0],[80,0,0,0],['1b',0,0,0],[36,0,0,0]] # Working


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

matrix = [['02','03','01','01'],['01','02','03','01'],['01','01','02','03'],['03','01','01','02']] # Working

inv_sbox = dict(map(reversed, sbox.items()))

inv_matrix = [['0e','0b','0d','09'],['09','0e','0b','0d'],['0d','09','0e','0b'],['0b','0d','09','0e']] # Working

special_character = chr(0)


key_table = []



def get_file(file):
        with open(file, 'r', encoding='utf8', errors='ignore') as file:
                result = file.readlines()

        return ''.join(result)


def save_changes(file, text):
        with open(file, 'w') as file:
                file.write(str(text))


def move(moving_list,position,new_position): 
	save = copy.copy(moving_list[position])
	del moving_list[position]
	moving_list.insert(new_position,save)


def display_rows(columns): 
	rows = []
	for x in range(4):
		for i in range(4):
			rows.append(columns[i][x])
	rows = split_columns(rows)
	return rows


def xor(num1,num2):
	num1 = int(str(num1),16)
	num2 = int(str(num2),16)
	return hex(num1 ^ num2)[2:]


def key_gen(passkey):
	global key_table

	hexNumbers = []

	for characters in passkey:
		result = hex(ord(characters))[2:]
		hexNumbers.append(result)

	columns = [[],[],[],[]]
	index = 0


	columns = split_columns(hexNumbers)
	return columns 


def check_hex(hex_list,o=False): 
	if o == False:
		for x in range(4):
			for i in range(4):
				if '0x' in hex_list[x][i]:
					hex_list[x][i] = (hex_list[x][i])[2:]
				if len(hex_list[x][i]) < 2:
					hex_list[x][i] = '0' + hex_list[x][i]
	else:
		for i in range(4):
			if '0x' in hex_list[i]:
				hex_list[i] = (hex_list[i])[2:]
			if len(hex_list[i]) < 2:
				hex_list[i] = '0' + hex_list[i]	
				
				

def sub_key_gen(key,rcon_index): 
	columns = key
	key_state = [[],[],[],[]]


	sub_column = []
	for x in range(4):
		sub_column.append(sbox[columns[3][x]])
	move(sub_column,0,3)


	index_columns = 1
	index_key_state = 0


	for x in range(4):
		a = xor(columns[0][x],sub_column[x])
		a = xor(a,rcon[rcon_index][x])
		key_state[0].append(a)


	for i in range(3):
		for x in range(4):
			a = xor(columns[index_columns][x],key_state[index_key_state][x])
			key_state[index_key_state + 1].append(a)
		index_columns += 1
		index_key_state += 1



	return key_state


def split_columns(res_list):
	columns = [[],[],[],[]]
	index = 0


	for x in range(4):
		for i in range(4):
			columns[x].append(res_list[index])
			index += 1
	return columns


def generate_sub_keys(key):
	global key_table
	key_table = []
	
	key_table.append(key)

	for i in range(10):
		newKey = sub_key_gen(key_table[i],i)
		check_hex(newKey,o=False)
		key_table.append(newKey)




def sub_bytes(ciphertext): 
	for x in range(4):
		for i in range(4):
			if int(str(ciphertext[x][i]),16) > 255:
				ciphertext[x][i] = int(str(ciphertext[x][i]),16) % 255
				ciphertext[x][i] = hex(ciphertext[x][i])[2:]
			ciphertext[x][i] = sbox[ciphertext[x][i]]

def shift_rows(ciphertext): 
	rows = display_rows(ciphertext)
	move(rows[1],0,3)

	move(rows[2],0,3)
	move(rows[2],0,3)

	for i in range(3):
		move(rows[3],0,3)

	rows = display_rows(rows)

	for x in range(4):
		for i in range(4):
			ciphertext[x][i] = rows[x][i]
	
def mix_columns(s):
	for i in range(4):
		mix_single_column(s[i])
	
def mix_single_column(a):
	for i in range(len(a)):
		a[i] = int(str(a[i]),16)
			
	t = a[0] ^ a[1] ^ a[2] ^ a[3]
	u = a[0]
	a[0] ^= t ^ xtime(a[0] ^ a[1])
	a[1] ^= t ^ xtime(a[1] ^ a[2])
	a[2] ^= t ^ xtime(a[2] ^ a[3])
	a[3] ^= t ^ xtime(a[3] ^ u)
	for i in range(len(a)):
		a[i] = hex(a[i])
	check_hex(a,o=True)	

def add_round_key(ciphertext,key): 
	for x in range(4):
		for i in range(4):
			ciphertext[x][i] = xor(ciphertext[x][i],key[x][i])
	check_hex(ciphertext,o=False)


def inv_sub_bytes(ciphertext):
	for x in range(4):
		for i in range(4):
			ciphertext[x][i] = inv_sbox[ciphertext[x][i]]

def inv_shift_rows(ciphertext):
	rows = display_rows(ciphertext)
	move(rows[1],3,0)

	move(rows[2],3,0)
	move(rows[2],3,0)

	for i in range(3):
		move(rows[3],3,0)

	rows = display_rows(rows)

	for x in range(4):
		for i in range(4):
			ciphertext[x][i] = rows[x][i]

def inv_mix_columns(s):
	for x in range(4):
		for i in range(4):
			s[x][i] = int(str(s[x][i]),16)
			
	for i in range(4):
		u = xtime(xtime(s[i][0] ^ s[i][2]))
		v = xtime(xtime(s[i][1] ^ s[i][3]))
		s[i][0] ^= u
		s[i][1] ^= v
		s[i][2] ^= u
		s[i][3] ^= v

	for x in range(4):
		for i in range(len(s)):
			s[x][i] = hex(s[x][i])
	check_hex(s,o=True)
	mix_columns(s)


def encrypt_block(block):
	add_round_key(block,key_table[0])
	# Rounds 1-9
	for x in range(1,10):
		sub_bytes(block)
		shift_rows(block)
		mix_columns(block)
		add_round_key(block,key_table[x])


	sub_bytes(block)
	shift_rows(block)
	add_round_key(block,key_table[10])

	return block


def decrypt_block(block):
	# First:
	add_round_key(block,key_table[10])
	inv_shift_rows(block)
	inv_sub_bytes(block)


	for x in range(9,0,-1):
		add_round_key(block,key_table[x])
		inv_mix_columns(block)
		inv_shift_rows(block)
		inv_sub_bytes(block)

	add_round_key(block,key_table[0])

	return block



def get_blocks(plaintext):
	blocks = []
	block = plaintext
	index = 0

	if len(plaintext) < 16:
		padding = 16 - (len(plaintext) % 16)
		for x in range(padding):
			block += special_character
		blocks.append(block)
		block = ''

	else:
		block = ''
		for i in plaintext:
			block += i
			if len(block) == 16:
				blocks.append(block)
				block = ''

		if len(block) != 0:
			blocks.append(block)

		for i in blocks:
			if len(i) == 16:
				index += 1
			else:
				break

		blocks[index] = blocks[index] + special_character * (16 - len(blocks[index]))

	for i in range(len(blocks)):
		blocks[i] = key_gen(blocks[i])

		

	return blocks




		
		
	
	
def single_line_block(block):
	result = ''
	for x in range(4):
		for i in range(4):
			result += block[x][i] + ' '
	return result


	
def split_16_bytes(byte_list):
	length = len(byte_list)
	amount = int(length / 16)
	index = 0
	
	result = []
	
	for i in range(amount):
		result.append(byte_list[index:index + 16])
		index += 16
	
	return result
	




def encrypt_text(text, passkey):
	passkey = key_gen(passkey)
	generate_sub_keys(passkey)
	
	result = get_blocks(text)
	save = ''

	for i in result:
		block = encrypt_block(i)
		block = single_line_block(block)
		save += block + '\n'

	save = save.rstrip('\n')
	return save


def decrypt_text(text, passkey):
	plaintext = ''
	
	passkey = key_gen(passkey)
	generate_sub_keys(passkey)
	
	result = text
	result = result.split()
	result = split_16_bytes(result)
	

	for i in range(len(result)):
		result[i] = split_columns(result[i])

		
	for i in range(len(result)):
		result[i] = decrypt_block(result[i])

		
	for i in range(len(result)):
		for x in range(4):
			for j in range(4):
				if chr(int(str(result[i][x][j]),16)) == special_character:
					break
				plaintext += chr(int(str(result[i][x][j]),16))

	return plaintext


def encrypt_file(file, passkey):
        data = get_file(file)
        data = encrypt_text(data, passkey)
        save_changes(file, data)


def decrypt_file(file, passkey):
        data = get_file(file)
        data = decrypt_text(data, passkey)
        save_changes(file, data)


if len(sys.argv) == 4:
        mode = sys.argv[1]
        file = sys.argv[2]
        passkey = sys.argv[3]

        if not mode in ['-e', '-d']:
                raise Exception('Invalid Mode, Must Be -e (encrypt), -d (decrypt)')

        if not os.path.exists(file):
                raise Exception('File Does Not Exist')

        if not len(passkey) == 16:
                raise Exception('Length Of Passkey Must Be 16')


        if mode == '-e':
                encrypt_file(file, passkey)

        elif mode == '-d':
                decrypt_file(file, passkey)


        

        
        

else:
        print('Usage: python3 AES-128.py [mode] [file] [passkey]')
        sys.exit()
	

