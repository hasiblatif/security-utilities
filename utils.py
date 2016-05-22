import sys
import binascii
import codecs
import struct
import os
import time
def to_hex_unints(params):
	if params["input_file_name"]!="":
		print "[-] Converting raw data to hexadecimal uints "
		infile = params["input_file_name"]
		
		outfile = params["outfile"] 
		data=''
		four_uints=''
		with codecs.open(infile,"r") as f:
			d=f.read()
			lines=binascii.hexlify(d)
			index=0
			bytes=0
			while index < len(lines):	
				i=lines[index:index+8]
				if len(i) < 8:
					for j in xrange(8-len(i)): #fill with 0s to make 4 bytes uint
						i+="0"
				#print i
				if index == 0:
					four_uints=''
				else:
					four_uints=','
			
				four_uints+="0x"+i[6:8]+i[4:6]+i[2:4]+i[0:2]
				data+=four_uints
				bytes+=len(data)-3 # excluding ',' and '0x'
			
				index+=8
		if outfile!="":
			writefile(outfile,data)
		else:
			print data
	else:
		print "input file missing"
		sys.exit(1)
def one_byte_encryption_decrytion_XOR(params):
	infile = params["input_file_name"] 
	outfile = params["outfile"] 
	index = 0
	if infile!="":
		key= params["decrypt_with_one_byte_key"]
		print "xoring using key:"+key +" (assuming ascii key)"
		len_key = len(key)
		print len_key
		if key!="":
			if len_key==1:
				key = ord(key)
			with open(infile,"r") as f: #../Downloads/NewProject1.swf
				data=f.read()
				a=''
				while index < len(data):
						if len_key == 1:
							bytes=data[index:index+len_key]
							a+=chr(ord(bytes) ^ key)
							index = index+len_key
						else:
							bytes=data[index:index+len_key]
							for i in range(len_key):
								try:
									#print bytes[i] , key[i]
									#print bytes
									a+=chr(ord(bytes[i]) ^ ord(key[i]))
								except Exception as e:
									#print e,i,bytes,key
									#print len(bytes),index
									pass
							index = index+len_key
				if outfile!="":
						writefile(outfile,a)
				else:
						print a
		else:
			print "key is missing"
			sys.exit(1)
	else:
		print "input file missing"
		sys.exit(1)
def find_EXE_by_XOR(params):
	if params["find_exe_with_key"]!= "":
		infile = params["input_file_name"] 
		outfile = params["outfile"]
		index=0
		key = params["find_exe_with_key"]
		len_key= len(key)
		if len_key==1:
			key=ord(key)
		infile_data=open(infile,"r").read()
		decrypted_data=''
		while index < len(infile_data):
			bytes=infile_data[index:index+len_key]
			try:
				if len_key == 1:
					decrypted_data+=chr(ord(bytes) ^ key)
				else:
					for i in range(len_key):
						decrypted_data+=chr(ord(bytes[i]) ^ ord(key[i]))
				index=index+len_key
			except Exception as e:
				#print e
				index=index+len_key
		if "MZ" and "DOS mode" in decrypted_data:
			MZ_offset=decrypted_data.find("DOS mode")-106
			PE_offset = struct.unpack("<I",decrypted_data[MZ_offset+60:MZ_offset+60+4])
			size_of_image =struct.unpack("<I",decrypted_data[PE_offset[0]+22+56:PE_offset[0]+22+56+4])
			print "[-] Windows Executable found at offset:" +  str(MZ_offset)
			
			print "[-] Writing decrypted file to decrypted.exe"
			time.sleep(1)
			writefile("decrypted.exe",decrypted_data[MZ_offset:MZ_offset+size_of_image[0]])
		if outfile!="":
			writefile(outfile,decrypted_data)
		else:
			pass
	else:
		print "[-] Trying bruteforce of one byte for decrytion"
		try:
			key = 0x00
			infile = params["input_file_name"] 
			infile_data=open(infile,"r").read()
			decrypted_data=''
			for i in range(0,0xff):
				key = i
				decrypted_data=''
				for j in range(0,240):
					decrypted_data += chr(key ^ ord(infile_data[j]))
			
				if "MZ" and "DOS mode" in decrypted_data:
					decrypted_data = ''
					for i in range(0,len(infile_data)):
						decrypted_data+=chr(key ^ ord(infile_data[i]))
					MZ_offset = decrypted_data.find("DOS mode") - 106
					PE_offset = struct.unpack("<I",decrypted_data[MZ_offset+60:MZ_offset+60+4])
					size_of_image =struct.unpack("<I",decrypted_data[PE_offset[0]+22+56:PE_offset[0]+22+56+4])
					print "[-] Windows Executable found at offset:" +  str(MZ_offset) +" and key is: " + chr(key)
			
					print "[-] Writing decrypted file to decrypted.exe"
					time.sleep(1)
					writefile("decrypted.exe",decrypted_data[MZ_offset:MZ_offset+size_of_image[0]])
					sys.exit(1)
		except Exception as e:
			print e
			sys.exit(1)
		
def writefile(outfile,data):
	
	of=codecs.open(outfile,"w")
	of.write(data)
	of.close()
	#print "-----------------------------------"
	print "[-] successfully generated:" + outfile
	#print "-----------------------------------"
	
def setParameters(args):
	
	parameters={}
	outfile= ""
	to_hex_unints =""
	decrypt_with_key=""
	input_file_name =""
	index = 0
	find_exe_with_key = ""
	find_exe_with_brute_force = False
	for i in args:
		try:
			if "-o" in i:
			
				outfile = args[index+1]
			if "-r" in i:
			
				to_hex_unints = True
			if "-k" in i:
				if "-" not in args[index+1]:
					decrypt_with_key = args[index+1]
				else:
					print "no encryption / decryption key provied"
					sys.exit(1)
			if "-e" in i:
				try:
					if "-" not in args[index+1]:
						find_exe_with_key = args[index+1]
					else:
						find_exe_with_brute_force = True
				except:
					find_exe_with_brute_force = True
			if "-i" in i:
				input_file_name = args[index+1] 
			index +=1
			
		except:
			index+=1
	parameters.update({"find_exe_with_key":find_exe_with_key,"find_exe_with_brute_force":find_exe_with_brute_force,"outfile":outfile,"to_hex_unints":to_hex_unints,"decrypt_with_one_byte_key":decrypt_with_key,"input_file_name":input_file_name})
	#print parameters
	return parameters
# main function 
def main(params):
	if params["to_hex_unints"] == True:
		to_hex_unints(params)
	if params["decrypt_with_one_byte_key"] != "":
		one_byte_encryption_decrytion_XOR(params)
	if params["find_exe_with_key"]!="" or params["find_exe_with_brute_force"]!=False:
		find_EXE_by_XOR(params)
	else:
		#print "exiting... " 
		exit(1)
if __name__=="__main__":
	if len(sys.argv)< 4:
		
		print "usage: python utils.py -i [input file] [switch] [options]"
		print "-----------------------------------"
		print "Following options are supported:"
		print "		-o file name	generate output file"
		print "		-r		raw to hexadeciaml uints words separated by comma,e.g abcdef -> 0xXXXXXXX, ..."
		print "		-k key		encryption / decrytion by XOR"
		print "		-e key		Find windows executable which is XORED"
		print "		-e		Find windows executable which is XORED using bryteforce by one byte key"
		
	else:
		args=sys.argv[1:]
		params=setParameters(args)  # set parameters in a dict, returns dict 
		main(params)
