import sys
from base64 import b64encode,b64decode
import binascii
import codecs
import struct
import os
import getopt
import re
import traceback
import hashlib
import time
from scapy.all import *
def to_hex_unints(params,infile,outfile):
	if params["input_file_name"]!="":
		print "[-] Converting raw data to hexadecimal uints "
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
def one_byte_encryption_decrytion_XOR(params,infile,outfile):
	index = 0
	if infile!="":
		key= params["decrypt_with_one_byte_key"]
		print "xoring using key:"+key +" (assuming ascii key)"
		len_key = len(key)
		if key!="":
			if len_key==1:
				key = ord(key)
			with open(infile,"r") as f:
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
									a+=chr(ord(bytes[i]) ^ ord(key[i]))
								except Exception as e:
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
def find_EXE_by_XOR(params,infile,outfile):
	if params["find_exe_with_key"]!= "":
		print "[-] Decrypring data with key:" + params["find_exe_with_key"]
		index=0
		key = params["find_exe_with_key"]
		len_key= len(key)
		if len_key==1:
			key=ord(key)
		infile_data=open(infile,"r").read()
		if  params["input_file_is_pcap"] == True:
			infile_data=extract_payload_from_pcap(infile)
		else:
			infile_data=open(infile,"rb").read()
		if "DOS mode" in infile_data:
				print "[-] Exe found in plain text. Extracting ..."
				extract_binary(infile_data,outfile)
				sys.exit(1)
		decrypted_data=''
		while index < len(infile_data):
			bytes=infile_data[index:index+len_key]
			try:
				if len_key == 1:
					decrypted_data+=chr(ord(bytes) ^ key)
				else:
					for i in range(len_key):
						decrypted_data+=chr(ord(bytes[i]) ^ ord(chr(key[i])))
				index=index+len_key
			except Exception as e:
				#print e
				index=index+len_key
		if "DOS mode" in decrypted_data:
			print "[-] Exe found with key: " + chr(key)
			extract_binary(decrypted_data,outfile)
			
		else:
			print "[-] could not find exe in:" +infile
		
	else:
		exe_found = False
		try:
			infile = params["input_file_name"]
			if  params["input_file_is_pcap"] == True:
				infile_data=extract_payload_from_pcap(infile)
			else:
				infile_data = open(infile,"rb").read()
			print "[-] Checking Exe in plaintext ..."
			for m in re.finditer("DOS mode",infile_data):
				extract_binary(infile_data,m.start(0),outfile)
				exe_found = True
			if not exe_found:
				print "[-] could not find exe in plaintext in ->" + infile
			print "[-] Trying XOR bruteforce of one byte for searching windows binary"
			exe_found = False
			decrypted_data=''
			for i in range(1,0xff):
				key = i
				decrypted_data=''
				for j in range(0,len(infile_data)):
					decrypted_data += chr(key ^ ord(infile_data[j]))
				for m in re.finditer("DOS mode",decrypted_data):
					print "[-] Exe found with key: " + hex(key)
					extract_binary(decrypted_data,m.start(0),outfile)
					exe_found = True
					
			if not exe_found:
				print "[-] could not find Xored exe in ->" + infile
		except Exception as e:
			print traceback.print_exc()
			sys.exit(1)
def extract_binary(data,dos_offset,outfile):
	try:
		
		if dos_offset:
			MZ_offset= dos_offset-108
			if data[MZ_offset:MZ_offset+2] == "MZ":
				print "[-] Windows Executable found at offset:" +  hex(MZ_offset)[2:] + " Extracting ..."
				PE_offset = struct.unpack("<I",data[MZ_offset+60:MZ_offset+60+4])
				header_size = 0x1000
				PE_header_size = 24
				size_of_dos_header = PE_offset[0]
				no_of_sections = struct.unpack("<h",data[MZ_offset+PE_offset[0]+6:MZ_offset+PE_offset[0]+6+2])
				size_of_optional_header= struct.unpack("<h",data[MZ_offset+PE_offset[0]+20:MZ_offset+PE_offset[0]+20+2])
				start_of_sections_headers = MZ_offset+size_of_dos_header+size_of_optional_header[0]+ PE_header_size
				section_sizes = 0
				index = 0
				for i in range(0,no_of_sections[0]):
					size = struct.unpack("<I", data[start_of_sections_headers+16+index:index+start_of_sections_headers+16+4])[0]
					section_sizes +=  size
					
					index+=40
				exe_size = section_sizes+ header_size
				if outfile!="":
					print "[-] Writing decrypted file to: " + outfile
					print "[-] md5 ->",  hashlib.md5(data[MZ_offset:MZ_offset + exe_size]).hexdigest().lower()
					writefile(outfile,data[MZ_offset:MZ_offset + exe_size])

				else:
					print data[MZ_offset:MZ_offset + exe_size]
	except Exception as e:
		print "Error while extracting binary: " + str(traceback.print_exc())
def extract_payload_from_pcap(infile):
	INFILE = infile
	paks = rdpcap(INFILE)
	data=''
	pk=''
	payload = ''
	decompressed_data=''
	for pak in paks:
		try:
			pk=str(pak[TCP].payload)
			for i in pk.split("\r\n\r\n"):
				try:
					decompressed_data+=zlib.decompress(i, 16+zlib.MAX_WBITS)
					payload+=decompressed_data
				except Exception as e:
					#print e
					payload+=i
					pass
		except:
			pass
	print "---------"
	print payload
	print "---------"
	return payload
def writefile(outfile,data):
	
	if os.path.exists(outfile):
			print "[-] File exists appending file_name ..."
			unique_file = False
			counter = 0
			while not unique_file:

				outfile += "_" + str(counter)
				if not os.path.exists(outfile):
					unique_file = True
				counter += 1


	of=codecs.open(outfile,"w")
	of.write(data)
	of.close()
	#print "-----------------------------------"
	print "[-] successfully generated: " + outfile
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
	base64 =""
	opts, args = getopt.getopt(args,"i:o:e:zraphxk:bD",["inputFileName=","outputFileName=","exe_with_key=","","","xor_key="])
	#sys.exit(1)
	raw_to_hex = False
	hex_to_raw = False
	input_file_is_pcap = False
	#print opts
	
	for opt, arg in opts:
		if opt in ("-i", "--inputFileName"):
			input_file_name = arg
		elif opt in ("-o", "--outputFileName"):
			outfile = arg
		elif opt in ("-p", ""):
			input_file_is_pcap =True
		elif opt in ("-r", ""):
			to_hex_unints = True
		elif opt in ("-k", "--xor_key"):
			decrypt_with_key = arg
		elif opt in ("-z", ""):
			find_exe_with_brute_force = True
		elif opt in ("-e", "--exe_with_key"):
			find_exe_with_key = arg
		elif opt in ("-b", "encode"):
			base64="encode"
		elif opt in ("-D", "decode"):
			base64 = "decode"
		elif opt in ("-x", ""):
			raw_to_hex = True
		elif opt in ("-a", ""):
			hex_to_raw = True
		elif opt in ("-h", ""):
			print_help()
			sys.exit(1)
	parameters.update({"input_file_is_pcap":input_file_is_pcap,"hex_to_raw":hex_to_raw,"raw_to_hex":raw_to_hex,"base64":base64,"find_exe_with_key":find_exe_with_key,"find_exe_with_brute_force":find_exe_with_brute_force,"outfile":outfile,"to_hex_unints":to_hex_unints,"decrypt_with_one_byte_key":decrypt_with_key,"input_file_name":input_file_name})
	#print parameters
	#sys.exit(1)
	return parameters
def base64(params,infile,outfile):
	
	data =open(infile).read()
	print params
	output= ''
	if params["base64"] == "encode":
		print "[-] converting to base64"
		output = b64encode(data)
	elif params["base64"] == "decode":
		print "[-] converting back to to base64"
		try:
			output=b64decode(data)
		except:
			print "not base64 encoded"
	else:
		print "Invalid arguments for base64"
		sys.exit(1)
	if outfile!="":
		writefile(outfile,output)
	else:
		print output
def raw_to_hex(params,infile,outfile):
	print "[-] converting to hex"
	data =open(infile).read()
	output= ''
	try:
		output = binascii.hexlify(data)
	except:
		output = binascii.hexlify(data+"0")
	if outfile!="":
		writefile(outfile,output)
	else:
		print output
def hex_to_raw(params,infile,outfile):
	print "[-] converting to raw"
	data =open(infile).read()
	output= ''
	try:
		output = binascii.unhexlify(data)
	except Exception as e:
		print e
		sys.exit(1)
	if outfile!="":
		writefile(outfile,output)
	else:
		print output
# main function 
def main(params):
		infile = params["input_file_name"] 
		outfile = params["outfile"]
		if params["to_hex_unints"] == True:
			to_hex_unints(params,infile,outfile)
		elif params["decrypt_with_one_byte_key"] != "":
			one_byte_encryption_decrytion_XOR(params,infile,outfile)
		elif params["find_exe_with_key"]!="" or params["find_exe_with_brute_force"]!=False:
			find_EXE_by_XOR(params,infile,outfile)
		elif params["base64"] == "encode" or params["base64"]=="decode":
			base64(params,infile,outfile)
		elif params["raw_to_hex"] == True:
			raw_to_hex(params,infile,outfile)
		elif params["hex_to_raw"] == True:
			hex_to_raw(params,infile,outfile)
		else:
			#print "exiting... " 
			exit(1)

def print_help():
	print "usage: python utils.py -i input_file [switch] [options]"
	print "-----------------------------------"
	print "Following options are supported:"
	print "		-p 		input file is a PCAP"
	print "		-o <output file name> generate output file"
	print "		-r		raw to hexadeciaml uints words separated by comma,e.g abcdef -> 0xXXXXXXX, ..."
	print "		-k <key>		encryption / decrytion by XOR"
	print "		-e <key>		Find XORED windows executable with provided key"
	print "		-z		Find XORED windows executable using bryteforce by one byte key"
	
	print "     -b   conversion to base64 "
	print "		-D	 base64 decode to raw/ascii "
	print "		-x 		raw input to hex"
	print "		-a 		hex to raw (ASCII)"
if __name__=="__main__":
	if len(sys.argv)< 4:
		
		print_help()
		
		
	else:
		args=sys.argv[1:]
		if os.path.exists(sys.argv[2]):
			params=setParameters(args)  # set parameters in a dict, returns dict 
			main(params)
		else:
			print "input file not found"
