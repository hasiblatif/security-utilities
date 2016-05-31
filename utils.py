import sys
from base64 import b64encode,b64decode
import binascii
import codecs
import struct
import os
import getopt
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
			infile_data=open(infile,"r").read()
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
		
		try:
			key = 0x00
			infile = params["input_file_name"]
			if  params["input_file_is_pcap"] == True:
				infile_data=extract_payload_from_pcap(infile)
			else:
				infile_data = open(infile,"r").read()
			if "DOS mode" in infile_data:
				print "[-] Exe found in plain text. Extracting ..."
				extract_binary(infile_data,outfile)
				sys.exit(1)
			print "[-] Trying XOR bruteforce of one byte for searching windows binary"
			decrypted_data=''
			for i in range(0,0xff):
				key = i
				decrypted_data=''
				for j in range(0,len(infile_data)):
					decrypted_data += chr(key ^ ord(infile_data[j]))
				if "DOS mode" in decrypted_data:
					print "[-] Exe found with key: " + chr(key)
					extract_binary(decrypted_data,outfile)
			print "[-] could not find exe in:" +infile
		except Exception as e:
			print e
			sys.exit(1)
def extract_binary(data,outfile):
	try:
		dos= data.find("DOS mode")
		MZ_offset=data[:dos].find("MZ")
		PE_offset = struct.unpack("<I",data[MZ_offset+60:MZ_offset+60+4])
		size_of_dos_header = PE_offset[0]
		no_of_sections = struct.unpack("<h",data[MZ_offset+PE_offset[0]+6:MZ_offset+PE_offset[0]+6+2])
		size_of_optional_header= struct.unpack("<h",data[MZ_offset+PE_offset[0]+20:MZ_offset+PE_offset[0]+20+2])
		start_of_sections_headers= MZ_offset+size_of_dos_header+size_of_optional_header[0]+24
		section_sizes = 0
		index = 0
		for i in range(0,no_of_sections[0]):
			section_sizes +=  struct.unpack("<I", data[start_of_sections_headers+16+index:index+start_of_sections_headers+16+4])[0]
			
			index+=40
		size_of_image =struct.unpack("<I",data[MZ_offset+PE_offset[0]+22+56:MZ_offset+PE_offset[0]+22+56+4])
		size_of_image = int(hex(size_of_image[0])[2:-4],16)
		print "[-] Windows Executable found at offset:" +  hex(MZ_offset)[2:] 
		if outfile!="":
			print "[-] Writing decrypted file to: " + outfile
			writefile(outfile,data[MZ_offset:MZ_offset+section_sizes+size_of_dos_header+size_of_optional_header[0]+24+(40*no_of_sections[0])])
		else:
	
			print data[MZ_offset:MZ_offset+section_sizes+size_of_dos_header+size_of_optional_header[0]+24+(40*no_of_sections[0])]
	except Exception as e:
		print "Error while extracting binary: " +str(e)
	sys.exit(1)
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
	return payload
def writefile(outfile,data):
	
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
	#opts, args = getopt.getopt(args,"hid:",["inputUrlsFileName=","dh_file="])
	#print opts
	raw_to_hex = False
	hex_to_raw = False
	input_file_is_pcap = False
	for i in args:
		try:
			if "-p" in i:
				input_file_is_pcap =True
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
			if "-b" in i:
				try:
					if "encode" in args[index+1] :
						base64="encode"
						
					elif "decode" in args[index+1] :
						base64 = "decode"
					else:
						print "base64 options are not given. provide 'enocde' or 'decode' with -b switch"
						sys.exit(1)
				except:
					print "base64 options are not given. provide 'enocde' or 'decode' with -b switch"
					base64= ""
			if "-x" in i:
				raw_to_hex = True
			if "-a" in i:
				hex_to_raw = True
			if "-i" in i:
				input_file_name = args[index+1] 
			index +=1
			
		except:
			index+=1
	parameters.update({"input_file_is_pcap":input_file_is_pcap,"hex_to_raw":hex_to_raw,"raw_to_hex":raw_to_hex,"base64":base64,"find_exe_with_key":find_exe_with_key,"find_exe_with_brute_force":find_exe_with_brute_force,"outfile":outfile,"to_hex_unints":to_hex_unints,"decrypt_with_one_byte_key":decrypt_with_key,"input_file_name":input_file_name})
	#print parameters
	return parameters
def base64(params,infile,outfile):
	
	data =open(infile).read()
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
			to_hex_unints(params)
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
	
if __name__=="__main__":
	if len(sys.argv)< 4:
		
		print "usage: python utils.py -i input_file [switch] [options]"
		print "-----------------------------------"
		print "Following options are supported:"
		print "		-p 		input file is a PCAP"
		print "		-o file name	generate output file"
		print "		-r		raw to hexadeciaml uints words separated by comma,e.g abcdef -> 0xXXXXXXX, ..."
		print "		-k key		encryption / decrytion by XOR"
		print "		-e key		Find XORED windows executable with provided key"
		print "		-e		Find XORED windows executable using bryteforce by one byte key"
		
		print "                -b encode|decode	 conversion to base64 and back"
		print "		-x 		raw input to hex"
		print "		-a 		hex to raw (ASCII)"
		
		
	else:
		args=sys.argv[1:]
		if os.path.exists(sys.argv[2]):
			params=setParameters(args)  # set parameters in a dict, returns dict 
			main(params)
		else:
			print "input file not found"
