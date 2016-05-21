import sys
import binascii

	
def to_hex_unints(params):
	if params["input_file_name"]!="":
		print "[-] Converting raw data to hexadecimal uints "
		infile = params["input_file_name"]
		
		outfile = params["outfile"] 
		data=''
		four_uints=''
		with open(infile,"r") as f:
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
	if infile!="":
		key= params["decrypt_with_one_byte_key"]
		if key!="":
			key = int(key,16)
			with open(infile) as f: #../Downloads/NewProject1.swf
				data=f.read()
				i=0
				a=''
				while i < len(data):
					try:
						#print data[i:i+2]
						a+=chr(ord(data[i:i+1]) ^ key)
						i=i+1
					except:
						#print "exception"
						i=i+1
	
				if outfile!="":
					writefile(outfile,data)
				else:
					print data
		else:
			print "key is missing"
			sys.exit(1)
	else:
		print "input file missing"
		sys.exit(1)
def find_EXE(params):
	
def writefile(outfile,data):
	
	of=open(outfile,"w")
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
			if "-i" in i:
				input_file_name = args[index+1] 
			index +=1
			
		except:
			index+=1
	parameters.update({"outfile":outfile,"to_hex_unints":to_hex_unints,"decrypt_with_one_byte_key":decrypt_with_key,"input_file_name":input_file_name})
	#print parameters
	return parameters
# main function 
def main(params):
	if params["to_hex_unints"] == True:
		to_hex_unints(params)
	if params["decrypt_with_one_byte_key"] != "":
		one_byte_encryption_decrytion_XOR(params)
	else:
		print "exiting... " 
		exit(1)
if __name__=="__main__":
	if len(sys.argv)< 4:
		
		print "usage: utils.py -i [input file] [switch] [options]"
		print "-----------------------------------"
		print "Following optional capabilities are supported:"
		print "     -[switch] [related options]"
		print "		-o [output file name] --> write to file"
		print "		-r --> raw to hex"
		print "		-k [one byte key] --> one byte encryption decrytion by XOR"
	else:
		args=sys.argv[1:]
		params=setParameters(args)  # set parameters in a dict, returns dict 
		#print params
		main(params)
