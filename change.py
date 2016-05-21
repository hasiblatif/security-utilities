import sys
import binascii
def main(switch,infile,outfile):
	if switch == "-r":
		to_hex_unints(switch,infile,outfile)
	else:
		print "Unrecognized switch: " + switch
		exit(1)
	
def to_hex_unints(switch,infile,outfile):
	data=''
	of=open(outfile,"w")
	with open(infile,"r") as f:
		d=f.read()
		lines=binascii.hexlify(d)
		index=0
		bytes=0
		while index < len(lines):	
			i=lines[index:index+8]
			if len(i) < 8:
				for j in xrange(8-len(i)):
					i+="0"
			#print i
			if index == 0:
				data=''
			else:
				data=','
			
			data+="0x"+i[6:8]+i[4:6]+i[2:4]+i[0:2]
			bytes+=len(data)-3 # excluding ',' and '0x'
			of.write(data)
			index+=8
	of.close()
	of=open(outfile,"r")
	print "-----------------------------------"
	print "successfully generated:" + outfile
	print "-----------------------------------"
	
if __name__=="__main__":
	if len(sys.argv)!=4:
		
		print "usage: change.py [switch] rawfile outfile"
		print "-----------------------------------"
		print "Following switches are supported:"
		print "		-r raw to hex"
	else:
		infile = sys.argv[2]
		outfile = sys.argv[3]
		switch = sys.argv[1]
		main(switch,infile,outfile)
		