# security-utilities
Utilities like encryption / decryption by XOR, find Windows executable in XORED data using key / bruteforce,

conversion to other data types, etc

## Usage:

python utils.py -i [input file] [options]

Following options are supported:

-o file name	    generate output file

-r		      raw to hexadeciaml uints separated by comma,e.g abcdef -> 0xXXXXXXX, ...

-k key		  encryption / decrytion by XOR

-e key		  Find windows executable which is XORED

-z		      Find windows executable which is XORED using bryteforce by one byte key

-p     If input file is a pcap

-x raw input to hex

-a hex to raw

-b <encode|decode>	 conversion to base64 and back

