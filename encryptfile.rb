#!/usr/bin/env ruby

###############################################
#
#   encrypt/decrypt a file 
#
##############################################

require 'optparse'
require_relative 'cryptlib.rb'

include CryptLib

options = {}

option_parser = OptionParser.new do |opts|
	opts.banner = 'Encrypt/decrypt a file!'
	opts.separator ""
	opts.separator "commands"
	opts.separator "    encrypt: encrypt file"
	opts.separator "    decrypt: decrypt file"
	opts.separator ""
	opts.separator "options"

	opts.on("-o","--output FILNAME",
		"the name of the encrypted/decrypted file ") do |outfilename|
		options[:dest_file] = outfilename 
	end

	opts.on("-p", "--password passwd","the password") do |passwd|
		options[:password] = passwd
	end

	opts.on("-h","--help","help") do 
		puts option_parser
	end
end

option_parser.parse!

options[:source_file] = ARGV[1]
options[:action] = ARGV[0].downcase
if ARGV[0].downcase != 'encrypt' and ARGV[0].downcase != 'decrypt'
	puts option_parser
	exit
end

if options[:dest_file] == nil
	options[:dest_file] = options[:source_file] +".enc" if options[:action] == "encrypt"
	options[:dest_file] = options[:source_file] +".dec" if options[:action] == "decrypt"
end

if options[:password].length <6
	puts "the password should at least 6 characters ..."
	exit
end

#if the source file exists
if !File.file?(options[:source_file])
	puts "File #{options[:source_file]} does not exist!"
	exit
end

#encrypt a file
def encryptfile(sourcefile,destfile,password)
	cryptInit()
	cryptAddRandom(nil,CRYPT_RANDOM_SLOWPOLL)

	pcryptEnvelope = FFI::MemoryPointer.new :int  
	pbufferSize = FFI::MemoryPointer.new :int 
	status = cryptCreateEnvelope(pcryptEnvelope,CRYPT_UNUSED,:CRYPT_FORMAT_CRYPTLIB)
	if not cryptStatusOK(status)
		puts "create envelope failed error code=#{status}"
		exit
	end	
	cryptEnvelope = pcryptEnvelope.get_int(0)
	cryptGetAttribute(cryptEnvelope,:CRYPT_ATTRIBUTE_BUFFERSIZE,pbufferSize)
	bufferSize = pbufferSize.get_int(0)

	puts "bufferSize = #{bufferSize}"	
	status = cryptSetAttributeString(cryptEnvelope,:CRYPT_ENVINFO_PASSWORD,password,password.length)
	penvelopedData = FFI::MemoryPointer.new :char, bufferSize	

	File.open(sourcefile,'rb') do |sfile|
		dataSize = sfile.size
		dfile = File.new(destfile,'wb')
		pbytesCopied = FFI::MemoryPointer.new :int
		pbytesPopped = FFI::MemoryPointer.new :int 
		content =sfile.sysread(dataSize)
		
		cryptPushData(cryptEnvelope,content,content.length,pbytesCopied)
		while pbytesCopied.get_int(0) < content.length
			puts "pushedDataSize = #{pbytesCopied.get_int(0)},content.length=#{content.length}"
			content = content[pbytesCopied.get_int(0),content.length]
			status = cryptPopData(cryptEnvelope,penvelopedData,bufferSize,pbytesPopped)

			bytesCopied = pbytesPopped.get_int(0)	
			puts "bytespoped = #{bytesCopied}"
			while bytesCopied > 0
				dfile.syswrite(penvelopedData.get_bytes(0,bytesCopied))
				status = cryptPopData(cryptEnvelope,penvelopedData,bufferSize,pbytesPopped)
				bytesCopied = pbytesPopped.get_int(0)	
			end
			cryptPushData(cryptEnvelope,content,content.length,pbytesCopied)
		end
		puts "pushedDataSize = #{pbytesCopied.get_int(0)},content.length=#{content.length}"
		cryptFlushData(cryptEnvelope)
		status = cryptPopData(cryptEnvelope,penvelopedData,bufferSize,pbytesCopied)
		bytesCopied = pbytesCopied.get_int(0)	
		puts "bytespoped = #{bytesCopied}"
		while bytesCopied > 0
			dfile.syswrite(penvelopedData.get_bytes(0,bytesCopied))
			status = cryptPopData(cryptEnvelope,penvelopedData,bufferSize,pbytesCopied)
			bytesCopied = pbytesCopied.get_int(0)	
		end		
		
		dfile.close
	end

	cryptDestroyEnvelope(cryptEnvelope)
	cryptEnd()
end

#decrypt a file
def decryptfile(sourcefile,destfile,password)
	cryptInit()
	cryptAddRandom(nil,CRYPT_RANDOM_SLOWPOLL)

	pcryptEnvelope = FFI::MemoryPointer.new :int  
	pbufferSize = FFI::MemoryPointer.new :int 
	status = cryptCreateEnvelope(pcryptEnvelope,CRYPT_UNUSED,:CRYPT_FORMAT_AUTO)
	if not cryptStatusOK(status)
		puts "create envelope failed error code=#{status}"
		exit
	end	
	cryptEnvelope = pcryptEnvelope.get_int(0)
	cryptGetAttribute(cryptEnvelope,:CRYPT_ATTRIBUTE_BUFFERSIZE,pbufferSize)
	bufferSize = pbufferSize.get_int(0)
	puts "bufferSize = #{bufferSize}"	
	
	pdenvelopedData = FFI::MemoryPointer.new :char, bufferSize	
	
	File.open(sourcefile,'rb') do |sfile|
		dataSize = sfile.size
		dfile = File.new(destfile,'wb')
		pbytesCopied = FFI::MemoryPointer.new :int
		pbytesPopped = FFI::MemoryPointer.new :int 

		content =sfile.sysread(dataSize)
		cryptPushData(cryptEnvelope,content,content.length,pbytesCopied)
		while (pbytesCopied.get_int(0) < content.length)
			content = content[pbytesCopied.get_int(0),content.length]
			status = cryptSetAttributeString(cryptEnvelope,:CRYPT_ENVINFO_PASSWORD,password,password.length)
			cryptPopData(cryptEnvelope,pdenvelopedData,bufferSize,pbytesPopped)
			bytesCopied = pbytesPopped.get_int(0)	
			while bytesCopied > 0
				dfile.syswrite(pdenvelopedData.get_bytes(0,bytesCopied))
				cryptPopData(cryptEnvelope,pdenvelopedData,bufferSize,pbytesPopped)
				bytesCopied = pbytesPopped.get_int(0)	
			end
			cryptPushData(cryptEnvelope,content,content.length,pbytesCopied)
		end

		cryptFlushData(cryptEnvelope)
		status = cryptSetAttributeString(cryptEnvelope,:CRYPT_ENVINFO_PASSWORD,password,password.length)
		cryptPopData(cryptEnvelope,pdenvelopedData,bufferSize,pbytesPopped)
		bytesCopied = pbytesPopped.get_int(0)	
		while bytesCopied > 0
			dfile.syswrite(pdenvelopedData.get_bytes(0,bytesCopied))
			cryptPopData(cryptEnvelope,pdenvelopedData,bufferSize,pbytesPopped)
			bytesCopied = pbytesPopped.get_int(0)	
		end
		dfile.close
	end

	cryptDestroyEnvelope(cryptEnvelope)
	cryptEnd()
end



puts "we willl #{ARGV[0]} file: #{ARGV[1]},the options are #{options.inspect}"
case 
	when options[:action] == "encrypt"
		encryptfile(options[:source_file],options[:dest_file],options[:password])
	when options[:action] == "decrypt"
		decryptfile(options[:source_file],options[:dest_file],options[:password])
end








