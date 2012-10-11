#!/usr/bin/env ruby
require_relative "cryptlib.rb"

puts "now testing the cryptlib library..."
CryptLib.cryptInit()
puts "hello"
#uts CryptLib.CRYPT_MODE_TYPE
n = CryptLib.cryptAddRandom(nil,CryptLib::CRYPT_RANDOM_SLOWPOLL)
puts CryptLib::CRYPT_RANDOM_SLOWPOLL

puts n
CryptLib.cryptEnd()
puts "end"


class SimpleStruct < FFI::Struct 
	layout :value,:double
end

 a = SimpleStruct.new
 a[:value] = 32
 puts "a[:value]=#{a[:value]}"

 pointer = FFI::MemoryPointer.new :char, SimpleStruct.size
 b = SimpleStruct.new pointer
 b[:value] = 45.6
 c = SimpleStruct.new pointer
 puts "c[:value]=#{c[:value]}"

 class ComplexStruct < FFI::Struct 
 	layout :context, :pointer,
 		:value1, :int32,
 		:value2, :uint64,
 		:value3, :char,
 		:next, :pointer
 end

 def cast_to_complex_struct(pointer)
 	ComplexStruct.new pointer
 end

my_struct = cast_to_complex_struct(FFI::MemoryPointer.new :char,ComplexStruct.size)
my_struct[:value1] = rand(1000)
my_struct[:value2] = 23

class MyArray < FFI::Struct 
	layout :value, :uint8,
		:string,[:uint8,20]
end

as = MyArray.new
#as[:string][0]=33
as[:string].to_ptr.put_string(0,"foo")
puts as[:string].to_ptr.read_string

aa = CryptLib::CRYPT_QUERY_INFO.new
aa[:blockSize] = 34
puts aa[:blockSize]


bb = CryptLib::CRYPT_OBJECT_INFO.new
bb[:cryptAlgo] = 1
puts bb[:cryptAlgo]


p "now testing the cryptlib functions..."

p 'encrypting the data'
CryptLib.cryptInit()

CryptLib.cryptAddRandom(nil,CryptLib::CRYPT_RANDOM_SLOWPOLL)
pcryptEnvelope = FFI::MemoryPointer.new :int 
status = CryptLib.cryptCreateEnvelope(pcryptEnvelope,CryptLib::CRYPT_UNUSED,:CRYPT_FORMAT_CRYPTLIB)
puts "status=#{status}"
if CryptLib.cryptStatusOK(status)
	puts "create envelope succeed"
end


cryptEnvelope = pcryptEnvelope.get_int(0)
text = "hello ruby and ffi, I am succeed!"
CryptLib.cryptSetAttributeString(cryptEnvelope,:CRYPT_ENVINFO_PASSWORD,"123456",6)
pbytesCopied = FFI::MemoryPointer.new :int 
status = CryptLib.cryptPushData(cryptEnvelope,text,text.length(),pbytesCopied)
puts "bytesCopied = #{pbytesCopied.get_int(0)}"
status = CryptLib.cryptFlushData(cryptEnvelope)
penvelopedData = FFI::MemoryPointer.new  :char,300
p status
status = CryptLib.cryptPopData(cryptEnvelope,penvelopedData,300,pbytesCopied)
p status
envelopedData = penvelopedData.get_bytes(0,300)
puts "bytesCopied = #{pbytesCopied.get_int(0)}"
puts envelopedData
CryptLib.cryptDestroyEnvelope(cryptEnvelope)


#decode string
pcryptEnvelope2 = FFI::MemoryPointer.new :int
status = CryptLib.cryptCreateEnvelope(pcryptEnvelope2,CryptLib::CRYPT_UNUSED,:CRYPT_FORMAT_AUTO)
p status
cryptEnvelope2 = pcryptEnvelope2.get_int(0)

pbytesCopied2 = FFI::MemoryPointer.new :int 

status = CryptLib.cryptPushData(cryptEnvelope2,penvelopedData,300,pbytesCopied2)
p status
status = CryptLib.cryptSetAttributeString(cryptEnvelope2,:CRYPT_ENVINFO_PASSWORD,"123456",6)
p status
bytesCopied2 = pbytesCopied2.get_int(0)
puts "bytesCopied2 = #{bytesCopied2}"
CryptLib.cryptFlushData(cryptEnvelope2)

pdecryptedData = FFI::MemoryPointer.new :char,60
CryptLib.cryptPopData(cryptEnvelope2,pdecryptedData,60,pbytesCopied2)
bytesCopied2 = pbytesCopied2.get_int(0)
puts pdecryptedData.get_string(0,60)
puts "bytesCopied2 = #{bytesCopied2}"
CryptLib.cryptEnd()

