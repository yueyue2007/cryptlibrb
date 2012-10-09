#!/home/xinyue/.rvm/bin/ruby
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
cryptEnvelope = FFI::MemoryPointer.new :pointer
CryptLib.cryptCreateEnvelope(cryptEnvelope,CryptLib::CRYPT_UNUSED,:CRYPT_FORMAT_CRYPTLIB)
CryptLib.cryptDestroyEnvelope(cryptEnvelope)

CryptLib.cryptEnd()

