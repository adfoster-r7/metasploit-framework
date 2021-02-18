#!/usr/bin/env ruby
require "openssl"
require 'digest/sha2'
require 'base64'

# We use the AES 256 bit cipher-block chaining symetric encryption
alg = "AES-256-CBC"

# We want a 256 bit key symetric key based on some passphrase
digest = Digest::SHA256.new
digest.update("symetric key")
key = digest.digest
# We could also have just created a random key
# key = OpenSSL::Cipher::Cipher.new(alg).random_key

# For security as part of the encryption algorithm, we create a random
# initialization vector.
iv = OpenSSL::Cipher::Cipher.new(alg).random_iv

# Example, we debug output our key in various formats
puts "Our key"
p key
# Base64 the key
puts "Our key base 64"
key64 = [key].pack('m')
puts key64
# Base64 decode the key
puts "Our key retrieved from base64"
p key64.unpack('m')[0]
raise 'Key Error' if(key.nil? or key.size != 32)

# Now we do the actual setup of the cipher
aes = OpenSSL::Cipher::Cipher.new(alg)
aes.key = key
aes.iv = iv
aes.encrypt

# Now we go ahead and encrypt our plain text.
cipher = aes.update("This is line 1\n")
cipher << aes.update("This is some other string without linebreak.")
cipher << aes.update("This follows immediately after period.")
cipher << aes.update("Same with this final sentence")
cipher << aes.final

puts "Our Encrypted data in base64"
cipher64 = [cipher].pack('m')
puts cipher64

decode_cipher = OpenSSL::Cipher::Cipher.new(alg)
decode_cipher.key = key
decode_cipher.iv = iv
decode_cipher.decrypt
plain = decode_cipher.update(cipher64.unpack('m')[0])
plain << decode_cipher.final
puts "Decrypted Text"
puts plain