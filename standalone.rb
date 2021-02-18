# -*- coding: binary -*-

# Extracted from:
#   lib/msf/core/post/windows/priv.rb
#   spec/lib/msf/core/post/windows/priv_spec.rb

require 'openssl'

def decrypt_lsa_data(policy_secret, lsa_key)

  sha256x = Digest::SHA256.new
  sha256x << lsa_key
  1000.times do
    sha256x << policy_secret[28,32]
  end

  aes = OpenSSL::Cipher.new("aes-256-cbc")
  aes.key = sha256x.digest

  puts("digest #{sha256x.digest.unpack("H*")[0]}")

  decrypted_data = ''

  (60...policy_secret.length).step(16) do |i|
    aes.decrypt
    aes.padding = 0
    decrypted_data << aes.update(policy_secret[i,16])
  end

  return decrypted_data
end


# From "HKLM\\Security\\Policy\\Secrets\\"
ciphertext =
  "\x00\x00\x00\x01\x68\x6e\x97\x93\xdb\xdb\xde\xc8\xf7\x40\x08\x79"+
    "\x9d\x91\x64\x1c\x03\x00\x00\x00\x00\x00\x00\x00\x68\x38\x3f\xc5"+
    "\x94\x10\xac\xcf\xbe\xf7\x8d\x12\xc0\xd5\xa2\x9d\x3d\x30\x30\xa8"+
    "\x6d\xbd\xc6\x48\xd3\xe4\x36\x33\x86\x91\x0d\x8d\x8f\xfc\xd4\x8a"+
    "\x87\x0c\x83\xde\xb4\x73\x9e\x21\x1b\x39\xef\x04\x36\x67\x97\x8a"+
    "\x43\x40\x79\xcf\xdb\x3d\xcc\xfe\x10\x0c\x78\x11\x00\x00\x00\x00"+
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
lsa_key =
  "\x93\x19\xb7\xb3\x93\x5b\xcb\x53\x5c\xb0\x54\xce\x0f\x5e\x27\xfd"+
    "\x4f\xd1\xe3\xd3\x5b\x8c\x90\x4c\x13\xda\xb8\x39\xcc\x4e\x28\x43"
plaintext =
  # Length of actual data?
  "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"+
    # Unicode msfadmin
    "\x6d\x00\x73\x00\x66\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00"+
    # As far as I can tell, the rest of the data is gibberish?
    # Possibly random padding, since plaintext seems to always be a
    # multiple of 16 bytes.
    "\xc3\x5f\x85\xc2\x62\x55\x25\x6c\x42\x89\x88\xc1\xe0\xe8\x17\x5e"

decrypted = decrypt_lsa_data(ciphertext, lsa_key)
is_equal = decrypted == plaintext

puts "plaintext=#{plaintext}"
puts "decrypted=#{decrypted}"

if is_equal
  puts "Successfully decrypted"
else
  puts "Failed to decrypt successfully"
end
