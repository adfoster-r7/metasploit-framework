# -*- coding: binary -*-

require 'rex/proto/kerberos/crypto/rc4_hmac'
require 'rex/proto/kerberos/crypto/rsa_md5'

module Rex
  module Proto
    module Kerberos
      module Crypto

        include Rex::Proto::Kerberos::Crypto::Rc4Hmac
        include Rex::Proto::Kerberos::Crypto::RsaMd5

        DES_CBC_MD5 = 3
        RSA_MD5 = 7
        AES128_CTS_HMAC_SHA1_96 = 17
        AES256_CTS_HMAC_SHA1_96 = 18
        RC4_HMAC = 23

        # Defined within rfc4120#section-5.5.1 - A unique number used as part of encryption to make certain types of
        # cryptographic attacks harder
        module EncKey
          TGS_REQ_AUTHENTICATOR = 7
          REQUEST_BODY = 10
          AS_RESPONSE = 8
          TGS_RESPONSE = 9
          AP_REQ_AUTHENTICATOR = 11
        end
      end
    end

  end
end
