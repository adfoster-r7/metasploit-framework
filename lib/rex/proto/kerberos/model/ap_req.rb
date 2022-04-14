# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a KRB_AP_REQ definition, containing the Kerberos protocol version number,
        # the message type KRB_AP_REQ, an options field to indicate any options in use, and the ticket and authenticator
        # themselves
        class ApReq < Element
          # @!attribute pvno
          #   @return [Integer] The protocol version number
          attr_accessor :pvno
          # @!attribute msg_type
          #   @return [Integer] The type of the protocol message
          attr_accessor :msg_type
          # @!attribute options
          #   @return [Integer] request options, affects processing
          attr_accessor :options
          # @!attribute ticket
          #   @return [Rex::Proto::Kerberos::Model::Ticket] The ticket authenticating the client to the server
          attr_accessor :ticket
          # @!attribute authenticator
          #   @return [Rex::Proto::Kerberos::Model::EncryptedData] This contains the authenticator, which includes the
          #   client's choice of a subkey
          attr_accessor :authenticator

          # Rex::Proto::Kerberos::Model::ApReq decoding isn't supported
          #
          # @raise [NotImplementedError]
          def decode(input)
            raise ::NotImplementedError, 'AP-REQ decoding not supported'
          end

          # Encodes the Rex::Proto::Kerberos::Model::ApReq into an ASN.1 String
          #
          # @return [String]
          def encode(hack_for_smb: false)
            elems = []

            # if hack_for_smb
            #
            #   elems << OpenSSL::ASN1::ASN1Data.new([RubySMB::Gss::OID_KERBEROS_5], 0, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Boolean.new(true)], 1, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([encode_pvno], 2, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 3, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([encode_options], 4, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([encode_ticket], 5, :CONTEXT_SPECIFIC)
            #   elems << OpenSSL::ASN1::ASN1Data.new([encode_authenticator], 6, :CONTEXT_SPECIFIC)
            # else
              elems << OpenSSL::ASN1::ASN1Data.new([encode_pvno], 0, :CONTEXT_SPECIFIC)
              elems << OpenSSL::ASN1::ASN1Data.new([encode_msg_type], 1, :CONTEXT_SPECIFIC)
              elems << OpenSSL::ASN1::ASN1Data.new([encode_options], 2, :CONTEXT_SPECIFIC)
              elems << OpenSSL::ASN1::ASN1Data.new([encode_ticket], 3, :CONTEXT_SPECIFIC)
              elems << OpenSSL::ASN1::ASN1Data.new([encode_authenticator], 4, :CONTEXT_SPECIFIC)
            # end
            seq = OpenSSL::ASN1::Sequence.new(elems)

            seq_asn1 = OpenSSL::ASN1::ASN1Data.new([seq], AP_REQ, :APPLICATION)

            if hack_for_smb
              return OpenSSL::ASN1::ASN1Data.new(
                [
                  RubySMB::Gss::OID_KERBEROS_5,
                  # a 2-byte TOK_ID field containing 01 00 for KRB_AP_REQ messages
                  "\x01\x00",
                  seq_asn1
                ],
                0,
                :APPLICATION
              ).to_der
            end

            seq_asn1.to_der
          end

          private

          # Encodes the pvno field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_pvno
            bn = OpenSSL::BN.new(pvno.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the msg_type field
          #
          # @return [OpenSSL::ASN1::Integer]
          def encode_msg_type
            bn = OpenSSL::BN.new(msg_type.to_s)
            int = OpenSSL::ASN1::Integer.new(bn)

            int
          end

          # Encodes the options field
          #
          # @return [OpenSSL::ASN1::BitString]
          def encode_options
            OpenSSL::ASN1::BitString.new([options].pack('N'))
          end

          # Encodes the ticket field
          #
          # @return [String]
          def encode_ticket
            ticket.encode
          end

          # Encodes the authenticator field
          #
          # @return [String]
          def encode_authenticator
            authenticator.encode
          end
        end
      end
    end
  end
end
