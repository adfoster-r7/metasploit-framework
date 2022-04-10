# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        VERSION = 5

        # Application Message Id's

        AS_REQ = 10
        AS_REP = 11
        TGS_REQ = 12
        TGS_REP = 13
        KRB_ERROR = 30
        TICKET = 1
        AUTHENTICATOR = 2
        AP_REQ = 14

        # From Principal
        # https://datatracker.ietf.org/doc/html/rfc4120#section-6.2

        # Name type not known
        NT_UNKNOWN = 0
        # The name of the principal
        NT_PRINCIPAL = 1
        # Service and other unique instances
        NT_SRV_INST = 2
        # Service with host name and instance
        NT_SRV_HST = 3
        # Service with host as remaining component
        NT_SRV_XHST = 4
        # Unique ID
        NT_UID = 5

        # TODO: Find a docs link for this other than wireshark/impacket
        # wireshark: https://github.com/wireshark/wireshark/blob/85df6d0273d8d52e9399d7d25c744a0ecd48f657/epan/dissectors/asn1/kerberos/k5.asn
        # impacket: https://github.com/SecureAuthCorp/impacket/blob/cd4fe47cfcb72d7d35237a99e3df95cedf96e94f/impacket/krb5/constants.py#L64
        #   Has comment with:
        #     #   Constants for krb5.asn1 package. I took them out from the RFC plus
        #     #   some data from [MS-KILE] as well.
        # mit krb5: https://github.com/krb5/krb5/blob/cd61bdcd6339b10e6cf3feb9f6cb369213e8d7fc/src/include/krb5/krb5.hin#L253-L255
        #
        # Microsoft's protocol testing doesn't have it:
        # https://github.com/microsoft/WindowsProtocolTestSuites/blob/03b3906b9745be72b1852f7ec6ac28ca838029b6/ProtoSDK/KerberosLib/Types/BasicTypes.cs#L1058-L1101
        #
        # Rubeus doesn't have it:
        # https://github.com/GhostPack/Rubeus/blob/89f1d1a2b6be43da5f0a8ff9950f45956c3f3cad/Rubeus/lib/Interop.cs#L203-L215
        #
        #
        # Older constants defined here:
        #   https://datatracker.ietf.org/doc/html/rfc4120#section-6.2
        #
        # Still can't find where NT_MS_PRINCIPAL is defined
        NT_MS_PRINCIPAL = -128

        # From padata

        PA_TGS_REQ = 1
        PA_ENC_TIMESTAMP = 2
        PA_PW_SALT = 3
        PA_PAC_REQUEST = 128

        AD_IF_RELEVANT = 1
      end
    end
  end
end

