Useful resources:

- [MS-KILE - Kerberos Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)
- [Kerberos Network Authentication Service - V5](https://datatracker.ietf.org/doc/html/rfc4120)
- [The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows](https://datatracker.ietf.org/doc/rfc4757/)
- [Kerberos Parameters](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)


Debugging enc_part responses of AS_REP:
```ruby
enc_part = "d5b664f9385aab2a81850a6ca5fe3d7c9333995e3319097e9e089a1fb2ae60480ce9ef94dee65c3c742ce34bffcc8563375b48bb08cf0702605df111d052ad27508bb5cbb855600ddfd53fe473ce5ac09394552243d9dd8d90"
encrypted_data = Rex::Proto::Kerberos::Model::EncryptedData.new; encrypted_data.etype = 23; encrypted_data.kvno = 2; encrypted_data.cipher = [enc_part].pack('H*'); decrypted = encrypted_data.decrypt(password_digest, Rex::Proto::Kerberos::Crypto::ENC_AS_RESPONSE); Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypted)
```

Debugging 

Useful Wireshark configuration, to debug the encrypted Kerberos tickets:

- https://docs.axway.com/bundle/axway-open-docs/page/docs/apigtw_kerberos/wireshark_tracing_for_kerberos_auth/index.html

Example: First generate a keytab from the Windows domain controller, assuming you have changed the password of the krbtgt account:

```
ktpass -princ krbtgt@ADF3.LOCAL -pass p4$$w0rd -out foo.keytab -ptype KRB5_NT_PRINCIPAL
```

Generate keytab for user account:
```
ktpass /crypto All /mapuser a /princ dc3.adf3.local/a@ADF3.LOCAL /pass p4$$w0rd /out new_foo1.keytab /ptype KRB5_NT_PRINCIPAL
```

Generate keytab for krbtgt account:
```
ktpass /crypto All /mapuser adf3.local@ADF3.local /princ dc3.adf3.local/krbtgt@ADF3.LOCAL /pass p4$$w0rd /out kerb.keytab /ptype KRB5_NT_PRINCIPAL
```

TODO: Join them


Generate a keytab which contains both the krbtgt account and the principal name:


User:

```

```

Now from your kerberos module:

```
msf6 auxiliary(gather/kerberos_test) > rerun smb://adf3.local;a:p4$$w0rd@192.168.123.243:88 domain=adf3.local user_file=/tmp/users.txt verbose=true
```

https://stackoverflow.com/questions/69192600/wireshark-kerberos-decrypt-shows-error-missing-keytype-18
krypto all
