import register_crypto_plugin

key1_private = register_crypto_plugin.PrivateEccKeyProxy.create_from_der_fmt(
    b"0w\x02\x01\x01\x04 \xafg~\x86R\x07H!\xc6{\xb8I5\xb86{JG;\xd7\x05\x1bLA"
    b"\xdd\x0c\x97r6\t\xdb>\xa0\n\x06\x08*\x86H\xce=\x03\x01\x07\xa1D\x03B\x00"
    b"\x04N\xa5\x98S\x8dc\x92\xea\x86\xd3\x16O\xf1T<\xa3\xac\x00w\xfeu.\x10IU"
    b"\xb8\x8c\xa7_,\x87\xfaE\x84\x1d\xe9\x10\xdd\xce\x01\xce\xb0\xb8\xd3\xd8U"
    b"\x1d1\x98\xe7o \xf0RV\x89\xf0\x12\x85u\xf7\\JS"
)
key1_public = register_crypto_plugin.PublicEccKeyProxy.create_from_der_fmt(
    b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B"
    b"\x00\x04N\xa5\x98S\x8dc\x92\xea\x86\xd3\x16O\xf1T<\xa3\xac\x00w\xfeu.\x10"
    b"IU\xb8\x8c\xa7_,\x87\xfaE\x84\x1d\xe9\x10\xdd\xce\x01\xce\xb0\xb8\xd3\xd8"
    b"U\x1d1\x98\xe7o \xf0RV\x89\xf0\x12\x85u\xf7\\JS"
)
key2_private = register_crypto_plugin.PrivateEccKeyProxy.create_from_der_fmt(
    b"0w\x02\x01\x01\x04 \x96\xf9sz\xe0\x9eJ\x12\xd8c\x96\x89\xdc4Kwf/\xdd\xa7U"
    b"\xc8\xac\xa7\xf6\r\x13\xb3\x10\xbf\x03\xf3\xa0\n\x06\x08*\x86H\xce=\x03"
    b"\x01\x07\xa1D\x03B\x00\x04iV\xb3\xbbZ\x01,\xbd\x04\x17\xb6\xd3\x01\x15Y"
    b"\xeb\x9b.h~'\x85\x1c\x83$\xe2\x7f*\xf5\x162\xdd\x8c\x19\xfdr\x8e;\x9c\xea"
    b"\xacA\xdd6j\x13\xe3\x19\x95I{b\xea{\x1c\xf3\xfa\xc8\x16wS\x91,g"
)
key2_public = register_crypto_plugin.PublicEccKeyProxy.create_from_der_fmt(
    b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B"
    b"\x00\x04iV\xb3\xbbZ\x01,\xbd\x04\x17\xb6\xd3\x01\x15Y\xeb\x9b.h~'\x85\x1c"
    b"\x83$\xe2\x7f*\xf5\x162\xdd\x8c\x19\xfdr\x8e;\x9c\xea\xacA\xdd6j\x13\xe3"
    b"\x19\x95I{b\xea{\x1c\xf3\xfa\xc8\x16wS\x91,g"
)

assert key1_private.compute_dh_secret(key2_public) == key2_private.compute_dh_secret(
    key1_public
)
