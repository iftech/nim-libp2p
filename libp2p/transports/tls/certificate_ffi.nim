# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import boringssl
import strutils
import results

const LIBP2P_OID = "1.3.6.1.4.1.53594.1.1"

const
  MBSTRING_FLAG* = 0x1000
  MBSTRING_UTF8* = MBSTRING_FLAG
  MBSTRING_ASC* = MBSTRING_FLAG or 1
  MBSTRING_BMP* = MBSTRING_FLAG or 2
  MBSTRING_UNIV* = MBSTRING_FLAG or 4

type CertError* = int32

const
  CERT_ERROR_NULL_PARAM* = CertError(-1)
  CERT_ERROR_MEMORY* = CertError(-2)
  CERT_ERROR_DRBG_INIT* = CertError(-3)
  CERT_ERROR_DRBG_CONFIG* = CertError(-4)
  CERT_ERROR_DRBG_SEED* = CertError(-5)
  CERT_ERROR_KEY_GEN* = CertError(-6)
  CERT_ERROR_CERT_GEN* = CertError(-7)
  CERT_ERROR_EXTENSION_GEN* = CertError(-8)
  CERT_ERROR_EXTENSION_ADD* = CertError(-9)
  CERT_ERROR_EXTENSION_DATA* = CertError(-10)
  CERT_ERROR_BIO_GEN* = CertError(-11)
  CERT_ERROR_SIGN* = CertError(-12)
  CERT_ERROR_ENCODING* = CertError(-13)
  CERT_ERROR_PARSE* = CertError(-14)
  CERT_ERROR_RAND* = CertError(-15)
  CERT_ERROR_ECKEY_GEN* = CertError(-16)
  CERT_ERROR_BIGNUM_CONV* = CertError(-17)
  CERT_ERROR_SET_KEY* = CertError(-18)
  CERT_ERROR_VALIDITY_PERIOD* = CertError(-19)
  CERT_ERROR_BIO_WRITE* = CertError(-20)
  CERT_ERROR_SERIAL_WRITE* = CertError(-21)
  CERT_ERROR_EVP_PKEY_EC_KEY* = CertError(-22)
  CERT_ERROR_X509_VER* = CertError(-23)
  CERT_ERROR_BIGNUM_GEN* = CertError(-24)
  CERT_ERROR_X509_NAME* = CertError(-25)
  CERT_ERROR_X509_CN* = CertError(-26)
  CERT_ERROR_X509_SUBJECT* = CertError(-27)
  CERT_ERROR_X509_ISSUER* = CertError(-28)
  CERT_ERROR_ASN1_TIME_GEN* = CertError(-29)
  CERT_ERROR_PUBKEY_SET* = CertError(-30)
  CERT_ERROR_ASN1_OCTET* = CertError(-31)
  CERT_ERROR_X509_READ* = CertError(-32)
  CERT_ERROR_PUBKEY_GET* = CertError(-33)
  CERT_ERROR_EXTENSION_NOT_FOUND* = CertError(-34)
  CERT_ERROR_EXTENSION_GET* = CertError(-35)
  CERT_ERROR_DECODE_SEQUENCE* = CertError(-36)
  CERT_ERROR_NOT_ENOUGH_SEQ_ELEMS* = CertError(-37)
  CERT_ERROR_NOT_OCTET_STR* = CertError(-38)
  CERT_ERROR_NID* = CertError(-39)
  CERT_ERROR_PUBKEY_DER_LEN* = CertError(-40)
  CERT_ERROR_PUBKEY_DER_CONV* = CertError(-41)
  CERT_ERROR_INIT_KEYGEN* = CertError(-42)
  CERT_ERROR_SET_CURVE* = CertError(-43)
  CERT_ERROR_X509_REQ_GEN* = CertError(-44)
  CERT_ERROR_X509_REQ_DER* = CertError(-45)
  CERT_ERROR_NO_PUBKEY* = CertError(-46)
  CERT_ERROR_X509_SAN* = CertError(-47)
  CERT_ERROR_CN_TOO_LONG* = CertError(-48)
  CERT_ERROR_CN_LABEL_TOO_LONG* = CertError(-49)
  CERT_ERROR_CN_EMPTY_LABEL* = CertError(-50)
  CERT_ERROR_CN_EMPTY* = CertError(-51)
  CERT_ERROR_ASN1_ENCODE* = CertError(-52)

type
  cert_format_t* = enum
    CERT_FORMAT_DER = 0
    CERT_FORMAT_PEM = 1

  ParsedCertificate = object
    signature*: seq[byte]
    identPubk*: seq[byte]
    certPubk*: seq[byte]
    validFrom*: string
    validTo*: string

  CertificateKey* = object
    pkey: ptr EVP_PKEY

template notNil(v: untyped, code: untyped): untyped =
  block:
    let tmp = v
    if tmp.isNil:
      return err(code)
    tmp

template checkIs1(v: untyped, code: untyped) =
  block:
    let tmp = v
    if tmp <= 0:
      return err(code)

proc cert_generate_key*(): Result[CertificateKey, CertError] =
  let kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil).notNil(CERT_ERROR_EVP_PKEY_EC_KEY)
  defer:
    EVP_PKEY_CTX_free(kctx)

  EVP_PKEY_keygen_init(kctx).checkIs1(CERT_ERROR_EVP_PKEY_EC_KEY)

  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1).checkIs1(
    CERT_ERROR_ECKEY_GEN
  )

  var pkey: ptr EVP_PKEY
  EVP_PKEY_keygen(kctx, pkey.addr).checkIs1(CERT_ERROR_KEY_GEN)

  return ok(CertificateKey(pkey: pkey))

proc cert_new_key_t*(seckey: seq[byte]): Result[CertificateKey, CertError] =
  if seckey.len == 0:
    return err(CERT_ERROR_NULL_PARAM)

  let bio =
    BIO_new_mem_buf(seckey[0].addr, ossl_ssize_t(seckey.len)).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  let pkey = d2i_PrivateKey_bio(bio, nil).notNil(CERT_ERROR_BIO_GEN)
  ok(CertificateKey(pkey: pkey))

proc bioToSeq*(bio: ptr BIO): Result[seq[byte], CertError] =
  let bptr: ptr BUF_MEM = nil
  BIO_get_mem_ptr(bio, bptr.addr).checkIs1(CERT_ERROR_BIO_GEN)
  discard bptr.notNil(CERT_ERROR_BIO_GEN)
  let outp =
    if bptr.length > 0:
      let seqb = newSeqUninit[byte](bptr.length)
      copyMem(addr seqb[0], cast[ptr byte](bptr.data), seqb.len)
      seqb
    else:
      return err(CERT_ERROR_BIO_GEN)
  ok(outp)

proc cert_serialize_privk*(
    key: CertificateKey, format: cert_format_t
): Result[seq[byte], CertError] =
  if key.pkey.isNil:
    return err(CERT_ERROR_NULL_PARAM)

  let bio = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  if format == CERT_FORMAT_DER:
    i2d_PrivateKey_bio(bio, key.pkey).checkIs1(CERT_ERROR_BIO_WRITE)
  else:
    # No encryption is used (NULL cipher, NULL password)
    PEM_write_bio_PrivateKey(bio, key.pkey, nil, nil, 0, nil, nil).checkIs1(
      CERT_ERROR_BIO_WRITE
    )
  ok(?bioToSeq(bio))

proc cert_serialize_pubk*(
    key: CertificateKey, format: cert_format_t
): Result[seq[byte], CertError] =
  if key.pkey.isNil:
    return err(CERT_ERROR_NULL_PARAM)

  let bio = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  if format == CERT_FORMAT_DER:
    i2d_PUBKEY_bio(bio, key.pkey).checkIs1(CERT_ERROR_BIO_WRITE)
  else:
    # No encryption is used (NULL cipher, NULL password)
    PEM_write_bio_PUBKEY(bio, key.pkey).checkIs1(CERT_ERROR_BIO_WRITE)

  ok(?bioToSeq(bio))

proc ensure_libp2p_oid(): Result[int, CertError] =
  var nid = OBJ_txt2nid(LIBP2P_OID.cstring)
  if nid == NID_undef:
    # OID not yet registered, create it
    nid = OBJ_create(LIBP2P_OID, "libp2p_tls", "libp2p TLS extension")
    if nid <= 0:
      return err(CERT_ERROR_NID)
  return ok(nid)

proc cert_generate*(
    key: CertificateKey,
    signature: seq[byte],
    ident_pubk: seq[byte],
    cn: string,
    validFrom: cstring,
    validTo: cstring,
    format: cert_format_t,
): Result[seq[byte], CertError] =
  if key.pkey.isNil:
    return err(CERT_ERROR_NULL_PARAM)
  if signature.len == 0 or ident_pubk.len == 0:
    return err(CERT_ERROR_EXTENSION_DATA)

  let x509 = X509_new().notNil(CERT_ERROR_CERT_GEN)
  defer:
    X509_free(x509)

  X509_set_version(x509, 2).checkIs1(CERT_ERROR_X509_VER)

  var serial_bytes: array[20, byte] # Adjust size as needed
  RAND_bytes(serial_bytes[0].addr, sizeof(serial_bytes).csize_t).checkIs1(
    CERT_ERROR_RAND
  )
  var serial_bn = BN_new().notNil(CERT_ERROR_BIGNUM_GEN)
  defer:
    BN_free(serial_bn)
  discard BN_bin2bn(serial_bytes[0].addr, 20, serial_bn).notNil(CERT_ERROR_BIGNUM_CONV)
  discard BN_to_ASN1_INTEGER(serial_bn, X509_get_serialNumber(x509)).notNil(
      CERT_ERROR_SERIAL_WRITE
    )

  # Set subject and issuer using the provided cn
  let name = X509_NAME_new().notNil(CERT_ERROR_X509_NAME)
  defer:
    X509_NAME_free(name)

  X509_NAME_add_entry_by_txt(
    name,
    "CN".cstring,
    MBSTRING_ASC,
    cast[ptr uint8](cn.cstring),
    ossl_ssize_t(cn.len),
    -1,
    0,
  )
    .checkIs1(CERT_ERROR_X509_CN)
  X509_set_subject_name(x509, name).checkIs1(CERT_ERROR_X509_SUBJECT)
  X509_set_issuer_name(x509, name).checkIs1(CERT_ERROR_X509_ISSUER)

  # Set validity period
  let start_time = ASN1_TIME_new().notNil(CERT_ERROR_ASN1_TIME_GEN)
  defer:
    ASN1_TIME_free(start_time)

  let end_time = ASN1_TIME_new().notNil(CERT_ERROR_ASN1_TIME_GEN)
  defer:
    ASN1_TIME_free(end_time)

  ASN1_TIME_set_string(start_time, validFrom).checkIs1(CERT_ERROR_VALIDITY_PERIOD)
  X509_set1_notBefore(x509, start_time).checkIs1(CERT_ERROR_VALIDITY_PERIOD)

  ASN1_TIME_set_string(end_time, validTo).checkIs1(CERT_ERROR_VALIDITY_PERIOD)
  X509_set1_notAfter(x509, end_time).checkIs1(CERT_ERROR_VALIDITY_PERIOD)

  X509_set_pubkey(x509, key.pkey).checkIs1(CERT_ERROR_PUBKEY_SET)

  # Add custom extension
  let nid = ?ensure_libp2p_oid()

  let oct_pubk = ASN1_OCTET_STRING_new().notNil(CERT_ERROR_ASN1_OCTET)
  defer:
    ASN1_OCTET_STRING_free(oct_pubk)
  ASN1_OCTET_STRING_set(oct_pubk, ident_pubk[0].addr, ident_pubk.len.cint).checkIs1(
    CERT_ERROR_EXTENSION_DATA
  )

  let oct_sign = ASN1_OCTET_STRING_new().notNil(CERT_ERROR_ASN1_OCTET)
  defer:
    ASN1_OCTET_STRING_free(oct_sign)
  ASN1_OCTET_STRING_set(oct_sign, signature[0].addr, signature.len.cint).checkIs1(
    CERT_ERROR_EXTENSION_DATA
  )

  # Calculate DER-encoded lengths of the OCTET STRINGs
  let oct_pubk_len = i2d_ASN1_OCTET_STRING(oct_pubk, nil)
  let oct_sign_len = i2d_ASN1_OCTET_STRING(oct_sign, nil)
  let seq_len = oct_pubk_len + oct_sign_len

  let # Compute the exact required length for the SEQUENCE
    total_len = ASN1_object_size(1, seq_len, V_ASN1_SEQUENCE)

  # Allocate the exact required space
  let seq_der: ptr uint8 =
    cast[ptr uint8](OPENSSL_malloc(total_len.csize_t)).notNil(CERT_ERROR_MEMORY)
  defer:
    OPENSSL_free(seq_der)

  # Encode the sequence. p is moved fwd as it is written
  var p = seq_der
  ASN1_put_object(p.addr, 1.cint, seq_len.cint, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)
  if i2d_ASN1_OCTET_STRING(oct_pubk, p.addr) < 0:
    return err(CERT_ERROR_ASN1_ENCODE)
  if i2d_ASN1_OCTET_STRING(oct_sign, p.addr) < 0:
    return err(CERT_ERROR_ASN1_ENCODE)

  # Wrap the encoded sequence in an ASN1_OCTET_STRING
  let ext_oct = ASN1_OCTET_STRING_new().notNil(CERT_ERROR_ASN1_OCTET)
  defer:
    ASN1_OCTET_STRING_free(ext_oct)
  ASN1_OCTET_STRING_set(ext_oct, seq_der, total_len).checkIs1(CERT_ERROR_EXTENSION_DATA)

  # Create extension with the octet string
  let ex = X509_EXTENSION_create_by_NID(nil, nid.cint, 0, ext_oct).notNil(
      CERT_ERROR_EXTENSION_GEN
    )
  defer:
    X509_EXTENSION_free(ex)

  X509_add_ext(x509, ex, -1).checkIs1(CERT_ERROR_EXTENSION_ADD)

  X509_sign(x509, key.pkey, EVP_sha256()).checkIs1(CERT_ERROR_SIGN)

  # Convert to requested format (DER or PEM)
  let bio = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  if format == CERT_FORMAT_DER:
    i2d_X509_bio(bio, x509).checkIs1(CERT_ERROR_BIO_WRITE)
  else: # PEM format
    PEM_write_bio_X509(bio, x509).checkIs1(CERT_ERROR_BIO_WRITE)

  ok(?bioToSeq(bio))

proc cert_parse*(
    cert: seq[byte], format: cert_format_t
): Result[ParsedCertificate, CertError] =
  if cert.len == 0:
    return err(CERT_ERROR_PARSE)

  let bio =
    BIO_new_mem_buf(cert[0].addr, ossl_ssize_t(cert.len)).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  let x509 = (
    if format == CERT_FORMAT_DER:
      d2i_X509_bio(bio, nil)
    else:
      PEM_read_bio_X509(bio, nil, nil, nil)
  ).notNil(CERT_ERROR_X509_READ)
  defer:
    X509_free(x509)

  # Find custom extension by OID - use the existing OID or create it if needed
  let nid = ?ensure_libp2p_oid()
  let extension_index = X509_get_ext_by_NID(x509, nid.cint, -1)
  if extension_index < 0:
    return err(CERT_ERROR_EXTENSION_NOT_FOUND)

  # Get extension
  let ex = X509_get_ext(x509, extension_index).notNil(CERT_ERROR_EXTENSION_GET)

  # Get extension data
  let ext_data = X509_EXTENSION_get_data(ex).notNil(CERT_ERROR_EXTENSION_DATA)
  let ext_data_len = ASN1_STRING_length(ext_data)
  if ext_data_len <= 0:
    return err(CERT_ERROR_EXTENSION_DATA)

  # Point to the data
  # const unsigned char *p;
  let p = ASN1_STRING_get0_data(ext_data).notNil(CERT_ERROR_EXTENSION_DATA)

  let as1Seq =
    d2i_ASN1_SEQUENCE_ANY(nil, p.addr, ext_data_len).notNil(CERT_ERROR_DECODE_SEQUENCE)
  defer:
    let proc1 = proc(freeFunc: OPENSSL_sk_free_func, v: pointer) {.cdecl.} =
      freeFunc(v)
    OPENSSL_sk_pop_free_ex(
      cast[ptr OPENSSL_STACK](as1Seq), proc1, cast[OPENSSL_sk_free_func](ASN1_TYPE_free)
    )

  # Check if we have exactly two items in the sequence
  if OPENSSL_sk_num(cast[ptr OPENSSL_STACK](as1Seq)) != 2:
    return err(CERT_ERROR_NOT_ENOUGH_SEQ_ELEMS)

  # Get the first octet string
  let type1 =
    cast[ptr ASN1_TYPE](OPENSSL_sk_value(cast[ptr OPENSSL_STACK](as1Seq), 0.csize_t))
  if type1.type_field != V_ASN1_OCTET_STRING:
    return err(CERT_ERROR_NOT_OCTET_STR)
  let oct1 = type1.value.octet_string
  let oct1_len = ASN1_STRING_length(oct1)
  if oct1_len <= 0:
    return err(CERT_ERROR_EXTENSION_DATA)
  let oct1_data = ASN1_STRING_get0_data(oct1).notNil(CERT_ERROR_EXTENSION_DATA)

  # Get the second octet string
  let type2 =
    cast[ptr ASN1_TYPE](OPENSSL_sk_value(cast[ptr OPENSSL_STACK](as1Seq), 1.csize_t))
  if type2.type_field != V_ASN1_OCTET_STRING:
    return err(CERT_ERROR_NOT_OCTET_STR)
  let oct2 = type2.value.octet_string
  let oct2_len = ASN1_STRING_length(oct2)
  if oct2_len <= 0:
    return err(CERT_ERROR_EXTENSION_DATA)
  let oct2_data = ASN1_STRING_get0_data(oct2).notNil(CERT_ERROR_EXTENSION_DATA)

  let ident_pubk = newSeqUninit[byte](oct1_len)
  copyMem(addr ident_pubk[0], oct1_data, oct1_len)

  let signature = newSeqUninit[byte](oct2_len)
  copyMem(addr signature[0], oct2_data, oct2_len)

  # Get public key
  let pkey = X509_get_pubkey(x509).notNil(CERT_ERROR_PUBKEY_GET)
  defer:
    EVP_PKEY_free(pkey)

  let pubkey_len = i2d_PUBKEY(pkey, nil)
  if (pubkey_len <= 0):
    return err(CERT_ERROR_PUBKEY_DER_LEN)

  var pubkey_buf = OPENSSL_malloc(pubkey_len.csize_t).notNil(CERT_ERROR_MEMORY)
  defer:
    OPENSSL_free(pubkey_buf)
  var temp = cast[ptr uint8](pubkey_buf)
  i2d_PUBKEY(pkey, temp.addr).checkIs1(CERT_ERROR_PUBKEY_DER_CONV)

  let cert_pubkey = newSeqUninit[byte](pubkey_len)
  copyMem(addr cert_pubkey[0], pubkey_buf, pubkey_len)

  let not_before = X509_get0_notBefore(x509)
  var valid_from = ""
  if not not_before.isNil:
    # Convert ASN1_TIME to a more usable format
    let bio_nb = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_MEMORY)
    defer:
      discard BIO_free(bio_nb)
    if ASN1_TIME_print(bio_nb, not_before) == 1:
      let plen = BIO_ctrl(bio_nb, BIO_CTRL_PENDING, 0, nil)
      var s = newString(plen)
      BIO_read(bio_nb, s[0].addr, plen.cint).checkIs1(CERT_ERROR_MEMORY)
      valid_from = s

  let not_after = X509_get0_notAfter(x509)
  var valid_to = ""
  if not not_after.isNil:
    # Convert ASN1_TIME to a more usable format
    let bio_nb = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_MEMORY)
    defer:
      discard BIO_free(bio_nb)
    if ASN1_TIME_print(bio_nb, not_after) == 1:
      let plen = BIO_ctrl(bio_nb, BIO_CTRL_PENDING, 0, nil)
      var s = newString(plen)
      BIO_read(bio_nb, s[0].addr, plen.cint).checkIs1(CERT_ERROR_MEMORY)
      valid_to = s

  return ok(
    ParsedCertificate(
      signature: signature,
      identPubk: ident_pubk,
      certPubk: cert_pubkey,
      validFrom: valid_from,
      validTo: valid_to,
    )
  )

proc cert_valid_to*(cert: seq[byte], format: cert_format_t): Result[string, CertError] =
  ## Returns the notAfter value without requiring a libp2p-specific extension.
  ##
  ## This is useful for certificates issued by external CAs, which do not carry
  ## the extension parsed by `cert_parse`.
  if cert.len == 0:
    return err(CERT_ERROR_PARSE)

  let bio =
    BIO_new_mem_buf(cert[0].addr, ossl_ssize_t(cert.len)).notNil(CERT_ERROR_BIO_GEN)
  defer:
    discard BIO_free(bio)

  let x509 = (
    if format == CERT_FORMAT_DER:
      d2i_X509_bio(bio, nil)
    else:
      PEM_read_bio_X509(bio, nil, nil, nil)
  ).notNil(CERT_ERROR_X509_READ)
  defer:
    X509_free(x509)

  let notAfter = X509_get0_notAfter(x509).notNil(CERT_ERROR_VALIDITY_PERIOD)
  let timeBio = BIO_new(BIO_s_mem()).notNil(CERT_ERROR_MEMORY)
  defer:
    discard BIO_free(timeBio)
  if ASN1_TIME_print(timeBio, notAfter) != 1:
    return err(CERT_ERROR_VALIDITY_PERIOD)

  let length = BIO_ctrl(timeBio, BIO_CTRL_PENDING, 0, nil)
  if length <= 0:
    return err(CERT_ERROR_VALIDITY_PERIOD)
  var validTo = newString(length)
  BIO_read(timeBio, validTo[0].addr, length.cint).checkIs1(CERT_ERROR_VALIDITY_PERIOD)
  ok(validTo)

proc cert_free_key*(key: CertificateKey): void =
  if key.pkey.isNil:
    return
  EVP_PKEY_free(key.pkey)

proc check_cn(cn: string): Result[void, CertError] =
  ## Function to check if a Common Name is correct
  ## each label should have <= 63 characters
  ## the whole CN should have <= 253 characters

  if cn.len == 0:
    return err(CERT_ERROR_CN_EMPTY)

  if cn.len > 253:
    return err(CERT_ERROR_CN_TOO_LONG)

  var s = cn
  # trim trailing dot if any before checking
  if s[^1] == '.':
    s.setLen(s.len - 1)

  for label in s.split("."):
    # detect empty label (like example..com)
    if label.len == 0:
      return err(CERT_ERROR_CN_EMPTY_LABEL)
    if label.len > 63:
      return err(CERT_ERROR_CN_LABEL_TOO_LONG)

  ok()

proc cert_signing_req*(cn: string, key: CertificateKey): Result[seq[byte], CertError] =
  ?check_cn(cn)

  if key.pkey.isNil:
    return err(CERT_ERROR_NO_PUBKEY)

  let x509_req = X509_REQ_new().notNil(CERT_ERROR_X509_REQ_GEN)
  defer:
    X509_REQ_free(x509_req)

  X509_REQ_set_pubkey(x509_req, key.pkey).checkIs1(CERT_ERROR_PUBKEY_SET)

  # Build SAN extension
  var ctx: X509V3_CTX
  X509V3_set_ctx(ctx.addr, nil, nil, x509_req, nil, 0)

  let sanStr = "DNS:" & cn
  let ext = X509V3_EXT_conf_nid(nil, ctx.addr, NID_subject_alt_name, sanStr.cstring)
    .notNil(CERT_ERROR_X509_SAN)
  let exts = OPENSSL_sk_new_null().notNil(CERT_ERROR_X509_SAN)
  defer:
    let proc1 = proc(freeFunc: OPENSSL_sk_free_func, v: pointer) {.cdecl.} =
      freeFunc(v)
    OPENSSL_sk_pop_free_ex(
      cast[ptr OPENSSL_STACK](exts),
      proc1,
      cast[OPENSSL_sk_free_func](X509_EXTENSION_free),
    )

  OPENSSL_sk_push(exts, ext).checkIs1(CERT_ERROR_X509_SAN)

  X509_REQ_add_extensions(x509_req, cast[ptr struct_stack_st_X509_EXTENSION](exts))
    .checkIs1(CERT_ERROR_X509_SAN)

  if X509_REQ_sign(x509_req, key.pkey, EVP_sha256()) <= 0:
    return err(CERT_ERROR_SIGN)

  var der: ptr uint8 = nil
  let der_len = i2d_X509_REQ(x509_req, der.addr)
  if der_len < 0:
    return err(CERT_ERROR_X509_REQ_DER)
  defer:
    OPENSSL_free(der)

  var outp = newSeqUninit[byte](der_len)
  copyMem(outp[0].addr, der, der_len)
  ok(outp)
