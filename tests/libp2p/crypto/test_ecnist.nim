# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import results, nimcrypto/utils
import ../../../libp2p/crypto/[crypto, ecnist, minasn1]
import ../../tools/[unittest, crypto, der]

const
  TestsCount = 10 # number of random tests

  # Test vectors obtained from BearSSL test vectors (test_crypto.c) by
  # conversion of raw values to ASN.1 DER binary encoded form.
  SignatureSecKeys = [
    """30770201010420C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B
       8A622B120F6721A00A06082A8648CE3D030107A1440342000460FED4BA255A9D
       31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC
       99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299""",
    """30770201010420C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B
       8A622B120F6721A00A06082A8648CE3D030107A1440342000460FED4BA255A9D
       31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC
       99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299""",
    """3081A402010104306B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA
       9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5A00706052B810400
       22A16403620004EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06
       AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244E
       A8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE73
       44FD2533264720""",
    """3081A402010104306B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA
       9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5A00706052B810400
       22A16403620004EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06
       AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244E
       A8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE73
       44FD2533264720""",
    """3081DC020101044200FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018F
       EE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB
       89EC0C08B0E996B83538A00706052B81040023A18189038186000401894550D0
       785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E
       45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4004931
       01C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB
       25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5""",
    """3081DC020101044200FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018F
       EE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB
       89EC0C08B0E996B83538A00706052B81040023A18189038186000401894550D0
       785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E
       45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4004931
       01C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB
       25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5""",
  ]

  SignaturePubKeys = [
    """3059301306072A8648CE3D020106082A8648CE3D0301070342000460FED4BA25
       5A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008
       B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299""",
    """3059301306072A8648CE3D020106082A8648CE3D0301070342000460FED4BA25
       5A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008
       B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299""",
    """3076301006072A8648CE3D020106052B8104002203620004EC3A4E415B4E19A4
       568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA90558660
       64A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9
       F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720""",
    """3076301006072A8648CE3D020106052B8104002203620004EC3A4E415B4E19A4
       568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA90558660
       64A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9
       F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720""",
    """30819B301006072A8648CE3D020106052B81040023038186000401894550D078
       5932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45
       DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A400493101
       C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25
       741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5""",
    """30819B301006072A8648CE3D020106052B81040023038186000401894550D078
       5932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45
       DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A400493101
       C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25
       741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5""",
  ]

  SignatureMessages = ["sample", "test", "sample", "test", "sample", "test"]

  SignatureVectors = [
    """3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0E
       A84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF406
       4DC4AB2F843ACDA8""",
    """3045022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3
       B0B7D383670220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0C
       C84250E46F0083""",
    """3065023021B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A2
       1D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD023100F3AA443FB107745BF4
       BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0
       CB8668A4FA0AB0""",
    """306402306D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB5
       1D451559F918EEDAF2293BE5B475CC8F0188636B02302D46F3BECBCC523D5F1A
       1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEF
       B14024787265""",
    """308187024201511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92
       B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D549728104
       21E7D87589E1A702414A171143A83163D6DF460AAF61522695F207A58B95C064
       4D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B
       931F7DE6C9D949A7ECFC""",
    """30818702410E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B
       41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76
       E6F1E4656AA8024200CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC64
       4766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619B
       FBC828E7769BCD694E86""",
  ]

  # This test vectors was generated using Go `crypto/ecdsa.go`.
  # Its non-deterministic ECDSA signatures.
  NDPrivateKeys = [
    """3077020101042068A2F6BCCA486C323C883328D890BA1C64A0B0CC9A8527D681
       0AE8FDBB1B695CA00A06082A8648CE3D030107A144034200048EA1E33E80527E
       FCAFB3E8924DD0CB3CF37DC406C65F6D69D6117B3F08A51E5280E2FE8AFAB32A
       3EB1F4701BC7171FA62DDF46764A00E4024F286EADF3691FA0""",
    """3081A402010104301BC69416E84B85827018F7FC9EFCB6E426C1369ECA33CF45
       10DBE38E065D5F78CB8F75185DCF2DBF5E239F18C424CF23A00706052B810400
       22A164036200040B63293E10AE9348832D96F3EC1A4789D7F4F3F4F16E119E52
       4227768FED3787D2FDEE6F4B9F2749EDBF4A0F1F72CACD1C7B3E9A7E2BD6E611
       90D71133C55E479D7F73EECD73CE9BF471CDDAE9C234F394FAC6258E3B877FE2
       5D6397D4B266CD""",
    """3081DC020101044201251023BBE7AA0121F34F39BD409021C4C3BB323E4729BF
       D6842103C5628EC88F081BD01A8B27F25268CB4CFE46AE2741925EBCA3FA95C1
       2A6D32AF161AEE2DB806A00706052B81040023A18189038186000400887F1A85
       48791B40C677D80E70F5DFE84B50F301C4067222BDF1EE75B805227287A309C2
       0C7E33E6FE93F651D6ABCE76E644DC16B220E34E68DCB5858262B00A07015923
       7B66B29CABBDC352420E3652F6DCF6EB4EC6E08B0957EDC9ACC35CD684B99A78
       E638C7937608749855C98C147DD46EE776234BA781D31C4FB05BB1D3648027""",
  ]

  NDPublicKeys = [
    """3059301306072A8648CE3D020106082A8648CE3D030107034200048EA1E33E80
       527EFCAFB3E8924DD0CB3CF37DC406C65F6D69D6117B3F08A51E5280E2FE8AFA
       B32A3EB1F4701BC7171FA62DDF46764A00E4024F286EADF3691FA0""",
    """3076301006072A8648CE3D020106052B81040022036200040B63293E10AE9348
       832D96F3EC1A4789D7F4F3F4F16E119E524227768FED3787D2FDEE6F4B9F2749
       EDBF4A0F1F72CACD1C7B3E9A7E2BD6E61190D71133C55E479D7F73EECD73CE9B
       F471CDDAE9C234F394FAC6258E3B877FE25D6397D4B266CD""",
    """30819B301006072A8648CE3D020106052B81040023038186000400887F1A8548
       791B40C677D80E70F5DFE84B50F301C4067222BDF1EE75B805227287A309C20C
       7E33E6FE93F651D6ABCE76E644DC16B220E34E68DCB5858262B00A070159237B
       66B29CABBDC352420E3652F6DCF6EB4EC6E08B0957EDC9ACC35CD684B99A78E6
       38C7937608749855C98C147DD46EE776234BA781D31C4FB05BB1D3648027""",
  ]

  NDMessages = [
    "sample", "sample", "sample", "test", "test", "test", "sample", "sample", "sample",
    "test", "test", "test", "sample", "sample", "sample", "test", "test", "test",
  ]

  NDSignatures = [
    """304502210088C7E8176CBA8EBE0672391AB698101FC78F187AE029ACF7EA846633
       2892B59B022078DA1A6792B7450084085881A482313C846F66162C15D9B50CBC2F
       19427ACC9C""",
    """30450221008C4CD62BB25709AE0F060AAACF6FE63B87FACE3DA2B77EE545AC2289
       7E250897022060A59D99C681DD736A6C18DC4ABF3635E749886A748908CB4E8E77
       457212FC47""",
    """3046022100F86C58A4607DDBD3E2C780B4FCB64848F9216D22FFBCE898BA8F9D05
       3EAF656E022100A5C2688897C0CC471602FF86D445B09EFB12EC64C75D9096A528
       1D90948952DE""",
    """304402206CCE912F77B6E20709CD2A7D7C5E046674DBC958C247B1E3F7AEC766CF
       A8EF72022056BF2A26EBD7AE4DA3080C75A2B2F247A941B87C941DC91F4FCBF19C
       8B106DEC""",
    """3046022100D940CBF42025B33E23C67390CBF160F78A6FE76DA6721F6551F4CA67
       E0C8D88D022100B51E501945EF340DBB5440D44242E71F67835E5B46C5F3E19FB8
       F5C24F036DA2""",
    """3045022100A6BE7BADFD38D2ABEF78CE48471DA0D6580E33C2BAF4B48D1155247D
       B5645E1E02206505D23CD41C10D1E55878FD9CF4072420F2DF7212728604F72DC2
       B1BB8DFAB0""",
    """306402307566A2ACC93DF36170A0A2A98CA18A979E5F3052488FAA272DDEE8306A
       CD6B48259E2BE3170346D3EFAA69B973909BA702300B066D618D3D1FB61328594B
       79C45F1AAE4F8C99F8FAED79A9ED8C729BC1932F11E5D05A4410FABF394CCFC6AA
       9A6AB9""",
    """3066023100AF3FCC8CCF5B2256ABF638BC18001985F4A8D9845EC6E1BE8E708D21
       E60256E8CD00833EFC0F2E793BDC9B433482A09A023100DBA731B3D6B14CE8EE96
       EDC083B97A01CE46A4B2F0583FCB9A2B7F12AC62985942DF386579E2CBBAF75C90
       C468B7D1CB""",
    """3065023100E9022EB07F766FCC68D345CF758FBC54EFCAC086CD8625DFDE588F67
       D06A4357DE5F9ED39298F5D9299C7AB24E6E5984023006838D2A052990DB3A5BCC
       12CAE45863DEC9023625C12D143DD4F75FCC50625FB35108BA2090C1FCAC48353F
       54A03021""",
    """3066023100C77C91B69D2064DD312A149C8074DCAC7FC734EB70AF3FF52F7F7D6E
       4253C163FF1A574ADC30C58DDD58CF06F883B880023100F780E8D1F094F6112EC7
       8317CF1BDEB068D1BB472D8CB6E49A707409F0A22C867A254EE80F8949260E31AB
       5AF9AD4060""",
    """3065023100D9027A9485BAB5BE90F2D9FCB14A494CA8B829C7A815F40DD17235D2
       4296927122CBC11A1417D9856E815DF81AF3950202305A617D78CEA2586A55EB85
       63B3563385753A6F84D2AF02C61F889DF6EDD6F1D0A3DE07BD859D7CB1D8264726
       696130D6""",
    """306502307F476CBE232E1BFED31061713B5611852B730ACB4053C6AB2D85C4563A
       581A773B4A76F65D8DDB76D09BC038AEB3B2AC023100C778A6DCB18451A251DD9D
       BD55F18CC45FAC16EA458270A6C7B8E0D7BC91264C66CDDB8013C17EC98365B0FA
       6B0049AA""",
    """30818802420137C1D1943C9ABCA116D87B46C2D7A146AE358F1378ACA58D405735
       20B6BEDECDC500EF9172B363B862734C528ED01484822E168FB6BFDB2342A0AB45
       8DD3B7BB8B024200FEDC89C8BF2611ABD27FDAD58E5DAAC9DD744D744017E29002
       573D0F6F8A6B13D6901ADC07D5C6D1746910340D8C2C0D6109F939C0172D1F229A
       818E0C6643E774""",
    """3081880242012173FFB97D1318F53F50818DAADB5B600ED928F39CD98F712C44BB
       810AB4EE74D02C385DFEBEFCC2DC56DE4EB2794681EC0345B170C3BEFCDF2A1693
       9DC6DDF58D024201724AB5BED8F88B30E84CB0A2ED4BDD12EB2222C9E4FC0897B9
       4390FD44FFE118A7EDB948E1AB7FDB1A19C920A4160DA4596DA5D2731D10143DE5
       103FFF93A51EF6""",
    """30818602416BADAFFFF67959764ADC0F45AB0911DE85D0FC0608A0AD60C14456E1
       01CBF51CBBEB9D0B2E71EBE3EC1B4D45851ED71CAFE0A83DF593C803350A6BB36E
       0EB18A21024169E20B6463357D4363BE05DF3B4FF5BC21FFAC652C7005E0314A3D
       A443D3B537608139CE14A94C7C3A53063910F1062E385A4464022C5E662CC53833
       EB870435E2""",
    """308187024158F13B64E188FF6BB766D129E087420D2070752D1E1F29BF64EE13C9
       5FF222D7E5DF595EC21FED066A83C0027CE60C1A7BD92B4641E34CBB34ECFDE5F6
       6762659D024201105D3482639186FC0322933998FE0E71E0BA359ED9BB8DE127E5
       73A88311F735FFD87CF279B667A2AF681122EDA9F7FC7784E0E942A287C917C7EC
       DFE2F8E6368C""",
    """30818802420145D48CA13B92808CAA7959574CDACF9959ED72A9ADC6FFCA0FD417
       0F2EFD854C8C479099F0784D717A56EC9F5777A0096CD251F96F2CCB6061D2C8CA
       CD09EB606C0242011683C215C7DE99E3D4FF8D543C6CFDCC49577A8978D10C818C
       002A51D7C8D7FBC1814D82EDA9521F19C8895DCE6CAE97F8926CCCE3863D5E120F
       77B6D2C891AB7F""",
    """308187024200F235341F4C39641FFBA7FFB1551C36E34F606F4C2970DE00096A37
       722D83D07D0ADFB3D33492F2645B15A19FFAF6424A03487CE2E099069006037956
       9972DC798A02412B6F169D23303B0C7764620514EF308F010EFB4E3A69912967EE
       303B177FA12B58C4602183BCB58D5DB30917584EDFE4BE4B42EC0EE3E3FB75BDA8
       C05CB9C3A2DA""",
  ]

  # ECDHE test vectors was made using Go's elliptic/curve
  ECDHEPrivateKeys = [
    "978edaa0671f5a37ec5372b62689e9328af71b6fb4ac3be24d195ca082b0f2fa",
    "a849c80cb4f507ab24569473c2b94a84608088e7cb448816ba60d91ade3c8470",
    "a23bf3eb7c515aab57974845d6b8c05c108bc7c5c68b2aa18bc9a05c4668993e",
    "1b35c3c3efea9ad4e78f47063cf17bc14ddb89bd9a8980b744a19b92076ae88d",
    "24c97a005fc6ce93c96f072d37bf8aeab0b97f2135845655c16df24e09cceafa",
    "fa52527eb5cd88d751807d05332164a66c9ae5bc4a4c37e7f21f1f64daad19d9",
    """fab46775d806e9135f5db2ee65bc32b530b2db7a3a85f25d69ffe4f39a7f3c01
       98d863ae1ed71ed3e5b9bbf882020c25""",
    """8494fb7f48c31617414fb444d3e0f28225a4ee04aee8e518cb6fece1c5603141
       525bc96ef570a8361ed1abe74b467daa""",
    """760a6543f29654b9b4e7a67a328d6f61895f29df53c031dd457342ba103fe452
       776791b52a4fd156e5cd0ec005a59ad0""",
    """15c44a82d4ab43cef6d8a33c01d41bfeaab21ee1aba6ecb7eff8db31c681337b
       3b11e785df0c7cf2f838be395591810b""",
    """16a646076ec966b59655343875980adb7aa25dbf8480b1fad73c0a4699f9262c
       bab67a8768754064afd68e1a12e405e6""",
    """bfe6d3a1e67f2e75d6204aff913b62163d6bc1ca2a281c0c6a95fbc989adddf8
       836ada035aa400ba8b47480bcc7b95c3""",
    """01920b49ce0ecf2a672ca2843d300140dde242af772ec89e4ad57dadf1610bb0
       912f613a3e29193a04691a5b4e8ae6130d8b610642c88f99cdd2b5b9e9269c26
       1fa5""",
    """015a7286a1ecc521e49ffed6b9740b2e7ebdb3762cb6be5f4c173c26686105c5
       73a06d59814c89b67c642e2fc85de46e4242565e64ec82d8ada5ac3e1ab1be4e
       091f""",
    """011a8d01ac83d3f7b1ac8ef06afb75ec7c1b176cf01405686cb2ead34f8bc278
       0972d2e348d49bdc0cb3fbf6414f7815aa4ea83eeed71a6a2fde7070bc074735
       86c3""",
    """014c09dcf8cc8d7fe59c5b2d9edf5c6a0a42700f540f1670e46be35e7edc8ed4
       01d32513cc9167a386623abd458cef9bd9facd0aa9b1d671b02c19bd71938b00
       d957""",
    """0172a4ee2f85ba7ea47e0fee1410344211df58415fbac933c793d138d75c4dd1
       664cfaf58e13c040f11191438dbf7394e36d7c3b2025d31af19fc6485b979a77
       2f39""",
    """011b3b6ac868ae156c66b140d92092167193e88f04909be61b3592c7006296e3
       cc1dab37955fea9e5ab24047c2ef717e402a88bd616ef27c68cf6976e68b6c69
       b326""",
  ]

  ECDHESecrets = [
    "0e6c0eb060c5e33b7125ab72fa70b21b472b64e137ac11238da14838dfb1603c",
    "1b42c4831dca82787ff4f411b3774165e788ead225bd34291d6582f714849984",
    "568ff01d85d325e31ee0eafb1be4ce7695aa996c5d8d8a804052f819b4c6baae",
    """595e63e5b14747b2c87f7042122327fbf9409ccecad2d794f706e84150ea8d0d
       67d0b2cdf3a7b2491db83188f64bc5c2""",
    """ad60579d3d6ab4d512d3e493d8d432fd0c5f91de61cf9375141c7521db792273
       88482177eb2c96e789830ff51ffe1955""",
    """6a04cfb7cb3514b8326bac52ff09d24e320d2662b9a7964a58c1fe32c25167e5
       d96dc59193b0d9a7463652a3e7096daf""",
    """0037b9b156c934a594ce991ec904c28b257de50930076b9702186c0f0c4affae
       02d3c5ff1c896339dbcb9f9d11a86a4c27d705a22e4a5297cb389cbb1bf55e47
       c07c""",
    """00f7916c1119c46d4c499f5c73cae3279466b104f87ef4c5092f38148b2dad84
       c18ecf7ce439ec59799c086557453484b454722d23135291d9d4ffe6e1719f16
       3d25""",
    """018c54bd7cb4aab23b07760c48e563a1828ff521442e5388eb62f916c33a8db2
       ec8bc6a5c8c41b3ebb09f0cf66bbae602d355161c97597b088060bb8456a4458
       35ab""",
  ]

suite "EC NIST-P256/384/521 test suite":
  test "[secp256r1] Private key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPrivateKey
      var skey2 = newSeq[byte](256)
      var key = EcPrivateKey.random(Secp256r1, rng()).expect("random key")
      var skey1 = key.getBytes().expect("bytes")
      check:
        key.toBytes(skey2).expect("bytes") > 0
      check:
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPrivateKey.init(skey1).expect("private key")
      var rkey4 = EcPrivateKey.init(skey2).expect("private key")
      check:
        rkey1 == key
        rkey2 == key
        rkey3 == key
        rkey4 == key
      rkey1.key.xlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp256r1] Public key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPublicKey
      var skey2 = newSeq[byte](256)
      var pair = EcKeyPair.random(Secp256r1, rng()).expect("random key")
      var skey1 = pair.pubkey.getBytes().expect("bytes")
      check:
        pair.pubkey.toBytes(skey2).expect("bytes") > 0
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPublicKey.init(skey1).expect("public key")
      var rkey4 = EcPublicKey.init(skey2).expect("public key")
      check:
        rkey1 == pair.pubkey
        rkey2 == pair.pubkey
        rkey3 == pair.pubkey
        rkey4 == pair.pubkey
      rkey1.key.qlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp256r1] ECDHE test":
    for i in 0 ..< TestsCount:
      var kp1 = EcKeyPair.random(Secp256r1, rng()).expect("random key")
      var kp2 = EcKeyPair.random(Secp256r1, rng()).expect("random key")
      var shared1 = kp2.pubkey.scalarMul(kp1.seckey)
      var shared2 = kp1.pubkey.scalarMul(kp2.seckey)
      check:
        isNil(shared1) == false
        isNil(shared2) == false
        shared1 == shared2

  test "[secp256r1] ECDHE test vectors":
    for i in 0 ..< 3:
      var key1 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2]))
      var key2 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2 + 1]))
      var seckey1 = EcPrivateKey.initRaw(key1).expect("initRaw key")
      var seckey2 = EcPrivateKey.initRaw(key2).expect("initRaw key")
      var pubkey1 = seckey1.getPublicKey().expect("public key")
      var pubkey2 = seckey2.getPublicKey().expect("public key")
      var secret1 = getSecret(pubkey2, seckey1)
      var secret2 = getSecret(pubkey1, seckey2)
      var expsecret = fromHex(stripSpaces(ECDHESecrets[i]))
      check:
        secret1 == expsecret
        secret2 == expsecret

  test "[secp256r1] ECDSA test vectors":
    for i in 0 ..< 2:
      var sk = EcPrivateKey.init(stripSpaces(SignatureSecKeys[i])).expect("private key")
      var expectpk =
        EcPublicKey.init(stripSpaces(SignaturePubKeys[i])).expect("private key")
      var checkpk = sk.getPublicKey().expect("public key")
      check expectpk == checkpk
      var checksig = sk.sign(SignatureMessages[i]).expect("signature")
      var expectsig =
        EcSignature.init(stripSpaces(SignatureVectors[i])).expect("signature")
      check:
        checksig == expectsig
        checksig.verify(SignatureMessages[i], checkpk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(SignatureMessages[i], checkpk) == false

  test "[secp256r1] ECDSA non-deterministic test vectors":
    var sk = EcPrivateKey.init(stripSpaces(NDPrivateKeys[0])).expect("private key")
    var pk = EcPublicKey.init(stripSpaces(NDPublicKeys[0])).expect("public key")
    var checkpk = sk.getPublicKey().expect("public key")
    check pk == checkpk
    for i in 0 ..< 6:
      var message = NDMessages[i]
      var checksig = EcSignature.init(stripSpaces(NDSignatures[i])).expect("signature")
      check checksig.verify(message, pk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(message, pk) == false

  test "[secp256r1] Generate/Sign/Serialize/Deserialize/Verify test":
    var message = "message to sign"
    for i in 0 ..< TestsCount:
      var kp = EcKeyPair.random(Secp256r1, rng()).expect("random key")
      var sig = kp.seckey.sign(message).expect("signature")
      var sersk = kp.seckey.getBytes().expect("bytes")
      var serpk = kp.pubkey.getBytes().expect("bytes")
      var sersig = sig.getBytes().expect("bytes")
      discard EcPrivateKey.init(sersk)
      var pubkey = EcPublicKey.init(serpk).expect("public key")
      var csig = EcSignature.init(sersig).expect("signature")
      check csig.verify(message, pubkey) == true
      let error = csig.buffer.high
      csig.buffer[error] = not (csig.buffer[error])
      check csig.verify(message, pubkey) == false

  test "[secp384r1] Private key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPrivateKey
      var skey2 = newSeq[byte](256)
      var key = EcPrivateKey.random(Secp384r1, rng()).expect("random key")
      var skey1 = key.getBytes().expect("bytes")
      check:
        key.toBytes(skey2).expect("bytes") > 0
      check:
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPrivateKey.init(skey1).expect("private key")
      var rkey4 = EcPrivateKey.init(skey2).expect("private key")
      check:
        rkey1 == key
        rkey2 == key
        rkey3 == key
        rkey4 == key
      rkey1.key.xlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp384r1] Public key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPublicKey
      var skey2 = newSeq[byte](256)
      var pair = EcKeyPair.random(Secp384r1, rng()).expect("random key")
      var skey1 = pair.pubkey.getBytes().expect("bytes")
      check:
        pair.pubkey.toBytes(skey2).expect("bytes") > 0
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPublicKey.init(skey1).expect("public key")
      var rkey4 = EcPublicKey.init(skey2).expect("public key")
      check:
        rkey1 == pair.pubkey
        rkey2 == pair.pubkey
        rkey3 == pair.pubkey
        rkey4 == pair.pubkey
      rkey1.key.qlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp384r1] ECDHE test":
    for i in 0 ..< TestsCount:
      var kp1 = EcKeyPair.random(Secp384r1, rng()).expect("random key")
      var kp2 = EcKeyPair.random(Secp384r1, rng()).expect("random key")
      var shared1 = kp2.pubkey.scalarMul(kp1.seckey)
      var shared2 = kp1.pubkey.scalarMul(kp2.seckey)
      check:
        isNil(shared1) == false
        isNil(shared2) == false
        shared1 == shared2

  test "[secp384r1] ECDHE test vectors":
    for i in 3 ..< 6:
      var key1 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2]))
      var key2 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2 + 1]))
      var seckey1 = EcPrivateKey.initRaw(key1).expect("private key")
      var seckey2 = EcPrivateKey.initRaw(key2).expect("private key")
      var pubkey1 = seckey1.getPublicKey().expect("public key")
      var pubkey2 = seckey2.getPublicKey().expect("public key")
      var secret1 = getSecret(pubkey2, seckey1)
      var secret2 = getSecret(pubkey1, seckey2)
      var expsecret = fromHex(stripSpaces(ECDHESecrets[i]))
      check:
        secret1 == expsecret
        secret2 == expsecret

  test "[secp384r1] ECDSA test vectors":
    for i in 2 ..< 4:
      var sk = EcPrivateKey.init(stripSpaces(SignatureSecKeys[i])).expect("private key")
      var expectpk =
        EcPublicKey.init(stripSpaces(SignaturePubKeys[i])).expect("public key")
      var checkpk = sk.getPublicKey().expect("public key")
      check expectpk == checkpk
      var checksig = sk.sign(SignatureMessages[i]).expect("signature")
      var expectsig =
        EcSignature.init(stripSpaces(SignatureVectors[i])).expect("signature")
      check:
        checksig == expectsig
        checksig.verify(SignatureMessages[i], checkpk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(SignatureMessages[i], checkpk) == false

  test "[secp384r1] ECDSA non-deterministic test vectors":
    var sk = EcPrivateKey.init(stripSpaces(NDPrivateKeys[1])).expect("private key")
    var pk = EcPublicKey.init(stripSpaces(NDPublicKeys[1])).expect("public key")
    var checkpk = sk.getPublicKey().expect("public key")
    check pk == checkpk
    for i in 6 ..< 12:
      var message = NDMessages[i]
      var checksig = EcSignature.init(stripSpaces(NDSignatures[i])).expect("signature")
      check checksig.verify(message, pk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(message, pk) == false

  test "[secp384r1] Generate/Sign/Serialize/Deserialize/Verify test":
    var message = "message to sign"
    for i in 0 ..< TestsCount:
      var kp = EcKeyPair.random(Secp384r1, rng()).expect("random key")
      var sig = kp.seckey.sign(message).expect("signature")
      var sersk = kp.seckey.getBytes().expect("bytes")
      var serpk = kp.pubkey.getBytes().expect("bytes")
      var sersig = sig.getBytes().expect("bytes")
      discard EcPrivateKey.init(sersk).expect("private key")
      var pubkey = EcPublicKey.init(serpk).expect("public key")
      var csig = EcSignature.init(sersig).expect("signature")
      check csig.verify(message, pubkey) == true
      let error = csig.buffer.high
      csig.buffer[error] = not (csig.buffer[error])
      check csig.verify(message, pubkey) == false

  test "[secp521r1] Private key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPrivateKey
      var skey2 = newSeq[byte](256)
      var key = EcPrivateKey.random(Secp521r1, rng()).expect("random key")
      var skey1 = key.getBytes().expect("bytes")
      check:
        key.toBytes(skey2).expect("bytes") > 0
      check:
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPrivateKey.init(skey1).expect("private key")
      var rkey4 = EcPrivateKey.init(skey2).expect("private key")
      check:
        rkey1 == key
        rkey2 == key
        rkey3 == key
        rkey4 == key
      rkey1.key.xlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp521r1] Public key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EcPublicKey
      var skey2 = newSeq[byte](256)
      var pair = EcKeyPair.random(Secp521r1, rng()).expect("random key")
      var skey1 = pair.pubkey.getBytes().expect("bytes")
      check:
        pair.pubkey.toBytes(skey2).expect("bytes") > 0
        rkey1.init(skey1).isOk
        rkey2.init(skey2).isOk
      var rkey3 = EcPublicKey.init(skey1).expect("public key")
      var rkey4 = EcPublicKey.init(skey2).expect("public key")
      check:
        rkey1 == pair.pubkey
        rkey2 == pair.pubkey
        rkey3 == pair.pubkey
        rkey4 == pair.pubkey
      rkey1.key.qlen = rkey1.buffer.len + 1
      check:
        rkey1.getBytes == EcResult[seq[byte]].err(EcKeyIncorrectError)

  test "[secp521r1] ECDHE test":
    for i in 0 ..< TestsCount:
      var kp1 = EcKeyPair.random(Secp521r1, rng()).expect("random key")
      var kp2 = EcKeyPair.random(Secp521r1, rng()).expect("random key")
      var shared1 = kp2.pubkey.scalarMul(kp1.seckey)
      var shared2 = kp1.pubkey.scalarMul(kp2.seckey)
      check:
        isNil(shared1) == false
        isNil(shared2) == false
        shared1 == shared2

  test "[secp521r1] ECDHE test vectors":
    for i in 6 ..< 9:
      var key1 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2]))
      var key2 = fromHex(stripSpaces(ECDHEPrivateKeys[i * 2 + 1]))
      var seckey1 = EcPrivateKey.initRaw(key1).expect("private key")
      var seckey2 = EcPrivateKey.initRaw(key2).expect("private key")
      var pubkey1 = seckey1.getPublicKey().expect("public key")
      var pubkey2 = seckey2.getPublicKey().expect("public key")
      var secret1 = getSecret(pubkey2, seckey1)
      var secret2 = getSecret(pubkey1, seckey2)
      var expsecret = fromHex(stripSpaces(ECDHESecrets[i]))
      check:
        secret1 == expsecret
        secret2 == expsecret

  test "[secp521r1] ECDSA test vectors":
    for i in 4 ..< 6:
      var sk = EcPrivateKey.init(stripSpaces(SignatureSecKeys[i])).expect("private key")
      var expectpk =
        EcPublicKey.init(stripSpaces(SignaturePubKeys[i])).expect("public key")
      var checkpk = sk.getPublicKey().expect("public key")
      check expectpk == checkpk
      var checksig = sk.sign(SignatureMessages[i]).expect("signature")
      var expectsig =
        EcSignature.init(stripSpaces(SignatureVectors[i])).expect("signature")
      check:
        checksig == expectsig
        checksig.verify(SignatureMessages[i], checkpk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(SignatureMessages[i], checkpk) == false

  test "[secp521r1] ECDSA non-deterministic test vectors":
    var sk = EcPrivateKey.init(stripSpaces(NDPrivateKeys[2])).expect("private key")
    var pk = EcPublicKey.init(stripSpaces(NDPublicKeys[2])).expect("public key")
    var checkpk = sk.getPublicKey().expect("public key")
    check pk == checkpk
    for i in 12 ..< 18:
      var message = NDMessages[i]
      var checksig = EcSignature.init(stripSpaces(NDSignatures[i])).expect("signature")
      check checksig.verify(message, pk) == true
      let error = checksig.buffer.high
      checksig.buffer[error] = not (checksig.buffer[error])
      check checksig.verify(message, pk) == false

  test "[secp521r1] Generate/Sign/Serialize/Deserialize/Verify test":
    var message = "message to sign"
    for i in 0 ..< TestsCount:
      var kp = EcKeyPair.random(Secp521r1, rng()).expect("random key")
      var sig = kp.seckey.sign(message).expect("signature")
      var sersk = kp.seckey.getBytes().expect("bytes")
      var serpk = kp.pubkey.getBytes().expect("bytes")
      var sersig = sig.getBytes().expect("bytes")
      discard EcPrivateKey.init(sersk).expect("private key")
      var pubkey = EcPublicKey.init(serpk).expect("public key")
      var csig = EcSignature.init(sersig).expect("signature")
      check csig.verify(message, pubkey) == true
      let error = csig.buffer.high
      csig.buffer[error] = not (csig.buffer[error])
      check csig.verify(message, pubkey) == false

  test "Private key toBytes returns EcInsufficientTargetSize for undersized buffer":
    for curve in [Secp256r1, Secp384r1, Secp521r1]:
      let key = EcPrivateKey.random(curve, rng()).expect("random key")
      # Determine correct size first, then use a buffer one byte too small.
      var full = newSeq[byte](512)
      let needed = key.toBytes(full).expect("bytes")
      var small = newSeq[byte](needed - 1)
      check:
        key.toBytes(small) == EcResult[int].err(EcInsufficientTargetSize)

  test "Public key toBytes returns EcInsufficientTargetSize for undersized buffer":
    for curve in [Secp256r1, Secp384r1, Secp521r1]:
      let pair = EcKeyPair.random(curve, rng()).expect("random key")
      # Determine correct size first, then use a buffer one byte too small.
      var full = newSeq[byte](512)
      let needed = pair.pubkey.toBytes(full).expect("bytes")
      var small = newSeq[byte](needed - 1)
      check:
        pair.pubkey.toBytes(small) == EcResult[int].err(EcInsufficientTargetSize)

  test "Private key DER with a malformed field is rejected":
    proc parse(data: seq[byte]): Result[void, Asn1Error] =
      var seckey: EcPrivateKey
      seckey.init(data)

    var scalar = newSeq[byte](SecKey256Length)
    scalar[^1] = 0x01
    let
      version = derUint(1)
      key = derField(Asn1Tag.OctetString, scalar)
      curve = derContext(0, [derField(Asn1Tag.Oid, Asn1OidSecp256r1)])
      shortKey = derField(Asn1Tag.OctetString, scalar[1 .. ^1])
      zeroKey = derField(Asn1Tag.OctetString, newSeq[byte](SecKey256Length))
      orderKey = derField(Asn1Tag.OctetString, newSeqWith(SecKey256Length, 0xFF'u8))
      unknownCurve = derContext(0, [derField(Asn1Tag.Oid, Asn1OidSecp256k1)])
      curveIn1 = derContext(1, [derField(Asn1Tag.Oid, Asn1OidSecp256r1)])
      bareCurve = derField(Asn1Tag.Oid, Asn1OidSecp256r1)

    check:
      parse(derSequence([version, key, curve])).isOk()
      parse(@[0x30'u8]).error == Asn1Error.Incomplete
      parse(version).error == Asn1Error.Incorrect
      parse(derSequence([derNull(), key, curve])).error == Asn1Error.Incorrect
      parse(derSequence([derUint(2), key, curve])).error == Asn1Error.Incorrect
      parse(derSequence([version, derUint(1), curve])).error == Asn1Error.Incorrect
      parse(derSequence([version, key, derContext(0, [derUint(1)])])).error ==
        Asn1Error.Incorrect
      parse(derSequence([version, shortKey, curve])).error == Asn1Error.Incorrect
      parse(derSequence([version, key, unknownCurve])).error == Asn1Error.Incorrect
      parse(derSequence([version, key, curveIn1])).error == Asn1Error.Incorrect
      parse(derSequence([version, key, bareCurve])).error == Asn1Error.Incorrect
      parse(derSequence([version, zeroKey, curve])).error == Asn1Error.Incorrect
      parse(derSequence([version, orderKey, curve])).error == Asn1Error.Incorrect
      EcPrivateKey.init(version).error == EcKeyIncorrectError

  test "Public key DER with a malformed field is rejected":
    proc parse(data: seq[byte]): Result[void, Asn1Error] =
      var pubkey: EcPublicKey
      pubkey.init(data)

    let pair = EcKeyPair.random(Secp256r1, rng()).expect("random key")
    var offCurve = newSeq[byte](PubKey256Length)
    offCurve[0] = 0x04
    offCurve[SecKey256Length] = 0x01
    offCurve[^1] = 0x01
    let
      ecPublicKey = derField(Asn1Tag.Oid, Asn1OidEcPublicKey)
      curve = derField(Asn1Tag.Oid, Asn1OidSecp256r1)
      algorithm = derSequence([ecPublicKey, curve])
      point = pair.pubkey.getRawBytes().expect("raw bytes")
      key = derBitString(point)
      rsaAlgorithm = derSequence([derField(Asn1Tag.Oid, Asn1OidRsaEncryption), curve])
      unknownCurve = derSequence([ecPublicKey, derField(Asn1Tag.Oid, Asn1OidSecp256k1)])

    check:
      EcPublicKey.init(derSequence([algorithm, key])).expect("public key") == pair.pubkey
      parse(derUint(1)).error == Asn1Error.Incorrect
      parse(derSequence([derUint(1), key])).error == Asn1Error.Incorrect
      parse(derSequence([derSequence([derNull(), curve]), key])).error ==
        Asn1Error.Incorrect
      parse(derSequence([rsaAlgorithm, key])).error == Asn1Error.Incorrect
      parse(derSequence([derSequence([ecPublicKey, derNull()]), key])).error ==
        Asn1Error.Incorrect
      parse(derSequence([unknownCurve, key])).error == Asn1Error.Incorrect
      parse(derSequence([algorithm, derField(Asn1Tag.OctetString, point)])).error ==
        Asn1Error.Incorrect
      parse(derSequence([algorithm, derBitString(offCurve)])).error ==
        Asn1Error.Incorrect
      EcPublicKey.init(derUint(1)).error == EcKeyIncorrectError

  test "Nil and uninitialized keys and signatures":
    var buf = newSeq[byte](256)
    let
      nilSeckey = EcPrivateKey(nil)
      nilPubkey = EcPublicKey(nil)
      nilSig = EcSignature(nil)
      emptySeckey = EcPrivateKey()
      emptyPubkey = EcPublicKey()

    check:
      nilSeckey.toBytes(buf).error == EcKeyIncorrectError
      nilPubkey.toBytes(buf).error == EcKeyIncorrectError
      nilSig.toBytes(buf).error == EcSignatureError
      nilSeckey.getBytes().error == EcKeyIncorrectError
      nilPubkey.getBytes().error == EcKeyIncorrectError
      nilSig.getBytes().error == EcSignatureError
      nilSeckey.getRawBytes().error == EcKeyIncorrectError
      nilPubkey.getRawBytes().error == EcKeyIncorrectError
      nilSig.getRawBytes().error == EcSignatureError
      nilSeckey.getPublicKey().error == EcKeyIncorrectError
      nilSeckey.sign("message").error == EcKeyIncorrectError
      emptySeckey.toBytes(buf).error == EcKeyIncorrectError
      emptySeckey.getBytes().error == EcKeyIncorrectError
      emptySeckey.getRawBytes().error == EcKeyIncorrectError
      emptySeckey.getPublicKey().error == EcKeyIncorrectError
      emptySeckey.sign("message").error == EcKeyIncorrectError
      emptyPubkey.toBytes(buf).error == EcKeyIncorrectError
      emptyPubkey.getBytes().error == EcKeyIncorrectError
      emptyPubkey.getRawBytes().error == EcKeyIncorrectError
      $nilPubkey == "Empty or uninitialized ECNIST key"
      $emptyPubkey == "Empty or uninitialized ECNIST key"
      $nilSig == "Empty or uninitialized ECNIST signature"
      $EcSignature(buffer: @[]) == "Empty or uninitialized ECNIST signature"

  test "Equality and copy with nil or empty values":
    let pair = EcKeyPair.random(Secp256r1, rng()).expect("random key")
    let sig = EcSignature.init(@[0x01'u8, 0x02, 0x03]).expect("signature")
    var pubkey: EcPublicKey
    var signature: EcSignature

    check:
      EcPublicKey(nil) == EcPublicKey(nil)
      EcPublicKey(nil) != pair.pubkey
      pair.pubkey != EcPublicKey(nil)
      EcPrivateKey(nil) == EcPrivateKey(nil)
      EcPrivateKey(nil) != pair.seckey
      pair.seckey != EcPrivateKey(nil)
      EcSignature(nil) == EcSignature(nil)
      EcSignature(nil) != sig
      sig != EcSignature(nil)
      EcSignature(buffer: @[]) == EcSignature(buffer: @[])
      EcSignature(buffer: @[]) != sig
      sig != EcSignature(buffer: @[])
      EcSignature(buffer: @[0x01'u8, 0x02]) != sig
      not pubkey.copy(EcPublicKey(nil))
      not signature.copy(EcSignature(buffer: @[]))

  test "Signature init and shared secret error paths":
    let p256 = EcKeyPair.random(Secp256r1, rng()).expect("random key")
    let p384 = EcKeyPair.random(Secp384r1, rng()).expect("random key")

    check:
      EcSignature.init(newSeq[byte]()).error == EcSignatureError
      EcSignature.initRaw(newSeq[byte](10)).error == EcSignatureError
      getSecret(p256.pubkey, p384.seckey).len == 0
      getSecret(p256.pubkey, p256.seckey).len == Secret256Length
