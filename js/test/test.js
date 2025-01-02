const assert = require('node:assert').strict;

const hw_transport = require("@ledgerhq/hw-transport");
const Transport = hw_transport.default


transport = new Transport()
transport.expected = [];

transport.exchange = function(apdu) {
  const pair = this.expected.shift();
  if (apdu.toString("hex") !== pair[0]) {
    console.log("Expected")
    console.log(pair[0])
    console.log("Received")
    console.log(apdu.toString("hex"))
  }
  assert.equal(apdu.toString("hex"), pair[0]);
  return Buffer.from(pair[1], "hex");
}


const my_package = require ("..");
const FlowApp = my_package.default;

const app = new FlowApp(transport);

async function runTest() {
  var res;
  var exp;
  
  //getVersion
  transport.expected = [
    ["3300000000", "6f01"],
    ["3300000000", "00000c0000311000049000"],
  ]
  res = await app.getVersion()
  assert.equal(res.returnCode, 0x6f01)
  res = await app.getVersion()
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.testMode, false)
  assert.equal(res.major, 0)
  assert.equal(res.minor, 12)
  assert.equal(res.patch, 0)
  assert.equal(transport.expected.length, 0)

  //getPublicKey
  transport.expected = [
    ["33010100162c0000801b0200800000008000000000000000000103", "6986"],
    ["33010100162c0000801b0200800000008000000000000000000103", "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d303430633737646564616139613731386231656461383262363630373665613434626230346464306336663538336463383961306437666361333264313266363732623635396138663861663235663164306237343537346238333066383335616336623461616366366262636431326634353534353234313439633534353932649000"],
    ["33010000162c0000801b0200800000008000000000000000000103", "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d303430633737646564616139613731386231656461383262363630373665613434626230346464306336663538336463383961306437666361333264313266363732623635396138663861663235663164306237343537346238333066383335616336623461616366366262636431326634353534353234313439633534353932649000"],
  ]
  const cryptoOptions = FlowApp.Hash["SHA2_256"] + FlowApp.Signature["SECP256K1"]
  res = await app.showAddressAndPubKey("m/44'/539'/0'/0/0", cryptoOptions)
  assert.equal(res.returnCode, 0x6986)
  res = await app.showAddressAndPubKey("m/44'/539'/0'/0/0", cryptoOptions)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.address, "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d")
  assert.equal(res.publicKey.toString("hex"), "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d")
  res = await app.getAddressAndPubKey("m/44'/539'/0'/0/0", cryptoOptions)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.address, "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d")
  assert.equal(res.publicKey.toString("hex"), "040c77dedaa9a718b1eda82b66076ea44bb04dd0c6f583dc89a0d7fca32d12f672b659a8f8af25f1d0b74574b830f835ac6b4aacf6bbcd12f4554524149c54592d")
  assert.equal(transport.expected.length, 0)

  //slotStatus
  transport.expected = [
    ["3310000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000019000"],
  ]
  
  res = await app.slotStatus()
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.status.toString("hex"), "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
  assert.equal(transport.expected.length, 0)

  //getSot
  transport.expected = [
    ["33110000010a", "6982"],
    ["33110000010a", "e467b9dd11fa00df2c0000801b02008001020080000000000000000001039000"],
  ]
  res = await app.getSlot(10)
  assert.equal(res.returnCode, 0x6982)
  res = await app.getSlot(10)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.account, "e467b9dd11fa00df")
  assert.equal(res.path, "m/44'/539'/513'/0/0")
  assert.equal(res.slotIdx, 10)
  assert.equal(res.options, 769)
  assert.equal(transport.expected.length, 0)
  
  //setSlot
  transport.expected = [
    ["331200001f0ae467b9dd11fa00de2c0000801b0200800102008000000000010000000102", "9000"],
  ]
  const cryptoOptions2 = FlowApp.Hash["SHA2_256"] + FlowApp.Signature["P256"]
  res = await app.setSlot(10, "e467b9dd11fa00de", "m/44'/539'/513'/0/1", cryptoOptions2)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(transport.expected.length, 0)
  
  //signMessage
  transport.expected = [
    ["3300000000", "00000b0000311000049000"],
    ["3300000000", "00000c0000311000049000"],
    ["33020000162c0000801b0200800102008000000000010000000103", "9000"],
    ["330210005f546869732069732061206e696365206d657373616765207468617420686173206f6e6c7920646973706c617961626c65206368617261637465727320616e642069732073686f727420656e6f75676820746f20626520646973706c61796564", "0fd4106fb418aee7dc8b001b80090fb0b76e4b903323389b745c994d1b8b2f9140c9753ffbdd1811a383d1fd03660ad494e579cff95f96b177262490c7a3d98201304402200fd4106fb418aee7dc8b001b80090fb0b76e4b903323389b745c994d1b8b2f91022040c9753ffbdd1811a383d1fd03660ad494e579cff95f96b177262490c7a3d9829000"]
  ]
  const message = "546869732069732061206e696365206d657373616765207468617420686173206f6e6c7920646973706c617961626c65206368617261637465727320616e642069732073686f727420656e6f75676820746f20626520646973706c61796564"    
  res = await app.signMessage("m/44'/539'/513'/0/1", Buffer.from(message, "hex"), cryptoOptions)
  assert.equal(res.returnCode, 0x04)
  res = await app.signMessage("m/44'/539'/513'/0/1", Buffer.from(message, "hex"), cryptoOptions)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.signatureCompact.toString("hex"), "0fd4106fb418aee7dc8b001b80090fb0b76e4b903323389b745c994d1b8b2f9140c9753ffbdd1811a383d1fd03660ad494e579cff95f96b177262490c7a3d98201")
  assert.equal(res.signatureDER.toString("hex"), "304402200fd4106fb418aee7dc8b001b80090fb0b76e4b903323389b745c994d1b8b2f91022040c9753ffbdd1811a383d1fd03660ad494e579cff95f96b177262490c7a3d982")
  assert.equal(transport.expected.length, 0)

  //signTransaction - arbitrary
  transport.expected = [
    ["3300000000", "00000b0000311000049000"],
    ["3300000000", "00000c0000311000049000"],
    ["33020000162c0000801b0200800000008000000000000000000103", "9000"],
    ["33020100faf906e9f906e5b90423696d706f727420466c6f775374616b696e67436f6c6c656374696f6e2066726f6d203078386430653837623635313539616536330a0a2f2f2f20437265617465732061206d616368696e65206163636f756e7420666f722061206e6f6465207468617420697320616c726561647920696e20746865207374616b696e6720636f6c6c656374696f6e0a2f2f2f20616e642061646473207075626c6963206b65797320746f20746865206e6577206163636f756e740a0a7472616e73616374696f6e286e6f646549443a20537472696e672c207075626c69634b6579733a205b537472696e675d29207b0a202020200a2020", "9000"],
    ["33020100fa20206c6574207374616b696e67436f6c6c656374696f6e5265663a2026466c6f775374616b696e67436f6c6c656374696f6e2e5374616b696e67436f6c6c656374696f6e0a0a2020202070726570617265286163636f756e743a20417574684163636f756e7429207b0a202020202020202073656c662e7374616b696e67436f6c6c656374696f6e526566203d206163636f756e742e626f72726f773c26466c6f775374616b696e67436f6c6c656374696f6e2e5374616b696e67436f6c6c656374696f6e3e2866726f6d3a20466c6f775374616b696e67436f6c6c656374696f6e2e5374616b696e67436f6c6c656374696f6e53746f726167", "9000"],
    ["33020100fa6550617468290a2020202020202020202020203f3f2070616e69632822436f756c64206e6f7420626f72726f772072656620746f205374616b696e67436f6c6c656374696f6e22290a0a20202020202020206966206c6574206d616368696e654163636f756e74203d2073656c662e7374616b696e67436f6c6c656374696f6e5265662e6372656174654d616368696e654163636f756e74466f724578697374696e674e6f6465286e6f646549443a206e6f646549442c2070617965723a206163636f756e7429207b0a2020202020202020202020206966207075626c69634b657973203d3d206e696c207c7c207075626c69634b657973212e", "9000"],
    ["33020100fa6c656e677468203d3d2030207b0a2020202020202020202020202020202070616e6963282243616e6e6f742070726f76696465207a65726f206b65797320666f7220746865206d616368696e65206163636f756e7422290a2020202020202020202020207d0a202020202020202020202020666f72206b657920696e207075626c69634b65797321207b0a202020202020202020202020202020206d616368696e654163636f756e742e6164645075626c69634b6579286b65792e6465636f64654865782829290a2020202020202020202020207d0a20202020202020207d20656c7365207b0a20202020202020202020202070616e69632822", "9000"],
    ["33020100fa436f756c64206e6f74206372656174652061206d616368696e65206163636f756e7420666f7220746865206e6f646522290a20202020202020207d0a202020207d0a7d0af9027cb85c7b2274797065223a22537472696e67222c2276616c7565223a2238383534393333356531646237623562343663326164353864646237306237613435653737306363356665373739363530626132366631306536626165356536227db9021b7b2274797065223a224172726179222c2276616c7565223a5b7b2274797065223a22537472696e67222c2276616c7565223a2266383435623834303665346634336637396433633164386361636233643566", "9000"],
    ["33020100fa336537616565646232396665616562343535396664623731613937653266643034333835363533313065383736373030333564383362633130666536376665333134646261353336336338313635343539356436343838346231656361643135313261363465363565303230313634227d2c7b2274797065223a22537472696e67222c2276616c7565223a226638343562383430366534663433663739643363316438636163623364356633653761656564623239666561656234353539666462373161393765326664303433383536353331306538373637303033356438336263313066653637666533313464626135333633633831363534", "9000"],
    ["33020100fa3539356436343838346231656361643135313261363465363565303230313634227d2c7b2274797065223a22537472696e67222c2276616c7565223a2266383435623834303665346634336637396433633164386361636233643566336537616565646232396665616562343535396664623731613937653266643034333835363533313065383736373030333564383362633130666536376665333134646261353336336338313635343539356436343838346231656361643135313261363465363565303230313634227d5d7da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f19c161bc24cf4b4", "9000"],
    ["3302020016040a88f19c161bc24cf4b4c988f19c161bc24cf4b4c0","93cd8452a5f6770cefcec110e66e82d5986aa734d71c7055a95b0b6a2b74423b69924df1208bd18f9ae21a3e6236b8fc5500c4cbb69266435ee5c0cb3c9e190d00304502210093cd8452a5f6770cefcec110e66e82d5986aa734d71c7055a95b0b6a2b74423b022069924df1208bd18f9ae21a3e6236b8fc5500c4cbb69266435ee5c0cb3c9e190d9000"],
  ]
  
  const tx = "f906e9f906e5b90423696d706f727420466c6f775374616b696e67436f6c6c656374696f6e2066726f6d203078386430653837623635313539616536330a0a2f2f2f20437265617465732061206d616368696e65206163636f756e7420666f722061206e6f646" +
             "5207468617420697320616c726561647920696e20746865207374616b696e6720636f6c6c656374696f6e0a2f2f2f20616e642061646473207075626c6963206b65797320746f20746865206e6577206163636f756e740a0a7472616e73616374696f6e286e6f" +
             "646549443a20537472696e672c207075626c69634b6579733a205b537472696e675d29207b0a202020200a202020206c6574207374616b696e67436f6c6c656374696f6e5265663a2026466c6f775374616b696e67436f6c6c656374696f6e2e5374616b696e6" +
             "7436f6c6c656374696f6e0a0a2020202070726570617265286163636f756e743a20417574684163636f756e7429207b0a202020202020202073656c662e7374616b696e67436f6c6c656374696f6e526566203d206163636f756e742e626f72726f773c26466c" +
             "6f775374616b696e67436f6c6c656374696f6e2e5374616b696e67436f6c6c656374696f6e3e2866726f6d3a20466c6f775374616b696e67436f6c6c656374696f6e2e5374616b696e67436f6c6c656374696f6e53746f7261676550617468290a20202020202" +
             "02020202020203f3f2070616e69632822436f756c64206e6f7420626f72726f772072656620746f205374616b696e67436f6c6c656374696f6e22290a0a20202020202020206966206c6574206d616368696e654163636f756e74203d2073656c662e7374616b" +
             "696e67436f6c6c656374696f6e5265662e6372656174654d616368696e654163636f756e74466f724578697374696e674e6f6465286e6f646549443a206e6f646549442c2070617965723a206163636f756e7429207b0a2020202020202020202020206966207" +
             "075626c69634b657973203d3d206e696c207c7c207075626c69634b657973212e6c656e677468203d3d2030207b0a2020202020202020202020202020202070616e6963282243616e6e6f742070726f76696465207a65726f206b65797320666f722074686520" +
             "6d616368696e65206163636f756e7422290a2020202020202020202020207d0a202020202020202020202020666f72206b657920696e207075626c69634b65797321207b0a202020202020202020202020202020206d616368696e654163636f756e742e61646" +
             "45075626c69634b6579286b65792e6465636f64654865782829290a2020202020202020202020207d0a20202020202020207d20656c7365207b0a20202020202020202020202070616e69632822436f756c64206e6f74206372656174652061206d616368696e" +
             "65206163636f756e7420666f7220746865206e6f646522290a20202020202020207d0a202020207d0a7d0af9027cb85c7b2274797065223a22537472696e67222c2276616c7565223a22383835343933333565316462376235623436633261643538646462373" +
             "06237613435653737306363356665373739363530626132366631306536626165356536227db9021b7b2274797065223a224172726179222c2276616c7565223a5b7b2274797065223a22537472696e67222c2276616c7565223a226638343562383430366534" +
             "6634336637396433633164386361636233643566336537616565646232396665616562343535396664623731613937653266643034333835363533313065383736373030333564383362633130666536376665333134646261353336336338313635343539356" +
             "436343838346231656361643135313261363465363565303230313634227d2c7b2274797065223a22537472696e67222c2276616c7565223a22663834356238343036653466343366373964336331643863616362336435663365376165656462323966656165" +
             "62343535396664623731613937653266643034333835363533313065383736373030333564383362633130666536376665333134646261353336336338313635343539356436343838346231656361643135313261363465363565303230313634227d2c7b227" +
             "4797065223a22537472696e67222c2276616c7565223a2266383435623834303665346634336637396433633164386361636233643566336537616565646232396665616562343535396664623731613937653266643034333835363533313065383736373030" +
             "333564383362633130666536376665333134646261353336336338313635343539356436343838346231656361643135313261363465363565303230313634227d5d7da0f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b2a88f" +
             "19c161bc24cf4b4040a88f19c161bc24cf4b4c988f19c161bc24cf4b4c0"
  res = await app.sign("m/44'/539'/0'/0/0", Buffer.from(tx, "hex"), cryptoOptions, "arbitrary")
  assert.equal(res.returnCode, 0x04)
  res = await app.sign("m/44'/539'/0'/0/0", Buffer.from(tx, "hex"), cryptoOptions, "arbitrary")
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.signatureCompact.toString("hex"), "93cd8452a5f6770cefcec110e66e82d5986aa734d71c7055a95b0b6a2b74423b69924df1208bd18f9ae21a3e6236b8fc5500c4cbb69266435ee5c0cb3c9e190d00")
  assert.equal(res.signatureDER.toString("hex"), "304502210093cd8452a5f6770cefcec110e66e82d5986aa734d71c7055a95b0b6a2b74423b022069924df1208bd18f9ae21a3e6236b8fc5500c4cbb69266435ee5c0cb3c9e190d")
  assert.equal(transport.expected.length, 0)
  
  //signTransaction - merkle tree. This needs to be fixed when merkle tree changes. FA.01, only metadata (330203) and proof is important (330204, 330205)
  //metadata: "029e46752d27947cc85e5fb62f4deecb12bd7b2a721211ef944acf528bd648dcd79e46752d27947cc85e5fb62f4deecb12bd7b2a721211ef944acf528bd648dcd7437265617465204163636f756e740003045075626c6963204b65790000065369676e617475726520416c672e0001054861736820416c672e0002"
  //proof1
  transport.expected = [
    ["3300000000", "00000c0000311000049000"],
    ["33020000162c0000801b0200800102008000000000000000000103", "9000"],
    ["3302010002f904","9000"],
    ["330203007b029e46752d27947cc85e5fb62f4deecb12bd7b2a721211ef944acf528bd648dcd79e46752d27947cc85e5fb62f4deecb12bd7b2a721211ef944acf528bd648dcd7437265617465204163636f756e740003045075626c6963204b65790000065369676e617475726520416c672e0001054861736820416c672e0002", "9000"],
    ["33020400e023b0dd67bd651dd2ae5c318486bf96f170173d6eb52bbb8867fc4b9914be7caac44d21aa30fcd3c717c02151cb60275dd84e97ab0f6e03f3b8b67c8701ce0e0066f2970da5775dece3467df9268d5f5349c57ba0cb5016bc3a4412eb9b1bd4b609e42bcf86c1357d31d8ed3d2569596e58f44efeef4a7aa2c89adc30242f2d6e589eb34bbae9b1da9ecddca7fd3d2e03d6a383b9b7c0209ef2711a657e7dedc5779cf5bedad006f073e50ac176159dfb9e020957d29b81947dbfe07d9136b1fa932bebc831854a61bc79fd527ce161c0fc279a6dce5d326499f0215356337bdf", "9000"],
    ["33020400e04f7c6cc135c8aa32426d5303a93685b67e7088d862f3cf1ed1d827abcdfd544c742d6e0015520cf3206f04bd73d312f1d20d767b28b5932e157f16d77369d5b0700b87fc1343839e67f28a65b58dc091282cde796ef16d069a3b60f6ee3f8c20413bed19a08455b0b72cf2bedc8aed52170ab7ccc6e1c582d4940fa14e09bb3563981575be94aaa4f14daa9f27c6c2fd72b46de3994ed71abaec45aa4b40615a63981575be94aaa4f14daa9f27c6c2fd72b46de3994ed71abaec45aa4b40615a63981575be94aaa4f14daa9f27c6c2fd72b46de3994ed71abaec45aa4b40615a", "9000"],
    ["33020400e07c5cb8603f41d182e1f7867630fc4faac07fa2e3eebd64cafedc8aa755e16f9888bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad9192988bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad9192988bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad9192988bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad9192988bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad9192988bd487007bf1a5be47cea944d797895181258aba33c77e8c75fe7e38ad91929", "9000"],
    ["33020500e05a8094539a9e1642a60775137dbcd1d048cf51e7e9bf027b72d46c9285a0f44294a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e94a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e94a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e94a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e94a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e94a4bf5f458f2def50f807bf419501bfd5e77a084c30592aa3803a522a3c272e", "47fba63d87cac1a4d3d6345eb9ad4a8197d15cad816326675b950dc084fc90eb09a4c529640f92a5f07c4f54221f26f08a09c3d635cac6cc633050e0dff9e844003044022047fba63d87cac1a4d3d6345eb9ad4a8197d15cad816326675b950dc084fc90eb022009a4c529640f92a5f07c4f54221f26f08a09c3d635cac6cc633050e0dff9e8449000"],
  ]

  tx2 = "f904"
  // This needs to be fixed if hash changes. FA.01
  scriptHash = "9e46752d27947cc85e5fb62f4deecb12bd7b2a721211ef944acf528bd648dcd7"
  res = await app.sign("m/44'/539'/513'/0/0", Buffer.from(tx2, "hex"), cryptoOptions, scriptHash)
  assert.equal(res.returnCode, 0x9000)
  assert.equal(res.signatureCompact.toString("hex"), "47fba63d87cac1a4d3d6345eb9ad4a8197d15cad816326675b950dc084fc90eb09a4c529640f92a5f07c4f54221f26f08a09c3d635cac6cc633050e0dff9e84400")
  assert.equal(res.signatureDER.toString("hex"), "3044022047fba63d87cac1a4d3d6345eb9ad4a8197d15cad816326675b950dc084fc90eb022009a4c529640f92a5f07c4f54221f26f08a09c3d635cac6cc633050e0dff9e844")
  assert.equal(transport.expected.length, 0)
}

runTest()


