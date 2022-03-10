import {
  encrypt_ballot,
} from "./simple_elections";
import {get_optional} from "./utils";
import {
  // encrypt_compatible_testing_demo,
  from_file_to_class,
  // from_file_to_class_manifest,
  // from_file_to_PlaintextBallots,
  from_test_file_to_valid_inputs,
  EncryptInput
} from "./serialization";
import {
  make_ciphertext_election_context,
  // PlaintextBallot
} from "./simple_election_data";
import { ElementModQ,ElementModP } from "./group";

import {InternalManifest} from "./manifest";
import * as fs from "fs";

describe("TestDeserialization", () => {

  // // Test encryption with decryption
  // test('testConvertJsonFileToObj', () => {
  //   if (!fs.existsSync('encrypted_data/' )){
  //     fs.mkdirSync('encrypted_data/');
  //   }
  //  fs.readdirSync('generated_data').forEach(ballotNum => {
  //   const plaintextBallots: PlaintextBallot[] = from_file_to_PlaintextBallots("generated_data/" + ballotNum + "/ballot.json");
  //   const inputs = from_file_to_class();
  //   const readin_manifest = from_file_to_class_manifest("generated_data/"  + ballotNum + "/manifest.json");
  //   const internal_manifest = new InternalManifest(readin_manifest);
  //   const context = make_ciphertext_election_context(
  //     1,
  //     1,
  //     new ElementModP(BigInt("830647157921994533723221005688631837480749398093445682001345686145740504886693557419420287148894620628327687420710726184348492930161894426493567555053596304649756865662220152329151716691934339041489536445247808117192732474571762845305844818677676027235934920872239155120388422503195221344180333410127696131933518090047779221829662472818614236336581270341516530022704420443521097772128662124700211839211210908721533915110539300139766705909309815876793687494911116485149385267865330061438844344021027447760903959136805223414385040803151787918988887581567106728305638458450493532895134074416008333717556907440325422540005263755609440349926174900556055858298011233206372856463781327705746366049681672365068236528055877038951830996931086933850260432495637363415002875938135062292231445719262483613467991371369722352993560079282071699535196245817558663511296549603008092897623602899067100100046991701043923308908034328428840035795408907896272755397659393862126111128719708642351119960293861305660688827861839076070133848354823436507263419927109258160045333741762936765504361331647521583134171766657762829386224953145958922580767709905067103552647337580390689696044087562378269531673703889514970340624863075080886563924366245877576117478210")),
  //     new ElementModQ(2),
  //     internal_manifest.manifest.crypto_hash(),
  //     undefined);
  //   const encryption_seed = new ElementModQ(BigInt('88136692332113344175662474900446441286169260372780056734314948839391938984061'));
  //   let idx = 0;
  //   for (const plaintextBallot of plaintextBallots) {
  //     const encrypted_ballot = encrypt_ballot(plaintextBallot, internal_manifest, context, encryption_seed, get_optional(inputs.nonce));
  //     if (!fs.existsSync('encrypted_data/' + ballotNum)){
  //       fs.mkdirSync('encrypted_data/' + ballotNum);
  //     }
  //     fs.writeFileSync(`encrypted_data/${ballotNum}/encrypted_ballot_${ballotNum}-${idx}.json`, encrypt_compatible_testing_demo(get_optional(encrypted_ballot)));
  //     idx++;
  //   }
  //  });
  // });

  // Test encryption with given test vectors
  test('testTestVectors', () => {
    const testFolder = `generated_test_inputs_ts`;
    if (!fs.existsSync(testFolder)){
      fs.mkdirSync(testFolder);
    }

    fs.readdirSync(testFolder).forEach(file => {
      if (file !== testFolder) {
        const path2TestVector = testFolder + "\\" + file;
        const encryptInputs: EncryptInput[] = from_test_file_to_valid_inputs(path2TestVector);
        for (const input of encryptInputs) {
          const inputs = from_file_to_class();
          const internal_manifest = new InternalManifest(input.manifest);
          const context = make_ciphertext_election_context(
          1,
          1,
          new ElementModP(BigInt("830647157921994533723221005688631837480749398093445682001345686145740504886693557419420287148894620628327687420710726184348492930161894426493567555053596304649756865662220152329151716691934339041489536445247808117192732474571762845305844818677676027235934920872239155120388422503195221344180333410127696131933518090047779221829662472818614236336581270341516530022704420443521097772128662124700211839211210908721533915110539300139766705909309815876793687494911116485149385267865330061438844344021027447760903959136805223414385040803151787918988887581567106728305638458450493532895134074416008333717556907440325422540005263755609440349926174900556055858298011233206372856463781327705746366049681672365068236528055877038951830996931086933850260432495637363415002875938135062292231445719262483613467991371369722352993560079282071699535196245817558663511296549603008092897623602899067100100046991701043923308908034328428840035795408907896272755397659393862126111128719708642351119960293861305660688827861839076070133848354823436507263419927109258160045333741762936765504361331647521583134171766657762829386224953145958922580767709905067103552647337580390689696044087562378269531673703889514970340624863075080886563924366245877576117478210")),
          new ElementModQ(2),
          internal_manifest.manifest.crypto_hash(),
          undefined);
//           console.log("manifest hash in ts is ", internal_manifest.manifest.crypto_hash());
          const encryption_seed = new ElementModQ(BigInt('88136692332113344175662474900446441286169260372780056734314948839391938984061'));
          const encrypted_ballot = get_optional(encrypt_ballot(input.plaintextBallot, internal_manifest, context, encryption_seed, get_optional(inputs.nonce)));
          expect(encrypted_ballot.crypto_hash.equals(input.output)).toBe(true);
        }
      }
    });
  });

 });
