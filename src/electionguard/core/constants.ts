import {Eq} from '../ballot/election-object-base';
import {ElGamalPublicKey} from './elgamal';
import {compatibleContextOrFail, ElementModQ} from './group-common';
import {hashElements} from './hash';

const pStrHex4096 =
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF93C467E37DB0C7A4D1BE3F810152CB56A1CECC3AF65CC0190C03DF34709AFFBD8E4B59FA03A9F0EED0649CCB621057D11056AE9132135A08E43B4673D74BAFEA58DEB878CC86D733DBE7BF38154B36CF8A96D1567899AAAE0C09D4C8B6B7B86FD2A1EA1DE62FF8643EC7C271827977225E6AC2F0BD61C746961542A3CE3BEA5DB54FE70E63E6D09F8FC28658E80567A47CFDE60EE741E5D85A7BD46931CED8220365594964B839896FCAABCCC9B31959C083F22AD3EE591C32FAB2C7448F2A057DB2DB49EE52E0182741E53865F004CC8E704B7C5C40BF304C4D8C4F13EDF6047C555302D2238D8CE11DF2424F1B66C2C5D238D0744DB679AF2890487031F9C0AEA1C4BB6FE9554EE528FDF1B05E5B256223B2F09215F3719F9C7CCC69DDF172D0D6234217FCC0037F18B93EF5389130B7A661E5C26E54214068BBCAFEA32A67818BD3075AD1F5C7E9CC3D1737FB28171BAF84DBB6612B7881C1A48E439CD03A92BF52225A2B38E6542E9F722BCE15A381B5753EA842763381CCAE83512B30511B32E5E8D80362149AD030AABA5F3A5798BB22AA7EC1B6D0F17903F4E22D840734AA85973F79A93FFB82A75C47C03D43D2F9CA02D03199BACEDDD4533A52566AFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
const qStrHex4096 =
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43';
const rStrHex4096 =
  '100000000000000000000000000000000000000000000000000000000000000bc93c467e37db0c7a4d1be3f810152cb56a1cecc3af65cc0190c03df34709b8af6a64c0cedcf2d559da9d97f095c3076c686037619148d2c86c317102afa2148031f04440ac0ff0c9a417a89212512e7607b2501daa4d38a2c1410c4836149e2bdb8c8260e627c4646963effe9e16e495d48bd215c6d8ec9d1667657a2a1c8506f2113ffad19a6b2bc7c45760456719183309f874bc9ace570ffda877aa2b23a2d6f291c1554ca2eb12f12cd009b8b8734a64ad51eb893bd891750b85162241d908f0c9709879758e7e8233eab3bf2d6ab53afa32aa153ad6682e5a0648897c9be18a0d50bece030c3432336ad9163e33f8e7daf498f14bb2852affa814841eb18dd5f0e89516d557776285c16071d211194ee1c3f34642036ab886e3ec28882ce4003dea335b4d935bae4b58235b9fb2bab713c8f705a1c7de42220209d6bbcacc467318601565272e4a63e38e2499754ae493ac1a8e83469eef35ca27c271bc792eee21156e617b922ea8f713c22cf282dc5d6385bb12868eb781278fa0ab2a8958fccb5ffe2e5c361fc174420122b0163ca4a46308c8c46c91ea7457c136a7d9fd4a7f529fd4a7f529fd4a7f529fd4a7f529fd4a7f529fd4a7f529fd4a7f52a';
const gStrHex4096 =
  '1D41E49C477E15EAEEF0C5E4AC08D4A46C268CD3424FC01D13769BDB43673218587BC86C4C1448D006A03699F3ABAE5FEB19E296F5D143CC5E4A3FC89088C9F4523D166EE3AE9D5FB03C0BDD77ADD5C017F6C55E2EC92C226FEF5C6C1DF2E7C36D90E7EAADE098241D3409983BCCD2B5379E9391FBC62F9F8D939D1208B160367C134264122189595EC85C8CDBE5F9D307F46912C04932F8C16815A76B4682BD6BDC0ED52B00D8D30F59C731D5A7FFAE8165D53CF96649AAC2B743DA56F14F19DACC5236F29B1AB9F9BEFC69697293D5DEAD8B5BF5DE9BAB6DE67C45719E56344A3CBDF3609824B1B578E34EAEB6DD3190AB3571D6D671C512282C1DA7BD36B4251D2584FADEA80B9E141423074DD9B5FB83ACBDEAD4C87A58FFF517F977A83080370A3B0CF98A1BC2978C47AAC29611FD6C40E2F9875C35D50443A9AA3F49611DCD3A0D6FF3CB3FACF31471BDB61860B92C594D4E46569BB39FEEADFF1FD64C836A6D6DB85C6BA7241766B7AB56BF739633B054147F7170921412E948D9E47402D15BB1C257318612C121C36B80EB8433C08E7D0B7149E3AB0A8735A92EDCE8FF943E28A2DCEACFCC69EC318909CB047BE1C5858844B5AD44F22EEB289E4CC554F7A5E2F3DEA026877FF92851816071CE028EB868D965CCB2D2295A8C55BD1C070B39B09AE06B37D29343B9D8997DC244C468B980970731736EE018BBADB987';

const pStrHex3072 =
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF93C467E37DB0C7A4D1BE3F810152CB56A1CECC3AF65CC0190C03DF34709AFFBD8E4B59FA03A9F0EED0649CCB621057D11056AE9132135A08E43B4673D74BAFEA58DEB878CC86D733DBE7BF38154B36CF8A96D1567899AAAE0C09D4C8B6B7B86FD2A1EA1DE62FF8643EC7C271827977225E6AC2F0BD61C746961542A3CE3BEA5DB54FE70E63E6D09F8FC28658E80567A47CFDE60EE741E5D85A7BD46931CED8220365594964B839896FCAABCCC9B31959C083F22AD3EE591C32FAB2C7448F2A057DB2DB49EE52E0182741E53865F004CC8E704B7C5C40BF304C4D8C4F13EDF6047C555302D2238D8CE11DF2424F1B66C2C5D238D0744DB679AF2890487031F9C0AEA1C4BB6FE9554EE528FDF1B05E5B256223B2F09215F3719F9C7CCC69DED4E530A6EC940C45314D16D3D864B4A8934F8B87C52AFA0961A0A6C5EE4A35377773FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
const qStrHex3072 = qStrHex4096;
const rStrHex3072 =
  '100000000000000000000000000000000000000000000000000000000000000BC93C467E37DB0C7A4D1BE3F810152CB56A1CECC3AF65CC0190C03DF34709B8AF6A64C0CEDCF2D559DA9D97F095C3076C686037619148D2C86C317102AFA2148031F04440AC0FF0C9A417A89212512E7607B2501DAA4D38A2C1410C4836149E2BDB8C8260E627C4646963EFFE9E16E495D48BD215C6D8EC9D1667657A2A1C8506F2113FFAD19A6B2BC7C45760456719183309F874BC9ACE570FFDA877AA2B23A2D6F291C1554CA2EB12F12CD009B8B8734A64AD51EB893BD891750B85162241D908F0C9709879758E7E8233EAB3BF2D6AB53AFA32AA153AD6682E5A0648897C9BE18A0D50BECE030C3432336AD9163E33F8E7DAF498F14BB2852AFFA814841EB18DD5F0E89516D557776285C16071D211194EE1C3F34642036AB886E3EC28966409FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F52A';
const gStrHex3072 =
  'AF8DC2057963C6C364119C014A27686BA780576748B72F670C4A5D4C3FAC1E228B84FBA88C4EAF94DF98755C6C73611BB54A14A6E232D238C917DA76D8A62B70837A15EEC1110C112561AB0EAE9E11DDCEC61F2BBD54BB762FC903494EF21F0F338FE26582453CE3FF02C53A77296126E59E1980CD49A56726A40CFDEF93A18141CF83442D0FDCDF9F1351B2D0CF814CE9C796402DC2218132D283605BDD15468EABA4B6F78E4DE3DE0766FA9915ED28E00D90757F494986092477C90C5FC305A56829088D996D227D2F018C1A16377B0014A8183F59CF8871C4659132BDDBA79E869AE8F65C93608D179A07D7D994E058E5F51B47C7209A25864DA9F1377C16B1C09C85B66CC3D527FAB3F6B2DF6D6BEA15206298BAC3E293F10E2E9B780ECE033A47CFC451221522BB709E1B94D8EA7487242185D8F8FB013E9E107395D53E22C55502FC1E4A915766F3C3B463A3EE4CB682926A0C4F87CD86181ABC6FB902BD8331DE18F59820C5D967D784B1C06E5A94F31EF8611B545D2F1E184CEAC312';

const montgomeryIPrimeStrHex3072 =
  '4990cce585869887acbcb4dbfcdfff8dd2155f16e6a81c0ded73ad82a8d9688460876c371b2c82bd5e5a45ea664cbe15d4bec04e76d9a9aead9cf2905d025e22bb70002999703653e293f01d979d18e6c3f14cb9101f7ebc228ea4bfc063d437ad3bdc8a2f8c1859d15078bffa2e12c3669ec7f6cd5aae090921b3e67322748d57b39d756fda06f68733356ab97e6f358aa3180d096df3457d23c6fb19b1d2b1232a4581a0ca2b2d628223743aca31b42b0164dc9cb1aaf0a10a07f8acf67334085105246b19b2d572532924d2896a326c4ff95d2cb81c100a02520f1e8491b4d585ea280594d3bcce688302d802e606b7bfb0866864383393c985cff3c577a2cfb89f56a64c94e8a857fd5c7a7b88e80b493fa2ba7ceb2d7f660438ce965b7b0d64cb2817b28178dbe6dc5abc37c35d27b270b68f6ae176cd624297907cff60ff72a5fa4e4ac600a0e312fd0007f13c3196532e478bd5764bc3efdd08813f632cde48a95a889c52653ecf695e1e8149b22cecdf89d3b569678e755d5d6ae55c';
const montgomeryPPrimeStrHex3072 =
  '4990cce585869887acbcb4dbfcdfff8dd2155f16e6a81c0ded73ad82a8d968847fa1a2bd53580d6bf10071cc0fe678cb793c1b849eea5a143002b1fd356a0293a293f953bb04ad1a2b598c8a1bdfb6759f2270cd554d57954c0ef37bc5d27b10990ee7e2b267ae425a366ae8786625466947a9636e7d933778a959a19f8f580d4e0b8bb457b4202dcc28b6d176fa5004b8b7e8ade60cce726233387fe3878f5689cf9e240379f09b7d71a53523c5f0c0ee2ca8aecf650c6056c20a096ed10b15a8bc1636074eee9800bd2c13cdc7e09aea06abd661a47bae7ca99edc5abd4fb082f8605e25091077050eb699049ebcf34e77931dafec91aac56ad74a5d6a72825c8ea0f10a1472d2ce14785cd143bb0d5685a1cd8c41b2e0bfa8726ce56c22e2ac96d6892bc14c57216ea6332e0981bcbe52e35cef21132fd9613f56fd73e17530a6ec940c45314d16d3d864b4a8934f8b87c52afa0961a0a6c5ee4a353777740000000000000000000000000000000000000000000000000000000000000001';

const montgomeryIPrimeStrHex4096 =
  'a499e87e56f5b20d02230de9ae874b06e28135f6ec3833baa77ee1df44b228cebaa35d818da5c8c84dff1220d7601002987b5fc48c7242bfcad2796e091658fbba430238e9140d901b931e8042565286ad62526cae5361284441511ef7b919df4cfda6b34e86fc193674d8b2a831be0852f9f424330966372e611198aec9a02ba429b8708f8180fad43dedae1a6c6050e4cbdc8a6b8b86cc903cca3e36d5921d321720408c0fd5a5bf20722f425ba4d1f89d94770193999acd6ccb75487846df656535fb45e7715f7d9a5d77e80efb2e0180cbd1b592bf45b7ddc09f266728044877516826cb0e50d91057a7b38ae6451438b88b7b8b6ac4214208196c42983e21ffd003f7f77028cab447e4344e2f567c35f990668d42c617b2db3191c753feb5273b9fbd7edc725dfdab532e53863bc6d74d820732e87293a4ddc7b56cfc124c43aae2520f6005b67dbcd3d576a4bfe5395f0779a46c7e669ffbb9894d9fb6020bff42fd114960e1657f1802d87d7b3b819298e4b35ce38aec1a7bff3ad6efea3f9380db2d5e635e5b5a38f0bc8d5f9130cf26c784d629cb71d32c0761d77ce16505ddea13c0655bdd7134ea7d4a8cb74a0eb5edc29b29144ad7f28a433748640b0c8b19bd486ef97d8721e93f481b6c4eed3f5a06feed96c7ac73465b933c42e6e17b2500053269c9c1aba24dbcbb476563ed25700da009d0b594e40ef8c1';
const montgomeryPPrimeStrHex4096 =
  'a499e87e56f5b20d02230de9ae874b06e28135f6ec3833baa77ee1df44b228cf003a9cdd261d03c46af15d8fb4eab753d86b12ee958e1287814b7162104ef7ba880b7bdd6d6b82f4db6010a8daede53463c293d84dbf5d9fb419fe60247678fff6954643e4027c5eea24cc376ce374a62d156d106743ed023df71ce2dc431fac3917ce9c52d2755860f1fc2cfbc78e819c1dfd94641244a9ca176054f2607e6cb533d36465aae567a42f74a827b0ea031d49d2a0cb353a9a30c0058ff9eb9edd6c309f05df2a3aa18bd4c46bf2ddd36f9caba882e0f1c8d9a1a37eecee8d933a5418f65e30d995493744762f1465b61aad9fa87909a3db268dd6ac572dff1ba7d3f82cf9a30c6081c9dc5563eb73754d9c67781fd858efbecd43c63930374eb65325d1d00efa9eb5b7d8a447f32fde6608ab1fe075f29f56829393e56f53f05c0916f632b33382098f79208f7881fc400616208c9c8902a215c835866b538d26bebfce85b18bad91ee9d4e941e4a72f9ff9fb20047d49cb49a6f2d8053feb2c645dd170fc8e3d7265290d3aba47eac2ac5feebad11e3921fb54e42a7e32e4abd9d5307cd9bc4bbe9e964110c2345252d0a7b3eded85259319805aefad7e594c034aa85973f79a93ffb82a75c47c03d43d2f9ca02d03199baceddd4533a52566b0000000000000000000000000000000000000000000000000000000000000001';

// 4096-bit P and 256-bit Q primes, plus generator G
export const production4096P = BigInt('0x' + pStrHex4096);
export const production4096Q = BigInt('0x' + qStrHex4096);
export const production4096G = BigInt('0x' + gStrHex4096);
export const production4096R = BigInt('0x' + rStrHex4096);
export const production4096MontIPrime = BigInt(
  '0x' + montgomeryIPrimeStrHex4096
);
export const production4096MontPPrime = BigInt(
  '0x' + montgomeryPPrimeStrHex4096
);

// 3072-bit P and 256-bit Q primes, plus generator G
export const production3072P = BigInt('0x' + pStrHex3072);
export const production3072Q = BigInt('0x' + qStrHex3072);
export const production3072G = BigInt('0x' + gStrHex3072);
export const production3072R = BigInt('0x' + rStrHex3072);
export const production3072MontIPrime = BigInt(
  '0x' + montgomeryIPrimeStrHex3072
);
export const production3072MontPPrime = BigInt(
  '0x' + montgomeryPPrimeStrHex3072
);

// 32-bit everything, suitable for accelerated testing
export const intTestP = 1879047647;
export const intTestQ = 134217689;
export const intTestR = 14;
export const intTestG = 1638;

/**
 * A public description of the mathematical group used for the encryption and processing of ballots.
 * One of these should accompany every batch of encrypted ballots, allowing future code that might
 * process those ballots to determine what parameters were in use and possibly give a warning or
 * error if they were unexpected.
 *
 * The byte arrays are defined to be big-endian.
 */
export class ElectionConstants implements Eq<ElectionConstants> {
  constructor(
    /** large prime or P. */
    readonly largePrime: bigint,
    /** small prime or Q. */
    readonly smallPrime: bigint,
    /** cofactor or R. */
    readonly cofactor: bigint,
    /** generator or G. */
    readonly generator: bigint
  ) {}

  equals(other: ElectionConstants): boolean {
    return (
      this.largePrime === other.largePrime &&
      this.smallPrime === other.smallPrime &&
      this.cofactor === other.cofactor &&
      this.generator === other.generator
    );
  }
}

/**
 * Configuration of election to allow edge cases. This class is here for
 * compatibility with the rest of ElectionGuard, but the fields here are
 * ignored by the current ElectionGuard-TypeScript implementation.
 */
export class EdgeCaseConfiguration implements Eq<EdgeCaseConfiguration> {
  constructor(
    /** Allow overvotes, votes exceeding selection limit, for the election. */
    readonly allowOvervotes: boolean,

    /**
     * Maximum votes, the maximum votes allowed on a selection for an aggregate ballot or tally.
     * This can also be seen as the maximum ballots where a selection on a ballot can only have one vote.
     */
    readonly maxVotes: number
  ) {}

  equals(other: EdgeCaseConfiguration): boolean {
    return (
      other instanceof EdgeCaseConfiguration &&
      other.allowOvervotes === this.allowOvervotes &&
      other.maxVotes === this.maxVotes
    );
  }
}

/**
 * The cryptographic context of an election. Equivalent to the "CiphertextElectionContext"
 * in the ElectionGuard-Python codebase. Note that some of these fields are not supported
 * by the current ElectionGuard-TypeScript implementation.
 */
export class ElectionContext implements Eq<ElectionContext> {
  constructor(
    /** The number of guardians necessary to generate the public key. */
    readonly numberOfGuardians: number,

    /** The quorum of guardians necessary to decrypt an election. Must be <= number_of_guardians. */
    readonly quorum: number,

    /** The joint public key (K) in the ElectionGuard Spec. */
    readonly jointPublicKey: ElGamalPublicKey,

    /** Matches Manifest.cryptoHashElement */
    readonly manifestHash: ElementModQ,

    /** The `base hash code (𝑄)` in the specification. */
    readonly cryptoBaseHash: ElementModQ,

    /** The `extended base hash code (𝑄')` in specification. */
    readonly cryptoExtendedBaseHash: ElementModQ,

    /**
     * the `commitment hash H(K 1,0 , K 2,0 ... , K n,0 )` of the public
     * commitments guardians make to each other in the specification
     */
    readonly commitmentHash: ElementModQ,

    /** Data to allow extending the context for special cases.  */
    readonly extendedData?: Record<string, string>,

    /** Configuration for the election edge cases. */
    readonly configuration?: EdgeCaseConfiguration
  ) {}

  equals(other: ElectionContext): boolean {
    return (
      this.numberOfGuardians === other.numberOfGuardians &&
      this.quorum === other.quorum &&
      this.jointPublicKey.equals(other.jointPublicKey) &&
      this.manifestHash.equals(other.manifestHash) &&
      this.cryptoBaseHash.equals(other.cryptoBaseHash) &&
      this.cryptoExtendedBaseHash.equals(other.cryptoExtendedBaseHash) &&
      this.commitmentHash.equals(other.commitmentHash)
      // we're ignoring the optional extendedData and configuration fields
    );
  }

  /** Simplified builder method, knows how to compute the base hashes. */
  static create(
    numberOfGuardians: number,
    quorum: number,
    elGamalPublicKey: ElGamalPublicKey,
    commitmentHash: ElementModQ,
    manifestHash: ElementModQ,
    extendedData?: Record<string, string>
  ): ElectionContext {
    const group = compatibleContextOrFail(
      elGamalPublicKey.element,
      commitmentHash,
      manifestHash
    );
    const cryptoBaseHash = hashElements(
      group,
      group.P,
      group.Q,
      group.G,
      numberOfGuardians,
      quorum,
      manifestHash
    );
    const cryptoExtendedBaseHash = hashElements(
      group,
      cryptoBaseHash,
      commitmentHash
    );

    return new ElectionContext(
      numberOfGuardians,
      quorum,
      elGamalPublicKey,
      manifestHash,
      cryptoBaseHash,
      cryptoExtendedBaseHash,
      commitmentHash,
      extendedData
    );
  }
}

export class EncryptionDevice {
  constructor(
    /** Unique identifier for device. */
    readonly deviceId: number,
    /** Used to identify session and protect the timestamp. */
    readonly sessionId: number,
    /** Election initialization value. */
    readonly launchCode: number,
    readonly location: string
  ) {}
}
