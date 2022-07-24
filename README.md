# 🗳 ElectionGuard Typescript

A typescript library that implements a subset of the [ElectionGuard](https://www.electionguard.vote/) spec to allow encryption of ballots in browsers.

## Features

- Ballot encryption

  **Note**: write-ins, overvotes, and undervotes are not supported in our implementation of ElectionGuard 1.0.

- Compatibility with [electionguard-python](https://github.com/microsoft/electionguard-python/)
- Support for [modern](https://caniuse.com/bigint) browsers
- Support for NodeJS >= 14

## Non-features

- Ballot decryption
- Verification

## Installation

### Node

**Note**: we haven't published a npm package yet.

```sh
npm install github:danwallach/electionguard
# or
yarn add electionguard@danwallach/electionguard
```

### Browser

As an **ES module**:

```html
<head>
  <!-- ... -->
  <script type="module">
    import {ManifestParty, bigIntContext4096} from './dist/electionguard.js';
    console.log(new ManifestParty(bigIntContext4096(), 'example'));
  </script>
</head>
```

As a **UMD module**:

```html
<head>
  <!-- ... -->
  <script src="./dist/electionguard.umd.js"></script>
</head>
<body>
  <!-- ... -->
  <script>
    console.log(
      new eg.ManifestParty(eg.bigIntContext4096(), 'example')
    );
  </script>
</body>
```

## Usage

```js
import {
  AsyncBallotEncryptor,
  bigIntContext4096,
  EncryptionDevice,
  PlaintextBallot,
  PlaintextContest,
  PlaintextSelection,
} from 'electionguard';

const context = bigIntContext4096();
const device = new EncryptionDevice(context, 55890250559315, 12345, 45678, 'polling-place');
let codeSeed = device.cryptoHashElement;

const manifestObj = {
  election_scope_id: 'hamilton-county-general-election',
  spec_version: '1.0',
  // ...
};
const electionContextObj = {
  number_of_guardians: 5,
  quorum: 3,
  // ...
};
const ballot = new PlaintextBallot(
  'ballot-8a27eaa6-f1c3-11ec-b605-aaf53b701db4',
  'congress-district-5-hamilton-county',
  [
    new PlaintextContest('president-vice-president-contest', [
      new PlaintextSelection('cramer-vuocolo-selection', 1),
    ]),
    // ...
  ]
);

const encryptor = AsyncBallotEncryptor.create(
  context,
  manifestObj,
  electionContextObj,
  false,
  ballot.ballotStyleId,
  ballot.ballotId,
  codeSeed
);
ballot.contests.forEach(contest => encryptor.encrypt(contest));

(async () => {
  const result = await encryptor.getSerializedEncryptedBallot();
  const {serializedEncryptedBallot, ballotHash} = result;

  const ballotHashModQ = context.createElementModQ(ballotHash);
  if (ballotHashModQ === undefined) {
    throw new Error('unable to create ElementModQ from ballotHash');
  }
  codeSeed = ballotHashModQ;

  console.log(JSON.stringify(serializedEncryptedBallot, null, 2));
})();
```

<!-- See `examples/` for more examples. -->

Check the [documentation](#documentation) for a full list of exports.

## Documentation

<!-- TODO: deploy these somewhere -->

You can generate API documentation using [TypeDoc](https://typedoc.org/guides/doccomments/).

```bash
npm run docs
```

### Development

```bash
# Install dependencies
npm install

# Now you can run various npm commands:
npm run test
npm run coverage
npm run build
npm run elgamal-bench
# ...

# Auto-indenter and linter (uses gts)
npm run fix
```

See also:

- [`NOTES.md`](./NOTES.md)
- [`PRECOMPUTE.md`](./PRECOMPUTE.md)

## License

[MIT License](./LICENSE)

## Authors

- Han Guo <alexiland@outlook.com>
- Xin Hao <xinhaofighting@gmail.com>
- Shreyas Minocha <shreyasminocha@rice.edu>
- Dan S. Wallach <dwallach@rice.edu> or <dwallach@gmail.com>
- Arthur Wu <wuwenqin200613@gmail.com>
- Yanyu Zhong <yanyuzhongzyy@gmail.com>
- Zihe Zhao <zz83@rice.edu>
