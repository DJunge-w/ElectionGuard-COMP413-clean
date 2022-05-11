![Microsoft Defending Democracy Program: ElectionGuard Python][banner image]

# 🗳 ETS: ElectionGuard Typescript


[banner image]: https://raw.githubusercontent.com/microsoft/electionguard-python/main/images/electionguard-banner.svg

## ❓ What Is Vote-by-mail?
 Vote by mail, or vote at home, is a method of voting that voters get their ballot delivered to them weeks before Election Day, fill it out at their convenience, then return it either in-person or by mail. There are two types of vote by mail system -- comprehensive vote by mail and absentee ballots. To ensure the integrity of elections and the validity of each ballot, risk-limiting audits are implemented and ballot tracking services are provided.

## ❓ What Is End-to-End Verifiable Voting?
 E2E verifiable voting is a way to guarantee voting system security, preventing someone other than the sender or recipient from accessing & modifying the ballots. The voters first vote the way they would traditionally on an electronic voting system, but in the end, an e2e system would use cryptography and generate a receipt of a long numeric sequence or a qrcode. This receipt is essentially a record of the vote that's been encrypted with a secret key the voter doesn't have. But it still allows voters to verify that their votes were counted. E2E verifiable voting is able to respond to voters' challenge on whether their ballots are included by providing mathematical proofs which show that the ballots add up to the officially announced totals.  That is the mechanism of how the voters can get confident evidence of their ballot being effective without revealing which candidates were voted for nor requiring them to trust election official results, software, hardware, and so on.


## ❓ What Is ElectionGuard?
ElectionGuard is an open source software development kit (SDK) that makes voting more secure, transparent and accessible. The ElectionGuard SDK leverages homomorphic encryption to ensure that votes recorded by electronic systems of any type remain encrypted, secure, and secret. Meanwhile, ElectionGuard also allows verifiable and accurate tallying of ballots by any 3rd party organization without compromising secrecy or security.

## ❗️Here comes Electionguard Typescript!
Our team focuses on building a bridge between the vote-by-mail system and end-to-end verifiable encryption. We want to create a user-friendly web application that not only allows user to vote and print out their ballot, but also performs chaum Peterson encryption while they are voting. This is actually an in-browser version of election guard. 

To achieve this, for Microsoft team, we built a typescript frontend implementation that uses the exactly same encryption logic as election guard. For Front end web interface, we built a fully encapsulated API to add the feature of ballot encryption for them. You can just use approximately few lines of code that calls encrpt_ballot in the front-end typescript, and we will handle everything else for you. 

## Workflow of ETS:
Data pipeline:
![workflow of ETS](README_src/workflow.png)

## Demo application:

[Please vote here!](https://comp413vote.surge.sh/)


## 💻 Requirements

- [Python 3.9](https://www.python.org/downloads/) is <ins>**required**</ins> to develop this SDK. If developer uses multiple versions of python, [pyenv](https://github.com/pyenv/pyenv) is suggested to assist version management.
- [Typescript 4.2](https://www.typescriptlang.org/download) is used to perform script written for front-end web applciation. 
- [Node & Yarn Package Management](https://yarnpkg.com/getting-started/install) is used to install all dependencies used for ballot encryption. 
- [GNU Make](https://www.gnu.org/software/make/manual/make.html) is used to simplify the commands and GitHub Actions. This approach is recommended to simplify the command line experience. This is built in for MacOS and Linux. For Windows, setup is simpler with [Chocolatey](https://chocolatey.org/install) and installing the provided [make package](https://chocolatey.org/packages/make). The other Windows option is [manually installing make](http://gnuwin32.sourceforge.net/packages/make.htm).
- [Gmpy2](https://gmpy2.readthedocs.io/en/latest/) is used for [Arbitrary-precision arithmetic](https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic) which
  has its own [installation requirements (native C libraries)](https://gmpy2.readthedocs.io/en/latest/intro.html#installation) on Linux and MacOS. **⚠️ Note:** _This is not required for Windows since the gmpy2 precompiled libraries are provided._
- [poetry 1.1.10](https://python-poetry.org/) is used to configure the python environment. Installation instructions can be found [here](https://python-poetry.org/docs/#installation).

## Robustness & Compatibility

Testing is always important in any engineering project. How do we know that our implementation is correct? 

Since we’re branching out from Microsoft’s python version, there’s one more thing we need to worry about: whether our version is compatible with Microsoft’s. That is to say, given the same inputs, we should come up with the exact same outputs as Microsoft’s version. To test that our version is correct, we’ve unit-tested each sub-pieces of our implementation. 

To make sure that our version is compatible with Microsoft’s, we built a test factory that contained input-output pairs generated from Microsoft’s version and used this [test factory](testVector.sh) to test against our version. Once we ensured that the test factory’s inputs resulted in the same outputs under our typescript version, we were confident that our implementation is compatible with Microsoft’s.

## Performance

We performed a benchmark encryption on a large ballot with 20 contests and 10 options. On average it takes about 11.3 seconds for entire encryption, about half seconds for each contest. With almost 90% of time spent on sequentially excrypting contests, it leaves us possibility for further acceleration by doing parallel encryption. The benchmarking ballot we used is considerably large. In reality, this large ballot is rarely the case. A more realistic use case is from our external collaborator Enhanced Voting, and according to them, our implementation of electionguard takes around 5-6 seconds, while the python version takes around 7 seconds. 

## Impact

This is not just a simple school project that will be left out once the semester is over. Our project has profound significance: 
1. We helped add an in-browser implementation to Microsoft Electoinguard, which widens the area where Electionguard can be used. Now Electionguard can also be used in-browser to provide secure, verifiable end-to-end encryption for vote-by-mail systems.

2. Out project is already used as a library by an online vote-by-mail system named Enhanced Voting. We had worked together with Enhanced Voting throughout the semester to integrate our in-browser Electionguard with their voting system. So our project will actually benefit a lot of vote-by-mail voters in making sure that their ballots are secure and verifiable just like any other voters who vote in person.

3. The test factory we built is generic enough to be used across different implementations of Electionguard. As you can imagine, there are also implementations of Electionguard in other languages. Our test factory will help them ensure their compatibility with Microsoft’s python version. 

Therefore, this is a project that has already benefited and will continue to benefit multiple parties. We are really glad to work on a project that has such a long-lasting impact during this semester. Hope you’ve enjoyed our presentation and thank you for listening. 

## Contributors  
* [Xin Hao](https://github.com/Xin128)
* [Alex Guo](alexiland@outlook.com)
* [Zihe Zhao](https://github.com/zihe-zhao)
* [Yanyu Zhong](https://github.com/yanyuzhong)
* [Arthur Wu](wuwenqin200613@gmail.com)
* [Shreyas Minocha](shreyasminocha@rice.edu)