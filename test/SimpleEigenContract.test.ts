import {SignerWithAddress} from "@nomicfoundation/hardhat-ethers/signers";
import {ethers, upgrades} from "hardhat";
import {expect} from "chai";
import {SimpleEigenContract} from "../typechain-types";
import {ZeroAddress} from "ethers";
import {
    init as attestationInit,
    KeyPair,
    G1Point,
    G2Point,
    Signature
} from '../eigensdk-js/src/crypto/bls/attestation';
import {g1PointToArgs, g2PointToArgs} from '../eigensdk-js/src/utils/helpers';
import {BN254, ISimpleEigenContract} from '../typechain-types/contracts/SimpleEigenContract';

describe("SimpleEigenContract", () => {
    let simpleEigenContract: SimpleEigenContract;
    let admin: SignerWithAddress;
    let dao: SignerWithAddress;
    let user1: SignerWithAddress;
    let user2: SignerWithAddress;
    let user3: SignerWithAddress;
    let validity_setter: SignerWithAddress;
    let staked_setter: SignerWithAddress;

    const socket1: string = "http://localhost:3000";
    const socket2: string = "http://localhost:3001";
    const socket3: string = "http://localhost:3002";

    function hashFunction(input: string): string {
        return ethers.keccak256(Buffer.from(input));
    }

    before(async () => {
        await attestationInit();
    });

    beforeEach(async () => {
        [admin, dao, user1, user2, user3, validity_setter, staked_setter] = await ethers.getSigners();

        const SimpleEigenContractFactory = await ethers.getContractFactory("SimpleEigenContract");
        simpleEigenContract = (await upgrades.deployProxy(SimpleEigenContractFactory, [await admin.getAddress()])) as unknown as SimpleEigenContract;
        await simpleEigenContract.waitForDeployment();

        // Grant DAO_ROLE to dao signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.DAO_ROLE(), await dao.getAddress());
        // Grant SET_VALIDITY_PERIOD_ROLE to setter signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.SET_VALIDITY_PERIOD_ROLE(), await validity_setter.getAddress());
        // Grant SET_STAKE_LIMIT_ROLE to setter signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.SET_STAKE_LIMIT_ROLE(), await staked_setter.getAddress());
    });

    describe("Initialization", () => {
        it("should set the admin correctly", async () => {
            expect(await simpleEigenContract.hasRole(await simpleEigenContract.DEFAULT_ADMIN_ROLE(), await admin.getAddress())).to.be.true;
        });

        it("Should set initial values correctly", async function () {
            const aggregatedG1 = await simpleEigenContract.aggregatedG1();
            expect(aggregatedG1.X).to.equal(0);
            expect(aggregatedG1.Y).to.equal(0);

            const totalStaked = await simpleEigenContract.totalStaked();
            expect(totalStaked).to.equal(0);

            const minStakedLimit = await simpleEigenContract.minStakedRatio();
            expect(minStakedLimit).to.equal(660000);

            const apkValidityPeriod = await simpleEigenContract.apkValidityPeriod();
            expect(apkValidityPeriod).to.equal(5 * 60); // 5 minutes in seconds
        });

        it("Should set initial aggregatedG1History and totalStakedHistoryHistory correctly", async function () {
            const zeroPoint = {X: 0, Y: 0};
            const [timestamp, staked] = await simpleEigenContract.getAggregatedG1History(zeroPoint);
            expect(timestamp).to.equal(0);
            expect(staked).to.equal(0);
        });


        it("Should revert when trying to initialize again", async function () {
            await expect(simpleEigenContract.initialize(user1.address))
                .to.be.revertedWith("Initializable: contract is already initialized");
        });
    });

    describe("Operator Management by DAO", () => {
        let mockG1Point: BN254.G1PointStruct;
        let mockG2Point: BN254.G2PointStruct;

        beforeEach(async () => {
            const mockkeyPair = new KeyPair();
            mockG1Point = g1PointToArgs(mockkeyPair.pubG1);
            mockG2Point = g2PointToArgs(mockkeyPair.pubG2);
        });

        it("should add an operator", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op);

            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(await user1.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(1000);
            expect(operatorInfo.pubG1.X).to.equal(mockG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(mockG1Point.Y);

            const [apkTimestamp, stakedAmount] = await simpleEigenContract.getAggregatedG1History(mockG1Point);
            expect(stakedAmount).to.be.equal(1000);
            expect(apkTimestamp).to.be.equal(0);
        });

        it("should not allow adding the same operator twice", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            const newOp = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 2000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op);
            await expect(simpleEigenContract.connect(dao).addOperatorDAO(newOp))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorAlreadyAdded");
        });

        it("should delete an operator", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 2000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op);
            const tx = await simpleEigenContract.connect(dao).deleteOperatorDAO(await user1.getAddress());
            const receipt = await tx.wait();
            const block = await ethers.provider.getBlock(receipt!.blockNumber);
            const deleteBlockTimestamp = block!.timestamp;

            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(ZeroAddress);
            const operatorIndex = await simpleEigenContract.address2Index(await user1.getAddress());
            expect(operatorIndex).to.equal(0);

            const [apkTimestamp, stakedAmount] = await simpleEigenContract.getAggregatedG1History(mockG1Point);
            expect(stakedAmount).to.be.equal(2000);
            expect(apkTimestamp).to.be.equal(deleteBlockTimestamp);
        });

        it("should not allow delete a non-existent operator", async () => {
            await expect(simpleEigenContract.connect(dao).deleteOperatorDAO(await user1.getAddress()))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorNotExisted");
        });

        it("should update an operator", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op);

            const newKeyPair = KeyPair.fromString("04");
            const newG1Point: BN254.G1PointStruct = g1PointToArgs(newKeyPair.pubG1);
            const newG2Point: BN254.G2PointStruct = g2PointToArgs(newKeyPair.pubG2);
            const newOp = {
                opAddress: await user1.getAddress(),
                socket: socket2,
                stakedAmount: 2000,
                pubG1: newG1Point,
                pubG2: newG2Point
            }
            const tx = await simpleEigenContract.connect(dao).updateOperatorDAO(newOp);
            const receipt = await tx.wait();
            const block = await ethers.provider.getBlock(receipt!.blockNumber);
            const updateBlockTimestamp = block!.timestamp;

            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.stakedAmount).to.equal(2000);
            expect(operatorInfo.pubG1.X).to.equal(newG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(newG1Point.Y);
            expect(operatorInfo.socket).to.equal(socket2);

            const [apkTimestamp, stakedAmount] = await simpleEigenContract.getAggregatedG1History(mockG1Point);
            expect(stakedAmount).to.be.equal(1000);
            expect(apkTimestamp).to.be.equal(updateBlockTimestamp);
            const [apkTimestamp2, stakedAmount2] = await simpleEigenContract.getAggregatedG1History(newG1Point);
            expect(stakedAmount2).to.be.equal(2000);
            expect(apkTimestamp2).to.be.equal(0);
        });

        it("should not allow updating a non-existent operator", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 2000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await expect(simpleEigenContract.connect(dao).updateOperatorDAO(op))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorNotExisted");
        });
    });

    describe("Operator Management using Signature", () => {
        let keyPair1: KeyPair;
        let keyPair2: KeyPair;
        let keyPair3: KeyPair;

        let encodedPair1G1: BN254.G1PointStruct;
        let encodedPair2G1: BN254.G1PointStruct;
        let encodedPair3G1: BN254.G1PointStruct;
        let encodedPair1G2: BN254.G2PointStruct;
        let encodedPair2G2: BN254.G2PointStruct;
        let encodedPair3G2: BN254.G2PointStruct;

        let op1: ISimpleEigenContract.OperatorStruct, op2: ISimpleEigenContract.OperatorStruct;
        let nonce1: ISimpleEigenContract.SynchronizationNonceStruct;

        const Action = {ADD: 0, DELETE: 1, UPDATE: 2};

        let initalStake1: bigint, initalStake2: bigint;

        beforeEach(async () => {
            keyPair1 = new KeyPair();
            keyPair2 = KeyPair.fromString("04");
            keyPair3 = KeyPair.fromString("08");

            encodedPair1G1 = g1PointToArgs(keyPair1.pubG1);
            encodedPair2G1 = g1PointToArgs(keyPair2.pubG1);
            encodedPair3G1 = g1PointToArgs(keyPair3.pubG1);
            encodedPair1G2 = g2PointToArgs(keyPair1.pubG2);
            encodedPair2G2 = g2PointToArgs(keyPair2.pubG2);
            encodedPair3G2 = g2PointToArgs(keyPair3.pubG2);

            initalStake1 = ethers.parseEther("10"); // 100 ETH
            initalStake2 = ethers.parseEther("30"); // 100 ETH

            let op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: initalStake1,
                pubG1: encodedPair1G1,
                pubG2: encodedPair1G2
            }
            let op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: initalStake2,
                pubG1: encodedPair2G1,
                pubG2: encodedPair2G2
            }

            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            nonce1 = {
                nonce: 1,
                blockNumber: (await ethers.provider.getBlock("latest"))!.number,
                txNumber: 1,
                eventNumber: 1
            }
        });

        it("should add an operator", async () => {
            // Define your parameters
            const op = {
                opAddress: await user3.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }
            const blockTimestamp = (await ethers.provider.getBlock('latest'))!.timestamp;

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.ADD,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const tx = await simpleEigenContract.connect(user3).addOperatorSig(
                op,
                signature,
                nonce1
            );
            const receipt = await tx.wait();
            const block = await ethers.provider.getBlock(receipt!.blockNumber);
            const addBlockTimestamp = block!.timestamp;

            const operatorInfo = await simpleEigenContract.operatorInfos(3);
            expect(operatorInfo.opAddress).to.equal(await user3.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(op.stakedAmount);
            expect(operatorInfo.pubG1.X).to.equal(encodedPair3G1.X);
            expect(operatorInfo.pubG1.Y).to.equal(encodedPair3G1.Y);
            expect(operatorInfo.pubG2.X[0]).to.equal(encodedPair3G2.X[0]);
            expect(operatorInfo.pubG2.Y[0]).to.equal(encodedPair3G2.Y[0]);
            expect(operatorInfo.pubG2.X[1]).to.equal(encodedPair3G2.X[1]);
            expect(operatorInfo.pubG2.Y[1]).to.equal(encodedPair3G2.Y[1]);

            const [apkTimestamp, totaSstakedAmount] = await simpleEigenContract.getAggregatedG1History(g1PointToArgs(aggregatedPubG1));
            expect(totaSstakedAmount).to.be.equal(initalStake1 + initalStake2);
            expect(apkTimestamp).to.be.equal(addBlockTimestamp);

            const [apkTimestamp2, totaSstakedAmount2] = await simpleEigenContract.getAggregatedG1History(g1PointToArgs(aggregatedPubG1.add(keyPair3.pubG1)));
            expect(totaSstakedAmount2).to.be.equal(op.stakedAmount + initalStake1 + initalStake2);
            expect(apkTimestamp2).to.be.equal(0);
        });

        it("should not allow add an operator with out of order nonce", async () => {
            // Define your parameters
            const op = {
                opAddress: await user3.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }
            const nonce2 = {
                nonce: 2,
                blockNumber: (await ethers.provider.getBlock("latest"))!.number,
                txNumber: 1,
                eventNumber: 1
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.ADD,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce2.nonce,
                    nonce2.blockNumber,
                    nonce2.txNumber,
                    nonce2.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                op,
                signature,
                nonce2
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidNonce");
        });

        it("should not allow add an operator with update signature", async () => {
            // Define your parameters
            const op = {
                opAddress: await user3.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.UPDATE,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                op,
                signature,
                nonce1
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should not allow add an operator with invalid signature", async () => {
            // Define your parameters
            const op = {
                opAddress: await user3.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.ADD,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                op,
                signature,
                nonce1
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should delete an operator", async () => {
            // Define your parameters

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.DELETE,
                    await user2.getAddress(),
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const tx = await simpleEigenContract.connect(user3).deleteOperatorSig(
                await user2.getAddress(),
                signature,
                nonce1
            );
            const receipt = await tx.wait();
            const block = await ethers.provider.getBlock(receipt!.blockNumber);
            const deleteBlockTimestamp = block!.timestamp;

            const operatorInfo = await simpleEigenContract.operatorInfos(2);
            expect(operatorInfo.opAddress).to.equal(ZeroAddress);
            const operatorIndex = await simpleEigenContract.address2Index(await user2.getAddress());
            expect(operatorIndex).to.equal(0);

            const [apkTimestamp, stakedAmount] = await simpleEigenContract.getAggregatedG1History(g1PointToArgs(aggregatedPubG1));
            expect(stakedAmount).to.be.equal(initalStake1 + initalStake2);
            expect(apkTimestamp).to.be.equal(deleteBlockTimestamp);

            const [apkTimestamp2, stakedAmount2] = await simpleEigenContract.getAggregatedG1History(encodedPair1G1);
            expect(stakedAmount2).to.be.equal(initalStake1);
            expect(apkTimestamp2).to.be.equal(0);
        });

        it("should not allow delete an operator with out of order nonce", async () => {
            // Define your parameters

            // Create the hash
            const nonce2 = {
                nonce: 2,
                blockNumber: (await ethers.provider.getBlock("latest"))!.number,
                txNumber: 1,
                eventNumber: 1
            }
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.DELETE,
                    await user2.getAddress(),
                    nonce2.nonce,
                    nonce2.blockNumber,
                    nonce2.txNumber,
                    nonce2.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).deleteOperatorSig(
                await user2.getAddress(),
                signature,
                nonce2
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidNonce");
        });

        it("should not allow delete with invalid signature", async () => {
            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.DELETE,
                    await user3.getAddress(),
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).deleteOperatorSig(
                await user3.getAddress(),
                signature,
                nonce1
            ))
                .to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should update an operator", async () => {
            // Define your parameters
            const op = {
                opAddress: await user2.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("200"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.UPDATE,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const tx = await simpleEigenContract.connect(user3).updateOperatorSig(
                op,
                signature,
                nonce1
            );
            const receipt = await tx.wait();
            const block = await ethers.provider.getBlock(receipt!.blockNumber);
            const updateBlockTimestamp = block!.timestamp;

            const operatorInfo = await simpleEigenContract.operatorInfos(2);
            expect(operatorInfo.opAddress).to.equal(await user2.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(op.stakedAmount);
            expect(operatorInfo.pubG1.X).to.equal(encodedPair3G1.X);
            expect(operatorInfo.pubG1.Y).to.equal(encodedPair3G1.Y);
            expect(operatorInfo.pubG2.X[0]).to.equal(encodedPair3G2.X[0]);
            expect(operatorInfo.pubG2.Y[0]).to.equal(encodedPair3G2.Y[0]);
            expect(operatorInfo.pubG2.X[1]).to.equal(encodedPair3G2.X[1]);
            expect(operatorInfo.pubG2.Y[1]).to.equal(encodedPair3G2.Y[1]);

            const [apkTimestamp, totalStakedAmount] = await simpleEigenContract.getAggregatedG1History(g1PointToArgs(aggregatedPubG1));
            expect(totalStakedAmount).to.be.equal(initalStake1 + initalStake2);
            expect(apkTimestamp).to.be.equal(updateBlockTimestamp);
            const [apkTimestamp2, totalStakedAmount2] = await simpleEigenContract.getAggregatedG1History(g1PointToArgs(keyPair1.pubG1.add(keyPair3.pubG1)));
            expect(totalStakedAmount2).to.be.equal(initalStake1 + op.stakedAmount);
            expect(apkTimestamp2).to.be.equal(0);
        });

        it("should not allow update an operator with out of order nonce", async () => {
            // Define your parameters
            const op = {
                opAddress: await user2.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }
            const nonce2 = {
                nonce: 2,
                blockNumber: (await ethers.provider.getBlock("latest"))!.number,
                txNumber: 1,
                eventNumber: 1
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.UPDATE,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce2.nonce,
                    nonce2.blockNumber,
                    nonce2.txNumber,
                    nonce2.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                op,
                signature,
                nonce2
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidNonce");
        });

        it("should not allow update an operator with invalid signature", async () => {
            // Define your parameters
            const op = {
                opAddress: await user2.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.ADD,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                op,
                signature,
                nonce1
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should not allow update an operator with add signature", async () => {
            // Define your parameters
            const op = {
                opAddress: await user2.getAddress(),
                socket: "127.0.0.1:8080",
                stakedAmount: ethers.parseEther("100"),
                pubG1: encodedPair3G1,
                pubG2: encodedPair3G2
            }

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8",
                    "address",
                    "string",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256[]",
                    "uint256[]",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256"
                ],
                [
                    Action.ADD,
                    op.opAddress,
                    op.socket,
                    op.stakedAmount,
                    encodedPair3G1.X,
                    encodedPair3G1.Y,
                    encodedPair3G2.X,
                    encodedPair3G2.Y,
                    nonce1.nonce,
                    nonce1.blockNumber,
                    nonce1.txNumber,
                    nonce1.eventNumber
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification            

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                op,
                signature,
                nonce1
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });
    });

    describe("Signature Verification", () => {
        it("should verify a valid signature", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should not verify an invalid signature", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const invalidSignature: Signature = sign1.add(sign1);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(invalidSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(invalidSignature.verify(aggregatedPubG2, msgHash)).to.be.false; // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.false;
        });

        it("should verify signature with a non-signer", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [3]
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should verify signature with previous active APK", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should not verify signature with previous inactive APK", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);
            await ethers.provider.send("evm_mine");

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature
            )).to.be.revertedWithCustomError(simpleEigenContract, "ExpiredAPK");
        });

        it("should verify signature with current APK", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const sign3: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2).add(sign3);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2).add(keyPair3.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);
            await ethers.provider.send("evm_mine");

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );
            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should verify signature with multiple non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 2000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 500,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 100,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1;
            const aggregatedPubG2: G2Point = keyPair1.pubG2;
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [2, 3]
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should verify signature with signer reported as non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 10,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [2]
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.false;
        });

        it("should not verify signature with non-reported non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.false;
        });

        it("should not verify signature with zero index as non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [0]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");

            const signature2: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [2, 0]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature2
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");
        });

        it("should not verify signature with non-registered operator as non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [3]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");

            const signature2: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [2, 3]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature2
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");
        });

        it("should verify signature with current APK with sufficient staked amount", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            // Set staking limit
            await simpleEigenContract.connect(staked_setter).setMinStakedRatio(1000000);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const sign3: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2).add(sign3);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2).add(keyPair3.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);
            await ethers.provider.send("evm_mine");

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );
            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should verify signature with current APK with insufficient staked amount", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            // Set staking limit
            await simpleEigenContract.connect(staked_setter).setMinStakedRatio(990000);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1).add(keyPair3.pubG1);

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);
            await ethers.provider.send("evm_mine");

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [3]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature
            )).to.be.revertedWithCustomError(simpleEigenContract, "InsufficientStaked");
        });

        it("should verify signature with previous APK with sufficient staked amount", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            // Set staking limit
            await simpleEigenContract.connect(staked_setter).setMinStakedRatio(990000);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: []
            }
            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                signature
            );
            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
        });

        it("should verify signature with previous APK with insufficient staked amount", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);

            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            // Add operators
            const op1 = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair1.pubG1),
                pubG2: g2PointToArgs(keyPair1.pubG2)
            }
            const op2 = {
                opAddress: await user2.getAddress(),
                socket: socket2,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair2.pubG1),
                pubG2: g2PointToArgs(keyPair2.pubG2)
            }
            const op3 = {
                opAddress: await user3.getAddress(),
                socket: socket3,
                stakedAmount: 1000,
                pubG1: g1PointToArgs(keyPair3.pubG1),
                pubG2: g2PointToArgs(keyPair3.pubG2)
            }
            await simpleEigenContract.connect(dao).addOperatorDAO(op1);
            await simpleEigenContract.connect(dao).addOperatorDAO(op2);
            await simpleEigenContract.connect(dao).addOperatorDAO(op3);

            // Set staking limit
            await simpleEigenContract.connect(staked_setter).setMinStakedRatio(990000);

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1;
            const aggregatedPubG2: G2Point = keyPair1.pubG2;
            const aggregatedPubG1: G1Point = keyPair1.pubG1.add(keyPair2.pubG1);

            const signature: ISimpleEigenContract.SignatureStruct = {
                apkG1: g1PointToArgs(aggregatedPubG1),
                apkG2: g2PointToArgs(aggregatedPubG2),
                sigma: g1PointToArgs(aggregatedSignature),
                nonSignerIndices: [2]
            }
            await expect(simpleEigenContract.verifySignature(
                msgHash,
                signature
            )).to.be.revertedWithCustomError(simpleEigenContract, "InsufficientStaked");
        });
    });

    describe("Access Control", () => {
        let mockG1Point: BN254.G1PointStruct;
        let mockG2Point: BN254.G2PointStruct;

        beforeEach(async () => {
            const mockkeyPair = new KeyPair();
            mockG1Point = g1PointToArgs(mockkeyPair.pubG1);
            mockG2Point = g2PointToArgs(mockkeyPair.pubG2);
        });

        it("should only allow DAO to add operators", async () => {
            const op = {
                opAddress: await user2.getAddress(),
                socket: socket1,
                stakedAmount: 1000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await expect(simpleEigenContract.connect(user1).addOperatorDAO(op))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to delete operators", async () => {
            await expect(simpleEigenContract.connect(user1).deleteOperatorDAO(await user1.getAddress()))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to update operators", async () => {
            const op = {
                opAddress: await user1.getAddress(),
                socket: socket1,
                stakedAmount: 2000,
                pubG1: mockG1Point,
                pubG2: mockG2Point
            }
            await expect(simpleEigenContract.connect(user1).updateOperatorDAO(op))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });
    });

    describe("Setters", () => {
        it("should only allow setter to set validity periods", async () => {
            const newAPKPeriod = 2;

            await expect(simpleEigenContract.connect(user1).setValidityPeriods(newAPKPeriod))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);

            await expect(simpleEigenContract.connect(staked_setter).setValidityPeriods(newAPKPeriod))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);

            await simpleEigenContract.connect(validity_setter).setValidityPeriods(newAPKPeriod);
            const apkValidityPeriod = await simpleEigenContract.apkValidityPeriod();
            expect(apkValidityPeriod).to.be.equal(newAPKPeriod);
        });

        it("should only allow setter to set min staked limit", async () => {
            const newMinStakedRatio = 1000000;

            await expect(simpleEigenContract.connect(user1).setMinStakedRatio(newMinStakedRatio))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);

            await expect(simpleEigenContract.connect(validity_setter).setMinStakedRatio(newMinStakedRatio))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);

            await simpleEigenContract.connect(staked_setter).setMinStakedRatio(newMinStakedRatio);
            const minStakedLimit = await simpleEigenContract.minStakedRatio();
            expect(minStakedLimit).to.be.equal(newMinStakedRatio);
        });
    });
});