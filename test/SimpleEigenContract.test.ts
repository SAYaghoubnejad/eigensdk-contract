import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { SimpleEigenContract } from "../typechain-types";
import { ZeroAddress } from "ethers";
import { 
    init as attestationInit,
    KeyPair, 
    G2Point, 
    Signature 
} from '../eigensdk-js/src/crypto/bls/attestation';
import { g1PointToArgs, g2PointToArgs} from '../eigensdk-js/src/utils/helpers';
import { BN254 } from '../typechain-types/contracts/SimpleEigenContract';

describe("SimpleEigenContract", () => {
    let simpleEigenContract: SimpleEigenContract;
    let admin: SignerWithAddress;
    let dao: SignerWithAddress;
    let user1: SignerWithAddress;
    let user2: SignerWithAddress;
    let user3: SignerWithAddress;
    let setter: SignerWithAddress;

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
        [admin, dao, user1, user2, user3, setter] = await ethers.getSigners();

        const SimpleEigenContractFactory = await ethers.getContractFactory("SimpleEigenContract");
        simpleEigenContract = (await upgrades.deployProxy(SimpleEigenContractFactory, [await admin.getAddress()])) as unknown as SimpleEigenContract;
        await simpleEigenContract.waitForDeployment();

        // Grant DAO_ROLE to dao signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.DAO_ROLE(), await dao.getAddress());
        // Grant SETTER_ROLE to setter signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.SETTER_ROLE(), await setter.getAddress());
    });

    describe("Initialization", () => {
        it("should set the admin correctly", async () => {
            expect(await simpleEigenContract.hasRole(await simpleEigenContract.DEFAULT_ADMIN_ROLE(), await admin.getAddress())).to.be.true;
        });

        it("should initialize aggregatedG1 to zero", async () => {
            const aggregatedG1 = await simpleEigenContract.aggregatedG1();
            expect(aggregatedG1.X).to.equal(0);
            expect(aggregatedG1.Y).to.equal(0);
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
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, mockG1Point, mockG2Point);
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(await user1.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(1000);
            expect(operatorInfo.pubG1.X).to.equal(mockG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(mockG1Point.Y);
        });

        it("should not allow adding the same operator twice", async () => {
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, mockG1Point, mockG2Point);
            await expect(simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 2000, mockG1Point, mockG2Point))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorAlreadyAdded");
        });

        it("should delete an operator", async () => {
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, mockG1Point, mockG2Point);
            await simpleEigenContract.connect(dao).deleteOperatorDAO(await user1.getAddress());
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(ZeroAddress);
            const operatorIndex = await simpleEigenContract.address2Index(await user1.getAddress());
            expect(operatorIndex).to.equal(0);
        });

        it("should not allow delete a non-existent operator", async () => {
            await expect(simpleEigenContract.connect(dao).deleteOperatorDAO(await user1.getAddress()))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorNotExisted");
        });

        it("should update an operator", async () => {
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, mockG1Point, mockG2Point);
            
            const newKeyPair = KeyPair.fromString("04");
            const newG1Point: BN254.G1PointStruct = g1PointToArgs(newKeyPair.pubG1);
            const newG2Point: BN254.G2PointStruct = g2PointToArgs(newKeyPair.pubG2);
            await simpleEigenContract.connect(dao).updateOperatorDAO(await user1.getAddress(), socket2, 2000, newG1Point, newG2Point);
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.stakedAmount).to.equal(2000);
            expect(operatorInfo.pubG1.X).to.equal(newG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(newG1Point.Y);
            expect(operatorInfo.socket).to.equal(socket2);
        });

        it("should not allow updating a non-existent operator", async () => {
            await expect(simpleEigenContract.connect(dao).updateOperatorDAO(await user1.getAddress(), socket1, 2000, mockG1Point, mockG2Point))
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

        const Action = { ADD: 0, DELETE: 1, UPDATE: 2 };

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

            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
        });

        it("should add an operator", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user3.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await simpleEigenContract.connect(user3).addOperatorSig(
                await user3.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            );
            
            const operatorInfo = await simpleEigenContract.operatorInfos(3);
            expect(operatorInfo.opAddress).to.equal(await user3.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(stakedAmount);
            expect(operatorInfo.pubG1.X).to.equal(encodedPair3G1.X);
            expect(operatorInfo.pubG1.Y).to.equal(encodedPair3G1.Y);
            expect(operatorInfo.pubG2.X[0]).to.equal(encodedPair3G2.X[0]);
            expect(operatorInfo.pubG2.Y[0]).to.equal(encodedPair3G2.Y[0]);
            expect(operatorInfo.pubG2.X[1]).to.equal(encodedPair3G2.X[1]);
            expect(operatorInfo.pubG2.Y[1]).to.equal(encodedPair3G2.Y[1]);
        });

        it("should not allow add an operator with future signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp + 1000;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user3.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                await user3.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidTimestamp");
        });

        it("should not allow add an operator with update signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.UPDATE, 
                    await user3.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                await user3.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should not allow add an operator with expired signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user3.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);

            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                await user3.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "SignatureExpired");
        });

        it("should not allow add an operator with invalid signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user3.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).addOperatorSig(
                await user3.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should delete an operator", async () => {
            // Define your parameters
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8", 
                    "address", 
                    "uint256"
                ],
                [
                    Action.DELETE, 
                    await user2.getAddress(), 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await simpleEigenContract.connect(user3).deleteOperatorSig(
                await user2.getAddress(), 
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            );
            
            const operatorInfo = await simpleEigenContract.operatorInfos(2);
            expect(operatorInfo.opAddress).to.equal(ZeroAddress);
            const operatorIndex = await simpleEigenContract.address2Index(await user2.getAddress());
            expect(operatorIndex).to.equal(0);
        });

        it("should not allow delete an operator with future signature", async () => {
            // Define your parameters
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp + 1000;

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8", 
                    "address", 
                    "uint256"
                ],
                [
                    Action.DELETE, 
                    await user2.getAddress(), 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).deleteOperatorSig(
                await user2.getAddress(), 
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidTimestamp");
        });

        it("should not allow delete with expired signature", async () => {
            // Define your parameters
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8", 
                    "address", 
                    "uint256"
                ],
                [
                    Action.DELETE, 
                    await user3.getAddress(), 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            await expect(simpleEigenContract.connect(user3).deleteOperatorSig(
                await user3.getAddress(),
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            ))
                .to.be.revertedWithCustomError(simpleEigenContract, "SignatureExpired");
        });

        it("should not allow delete with invalid signature", async () => {
            // Define your parameters
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

            // Create the hash
            const msgHash = ethers.solidityPackedKeccak256(
                [
                    "uint8", 
                    "address", 
                    "uint256"
                ],
                [
                    Action.DELETE, 
                    await user3.getAddress(), 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification
            await expect(simpleEigenContract.connect(user3).deleteOperatorSig(
                await user3.getAddress(),
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            ))
                .to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should update an operator", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.UPDATE, 
                    await user2.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await simpleEigenContract.connect(user3).updateOperatorSig(
                await user2.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            );
            
            const operatorInfo = await simpleEigenContract.operatorInfos(2);
            expect(operatorInfo.opAddress).to.equal(await user2.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(stakedAmount);
            expect(operatorInfo.pubG1.X).to.equal(encodedPair3G1.X);
            expect(operatorInfo.pubG1.Y).to.equal(encodedPair3G1.Y);
            expect(operatorInfo.pubG2.X[0]).to.equal(encodedPair3G2.X[0]);
            expect(operatorInfo.pubG2.Y[0]).to.equal(encodedPair3G2.Y[0]);
            expect(operatorInfo.pubG2.X[1]).to.equal(encodedPair3G2.X[1]);
            expect(operatorInfo.pubG2.Y[1]).to.equal(encodedPair3G2.Y[1]);
        });

        it("should not allow update an operator with future signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp + 1000;

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
                    "uint256"
                ],
                [
                    Action.UPDATE, 
                    await user2.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                await user2.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidTimestamp");
        });

        it("should not allow update an operator with expired signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user2.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await ethers.provider.send("evm_increaseTime", [10 * 3600]);

            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                await user2.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "SignatureExpired");
        });

        it("should not allow update an operator with expired signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user2.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair3.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair3.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                await user2.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });

        it("should not allow update an operator with add signature", async () => {
            // Define your parameters
            const socket = "127.0.0.1:8080";
            const stakedAmount = ethers.parseEther("100"); // 100 ETH
            const blockTimestamp = (await ethers.provider.getBlock('latest')).timestamp;

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
                    "uint256"
                ],
                [
                    Action.ADD, 
                    await user2.getAddress(), 
                    socket, 
                    stakedAmount, 
                    encodedPair3G1.X, 
                    encodedPair3G1.Y, 
                    encodedPair3G2.X, 
                    encodedPair3G2.Y, 
                    blockTimestamp
                ]
            );

            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            expect(aggregatedSignature.verify(aggregatedPubG2, msgHash)).to.be.true;  // local verification

            await expect(simpleEigenContract.connect(user3).updateOperatorSig(
                await user2.getAddress(), 
                socket, 
                stakedAmount, 
                encodedPair3G1, 
                encodedPair3G2,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                blockTimestamp,
                []
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidSignature");
        });
    });

    describe("Signature Verification", () => {
        it("should verify a valid signature", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);
            
            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                []  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const invalidSignature: Signature = sign1.add(sign1);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedInvalidSignature: BN254.G1PointStruct = g1PointToArgs(invalidSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedInvalidSignature,
                []  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair3G1: BN254.G1PointStruct = g1PointToArgs(keyPair3.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            const encodedPair3G2: BN254.G2PointStruct = g2PointToArgs(keyPair3.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await admin.getAddress(), socket3, 1000, encodedPair3G1, encodedPair3G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [3]  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair3G1: BN254.G1PointStruct = g1PointToArgs(keyPair3.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            const encodedPair3G2: BN254.G2PointStruct = g2PointToArgs(keyPair3.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await admin.getAddress(), socket3, 1000, encodedPair3G1, encodedPair3G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1;
            const aggregatedPubG2: G2Point = keyPair1.pubG2;

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [2, 3]  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [2]  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair3G1: BN254.G1PointStruct = g1PointToArgs(keyPair3.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            const encodedPair3G2: BN254.G2PointStruct = g2PointToArgs(keyPair3.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await admin.getAddress(), socket3, 1000, encodedPair3G1, encodedPair3G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                []  // No non-signer indices
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

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            await expect(simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [0]  // No non-signer indices
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");

            await expect(simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [2, 0]  // No non-signer indices
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");
        });

        it("should not verify signature with non-registered operator as non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);
            
            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            const encodedPair1G1: BN254.G1PointStruct = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1PointStruct = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2PointStruct = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2PointStruct = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperatorDAO(await user1.getAddress(), socket1, 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperatorDAO(await user2.getAddress(), socket2, 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const encodedAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            await expect(simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [3]  // No non-signer indices
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");

            await expect(simpleEigenContract.verifySignature(
                msgHash,
                encodedAggregatedPubG2,
                encodedAggregatedSignature,
                [2, 3]  // No non-signer indices
            )).to.be.revertedWithCustomError(simpleEigenContract, "InvalidOperatorIndex");
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
            await expect(simpleEigenContract.connect(user1).addOperatorDAO(await user2.getAddress(), socket1, 1000, mockG1Point, mockG2Point))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to delete operators", async () => {
            await expect(simpleEigenContract.connect(user1).deleteOperatorDAO(await user1.getAddress()))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to update operators", async () => {
            await expect(simpleEigenContract.connect(user1).updateOperatorDAO(await user1.getAddress(), socket1, 2000, mockG1Point, mockG2Point))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });
    });

    describe("Setters", () => {
        it("should only allow setter to set validity period", async () => {
            const newPeriod = 1;
            
            await expect(simpleEigenContract.connect(user1).setValidityPeriod(1))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);

            await simpleEigenContract.connect(setter).setValidityPeriod(newPeriod);
            const validityPeriod = await simpleEigenContract.signatureValidityPeriod();
            expect(validityPeriod).to.be.equal(newPeriod);
        });
    });
});