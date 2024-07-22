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
        [admin, dao, user1, user2, setter] = await ethers.getSigners();

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


    describe("Operator Management", () => {
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

            const eachAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            console.log("is locally verified:", aggregatedSignature.verify(aggregatedPubG2, msgHash));

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                eachAggregatedPubG2,
                encodedAggregatedSignature,
                []  // No non-signer indices
            );

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

            const eachAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedInvalidSignature: BN254.G1PointStruct = g1PointToArgs(invalidSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                eachAggregatedPubG2,
                encodedInvalidSignature,
                []  // No non-signer indices
            );

            expect(pairingSuccessful).to.be.false;
            expect(signatureIsValid).to.be.false;
        });

        it("should verify signature with non-signers", async () => {
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

            const eachAggregatedPubG2: BN254.G2PointStruct = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1PointStruct = g1PointToArgs(aggregatedSignature);

            console.log("is locally verified:", aggregatedSignature.verify(aggregatedPubG2, msgHash));

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                eachAggregatedPubG2,
                encodedAggregatedSignature,
                [3]  // No non-signer indices
            );

            expect(pairingSuccessful).to.be.true;
            expect(signatureIsValid).to.be.true;
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