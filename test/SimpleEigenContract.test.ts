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
import { BN254 } from './utils/BN254';

describe("SimpleEigenContract", () => {
    let simpleEigenContract: SimpleEigenContract;
    let admin: SignerWithAddress;
    let dao: SignerWithAddress;
    let user1: SignerWithAddress;
    let user2: SignerWithAddress;

    function hashFunction(input: string): string {
        return ethers.keccak256(Buffer.from(input));
    }

    before(async () => {
        await attestationInit();
    });

    beforeEach(async () => {
        [admin, dao, user1, user2] = await ethers.getSigners();

        const SimpleEigenContractFactory = await ethers.getContractFactory("SimpleEigenContract");
        simpleEigenContract = (await upgrades.deployProxy(SimpleEigenContractFactory, [await admin.getAddress()])) as SimpleEigenContract;
        await simpleEigenContract.waitForDeployment();

        // Grant DAO_ROLE to dao signer
        await simpleEigenContract.connect(admin).grantRole(await simpleEigenContract.DAO_ROLE(), await dao.getAddress());
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
        let mockG1Point: BN254.G1Point;
        let mockG2Point: BN254.G2Point;

        beforeEach(async () => {
            const mockkeyPair = new KeyPair();
            mockG1Point = g1PointToArgs(mockkeyPair.pubG1);
            mockG2Point = g2PointToArgs(mockkeyPair.pubG2);
        });

        it("should add an operator", async () => {
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, mockG1Point, mockG2Point);
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(await user1.getAddress());
            expect(operatorInfo.stakedAmount).to.equal(1000);
            expect(operatorInfo.pubG1.X).to.equal(mockG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(mockG1Point.Y);
        });

        it("should not allow adding the same operator twice", async () => {
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, mockG1Point, mockG2Point);
            await expect(simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 2000, mockG1Point, mockG2Point))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorAlreadyAdded");
        });

        it("should delete an operator", async () => {
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, mockG1Point, mockG2Point);
            await simpleEigenContract.connect(dao).deleteOperator(1);
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.opAddress).to.equal(ZeroAddress);
        });

        it("should update an operator", async () => {
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, mockG1Point, mockG2Point);
            
            const newKeyPair = KeyPair.fromString("04");
            const newG1Point: BN254.G1Point = g1PointToArgs(newKeyPair.pubG1);
            const newG2Point: BN254.G2Point = g2PointToArgs(newKeyPair.pubG2);
            await simpleEigenContract.connect(dao).updateOperator(await user1.getAddress(), 2000, newG1Point, newG2Point);
            
            const operatorInfo = await simpleEigenContract.operatorInfos(1);
            expect(operatorInfo.stakedAmount).to.equal(2000);
            expect(operatorInfo.pubG1.X).to.equal(newG1Point.X);
            expect(operatorInfo.pubG1.Y).to.equal(newG1Point.Y);
        });

        it("should not allow updating a non-existent operator", async () => {
            await expect(simpleEigenContract.connect(dao).updateOperator(await user1.getAddress(), 2000, mockG1Point, mockG2Point))
                .to.be.revertedWithCustomError(simpleEigenContract, "OperatorNotExisted");
        });
    });

    describe("Signature Verification", () => {
        it("should verify a valid signature", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);
            
            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");

            const encodedPair1G1: BN254.G1Point = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1Point = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2Point = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2Point = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperator(await user2.getAddress(), 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const eachAggregatedPubG2: BN254.G2Point = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1Point = g1PointToArgs(aggregatedSignature);

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

            const encodedPair1G1: BN254.G1Point = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1Point = g1PointToArgs(keyPair2.pubG1);
            const encodedPair1G2: BN254.G2Point = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2Point = g2PointToArgs(keyPair2.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperator(await user2.getAddress(), 1000, encodedPair2G1, encodedPair2G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const invalidSignature: Signature = sign1.add(sign1);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const eachAggregatedPubG2: BN254.G2Point = g2PointToArgs(aggregatedPubG2);
            const encodedInvalidSignature: BN254.G1Point = g1PointToArgs(invalidSignature);

            const [pairingSuccessful, signatureIsValid] = await simpleEigenContract.verifySignature(
                msgHash,
                eachAggregatedPubG2,
                encodedInvalidSignature,
                []  // No non-signer indices
            );

            expect(pairingSuccessful).to.be.false;
            expect(signatureIsValid).to.be.false;
        });

        it.only("should verify signature with non-signers", async () => {
            const textMessage = "sample text to sign";
            const msgHash = hashFunction(textMessage);
            
            const keyPair1 = new KeyPair();
            const keyPair2 = KeyPair.fromString("04");
            const keyPair3 = KeyPair.fromString("08");

            const encodedPair1G1: BN254.G1Point = g1PointToArgs(keyPair1.pubG1);
            const encodedPair2G1: BN254.G1Point = g1PointToArgs(keyPair2.pubG1);
            const encodedPair3G1: BN254.G1Point = g1PointToArgs(keyPair3.pubG1);
            const encodedPair1G2: BN254.G2Point = g2PointToArgs(keyPair1.pubG2);
            const encodedPair2G2: BN254.G2Point = g2PointToArgs(keyPair2.pubG2);
            const encodedPair3G2: BN254.G2Point = g2PointToArgs(keyPair3.pubG2);
            
            // Add operators
            await simpleEigenContract.connect(dao).addOperator(await user1.getAddress(), 1000, encodedPair1G1, encodedPair1G2);
            await simpleEigenContract.connect(dao).addOperator(await user2.getAddress(), 1000, encodedPair2G1, encodedPair2G2);
            await simpleEigenContract.connect(dao).addOperator(await admin.getAddress(), 1000, encodedPair3G1, encodedPair3G2);
            
            const sign1: Signature = keyPair1.signMessage(msgHash);
            const sign2: Signature = keyPair2.signMessage(msgHash);
            const aggregatedSignature: Signature = sign1.add(sign2);
            const aggregatedPubG2: G2Point = keyPair1.pubG2.add(keyPair2.pubG2);

            const eachAggregatedPubG2: BN254.G2Point = g2PointToArgs(aggregatedPubG2);
            const encodedAggregatedSignature: BN254.G1Point = g1PointToArgs(aggregatedSignature);

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
        let mockG1Point: BN254.G1Point;
        let mockG2Point: BN254.G2Point;

        beforeEach(async () => {
            const mockkeyPair = new KeyPair();
            mockG1Point = g1PointToArgs(mockkeyPair.pubG1);
            mockG2Point = g2PointToArgs(mockkeyPair.pubG2);
        });

        it("should only allow DAO to add operators", async () => {
            await expect(simpleEigenContract.connect(user1).addOperator(await user2.getAddress(), 1000, mockG1Point, mockG2Point))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to delete operators", async () => {
            await expect(simpleEigenContract.connect(user1).deleteOperator(1))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });

        it("should only allow DAO to update operators", async () => {
            await expect(simpleEigenContract.connect(user1).updateOperator(await user1.getAddress(), 2000, mockG1Point, mockG2Point))
                .to.be.revertedWith(/AccessControl: account .* is missing role .*/);
        });
    });
});