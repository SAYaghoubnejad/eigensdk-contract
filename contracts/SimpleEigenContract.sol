// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {BN254} from "./libraries/BN254.sol";
import "./interfaces/ISimpleEigenContract.sol";

/// @title SimpleEigenContract
/// @notice A contract for managing operators with BLS signatures
/// @dev Inherits from AccessControlUpgradeable for role-based access control
contract SimpleEigenContract is ISimpleEigenContract, AccessControlUpgradeable {
    using BN254 for BN254.G1Point;

    // Roles
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");
    bytes32 public constant SET_VALIDITY_PERIOD_ROLE = keccak256("SET_VALIDITY_PERIOD_ROLE");
    bytes32 public constant SET_STAKE_LIMIT_ROLE = keccak256("SET_STAKE_LIMIT_ROLE");

    /// @dev Gas cost for the pairing equality check
    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120000;
    /// @notice Duration for which a signature is considered valid
    uint256 public signatureValidityPeriod;
    /// @notice Duration for which an APK is considered valid
    uint256 public apkValidityPeriod;
    /// @notice Current aggregated G1 point
    BN254.G1Point public aggregatedG1;
    /// @notice Total amount staked by all operators
    uint256 public totalStaked;
    /// @notice Minimum required stake amount
    uint256 public minStakedLimit;

    /// @notice Last assigned operator index
    uint32 public lastIndex;
    /// @notice Mapping from index to operator information
    mapping(uint32 => Operator) public operatorInfos;
    /// @notice Mapping from operator address to index
    mapping(address => uint32) public address2Index;

    /// @notice Mapping to store aggregated history for G1 points
    /// @dev The key is a bytes32 hash of the G1Point, and the value is a uint256
    mapping(bytes32 => uint256) public aggregatedG1History;

    /// @notice Mapping to store aggregated history for G1 points
    /// @dev The key is a bytes32 hash of the G1Point, and the value is a uint256
    mapping(bytes32 => uint256) public totalStakedHistoryHistory;

    /*******************************************************************************
                                PUBLIC FUNCTIONS
    *******************************************************************************/

    /// @inheritdoc ISimpleEigenContract
    function initialize(address admin_) public override initializer {
        aggregatedG1 = BN254.G1Point(uint256(0), uint256(0));
        setAggregatedG1History(aggregatedG1, 0, 0);
        totalStaked = 0;
        minStakedLimit = 0;
        signatureValidityPeriod = 5 minutes;
        apkValidityPeriod = 5 minutes;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
    }

    /// @inheritdoc ISimpleEigenContract
    function addOperatorDAO(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_
    ) public override onlyRole(DAO_ROLE) {
        _addOperator(opAddress_, socket_, stakedAmount_, pubG1_, pubG2_);
    }

    /// @inheritdoc ISimpleEigenContract
    function deleteOperatorDAO(address opAddress_) public override onlyRole(DAO_ROLE) {
        _deleteOperator(opAddress_);
    }

    /// @inheritdoc ISimpleEigenContract
    function updateOperatorDAO(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_
    ) public override onlyRole(DAO_ROLE) {
        _updateOperator(opAddress_, socket_, stakedAmount_, pubG1_, pubG2_);
    }

    /// @inheritdoc ISimpleEigenContract
    function addOperatorSig(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) public override {
        if (sigTimestamp_ > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - sigTimestamp_ > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Add, opAddress_, socket_, stakedAmount_, pubG1_.X, pubG1_.Y, pubG2_.X, pubG2_.Y, sigTimestamp_));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, signature_);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _addOperator(opAddress_, socket_, stakedAmount_, pubG1_, pubG2_);
    }

    /// @inheritdoc ISimpleEigenContract
    function deleteOperatorSig(
        address opAddress_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) public override {
        if (sigTimestamp_ > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - sigTimestamp_ > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Delete, opAddress_, sigTimestamp_));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, signature_);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _deleteOperator(opAddress_);
    }

    /// @inheritdoc ISimpleEigenContract
    function updateOperatorSig(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) public override {
        if (sigTimestamp_ > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - sigTimestamp_ > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Update, opAddress_, socket_, stakedAmount_, pubG1_.X, pubG1_.Y, pubG2_.X, pubG2_.Y, sigTimestamp_));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash,signature_);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _updateOperator(opAddress_, socket_, stakedAmount_, pubG1_, pubG2_);
    }

    /// @inheritdoc ISimpleEigenContract
    function setAggregatedG1History(BN254.G1Point memory point_, uint256 value_, uint256 totalStakedAmount_) public override {
        bytes32 key = keccak256(abi.encode(point_));
        aggregatedG1History[key] = value_;
        totalStakedHistoryHistory[key] = totalStakedAmount_;
    }

    /// @inheritdoc ISimpleEigenContract
    function getAggregatedG1History(BN254.G1Point memory point_) public view override returns (uint256, uint256) {
        bytes32 key = keccak256(abi.encode(point_));
        return (aggregatedG1History[key], totalStakedHistoryHistory[key]);
    }

    /// @inheritdoc ISimpleEigenContract
    function verifySignature(
        bytes32 msgHash_,
        Signature memory signature_
    ) public view override returns (bool pairingSuccessful, bool signatureIsValid) {
        (uint256 apkTimestamp, uint256 stakedAmount) = getAggregatedG1History(signature_.apkG1);
        if (apkTimestamp != 0 && block.timestamp - apkTimestamp > apkValidityPeriod){
            revert ExpiredAPK();
        }

        if (signature_.nonSignerIndices.length != 0) {
            if (signature_.nonSignerIndices[0] == 0 || operatorInfos[signature_.nonSignerIndices[0]].opAddress == address(0)){
                revert InvalidOperatorIndex();
            }
            BN254.G1Point memory apk = operatorInfos[signature_.nonSignerIndices[0]].pubG1;
            stakedAmount -= operatorInfos[signature_.nonSignerIndices[0]].stakedAmount;
            for (uint32 i = 1; i < signature_.nonSignerIndices.length; i++) {
                if (signature_.nonSignerIndices[i] == 0 || operatorInfos[signature_.nonSignerIndices[i]].opAddress == address(0)){
                    revert InvalidOperatorIndex();
                }
                apk = apk.plus(operatorInfos[signature_.nonSignerIndices[i]].pubG1);
                stakedAmount -= operatorInfos[signature_.nonSignerIndices[i]].stakedAmount;
            }
            signature_.apkG1 = signature_.apkG1.plus(apk.negate());
        }

        if (stakedAmount < minStakedLimit){
            revert InsufficientStaked();
        }
        return _trySignatureAndApkVerification(msgHash_, signature_.apkG1, signature_.apkG2, signature_.sigma);
    }

    /*******************************************************************************
                             SETTER FUNCTIONS
    *******************************************************************************/

    /// @inheritdoc ISimpleEigenContract
    function setValidityPeriods(uint256 signatureValidityPeriod_, uint256 apkValidityPeriod_) public override onlyRole(SET_VALIDITY_PERIOD_ROLE) {
        signatureValidityPeriod = signatureValidityPeriod_;
        apkValidityPeriod = apkValidityPeriod_;
        emit ValidityPeriodsUpdated(signatureValidityPeriod_, apkValidityPeriod_);
    }

    /// @inheritdoc ISimpleEigenContract
    function setMinStakedLimit(uint256 minStakedLimit_) public override onlyRole(SET_STAKE_LIMIT_ROLE) {
        minStakedLimit = minStakedLimit_;
        emit MinStakedLimitUpdated(minStakedLimit_);
    }

    /*******************************************************************************
                            INTERNAL FUNCTIONS
    *******************************************************************************/

    /// @notice Verifies a BLS aggregate signature and the veracity of a calculated G1 Public key
    /// @param msgHash_ Hash of the message
    /// @param apk_ Claimed G1 public key
    /// @param apkG2_ Provided G2 public key
    /// @param sigma_ G1 point signature
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return siganatureIsValid True if the signature is valid
    function _trySignatureAndApkVerification(
        bytes32 msgHash_,
        BN254.G1Point memory apk_,
        BN254.G2Point memory apkG2_,
        BN254.G1Point memory sigma_
    ) internal view returns (bool pairingSuccessful, bool siganatureIsValid) {
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash_, apk_.X, apk_.Y, apkG2_.X[0], apkG2_.X[1], apkG2_.Y[0], apkG2_.Y[1], sigma_.X, sigma_.Y))) % BN254.FR_MODULUS;
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma_.plus(apk_.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash_).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2_,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }

    /// @notice Add a new operator
    /// @param opAddress_ Address of the operator
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ Staked amount by the operator
    /// @param pubG1_ Public G1 point of the operator
    /// @param pubG2_ Public G2 point of the operator
    function _addOperator(address opAddress_, string calldata socket_, uint256 stakedAmount_, BN254.G1Point calldata pubG1_, BN254.G2Point calldata pubG2_) internal {
        if (address2Index[opAddress_] != 0) {
            revert OperatorAlreadyAdded();
        }
        lastIndex = lastIndex + 1;
        operatorInfos[lastIndex] = Operator(opAddress_, socket_, stakedAmount_, pubG1_, pubG2_);
        address2Index[opAddress_] = lastIndex;
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(pubG1_);
        totalStaked += stakedAmount_;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        emit OperatorAdded(lastIndex, opAddress_, stakedAmount_, pubG1_, pubG2_);
    }

    /// @notice Delete an existing operator
    /// @param opAddress_ Address of the operator to be deleted
    function _deleteOperator(address opAddress_) internal {
        uint32 index = address2Index[opAddress_];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        delete address2Index[opAddress_];
        delete operatorInfos[index];
        emit OperatorDeleted(index, opAddress_);
    }

    /// @notice Update an existing operator
    /// @param opAddress_ Address of the operator to be updated
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ New staked amount by the operator
    /// @param pubG1_ New public G1 point of the operator
    /// @param pubG2_ New public G2 point of the operator
    function _updateOperator(address opAddress_, string calldata socket_, uint256 stakedAmount_, BN254.G1Point calldata pubG1_, BN254.G2Point calldata pubG2_) internal {
        uint32 index = address2Index[opAddress_];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        operatorInfos[index].stakedAmount = stakedAmount_;
        operatorInfos[index].socket = socket_;
        operatorInfos[index].pubG1 = pubG1_;
        operatorInfos[index].pubG2 = pubG2_;
        aggregatedG1 = aggregatedG1.plus(pubG1_);
        totalStaked += stakedAmount_;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        emit OperatorUpdated(index, opAddress_, stakedAmount_, pubG1_, pubG2_);
    }
}
