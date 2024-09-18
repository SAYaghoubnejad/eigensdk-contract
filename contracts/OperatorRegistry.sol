// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {BN254} from "./libraries/BN254.sol";
import "./interfaces/IOperatorRegistry.sol";

/// @title SimpleEigenContract
/// @notice A contract for managing operators with BLS signatures
/// @dev Inherits from AccessControlUpgradeable for role-based access control
contract OperatorRegistry is IOperatorRegistry, AccessControlUpgradeable {
    using BN254 for BN254.G1Point;

    // Roles
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");
    bytes32 public constant SET_VALIDITY_PERIOD_ROLE = keccak256("SET_VALIDITY_PERIOD_ROLE");
    bytes32 public constant SET_STAKE_LIMIT_ROLE = keccak256("SET_STAKE_LIMIT_ROLE");

    /// @dev Gas cost for the pairing equality check
    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120000;
    /// @notice Duration for which an APK is considered valid
    uint256 public apkValidityPeriod;
    /// @notice The last nonce used to add, delete, or update OPs
    SynchronizationNonce public lastNonce;
    /// @notice Current aggregated G1 point
    BN254.G1Point public aggregatedG1;
    /// @notice Total amount staked by all operators
    uint256 public totalStaked;
    /// @notice Minimum required stake amount ratio
    uint256 public minStakedRatio;
    /// @notice Total number of operators
    uint256 public activeOperators;

    /// @notice Last assigned operator index
    uint32 public lastIndex;
    /// @notice Mapping from index to operator information
    mapping(uint32 => Operator) public operatorInfos;
    /// @notice Mapping from operator address to index
    mapping(address => uint32) public address2Index;
    /// @notice Mapping from index to operator address
    mapping(uint32 => address) public index2address;

    /// @notice Mapping to store aggregated history for G1 points
    /// @dev The key is a bytes32 hash of the G1Point, and the value is a uint256
    mapping(bytes32 => uint256) public aggregatedG1History;

    /// @notice Mapping to store aggregated history for G1 points
    /// @dev The key is a bytes32 hash of the G1Point, and the value is a uint256
    mapping(bytes32 => uint256) public totalStakedHistory;

    /*******************************************************************************
                                PUBLIC FUNCTIONS
    *******************************************************************************/

    /// @inheritdoc IOperatorRegistry
    function initialize(address admin_) public override initializer {
        aggregatedG1 = BN254.G1Point(uint256(0), uint256(0));
        _setAggregatedG1History(aggregatedG1, 0, 0);
        totalStaked = 0;
        activeOperators = 0;
        minStakedRatio = 660000; // 66%
        apkValidityPeriod = 5 minutes;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
    }

    /// @inheritdoc IOperatorRegistry
    function addOperatorDAO(
        Operator calldata op_
    ) public override onlyRole(DAO_ROLE) {
        _addOperator(op_);
    }

    /// @inheritdoc IOperatorRegistry
    function deleteOperatorDAO(address opAddress_) public override onlyRole(DAO_ROLE) {
        _deleteOperator(opAddress_);
    }

    /// @inheritdoc IOperatorRegistry
    function updateOperatorDAO(
        Operator calldata op_
    ) public override onlyRole(DAO_ROLE) {
        _updateOperator(op_);
    }

    /// @inheritdoc IOperatorRegistry
    function addOperatorSig(
        Operator calldata op_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
    ) public override {
        if (nonce_.nonce != lastNonce.nonce + 1 || nonce_.blockNumber < lastNonce.blockNumber) {
            revert InvalidNonce();
        }
        bytes32 _hash = keccak256(abi.encodePacked(
            Action.Add,
            op_.opAddress,
            op_.socket,
            op_.stakedAmount,
            op_.pubG1.X,
            op_.pubG1.Y,
            op_.pubG2.X,
            op_.pubG2.Y,
            nonce_.nonce,
            nonce_.blockNumber,
            nonce_.txNumber,
            nonce_.eventNumber
        ));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, signature_);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        lastNonce = nonce_;
        _addOperator(op_);
    }

    /// @inheritdoc IOperatorRegistry
    function deleteOperatorSig(
        address opAddress_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
    ) public override {
        if (nonce_.nonce != lastNonce.nonce + 1 || nonce_.blockNumber < lastNonce.blockNumber) {
            revert InvalidNonce();
        }
        bytes32 _hash = keccak256(abi.encodePacked(
            Action.Delete,
            opAddress_,
            nonce_.nonce,
            nonce_.blockNumber,
            nonce_.txNumber,
            nonce_.eventNumber
        ));
        bool signatureIsValid;
        (, signatureIsValid) = verifySignature(_hash, signature_);
        if (signatureIsValid == false) {
            revert InvalidSignature();
        }
        lastNonce = nonce_;
        _deleteOperator(opAddress_);
    }

    /// @inheritdoc IOperatorRegistry
    function updateOperatorSig(
        Operator calldata op_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
    ) public override {
        if (nonce_.nonce != lastNonce.nonce + 1 || nonce_.blockNumber < lastNonce.blockNumber) {
            revert InvalidNonce();
        }
        bytes32 _hash = keccak256(abi.encodePacked(
            Action.Update,
            op_.opAddress,
            op_.socket,
            op_.stakedAmount,
            op_.pubG1.X,
            op_.pubG1.Y,
            op_.pubG2.X,
            op_.pubG2.Y,
            nonce_.nonce,
            nonce_.blockNumber,
            nonce_.txNumber,
            nonce_.eventNumber
        ));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, signature_);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        lastNonce = nonce_;
        _updateOperator(op_);
    }

    /// @inheritdoc IOperatorRegistry
    function getAggregatedG1History(BN254.G1Point memory point_) public view override returns (uint256, uint256) {
        bytes32 key = keccak256(abi.encode(point_));
        return (aggregatedG1History[key], totalStakedHistory[key]);
    }

    /// @inheritdoc IOperatorRegistry
    function verifySignature(
        bytes32 msgHash_,
        Signature memory signature_
    ) public view override returns (bool pairingSuccessful, bool signatureIsValid) {
        (uint256 apkTimestamp, uint256 totalStakedAmount) = getAggregatedG1History(signature_.apkG1);
        uint256 stakedAmount = totalStakedAmount;
        if (apkTimestamp != 0 && block.timestamp - apkTimestamp > apkValidityPeriod) {
            revert ExpiredAPK();
        }

        if (signature_.nonSignerIndices.length != 0) {
            if (signature_.nonSignerIndices[0] == 0 || operatorInfos[signature_.nonSignerIndices[0]].opAddress == address(0)) {
                revert InvalidOperatorIndex();
            }
            BN254.G1Point memory apk = operatorInfos[signature_.nonSignerIndices[0]].pubG1;
            stakedAmount -= operatorInfos[signature_.nonSignerIndices[0]].stakedAmount;
            for (uint32 i = 1; i < signature_.nonSignerIndices.length; i++) {
                if (signature_.nonSignerIndices[i] == 0 || operatorInfos[signature_.nonSignerIndices[i]].opAddress == address(0)) {
                    revert InvalidOperatorIndex();
                }
                apk = apk.plus(operatorInfos[signature_.nonSignerIndices[i]].pubG1);
                stakedAmount -= operatorInfos[signature_.nonSignerIndices[i]].stakedAmount;
            }
            signature_.apkG1 = signature_.apkG1.plus(apk.negate());
        }

        if (stakedAmount < (minStakedRatio * totalStakedAmount) / (10 ** 6)) {
            revert InsufficientStaked();
        }
        return _trySignatureAndApkVerification(msgHash_, signature_.apkG1, signature_.apkG2, signature_.sigma);
    }

    /// @inheritdoc IOperatorRegistry
    function getOperators(uint32 from_, uint32 to_) external view override returns (Operator[] memory operators){
        if (to_ == 0){
            to_ = lastIndex;
        }
        if (from_ == 0){
            from_ = 1;
        }
        if (from_ > lastIndex || to_ > lastIndex || to_ < from_){
            revert InvalidIndex();
        }
        uint256 missed = 0;
        operators = new Operator[](activeOperators);
        for (uint32 i = from_; i <= to_; i++){
            if (index2address[i] != address(0)){
                operators[i - from_ - missed] = operatorInfos[i];
            }
            else{
                missed = missed + 1;
            }
        }
    }

    /*******************************************************************************
                             SETTER FUNCTIONS
    *******************************************************************************/

    /// @inheritdoc IOperatorRegistry
    function setValidityPeriods(uint256 apkValidityPeriod_) public override onlyRole(SET_VALIDITY_PERIOD_ROLE) {
        apkValidityPeriod = apkValidityPeriod_;
        emit ValidityPeriodsUpdated(apkValidityPeriod_);
    }

    /// @inheritdoc IOperatorRegistry
    function setMinStakedRatio(uint256 minStakedRatio_) public override onlyRole(SET_STAKE_LIMIT_ROLE) {
        minStakedRatio = minStakedRatio_;
        emit MinStakedRatioUpdated(minStakedRatio_);
    }

    /*******************************************************************************
                            INTERNAL FUNCTIONS
    *******************************************************************************/
    /// @notice Sets the aggregated history for a G1 point
    /// @param point_ The BN254.G1Point to set the history for
    /// @param value_ The uint256 value to associate with the point
    /// @param totalStakedAmount_ The total staked amount at the time of setting the history
    function _setAggregatedG1History(BN254.G1Point memory point_, uint256 value_, uint256 totalStakedAmount_) internal {
        bytes32 key = keccak256(abi.encode(point_));
        aggregatedG1History[key] = value_;
        totalStakedHistory[key] = totalStakedAmount_;
    }

    /// @notice Verifies a BLS aggregate signature and the veracity of a calculated G1 Public key
    /// @param msgHash_ Hash of the message
    /// @param apk_ Claimed G1 public key
    /// @param apkG2_ Provided G2 public key
    /// @param sigma_ G1 point signature
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return signatureIsValid True if the signature is valid
    function _trySignatureAndApkVerification(
        bytes32 msgHash_,
        BN254.G1Point memory apk_,
        BN254.G2Point memory apkG2_,
        BN254.G1Point memory sigma_
    ) internal view returns (bool pairingSuccessful, bool signatureIsValid) {
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash_, apk_.X, apk_.Y, apkG2_.X[0], apkG2_.X[1], apkG2_.Y[0], apkG2_.Y[1], sigma_.X, sigma_.Y))) % BN254.FR_MODULUS;
        (pairingSuccessful, signatureIsValid) = BN254.safePairing(
            sigma_.plus(apk_.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash_).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2_,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }

    /// @notice Add a new operator
    /// @param op_ The Operator to be added
    function _addOperator(Operator calldata op_) internal {
        if (address2Index[op_.opAddress] != 0) {
            revert OperatorAlreadyAdded();
        }
        lastIndex = lastIndex + 1;
        operatorInfos[lastIndex] = Operator(op_.opAddress, op_.socket, op_.stakedAmount, op_.pubG1, op_.pubG2);
        address2Index[op_.opAddress] = lastIndex;
        index2address[lastIndex] = op_.opAddress;
        _setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(op_.pubG1);
        totalStaked += op_.stakedAmount;
        _setAggregatedG1History(aggregatedG1, 0, totalStaked);
        activeOperators = activeOperators + 1;
        emit OperatorAdded(lastIndex, op_.opAddress, op_.socket, op_.stakedAmount, op_.pubG1, op_.pubG2);
    }

    /// @notice Delete an existing operator
    /// @param opAddress_ Address of the operator to be deleted
    function _deleteOperator(address opAddress_) internal {
        uint32 index = address2Index[opAddress_];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        _setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        _setAggregatedG1History(aggregatedG1, 0, totalStaked);
        delete address2Index[opAddress_];
        delete operatorInfos[index];
        delete index2address[index];
        activeOperators = activeOperators - 1;
        emit OperatorDeleted(index, opAddress_);
    }

    /// @notice Update an existing operator
    /// @param op_ The Operator to be updated
    function _updateOperator(Operator calldata op_) internal {
        uint32 index = address2Index[op_.opAddress];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        _setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        operatorInfos[index] = op_;
        aggregatedG1 = aggregatedG1.plus(op_.pubG1);
        totalStaked += op_.stakedAmount;
        _setAggregatedG1History(aggregatedG1, 0, totalStaked);
        emit OperatorUpdated(index, op_.opAddress, op_.socket, op_.stakedAmount, op_.pubG1, op_.pubG2);
    }
}
