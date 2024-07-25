// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {BN254} from "./libraries/BN254.sol";

/// @title SimpleEigenContract
/// @notice A contract for managing operators with BLS signatures
/// @dev Inherits from AccessControlUpgradeable for role-based access control
contract SimpleEigenContract is AccessControlUpgradeable {
    using BN254 for BN254.G1Point;

    /// @notice Enum representing different actions for operators
    enum Action {
        Add,  // 0
        Delete,   // 1
        Update // 2
    }

    /// @notice Struct representing an operator's information
    struct Operator {
        address opAddress;
        string socket;
        uint256 stakedAmount;
        BN254.G1Point pubG1;
        BN254.G2Point pubG2;
    }

    /// @notice Struct representing a signature
    struct Signature {
        BN254.G1Point apkG1;
        BN254.G2Point apkG2;
        BN254.G1Point sigma;
        uint32[] nonSignerIndices;
    }

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
                                EVENTS AND ERRORS
    *******************************************************************************/

    // Events
    event OperatorAdded(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    event OperatorDeleted(uint32 indexed index, address indexed opAddress);
    event OperatorUpdated(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    event ValidityPeriodsUpdated(uint256 signatureValidityPeriod, uint256 apkValidityPeriod);
    event MinStakedLimitUpdated(uint256 minStakedLimit);

    // Errors
    error OperatorAlreadyAdded();
    error OperatorNotExisted();
    error InvalidSignature();
    error SignatureExpired();
    error InvalidTimestamp();
    error InvalidOperatorIndex();
    error InsufficientStaked();
    error ExpiredAPK();

    /*******************************************************************************
                                PUBLIC FUNCTIONS
    *******************************************************************************/

    /// @notice Initialize the contract
    /// @param _admin Address of the admin, can set rakeback token and rakeback tiers
    function initialize(address _admin) public initializer {
        aggregatedG1 = BN254.G1Point(uint256(0), uint256(0));
        setAggregatedG1History(aggregatedG1, 0, 0);
        totalStaked = 0;
        minStakedLimit = 0;
        signatureValidityPeriod = 5 minutes;
        apkValidityPeriod = 5 minutes;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /// @notice Add a new operator by DAO
    /// @param _opAddress Address of the operator
    /// @param _socket Socket of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    function addOperatorDAO(
        address _opAddress,
        string calldata _socket,
        uint256 _stakedAmount,
        BN254.G1Point calldata _pubG1,
        BN254.G2Point calldata _pubG2
    ) public onlyRole(DAO_ROLE) {
        _addOperator(_opAddress, _socket, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator by DAO
    /// @param opAddress Address of the operator to be deleted
    function deleteOperatorDAO(address opAddress) public onlyRole(DAO_ROLE) {
        _deleteOperator(opAddress);
    }

    /// @notice Update an existing operator by DAO
    /// @param opAddress Address of the operator to be updated
    /// @param _socket Socket of the operator
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    function updateOperatorDAO(
        address opAddress,
        string calldata _socket,
        uint256 _stakedAmount,
        BN254.G1Point calldata _pubG1,
        BN254.G2Point calldata _pubG2
    ) public onlyRole(DAO_ROLE) {
        _updateOperator(opAddress, _socket, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Add a new operator uisng Signature
    /// @param _opAddress Address of the operator
    /// @param _socket Socket of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    /// @param _signature Signature to add an operator
    /// @param _sigTimestamp Timestamp of the signature
    function addOperatorSig(
        address _opAddress,
        string calldata _socket,
        uint256 _stakedAmount,
        BN254.G1Point calldata _pubG1,
        BN254.G2Point calldata _pubG2,
        Signature memory _signature,
        uint256 _sigTimestamp
    ) public {
        if (_sigTimestamp > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - _sigTimestamp > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Add, _opAddress, _socket, _stakedAmount, _pubG1.X, _pubG1.Y, _pubG2.X, _pubG2.Y, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, _signature);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _addOperator(_opAddress, _socket, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator uisng Signature
    /// @param _opAddress Address of the operator to be deleted
    /// @param _signature Signature to delete an operator
    /// @param _sigTimestamp Timestamp of the signature
    function deleteOperatorSig(
        address _opAddress,
        Signature memory _signature,
        uint256 _sigTimestamp
    ) public {
        if (_sigTimestamp > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - _sigTimestamp > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Delete, _opAddress, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, _signature);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _deleteOperator(_opAddress);
    }

    /// @notice Update an existing operator uisng Signature
    /// @param _opAddress Address of the operator to be updated
    /// @param _socket Socket of the operator
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    /// @param _signature Signature to update an operator
    /// @param _sigTimestamp Timestamp of the signature
    function updateOperatorSig(
        address _opAddress,
        string calldata _socket,
        uint256 _stakedAmount,
        BN254.G1Point calldata _pubG1,
        BN254.G2Point calldata _pubG2,
        Signature memory _signature,
        uint256 _sigTimestamp
    ) public {
        if (_sigTimestamp > block.timestamp) {
            revert InvalidTimestamp();
        }
        if (block.timestamp - _sigTimestamp > signatureValidityPeriod) {
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Update, _opAddress, _socket, _stakedAmount, _pubG1.X, _pubG1.Y, _pubG2.X, _pubG2.Y, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash,_signature);
        if (siganatureIsValid == false) {
            revert InvalidSignature();
        }
        _updateOperator(_opAddress, _socket, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Sets the aggregated history for a G1 point
    /// @param point The BN254.G1Point to set the history for
    /// @param value The uint256 value to associate with the point
    function setAggregatedG1History(BN254.G1Point memory point, uint256 value, uint256 totalStakedAmount) public {
        bytes32 key = keccak256(abi.encode(point));
        aggregatedG1History[key] = value;
        totalStakedHistoryHistory[key] = totalStakedAmount;
    }

    /// @notice Retrieves the aggregated history for a G1 point
    /// @param point The BN254.G1Point to get the history for
    /// @return The uint256 value associated with the point
    function getAggregatedG1History(BN254.G1Point memory point) public view returns (uint256, uint256) {
        bytes32 key = keccak256(abi.encode(point));
        return (aggregatedG1History[key], totalStakedHistoryHistory[key]);
    }

    /// @notice Verify a signature
    /// @param msgHash Hash of the message
    /// @param signature to be verified
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return siganatureIsValid True if the signature is valid
    function verifySignature(
        bytes32 msgHash,
        Signature memory signature
    ) public view returns (bool pairingSuccessful, bool siganatureIsValid) {
        (uint256 apkTimestamp, uint256 stakedAmount) = getAggregatedG1History(signature.apkG1);
        if (apkTimestamp != 0 && block.timestamp - apkTimestamp > apkValidityPeriod){
            revert ExpiredAPK();
        }

        if (signature.nonSignerIndices.length != 0) {
            if (signature.nonSignerIndices[0] == 0 || operatorInfos[signature.nonSignerIndices[0]].opAddress == address(0)){
                revert InvalidOperatorIndex();
            }
            BN254.G1Point memory apk = operatorInfos[signature.nonSignerIndices[0]].pubG1;
            stakedAmount -= operatorInfos[signature.nonSignerIndices[0]].stakedAmount;
            for (uint32 i = 1; i < signature.nonSignerIndices.length; i++) {
                if (signature.nonSignerIndices[i] == 0 || operatorInfos[signature.nonSignerIndices[i]].opAddress == address(0)){
                    revert InvalidOperatorIndex();
                }
                apk = apk.plus(operatorInfos[signature.nonSignerIndices[i]].pubG1);
                stakedAmount -= operatorInfos[signature.nonSignerIndices[i]].stakedAmount;
            }
            signature.apkG1 = signature.apkG1.plus(apk.negate());
        }

        if (stakedAmount < minStakedLimit){
            revert InsufficientStaked();
        }
        return trySignatureAndApkVerification(msgHash, signature.apkG1, signature.apkG2, signature.sigma);
    }

    /*******************************************************************************
                             SETTER FUNCTIONS
    *******************************************************************************/

    /// @notice Update vlidity period for signature and APK
    /// @param signatureValidityPeriod_ New signature vlidity period
    /// @param apkValidityPeriod_ New APK vlidity period
    function setValidityPeriods(uint256 signatureValidityPeriod_, uint256 apkValidityPeriod_) public onlyRole(SET_VALIDITY_PERIOD_ROLE) {
        signatureValidityPeriod = signatureValidityPeriod_;
        apkValidityPeriod = apkValidityPeriod_;
        emit ValidityPeriodsUpdated(signatureValidityPeriod_, apkValidityPeriod_);
    }

    /// @notice Update minimum staked limit
    /// @param minStakedLimit_ New minimum limit for staked amount
    function setMinStakedLimit(uint256 minStakedLimit_) public onlyRole(SET_STAKE_LIMIT_ROLE) {
        minStakedLimit = minStakedLimit_;
        emit MinStakedLimitUpdated(minStakedLimit_);
    }

    /*******************************************************************************
                            INTERNAL FUNCTIONS
    *******************************************************************************/

    /// @notice Verifies a BLS aggregate signature and the veracity of a calculated G1 Public key
    /// @param msgHash Hash of the message
    /// @param apk Claimed G1 public key
    /// @param apkG2 Provided G2 public key
    /// @param sigma G1 point signature
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return siganatureIsValid True if the signature is valid
    function trySignatureAndApkVerification(
        bytes32 msgHash,
        BN254.G1Point memory apk,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) internal view returns (bool pairingSuccessful, bool siganatureIsValid) {
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash, apk.X, apk.Y, apkG2.X[0], apkG2.X[1], apkG2.Y[0], apkG2.Y[1], sigma.X, sigma.Y))) % BN254.FR_MODULUS;
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma.plus(apk.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }

    /// @notice Add a new operator
    /// @param _opAddress Address of the operator
    /// @param _socket Socket of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    function _addOperator(address _opAddress, string calldata _socket, uint256 _stakedAmount, BN254.G1Point calldata _pubG1, BN254.G2Point calldata _pubG2) internal {
        if (address2Index[_opAddress] != 0) {
            revert OperatorAlreadyAdded();
        }
        lastIndex = lastIndex + 1;
        operatorInfos[lastIndex] = Operator(_opAddress, _socket, _stakedAmount, _pubG1, _pubG2);
        address2Index[_opAddress] = lastIndex;
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(_pubG1);
        totalStaked += _stakedAmount;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        emit OperatorAdded(lastIndex, _opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator
    /// @param _opAddress Address of the operator to be deleted
    function _deleteOperator(address _opAddress) internal {
        uint32 index = address2Index[_opAddress];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        delete address2Index[_opAddress];
        delete operatorInfos[index];
        emit OperatorDeleted(index, _opAddress);
    }

    /// @notice Update an existing operator
    /// @param _opAddress Address of the operator to be updated
    /// @param _socket Socket of the operator
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    function _updateOperator(address _opAddress, string calldata _socket, uint256 _stakedAmount, BN254.G1Point calldata _pubG1, BN254.G2Point calldata _pubG2) internal {
        uint32 index = address2Index[_opAddress];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        setAggregatedG1History(aggregatedG1, block.timestamp, totalStaked);
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        totalStaked -= operatorInfos[index].stakedAmount;
        operatorInfos[index].stakedAmount = _stakedAmount;
        operatorInfos[index].socket = _socket;
        operatorInfos[index].pubG1 = _pubG1;
        operatorInfos[index].pubG2 = _pubG2;
        aggregatedG1 = aggregatedG1.plus(_pubG1);
        totalStaked += _stakedAmount;
        setAggregatedG1History(aggregatedG1, 0, totalStaked);
        emit OperatorUpdated(index, _opAddress, _stakedAmount, _pubG1, _pubG2);
    }
}
