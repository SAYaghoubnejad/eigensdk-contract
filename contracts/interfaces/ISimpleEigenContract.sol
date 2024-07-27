// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {BN254} from "../libraries/BN254.sol";

/// @title ISimpleEigenContract
/// @notice Interface for the SimpleEigenContract
/// @dev Defines the external functions and events for managing operators with BLS signatures
interface ISimpleEigenContract {
    /// @notice Enum representing different actions for operators
    enum Action {
        Add,
        Delete,
        Update
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

    /// @notice Event emitted when an operator is added
    event OperatorAdded(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    /// @notice Event emitted when an operator is deleted
    event OperatorDeleted(uint32 indexed index, address indexed opAddress);
    /// @notice Event emitted when an operator is updated
    event OperatorUpdated(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    /// @notice Event emitted when validity periods are updated
    event ValidityPeriodsUpdated(uint256 signatureValidityPeriod, uint256 apkValidityPeriod);
    /// @notice Event emitted when minimum staked limit is updated
    event MinStakedLimitUpdated(uint256 minStakedLimit);

    /// @notice Thrown when trying to add an operator that already exists
    error OperatorAlreadyAdded();
    /// @notice Thrown when trying to interact with a non-existent operator
    error OperatorNotExisted();
    /// @notice Thrown when a signature is invalid
    error InvalidSignature();
    /// @notice Thrown when a signature has expired
    error SignatureExpired();
    /// @notice Thrown when the provided timestamp is invalid
    error InvalidTimestamp();
    /// @notice Thrown when an invalid operator index is provided
    error InvalidOperatorIndex();
    /// @notice Thrown when the staked amount is insufficient
    error InsufficientStaked();
    /// @notice Thrown when the APK has expired
    error ExpiredAPK();

    /// @notice Initialize the contract
    /// @param admin_ Address of the admin, can set rakeback token and rakeback tiers
    function initialize(address admin_) external;

    /// @notice Add a new operator by DAO
    /// @param opAddress_ Address of the operator
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ Staked amount by the operator
    /// @param pubG1_ Public G1 point of the operator
    /// @param pubG2_ Public G2 point of the operator
    function addOperatorDAO(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_
    ) external;

    /// @notice Delete an existing operator by DAO
    /// @param opAddress_ Address of the operator to be deleted
    function deleteOperatorDAO(address opAddress_) external;

    /// @notice Update an existing operator by DAO
    /// @param opAddress_ Address of the operator to be updated
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ New staked amount by the operator
    /// @param pubG1_ New public G1 point of the operator
    /// @param pubG2_ New public G2 point of the operator
    function updateOperatorDAO(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_
    ) external;

    /// @notice Add a new operator using Signature
    /// @param opAddress_ Address of the operator
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ Staked amount by the operator
    /// @param pubG1_ Public G1 point of the operator
    /// @param pubG2_ Public G2 point of the operator
    /// @param signature_ Signature to add an operator
    /// @param sigTimestamp_ Timestamp of the signature
    function addOperatorSig(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) external;

    /// @notice Delete an existing operator using Signature
    /// @param opAddress_ Address of the operator to be deleted
    /// @param signature_ Signature to delete an operator
    /// @param sigTimestamp_ Timestamp of the signature
    function deleteOperatorSig(
        address opAddress_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) external;

    /// @notice Update an existing operator using Signature
    /// @param opAddress_ Address of the operator to be updated
    /// @param socket_ Socket of the operator
    /// @param stakedAmount_ New staked amount by the operator
    /// @param pubG1_ New public G1 point of the operator
    /// @param pubG2_ New public G2 point of the operator
    /// @param signature_ Signature to update an operator
    /// @param sigTimestamp_ Timestamp of the signature
    function updateOperatorSig(
        address opAddress_,
        string calldata socket_,
        uint256 stakedAmount_,
        BN254.G1Point calldata pubG1_,
        BN254.G2Point calldata pubG2_,
        Signature memory signature_,
        uint256 sigTimestamp_
    ) external;

    /// @notice Sets the aggregated history for a G1 point
    /// @param point_ The BN254.G1Point to set the history for
    /// @param value_ The uint256 value to associate with the point
    /// @param totalStakedAmount_ The total staked amount at the time of setting the history
    function setAggregatedG1History(BN254.G1Point memory point_, uint256 value_, uint256 totalStakedAmount_) external;

    /// @notice Retrieves the aggregated history for a G1 point
    /// @param point_ The BN254.G1Point to get the history for
    /// @return The uint256 value associated with the point and the total staked amount
    function getAggregatedG1History(BN254.G1Point memory point_) external view returns (uint256, uint256);

    /// @notice Verify a signature
    /// @param msgHash_ Hash of the message
    /// @param signature_ to be verified
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return signatureIsValid True if the signature is valid
    function verifySignature(
        bytes32 msgHash_,
        Signature memory signature_
    ) external view returns (bool pairingSuccessful, bool signatureIsValid);

    /// @notice Update validity period for signature and APK
    /// @param signatureValidityPeriod_ New signature validity period
    /// @param apkValidityPeriod_ New APK validity period
    function setValidityPeriods(uint256 signatureValidityPeriod_, uint256 apkValidityPeriod_) external;

    /// @notice Update minimum staked limit
    /// @param minStakedLimit_ New minimum limit for staked amount
    function setMinStakedLimit(uint256 minStakedLimit_) external;
}