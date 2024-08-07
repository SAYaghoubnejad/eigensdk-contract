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

    /// @notice Struct representing the nonce of signature using for synchronization
    struct SynchronizationNonce {
        uint256 nonce;
        uint256 blockNumber;
        uint256 txNumber;
        uint256 eventNumber;
    }

    /// @notice Event emitted when an operator is added
    event OperatorAdded(uint32 indexed index, address indexed opAddress, string socket, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    /// @notice Event emitted when an operator is deleted
    event OperatorDeleted(uint32 indexed index, address indexed opAddress);
    /// @notice Event emitted when an operator is updated
    event OperatorUpdated(uint32 indexed index, address indexed opAddress, string socket, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    /// @notice Event emitted when validity periods are updated
    event ValidityPeriodsUpdated(uint256 apkValidityPeriod);
    /// @notice Event emitted when minimum staked ratio is updated
    event MinStakedRatioUpdated(uint256 minStakedRatio);

    /// @notice Thrown when trying to add an operator that already exists
    error OperatorAlreadyAdded();
    /// @notice Thrown when trying to interact with a non-existent operator
    error OperatorNotExisted();
    /// @notice Thrown when a signature is invalid
    error InvalidSignature();
    /// @notice Thrown when an invalid operator index is provided
    error InvalidOperatorIndex();
    /// @notice Thrown when the staked amount is insufficient
    error InsufficientStaked();
    /// @notice Thrown when the APK has expired
    error ExpiredAPK();
    /// @notice Thrown when the nonce of signature is invalid
    error InvalidNonce();
    /// @notice Thrown when index to access an array is invalid
    error InvalidIndex();

    /// @notice Initialize the contract
    /// @param admin_ Address of the admin, can set rakeback token and rakeback tiers
    function initialize(address admin_) external;

    /// @notice Add a new operator by DAO
    /// @param op_ The Operator to be added
    function addOperatorDAO(
        Operator calldata op_
    ) external;

    /// @notice Delete an existing operator by DAO
    /// @param opAddress_ Address of the operator to be deleted
    function deleteOperatorDAO(address opAddress_) external;

    /// @notice Update an existing operator by DAO
    /// @param op_ The Operator to be added
    function updateOperatorDAO(
        Operator calldata op_
    ) external;

    /// @notice Add a new operator using Signature
    /// @param op_ The Operator to be added
    /// @param signature_ Signature to add an operator
    /// @param nonce_ The nonce used for adding operator
    function addOperatorSig(
        Operator calldata op_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
    ) external;

    /// @notice Delete an existing operator using Signature
    /// @param opAddress_ Address of the operator to be deleted
    /// @param signature_ Signature to delete an operator
    /// @param nonce_ The nonce used for deleting operator
    function deleteOperatorSig(
        address opAddress_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
    ) external;

    /// @notice Update an existing operator using Signature
    /// @param op_ The Operator to be added
    /// @param signature_ Signature to update an operator
    /// @param nonce_ The nonce used for updating operator
    function updateOperatorSig(
        Operator calldata op_,
        Signature memory signature_,
        SynchronizationNonce calldata nonce_
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

    /// @notice Update validity period for APK
    /// @param apkValidityPeriod_ New APK validity period
    function setValidityPeriods(uint256 apkValidityPeriod_) external;

    /// @notice Update minimum staked ratio
    /// @param minStakedRatio_ New minimum ratio for staked amount
    function setMinStakedRatio(uint256 minStakedRatio_) external;

    /// @notice Get operators within a specified range
    /// @param from_ The starting index of the range (inclusive)
    /// @param to_ The ending index of the range (exclusive)
    /// @return operators An array of operator infos within the specified range
    function getOperators(uint32 from_, uint32 to_) external view returns (Operator[] memory operators);
}