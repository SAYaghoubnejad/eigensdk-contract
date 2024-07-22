// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {BN254} from "./libraries/BN254.sol";

contract SimpleEigenContract is AccessControlUpgradeable {
    using BN254 for BN254.G1Point;

    enum Action {
        Add,  // 0
        Delete,   // 1
        Update // 2
    }

    // Roles
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");

    // Gas cost for the pairing equality check
    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120000;
    uint256 public signatureValidityPeriod; 

    struct Operator {
        address opAddress;
        uint256 stakedAmount;
        BN254.G1Point pubG1;
        BN254.G2Point pubG2;
    }

    uint32 public lastIndex;
    // Mapping from index to operator information
    mapping(uint32 => Operator) public operatorInfos;
    // Mapping from operator address to index
    mapping(address => uint32) public address2Index;

    BN254.G1Point public aggregatedG1;

    /*******************************************************************************
                                EVENTS AND ERRORS
    *******************************************************************************/

    // Events
    event OperatorAdded(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    event OperatorDeleted(uint32 indexed index, address indexed opAddress);
    event OperatorUpdated(uint32 indexed index, address indexed opAddress, uint256 stakedAmount, BN254.G1Point pubG1, BN254.G2Point pubG2);
    event SignatureValidityPeriodUpdated(uint256 validityPeriod);

    // Errors
    error OperatorAlreadyAdded();
    error OperatorNotExisted();
    error InvalidSignature();
    error SignatureExpired();

    /*******************************************************************************
                                PUBLIC FUNCTIONS
    *******************************************************************************/

    /// @notice Initialize the contract
    /// @param _admin Address of the admin, can set rakeback token and rakeback tiers
    function initialize(address _admin) public initializer {
        aggregatedG1 = BN254.G1Point(uint256(0), uint256(0));
        signatureValidityPeriod = 5 minutes;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /// @notice Add a new operator by DAO
    /// @param _opAddress Address of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    function addOperatorDAO(address _opAddress, uint256 _stakedAmount, BN254.G1Point memory _pubG1, BN254.G2Point memory _pubG2) public onlyRole(DAO_ROLE) {
        _addOperator(_opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator by DAO
    /// @param opAddress Address of the operator to be deleted
    function deleteOperatorDAO(address opAddress) public onlyRole(DAO_ROLE) {
        _deleteOperator(opAddress);
    }

    /// @notice Update an existing operator by DAO
    /// @param opAddress Address of the operator to be updated
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    function updateOperatorDAO(address opAddress, uint256 _stakedAmount, BN254.G1Point memory _pubG1, BN254.G2Point memory _pubG2) public onlyRole(DAO_ROLE) {
        _updateOperator(opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Add a new operator uisng Signature
    /// @param _opAddress Address of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    /// @param _apkG2 Aggregate G2 public key of all signers
    /// @param _sigma Aggregate G1 signature of all signers
    /// @param _sigTimestamp Timestamp of the signature
    /// @param _nonSignerIndices Indices of non-signers
    function addOperatorSig(
        address _opAddress, 
        uint256 _stakedAmount, 
        BN254.G1Point memory _pubG1, 
        BN254.G2Point memory _pubG2,
        BN254.G2Point memory _apkG2,
        BN254.G1Point memory _sigma,
        uint256 _sigTimestamp,
        uint32[] memory _nonSignerIndices
    ) public {
        if(_sigTimestamp + signatureValidityPeriod > block.timestamp){
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Add, _opAddress, _stakedAmount, _pubG1.X, _pubG1.Y, _pubG2.X, _pubG2.Y, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, _apkG2, _sigma, _nonSignerIndices);
        if(siganatureIsValid == false){
            revert InvalidSignature();
        }
        _addOperator(_opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator uisng Signature
    /// @param _opAddress Address of the operator to be deleted
    /// @param _apkG2 Aggregate G2 public key of all signers
    /// @param _sigma Aggregate G1 signature of all signers
    /// @param _sigTimestamp Timestamp of the signature
    /// @param _nonSignerIndices Indices of non-signers
    function deleteOperatorSig(
        address _opAddress,
        BN254.G2Point memory _apkG2,
        BN254.G1Point memory _sigma,
        uint256 _sigTimestamp,
        uint32[] memory _nonSignerIndices
    ) public {
        if(_sigTimestamp + signatureValidityPeriod > block.timestamp){
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Delete, _opAddress, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, _apkG2, _sigma, _nonSignerIndices);
        if(siganatureIsValid == false){
            revert InvalidSignature();
        }
        _deleteOperator(_opAddress);
    }

    /// @notice Update an existing operator uisng Signature
    /// @param _opAddress Address of the operator to be updated
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    /// @param _apkG2 Aggregate G2 public key of all signers
    /// @param _sigma Aggregate G1 signature of all signers
    /// @param _sigTimestamp Timestamp of the signature
    /// @param _nonSignerIndices Indices of non-signers
    function updateOperatorSig(
        address _opAddress, 
        uint256 _stakedAmount, 
        BN254.G1Point memory _pubG1, 
        BN254.G2Point memory _pubG2,
        BN254.G2Point memory _apkG2,
        BN254.G1Point memory _sigma,
        uint256 _sigTimestamp,
        uint32[] memory _nonSignerIndices
    ) public {
        if(_sigTimestamp + signatureValidityPeriod > block.timestamp){
            revert SignatureExpired();
        }
        bytes32 _hash = keccak256(abi.encodePacked(Action.Update, _opAddress, _stakedAmount, _pubG1.X, _pubG1.Y, _pubG2.X, _pubG2.Y, _sigTimestamp));
        bool siganatureIsValid;
        (, siganatureIsValid) = verifySignature(_hash, _apkG2, _sigma, _nonSignerIndices);
        if(siganatureIsValid == false){
            revert InvalidSignature();
        }
        _updateOperator(_opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Verify a signature
    /// @param msgHash Hash of the message
    /// @param apkG2 Aggregate G2 public key of all signers
    /// @param sigma Aggregate G1 signature of all signers
    /// @param nonSignerIndices Indices of non-signers
    /// @return pairingSuccessful True if the pairing precompile call was successful
    /// @return siganatureIsValid True if the signature is valid
    function verifySignature(
        bytes32 msgHash,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma,
        uint32[] memory nonSignerIndices
    ) public view returns (bool pairingSuccessful, bool siganatureIsValid) {
        BN254.G1Point memory apkG1;
        if (nonSignerIndices.length == 0) {
            apkG1 = aggregatedG1;
        } else {
            BN254.G1Point memory apk = operatorInfos[nonSignerIndices[0]].pubG1;
            for (uint32 i = 1; i < nonSignerIndices.length; i++) {
                require(operatorInfos[nonSignerIndices[i]].opAddress != address(0), "Invalid operator index");
                apk = apk.plus(operatorInfos[nonSignerIndices[i]].pubG1);
            }
            apk = apk.negate();
            apkG1 = apk.plus(aggregatedG1);
        }

        return trySignatureAndApkVerification(msgHash, apkG1, apkG2, sigma);
    }

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
    ) public view returns (bool pairingSuccessful, bool siganatureIsValid) {
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash, apk.X, apk.Y, apkG2.X[0], apkG2.X[1], apkG2.Y[0], apkG2.Y[1], sigma.X, sigma.Y))) % BN254.FR_MODULUS;
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma.plus(apk.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }

    /*******************************************************************************
                             SETTER FUNCTIONS
    *******************************************************************************/

    /// @notice Update signature vlidity period
    /// @param _signatureValidityPeriod New signature vlidity period
    function setValidityPeriod(uint256 _signatureValidityPeriod) public onlyRole(SETTER_ROLE){
        signatureValidityPeriod = _signatureValidityPeriod;
        emit SignatureValidityPeriodUpdated(_signatureValidityPeriod);
    }

    /*******************************************************************************
                            INTERNAL FUNCTIONS
    *******************************************************************************/

    /// @notice Add a new operator
    /// @param _opAddress Address of the operator
    /// @param _stakedAmount Staked amount by the operator
    /// @param _pubG1 Public G1 point of the operator
    /// @param _pubG2 Public G2 point of the operator
    function _addOperator(address _opAddress, uint256 _stakedAmount, BN254.G1Point memory _pubG1, BN254.G2Point memory _pubG2) internal {
        if (address2Index[_opAddress] != 0) {
            revert OperatorAlreadyAdded();
        }
        lastIndex = lastIndex + 1;
        operatorInfos[lastIndex] = Operator(_opAddress, _stakedAmount, _pubG1, _pubG2);
        address2Index[_opAddress] = lastIndex;
        aggregatedG1 = aggregatedG1.plus(_pubG1);
        emit OperatorAdded(lastIndex, _opAddress, _stakedAmount, _pubG1, _pubG2);
    }

    /// @notice Delete an existing operator
    /// @param _opAddress Address of the operator to be deleted
    function _deleteOperator(address _opAddress) internal {
        uint32 index = address2Index[_opAddress];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        delete address2Index[_opAddress];
        delete operatorInfos[index];
        emit OperatorDeleted(index, _opAddress);
    }

    /// @notice Update an existing operator
    /// @param _opAddress Address of the operator to be updated
    /// @param _stakedAmount New staked amount by the operator
    /// @param _pubG1 New public G1 point of the operator
    /// @param _pubG2 New public G2 point of the operator
    function _updateOperator(address _opAddress, uint256 _stakedAmount, BN254.G1Point memory _pubG1, BN254.G2Point memory _pubG2) internal {
        uint32 index = address2Index[_opAddress];
        if (index == 0) {
            revert OperatorNotExisted();
        }
        aggregatedG1 = aggregatedG1.plus(operatorInfos[index].pubG1.negate());
        operatorInfos[index].stakedAmount = _stakedAmount;
        operatorInfos[index].pubG1 = _pubG1;
        operatorInfos[index].pubG2 = _pubG2;
        aggregatedG1 = aggregatedG1.plus(_pubG1);
        emit OperatorUpdated(index, _opAddress, _stakedAmount, _pubG1, _pubG2);
    }
}
