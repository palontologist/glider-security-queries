// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable Contract Examples for Glider Query Testing
 * @notice Comprehensive test cases for various vulnerability patterns
 */

// ============================================
// REENTRANCY EXAMPLES
// ============================================

contract VulnerableReentrancy {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: State change after external call
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        // State change AFTER external call - REENTRANCY!
        balances[msg.sender] = 0;
    }
    
    // VULNERABLE: Transfer after external call
    function withdrawTransfer() external {
        uint256 amount = balances[msg.sender];
        msg.sender.transfer(amount);  // Can reenter via fallback
        balances[msg.sender] = 0;
    }
}

contract SafeReentrancy {
    mapping(address => uint256) public balances;
    bool private locked;
    
    // SAFE: Checks-effects-interactions pattern
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;  // State change FIRST
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // SAFE: ReentrancyGuard pattern
    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function withdrawGuarded() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}


// ============================================
// ACCESS CONTROL EXAMPLES
// ============================================

contract VulnerableAccessControl {
    address public owner;
    uint256 public fee;
    address public feeReceiver;
    bool public paused;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: No access control
    function setFee(uint256 _fee) external {
        fee = _fee;
    }
    
    // VULNERABLE: No access control
    function setFeeReceiver(address _receiver) external {
        feeReceiver = _receiver;
    }
    
    // VULNERABLE: No access control
    function withdrawFees() external {
        payable(feeReceiver).transfer(address(this).balance);
    }
    
    // VULNERABLE: No access control
    function pause() external {
        paused = true;
    }
}

contract SafeAccessControl {
    address public owner;
    uint256 public fee;
    address public feeReceiver;
    bool public paused;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // SAFE: With access control
    function setFee(uint256 _fee) external onlyOwner {
        fee = _fee;
    }
    
    // SAFE: With access control
    function setFeeReceiver(address _receiver) external onlyOwner {
        feeReceiver = _receiver;
    }
    
    // SAFE: With access control
    function withdrawFees() external onlyOwner {
        payable(feeReceiver).transfer(address(this).balance);
    }
}


// ============================================
// UNCHECKED LOW-LEVEL CALLS
// ============================================

contract VulnerableUncheckedCalls {
    address public target;
    
    constructor(address _target) {
        target = _target;
    }
    
    // VULNERABLE: call without check
    function callTarget(bytes calldata data) external {
        (bool success, ) = target.call(data);
        // Missing validation
    }
    
    // VULNERABLE: delegatecall without check
    function delegatecallTarget(bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        // Missing validation
    }
    
    // VULNERABLE: staticcall without check
    function staticcallTarget(bytes calldata data) external {
        (bool success, ) = target.staticcall(data);
        // Missing validation
    }
    
    // VULNERABLE: send without check
    function sendEth(address payable to, uint256 amount) external {
        to.send(amount);
        // Missing validation
    }
    
    // VULNERABLE: transfer without check (reverts on failure but still unchecked pattern)
    function transferEth(address payable to, uint256 amount) external {
        to.transfer(amount);
    }
}

contract SafeUncheckedCalls {
    address public target;
    
    constructor(address _target) {
        target = _target;
    }
    
    // SAFE: call with validation
    function callTarget(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
        return result;
    }
    
    // SAFE: delegatecall with validation
    function delegatecallTarget(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }
    
    // SAFE: Using OpenZeppelin Address library
    function callTargetSafe(bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        _verifyCallResult(success, result, "Call failed");
        return result;
    }
    
    function _verifyCallResult(bool success, bytes memory result, string memory errorMessage) internal pure {
        if (!success) {
            if (result.length == 0) {
                revert(errorMessage);
            } else {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }
}


// ============================================
// INTEGER OVERFLOW (Solidity < 0.8.0)
// ============================================

// Note: These are vulnerable in Solidity < 0.8.0 or within unchecked{} blocks

contract VulnerableArithmetic {
    // VULNERABLE in < 0.8.0
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
    
    function sub(uint256 a, uint256 b) external pure returns (uint256) {
        return a - b;
    }
    
    function mul(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }
    
    // VULNERABLE: unchecked block in 0.8.0+
    function addUnchecked(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            return a + b;
        }
    }
    
    // VULNERABLE: User-controlled arithmetic
    mapping(address => uint256) public balances;
    
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;  // User controls amount
    }
    
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;  // User controls amount
    }
}

contract SafeArithmetic {
    // SAFE: Using SafeMath (for < 0.8.0) or built-in checks (>= 0.8.0)
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;  // Built-in overflow check in 0.8.0+
    }
    
    // SAFE: Explicit checks
    function safeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "Overflow");
        return c;
    }
}


// ============================================
// GOVERNANCE EXAMPLES
// ============================================

contract VulnerableGovernance {
    struct Proposal {
        address target;
        bytes data;
        uint256 startTime;
        uint256 endTime;
        uint256 quorum;
        bool executed;
    }
    
    Proposal[] public proposals;
    mapping(address => uint256) public votes;
    
    // VULNERABLE: No quorum check, no state validation
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        // Missing: require(block.timestamp >= p.endTime, "Voting not ended");
        // Missing: require(votes[proposalId] >= p.quorum, "Quorum not reached");
        // Missing: require(!p.executed, "Already executed");
        
        (bool success, ) = p.target.call(p.data);
        // Missing validation
        p.executed = true;
    }
}

contract SafeGovernance {
    struct Proposal {
        address target;
        bytes data;
        uint256 startTime;
        uint256 endTime;
        uint256 quorum;
        uint256 voteCount;
        bool executed;
        bool canceled;
    }
    
    Proposal[] public proposals;
    
    // SAFE: Full validation
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        
        require(block.timestamp >= p.endTime, "Voting not ended");
        require(p.voteCount >= p.quorum, "Quorum not reached");
        require(!p.executed, "Already executed");
        require(!p.canceled, "Proposal canceled");
        
        (bool success, bytes memory result) = p.target.call(p.data);
        require(success, "Execution failed");
        
        p.executed = true;
    }
}


// ============================================
// PROXY UPGRADE EXAMPLES
// ============================================

contract VulnerableProxy {
    address public implementation;
    address public admin;
    
    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }
    
    // VULNERABLE: Upgrade without initialization validation
    function upgradeTo(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
        // Missing: validate initialization delegatecall
        (bool success, ) = newImpl.delegatecall(abi.encodeWithSignature("initialize()"));
        // No validation of success!
    }
    
    // VULNERABLE: UUPS upgrade without validation
    function upgradeToAndCall(address newImpl, bytes calldata data) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
        if (data.length > 0) {
            (bool success, ) = newImpl.delegatecall(data);
            // Missing validation!
        }
    }
}

contract SafeProxy {
    address public implementation;
    address public admin;
    
    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }
    
    // SAFE: Upgrade with initialization validation
    function upgradeTo(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
        
        // Validate initialization
        (bool success, bytes memory result) = newImpl.delegatecall(abi.encodeWithSignature("initialize()"));
        require(success, "Initialization failed");
    }
    
    // SAFE: Using OpenZeppelin's verifyCallResult
    function upgradeToAndCall(address newImpl, bytes calldata data) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
        if (data.length > 0) {
            (bool success, bytes memory result) = newImpl.delegatecall(data);
            _verifyCallResult(success, result, "Upgrade initialization failed");
        }
    }
    
    function _verifyCallResult(bool success, bytes memory result, string memory errorMessage) internal pure {
        if (!success) {
            if (result.length == 0) {
                revert(errorMessage);
            } else {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }
}


// ============================================
// ORACLE MANIPULATION EXAMPLES
// ============================================

interface IPriceOracle {
    function latestRoundData() external view returns (uint80 roundId, int256 price, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract VulnerableOracle {
    IPriceOracle public priceFeed;
    
    constructor(address _feed) {
        priceFeed = IPriceOracle(_feed);
    }
    
    // VULNERABLE: Single oracle, no validation
    function getAssetPrice() external view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return uint256(price);  // No staleness check, no deviation check
    }
    
    // VULNERABLE: Using price directly for critical operation
    function liquidate(address borrower, uint256 collateral) external {
        uint256 price = getAssetPrice();
        // Liquidation logic using unvalidated price
    }
}

contract SafeOracle {
    IPriceOracle public priceFeed;
    IPriceOracle public secondaryFeed;
    uint256 public maxDeviationBps;  // Basis points
    uint256 public heartbeat;  // Max age in seconds
    
    constructor(address _feed, address _secondaryFeed, uint256 _maxDeviationBps, uint256 _heartbeat) {
        priceFeed = IPriceOracle(_feed);
        secondaryFeed = IPriceOracle(_secondaryFeed);
        maxDeviationBps = _maxDeviationBps;
        heartbeat = _heartbeat;
    }
    
    // SAFE: Multiple sources + deviation check + staleness check
    function getAssetPrice() external view returns (uint256) {
        (, int256 price1, , uint256 updatedAt1, ) = priceFeed.latestRoundData();
        (, int256 price2, , uint256 updatedAt2, ) = secondaryFeed.latestRoundData();
        
        require(block.timestamp - updatedAt1 <= heartbeat, "Primary oracle stale");
        require(block.timestamp - updatedAt2 <= heartbeat, "Secondary oracle stale");
        
        uint256 diff = price1 > price2 ? uint256(price1 - price2) : uint256(price2 - price1);
        uint256 maxDiff = (uint256(price1) * maxDeviationBps) / 10000;
        require(diff <= maxDiff, "Price deviation too high");
        
        return (uint256(price1) + uint256(price2)) / 2;
    }
}


// ============================================
// TX.ORIGIN AUTHENTICATION EXAMPLES
// ============================================

contract VulnerableTxOrigin {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Using tx.origin for authentication
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "Not owner");  // PHISHING VULNERABLE!
        owner = newOwner;
    }
    
    // VULNERABLE: tx.origin in authorization
    function withdraw() external {
        require(tx.origin == owner, "Not authorized");
        payable(owner).transfer(address(this).balance);
    }
    
    // VULNERABLE: tx.origin for access control
    function adminAction() external {
        if (tx.origin != owner) {
            revert("Not admin");
        }
        // Admin logic
    }
    
    // VULNERABLE: Setting owner via tx.origin in non-constructor
    function transferOwnershipTxOrigin(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}

contract SafeTxOrigin {
    address public owner;
    
    constructor() {
        owner = msg.sender;  // SAFE: constructor uses msg.sender
    }
    
    // SAFE: Using msg.sender for authentication
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
    
    // SAFE: msg.sender in authorization
    function withdraw() external {
        require(msg.sender == owner, "Not authorized");
        payable(owner).transfer(address(this).balance);
    }
    
    // SAFE: Ownable pattern with msg.sender
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function adminAction() external onlyOwner {
        // Admin logic
    }
    
    // SAFE: Proper ownership transfer
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}


// ============================================
// TX.ORIGIN FALSE POSITIVE CASES (Legitimate uses)
// ============================================

contract TxOriginLegitimate {
    // LEGITIMATE: Logging tx.origin for analytics
    event UserAction(address indexed user, address indexed origin, string action);
    
    function logAction(string calldata action) external {
        emit UserAction(msg.sender, tx.origin, action);  // Not auth - just logging
    }
    
    // LEGITIMATE: Checking if called directly vs via contract
    function isDirectCall() external view returns (bool) {
        return msg.sender == tx.origin;  // Not auth - just detection
    }
}