// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import "../../core/libraries/TokenHelper.sol";
import "./IPSwapAggregator.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

abstract contract OKXScaleHelper {
    address public immutable _tokenApprove;
    uint256 internal constant _COMMISSION_RATE_MASK =
        0x000000000000ffffffffffff0000000000000000000000000000000000000000;
    uint256 internal constant _COMMISSION_FLAG_MASK =
        0xffffffffffff0000000000000000000000000000000000000000000000000000;
    uint256 internal constant FROM_TOKEN_COMMISSION =
        0x3ca20afc2aaa0000000000000000000000000000000000000000000000000000;
    uint256 internal constant TO_TOKEN_COMMISSION = 0x3ca20afc2bbb0000000000000000000000000000000000000000000000000000;
    uint256 internal constant FROM_TOKEN_COMMISSION_DUAL =
        0x22220afc2aaa0000000000000000000000000000000000000000000000000000;
    uint256 internal constant TO_TOKEN_COMMISSION_DUAL =
        0x22220afc2bbb0000000000000000000000000000000000000000000000000000;
    uint256 internal constant _TO_B_COMMISSION_MASK =
        0x8000000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant _ADDRESS_MASK = 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;

    uint256 internal constant _TRIM_FLAG_MASK = 0xffffffffffff0000000000000000000000000000000000000000000000000000;
    uint256 internal constant _TRIM_EXPECT_AMOUNT_OUT_OR_ADDRESS_MASK =
        0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;
    uint256 internal constant _TRIM_RATE_MASK = 0x000000000000ffffffffffff0000000000000000000000000000000000000000;
    uint256 internal constant TRIM_FLAG = 0x7777777711110000000000000000000000000000000000000000000000000000;
    uint256 internal constant TRIM_DUAL_FLAG = 0x7777777722220000000000000000000000000000000000000000000000000000;

    // @dev `allowUnsupportedChain` is a safe guard to prevent deploying this contract on unsupported chains by mistake
    // @dev Please add new `__getTokenApproveForChain` entry when deploying to a new chain.
    constructor(bool allowUnsupportedChain) {
        _tokenApprove = __getTokenApproveForChain(block.chainid);
        if (!allowUnsupportedChain) {
            require(_tokenApprove != address(0), "PendleSwap: OKX chain not supported");
        }
    }

    // https://web3.okx.com/build/dev-docs/dex-api/dex-smart-contract#token-approval
    function __getTokenApproveForChain(uint256 chainid) private pure returns (address) {
        if (chainid == 1) {
            return 0x40aA958dd87FC8305b97f2BA922CDdCa374bcD7f;
        }
        if (chainid == 10) {
            return 0x68D6B739D2020067D1e2F713b999dA97E4d54812;
        }
        if (chainid == 56) {
            return 0x2c34A2Fb1d0b4f55de51E1d0bDEfaDDce6b7cDD6;
        }
        if (chainid == 42161) {
            return 0x70cBb871E8f30Fc8Ce23609E9E0Ea87B6b222F58;
        }
        if (chainid == 8453 || chainid == 5000) {
            return 0x57df6092665eb6058DE53939612413ff4B09114E;
        }
        if (chainid == 146) {
            return 0xD321ab5589d3E8FA5Df985ccFEf625022E2DD910;
        }
        if (chainid == 9745) {
            return 0x9FD43F5E4c24543b2eBC807321E58e6D350d6a5A;
        }
        return address(0);
    }

    function _okx_getTokenApprove() internal view returns (address) {
        require(_tokenApprove != address(0), "PendleSwap: OKX chain not supported");
        return _tokenApprove;
    }

    function _okxScaling(
        bytes calldata rawCallData,
        uint256 actualAmount
    ) internal pure returns (bytes memory scaledCallData) {
        bytes4 selector = bytes4(rawCallData[:4]);
        bytes calldata dataToDecode = rawCallData[4:];

        (, IOKXDexRouter.TrimInfo memory trimInfo) = _getCommissionAndTrimInfo();
        bytes memory trimCallData = trimInfo.hasTrim 
            ? _encodeTrimInfo(trimInfo.trimRate, trimInfo.trimAddress, trimInfo.expectAmountOut, trimInfo.chargeRate, trimInfo.chargeAddress)
            : "";

        if (selector == IOKXDexRouter.uniswapV3SwapTo.selector) {
            (uint256 receiver, uint256 amount, uint256 minReturn, uint256[] memory pools) = abi.decode(
                dataToDecode,
                (uint256, uint256, uint256, uint256[])
            );

            minReturn = (minReturn * actualAmount) / amount;
            amount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, receiver, amount, minReturn, pools), trimCallData);
        } else if (selector == IOKXDexRouter.smartSwapTo.selector) {
            (
                uint256 orderId,
                address receiver,
                IOKXDexRouter.BaseRequest memory baseRequest,
                uint256[] memory batchesAmount,
                IOKXDexRouter.RouterPath[][] memory batches,
                IOKXDexRouter.PMMSwapRequest[] memory extraData
            ) = abi.decode(
                    dataToDecode,
                    (
                        uint256,
                        address,
                        IOKXDexRouter.BaseRequest,
                        uint256[],
                        IOKXDexRouter.RouterPath[][],
                        IOKXDexRouter.PMMSwapRequest[]
                    )
                );

            batchesAmount = _scaleArray(batchesAmount, actualAmount, baseRequest.fromTokenAmount);
            baseRequest.minReturnAmount = (baseRequest.minReturnAmount * actualAmount) / baseRequest.fromTokenAmount;
            baseRequest.fromTokenAmount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, orderId, receiver, baseRequest, batchesAmount, batches, extraData), trimCallData);
        } else if (selector == IOKXDexRouter.unxswapTo.selector) {
            (uint256 srcToken, uint256 amount, uint256 minReturn, address receiver, bytes32[] memory pools) = abi
                .decode(dataToDecode, (uint256, uint256, uint256, address, bytes32[]));

            minReturn = (minReturn * actualAmount) / amount;
            amount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, srcToken, amount, minReturn, receiver, pools), trimCallData);
        } else if (selector == IOKXDexRouter.unxswapByOrderId.selector) {
            (uint256 srcToken, uint256 amount, uint256 minReturn, bytes32[] memory pools) = abi.decode(
                dataToDecode,
                (uint256, uint256, uint256, bytes32[])
            );

            minReturn = (minReturn * actualAmount) / amount;
            amount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, srcToken, amount, minReturn, pools), trimCallData);
        } else if (selector == IOKXDexRouter.smartSwapByOrderId.selector) {
            (
                uint256 orderId,
                IOKXDexRouter.BaseRequest memory baseRequest,
                uint256[] memory batchesAmount,
                IOKXDexRouter.RouterPath[][] memory batches,
                IOKXDexRouter.PMMSwapRequest[] memory extraData
            ) = abi.decode(
                    dataToDecode,
                    (
                        uint256,
                        IOKXDexRouter.BaseRequest,
                        uint256[],
                        IOKXDexRouter.RouterPath[][],
                        IOKXDexRouter.PMMSwapRequest[]
                    )
                );

            batchesAmount = _scaleArray(batchesAmount, actualAmount, baseRequest.fromTokenAmount);
            baseRequest.minReturnAmount = (baseRequest.minReturnAmount * actualAmount) / baseRequest.fromTokenAmount;
            baseRequest.fromTokenAmount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, orderId, baseRequest, batchesAmount, batches, extraData), trimCallData);
        } else if (selector == IOKXDexRouter.dagSwapByOrderId.selector) {
            (
                uint256 orderId,
                IOKXDexRouter.BaseRequest memory baseRequest,
                IOKXDexRouter.RouterPath[] memory paths
            ) = abi.decode(dataToDecode, (uint256, IOKXDexRouter.BaseRequest, IOKXDexRouter.RouterPath[]));

            baseRequest.minReturnAmount = (baseRequest.minReturnAmount * actualAmount) / baseRequest.fromTokenAmount;
            baseRequest.fromTokenAmount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, orderId, baseRequest, paths), trimCallData);
        } else if (selector == IOKXDexRouter.dagSwapTo.selector) {
            (
                uint256 orderId,
                address receiver,
                IOKXDexRouter.BaseRequest memory baseRequest,
                IOKXDexRouter.RouterPath[] memory paths
            ) = abi.decode(dataToDecode, (uint256, address, IOKXDexRouter.BaseRequest, IOKXDexRouter.RouterPath[]));

            baseRequest.minReturnAmount = (baseRequest.minReturnAmount * actualAmount) / baseRequest.fromTokenAmount;
            baseRequest.fromTokenAmount = actualAmount;

            return bytes.concat(abi.encodeWithSelector(selector, orderId, receiver, baseRequest, paths), trimCallData);
        } else {
            revert("PendleSwap: OKX selector not supported");
        }
    }

    function _scaleArray(
        uint256[] memory arr,
        uint256 newAmount,
        uint256 oldAmount
    ) internal pure returns (uint256[] memory scaledArr) {
        scaledArr = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            scaledArr[i] = (arr[i] * newAmount) / oldAmount;
        }
    }

    function _getCommissionAndTrimInfo()
        internal
        pure
        returns (IOKXDexRouter.CommissionInfo memory commissionInfo, IOKXDexRouter.TrimInfo memory trimInfo)
    {
        assembly ("memory-safe") {
            // let freePtr := mload(0x40)
            // mstore(0x40, add(freePtr, 0x100))
            let commissionData := calldataload(sub(calldatasize(), 0x20))
            let flag := and(commissionData, TRIM_FLAG)
            let isDualreferrers := or(eq(flag, FROM_TOKEN_COMMISSION_DUAL), eq(flag, TO_TOKEN_COMMISSION_DUAL))
            mstore(commissionInfo, or(eq(flag, FROM_TOKEN_COMMISSION), eq(flag, FROM_TOKEN_COMMISSION_DUAL))) // isFromTokenCommission
            mstore(add(0x20, commissionInfo), or(eq(flag, TO_TOKEN_COMMISSION), eq(flag, TO_TOKEN_COMMISSION_DUAL))) // isToTokenCommission
            mstore(add(0x40, commissionInfo), shr(160, and(commissionData, _COMMISSION_RATE_MASK))) //commissionRate1
            mstore(add(0x60, commissionInfo), and(commissionData, _ADDRESS_MASK)) //referrerAddress1
            commissionData := calldataload(sub(calldatasize(), 0x40))
            mstore(
                add(0xe0, commissionInfo),
                gt(and(commissionData, _TO_B_COMMISSION_MASK), 0) //isToBCommission
            )
            mstore(
                add(0x80, commissionInfo),
                and(commissionData, _ADDRESS_MASK) //token
            )
            switch eq(isDualreferrers, 1)
            case 1 {
                let commissionData2 := calldataload(sub(calldatasize(), 0x60))
                mstore(add(0xa0, commissionInfo), shr(160, and(commissionData2, _COMMISSION_RATE_MASK))) //commissionRate2
                mstore(add(0xc0, commissionInfo), and(commissionData2, _ADDRESS_MASK)) //referrerAddress2
            }
            default {
                mstore(add(0xa0, commissionInfo), 0) //commissionRate2
                mstore(add(0xc0, commissionInfo), 0) //referrerAddress2
            }
            // calculate offset based on commission flag
            let offset := 0x00
            if eq(isDualreferrers, 1) {
                offset := 0x60 // 96 bytes for dual commission
            }
            if or(eq(flag, FROM_TOKEN_COMMISSION), eq(flag, TO_TOKEN_COMMISSION)) {
                offset := 0x40 // 64 bytes for single commission
            }
            // get first bytes32 of trim data
            let trimData := calldataload(sub(calldatasize(), add(offset, 32)))
            flag := and(trimData, _TRIM_FLAG_MASK)
            mstore(trimInfo, or(eq(flag, TRIM_FLAG), eq(flag, TRIM_DUAL_FLAG))) // hasTrim
            mstore(add(0x20, trimInfo), shr(160, and(trimData, _TRIM_RATE_MASK))) // trimRate
            mstore(add(0x40, trimInfo), and(trimData, _TRIM_EXPECT_AMOUNT_OUT_OR_ADDRESS_MASK)) // trimAddress
            // get second bytes32 of trim data
            trimData := calldataload(sub(calldatasize(), add(offset, 64)))
            mstore(add(0x60, trimInfo), and(trimData, _TRIM_EXPECT_AMOUNT_OUT_OR_ADDRESS_MASK)) // expectAmountOut
            switch eq(flag, TRIM_DUAL_FLAG)
            case 1 {
                // get third bytes32 of trim data
                trimData := calldataload(sub(calldatasize(), add(offset, 96)))
                mstore(add(0x80, trimInfo), shr(160, and(trimData, _TRIM_RATE_MASK))) // chargeRate
                mstore(add(0xa0, trimInfo), and(trimData, _TRIM_EXPECT_AMOUNT_OUT_OR_ADDRESS_MASK)) // chargeAddress
            }
            default {
                mstore(add(0x80, trimInfo), 0) // chargeRate
                mstore(add(0xa0, trimInfo), 0) // chargeAddress
            }
        }
    }

    function _encodeTrimInfo(
        uint256 trimRate,
        address trimAddress,
        uint256 expectAmountOut,
        uint256 chargeRate,
        address chargeAddress
    ) internal pure returns (bytes memory encodedData) {
        // Determine if it's dual trim
        bool isDualTrim = chargeRate > 0 || chargeAddress != address(0);

        if (isDualTrim) {
            // Dual trim: 3 chunks of 32 bytes each (96 bytes total)
            encodedData = new bytes(96);

            // Chunk 1: trim_flag (6 bytes) + charge_rate (6 bytes) + charge_address (20 bytes)
            uint256 chunk1 = TRIM_DUAL_FLAG | (uint256(chargeRate) << 160) | uint256(uint160(chargeAddress));

            // Chunk 2: trim_flag (6 bytes) + padding (6 bytes) + expect_amount (20 bytes)
            // Note: expectAmountOut is truncated to 20 bytes (160 bits)
            uint256 chunk2 = TRIM_DUAL_FLAG | (uint256(uint160(expectAmountOut)));

            // Chunk 3: trim_flag (6 bytes) + trim_rate (6 bytes) + trim_address (20 bytes)
            uint256 chunk3 = TRIM_DUAL_FLAG | (uint256(trimRate) << 160) | uint256(uint160(trimAddress));

            assembly {
                mstore(add(encodedData, 32), chunk1) // First chunk first
                mstore(add(encodedData, 64), chunk2) // Second chunk
                mstore(add(encodedData, 96), chunk3) // Third chunk last
            }
        } else {
            // Simple trim: 2 chunks of 32 bytes each (64 bytes total)
            encodedData = new bytes(64);

            // Chunk 1: trim_flag (6 bytes) + padding (6 bytes) + expect_amount (20 bytes)
            // Note: expectAmountOut is truncated to 20 bytes (160 bits)
            uint256 chunk1 = TRIM_FLAG | (uint256(uint160(expectAmountOut)));

            // Chunk 2: trim_flag (6 bytes) + trim_rate (6 bytes) + trim_address (20 bytes)
            uint256 chunk2 = TRIM_FLAG | (uint256(trimRate) << 160) | uint256(uint160(trimAddress));

            assembly {
                mstore(add(encodedData, 32), chunk1) // First chunk first
                mstore(add(encodedData, 64), chunk2) // Second chunk last
            }
        }

        return encodedData;
    }
}

interface IOKXDexRouter {
    struct BaseRequest {
        uint256 fromToken;
        address toToken;
        uint256 fromTokenAmount;
        uint256 minReturnAmount;
        uint256 deadLine;
    }

    struct RouterPath {
        address[] mixAdapters;
        address[] assetTo;
        uint256[] rawData;
        bytes[] extraData;
        uint256 fromToken;
    }

    struct PMMSwapRequest {
        uint256 pathIndex;
        address payer;
        address fromToken;
        address toToken;
        uint256 fromTokenAmountMax;
        uint256 toTokenAmountMax;
        uint256 salt;
        uint256 deadLine;
        bool isPushOrder;
        bytes extension;
    }

    struct CommissionInfo {
        bool isFromTokenCommission; //0x00
        bool isToTokenCommission; //0x20
        uint256 commissionRate; //0x40
        address refererAddress; //0x60
        address token; //0x80
        uint256 commissionRate2; //0xa0
        address refererAddress2; //0xc0
        bool isToBCommission; //0xe0
    }

    struct TrimInfo {
        bool hasTrim; // 0x00
        uint256 trimRate; // 0x20
        address trimAddress; // 0x40
        uint256 expectAmountOut; // 0x60
        uint256 chargeRate; // 0x80
        address chargeAddress; // 0xa0
    }

    // // address marketMaker;
    // // uint256 subIndex;
    // // bytes signature;
    // // uint256 source;  1byte type + 1byte bool（reverse） + 0...0 + 20 bytes address

    // function smartSwapByInvest(
    //     BaseRequest calldata baseRequest,
    //     uint256[] calldata batchesAmount,
    //     RouterPath[][] calldata batches,
    //     PMMSwapRequest[] calldata extraData,
    //     address to
    // ) external payable;

    function uniswapV3SwapTo(
        uint256 receiver,
        uint256 amount,
        uint256 minReturn,
        uint256[] calldata pools
    ) external payable returns (uint256 returnAmount);

    function smartSwapTo(
        uint256 orderId,
        address receiver,
        BaseRequest calldata baseRequest,
        uint256[] calldata batchesAmount,
        RouterPath[][] calldata batches,
        PMMSwapRequest[] calldata extraData
    ) external payable;

    function unxswapTo(
        uint256 srcToken,
        uint256 amount,
        uint256 minReturn,
        address receiver,
        // solhint-disable-next-line no-unused-vars
        bytes32[] calldata pools
    ) external payable returns (uint256 returnAmount);

    function unxswapByOrderId(
        uint256 srcToken,
        uint256 amount,
        uint256 minReturn,
        // solhint-disable-next-line no-unused-vars
        bytes32[] calldata pools
    ) external payable returns (uint256 returnAmount);

    function smartSwapByOrderId(
        uint256 orderId,
        BaseRequest calldata baseRequest,
        uint256[] calldata batchesAmount,
        RouterPath[][] calldata batches,
        PMMSwapRequest[] calldata extraData
    ) external payable returns (uint256 returnAmount);

    function dagSwapByOrderId(
        uint256 orderId,
        BaseRequest calldata baseRequest,
        RouterPath[] calldata paths
    ) external payable returns (uint256 returnAmount);

    function dagSwapTo(
        uint256 orderId,
        address receiver,
        BaseRequest calldata baseRequest,
        RouterPath[] calldata paths
    ) external payable returns (uint256 returnAmount);
}
