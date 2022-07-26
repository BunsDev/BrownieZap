// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// File: soulswap-lib/contracts/libraries/TransferHelper.sol

// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false
library TransferHelper {
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeApprove: approve failed'
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeTransfer: transfer failed'
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::transferFrom: transferFrom failed'
        );
    }

    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper::safeTransferETH: ETH transfer failed');
    }
}

// File: soulswap-core/contracts/interfaces/ISoulSwapPair.sol

pragma solidity >=0.5.0;

interface ISoulSwapPair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}

pragma solidity >=0.6.2;

interface ISoulSwapRouter {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

pragma solidity >=0.6.2;

interface IHyperswapRouter01 {
    function factory() external pure returns (address);
    function WFTM() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityFTM(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountFTMMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountFTM, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityFTM(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountFTMMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountFTM);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityFTMWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountFTMMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountFTM);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactFTMForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactFTM(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForFTM(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapFTMForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

pragma solidity ^0.8.4;

interface IZap {
    function swapToken(address _from, uint amount, address _to, address routerAddr, address _recipient) external;
    function swapToNative(address _from, uint amount, address routerAddr, address _recipient) external;
    function zapIn(address _to, address routerAddr, address _recipient) external payable;
    function zapInToLPVault(address _to, address routerAddr, address _vault, address _recipient) external payable;
    function zapInToSSVault(address _to, address routerAddr, address _vault, address _recipient) external payable;
    function zapInToken(address _from, uint amount, address _to, address routerAddr, address _recipient) external;
    function zapInTokenToLPVault(address _from, uint amount, address _to, address routerAddr, address _vault, address _recipient) external;
    function zapInTokenToSSVault(address _from, uint amount, address _to, address routerAddr, address _vault, address _recipient) external;
    function zapAcross(address _from, uint amount, address _toRouter, address _recipient) external;
    function zapOut(address _from, uint amount, address routerAddr, address _recipient) external;
    function zapOutToken(address _from, uint amount, address _to, address routerAddr, address _recipient) external;
}

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IVault is IERC20 {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
    function want() external pure returns (address);
}

contract FTMZap is Ownable {
    using SafeMath for uint;
    using SafeERC20 for IERC20;

    /* ========== STATE VARIABLES ========== */

    address public WNATIVE; // 0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83; (250)
    address public SOUL_SWAP_ROUTER; // = 0x6b3d631B87FE27aF29efeC61d2ab8CE4d621cCBF; (250)

    mapping (address => bool) public useNativeRouter;

    constructor(address _WNATIVE, address _SOUL_SWAP_ROUTER) Ownable() {
       WNATIVE = _WNATIVE;
       SOUL_SWAP_ROUTER = _SOUL_SWAP_ROUTER;
    }

    /* ========== EXTERNAL FUNCTIONS ========== */

    receive() external payable {}

    /* ========== BASIC FUNCTIONS ========== */

    function zapInToken(address _from, uint amount, address _to, address _recipient) external {
        // From an ERC20 to an LP token, through specified router, going through base asset if necessary
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        // we'll need this approval to add liquidity
        _approveTokenIfNeeded(_from, SOUL_SWAP_ROUTER);
        _swapTokenToLP(_from, amount, _to, _recipient, SOUL_SWAP_ROUTER);
    }

    function zapInTokenToLPVault(address _from, uint amount, address _to, address _vault, address _recipient) external {
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, SOUL_SWAP_ROUTER);
        _approveTokenIfNeeded(_to, _vault);
        uint lps = _swapTokenToLP(_from, amount, _to, address(this), SOUL_SWAP_ROUTER);
        IVault vault = IVault(_vault);
        vault.deposit(lps);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapInTokenToSingleSideVault(address _from, uint amount, address _to, address _vault, address _recipient) external {
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, SOUL_SWAP_ROUTER);
        _approveTokenIfNeeded(_to, _vault);
        uint tokens = _swap(_from, amount, _to, address(this), SOUL_SWAP_ROUTER);
        IVault vault = IVault(_vault);
        vault.deposit(tokens);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapIn(address _to, address _recipient) external payable {
        // NATIVE --> LP token through the SoulSwap router
        _swapNativeToLP(_to, msg.value, _recipient, SOUL_SWAP_ROUTER);
    }

    function zapOut(address _from, uint amount) external {
        // LP --> NATIVE through specified router
        // take the LP token
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, SOUL_SWAP_ROUTER);

        // get pairs for LP
        address token0 = ISoulSwapPair(_from).token0();
        address token1 = ISoulSwapPair(_from).token1();
        _approveTokenIfNeeded(token0, SOUL_SWAP_ROUTER);
        _approveTokenIfNeeded(token1, SOUL_SWAP_ROUTER);
        // check if either is already native token
        if (token0 == WNATIVE || token1 == WNATIVE) {
            // if so, we only need to swap one, figure out which and how much
            address token = token0 != WNATIVE ? token0 : token1;
            uint amtToken;
            uint amtETH;
            (amtToken, amtETH) = ISoulSwapRouter(SOUL_SWAP_ROUTER).removeLiquidityETH(token, amount, 0, 0, address(this), block.timestamp);
            // swap with msg.sender as recipient, so they already get the NATIVE
            _swapTokenForNative(token, amtToken, msg.sender, SOUL_SWAP_ROUTER);
            // send other half of NATIVE
            TransferHelper.safeTransferETH(msg.sender, amtETH);
        } else {
            // convert both for NATIVE (msg.sender as recipient)
            uint amt0;
            uint amt1;
            (amt0, amt1) = ISoulSwapRouter(SOUL_SWAP_ROUTER).removeLiquidity(token0, token1, amount, 0, 0, address(this), block.timestamp);
            _swapTokenForNative(token0, amt0, msg.sender, SOUL_SWAP_ROUTER);
            _swapTokenForNative(token1, amt1, msg.sender, SOUL_SWAP_ROUTER);
        }
    }

    function zapOutToken(address _from, uint amount, address _to, address _recipient) external {
        // LP --> ERC20 (through SoulSwap Router)
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, SOUL_SWAP_ROUTER);

        address token0 = ISoulSwapPair(_from).token0();
        address token1 = ISoulSwapPair(_from).token1();
        _approveTokenIfNeeded(token0, SOUL_SWAP_ROUTER);
        _approveTokenIfNeeded(token1, SOUL_SWAP_ROUTER);
        uint amt0;
        uint amt1;
        (amt0, amt1) = ISoulSwapRouter(SOUL_SWAP_ROUTER).removeLiquidity(token0, token1, amount, 0, 0, address(this), block.timestamp);
        if (token0 != _to) {
            amt0 = _swap(token0, amt0, _to, address(this), SOUL_SWAP_ROUTER);
        }
        if (token1 != _to) {
            amt1 = _swap(token1, amt1, _to, address(this), SOUL_SWAP_ROUTER);
        }
        IERC20(_to).safeTransfer(_recipient, amt0.add(amt1));
    }


    /* ========== CUSTOM FUNCTIONS ========== */

    function zapInToken(address _from, uint amount, address _to, address routerAddr, address _recipient) external {
        // From an ERC20 to an LP token, through specified router, going through base asset if necessary
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        // we'll need this approval to add liquidity
        _approveTokenIfNeeded(_from, routerAddr);
        _swapTokenToLP(_from, amount, _to, _recipient, routerAddr);

    }

    function zapInTokenToLPVault(address _from, uint amount, address _to, address routerAddr, address _vault, address _recipient) external {
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, routerAddr);
        _approveTokenIfNeeded(_to, _vault);
        uint lps = _swapTokenToLP(_from, amount, _to, address(this), routerAddr);
        IVault vault = IVault(_vault);
        vault.deposit(lps);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapInTokenToSingleSideVault(address _from, uint amount, address _to, address routerAddr, address _vault, address _recipient) external {
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, routerAddr);
        _approveTokenIfNeeded(_to, _vault);
        uint tokens = _swap(_from, amount, _to, address(this), routerAddr);
        IVault vault = IVault(_vault);
        vault.deposit(tokens);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapIn(address _to, address routerAddr, address _recipient) external payable {
        // from Native to an LP token through the specified router
        _swapNativeToLP(_to, msg.value, _recipient, routerAddr);
    }

    function zapInToLPVault(address _to, address routerAddr, address _vault, address _recipient) external payable {
        _approveTokenIfNeeded(_to, _vault);
        uint lps = _swapNativeToLP(_to, msg.value, address(this), routerAddr);
        IVault vault = IVault(_vault);
        vault.deposit(lps);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapInToSingleSidedVault(address _to, address routerAddr, address _vault, address _recipient) external payable {
        _approveTokenIfNeeded(_to, _vault);
        uint lps = _swapNativeForToken(_to, msg.value, address(this), routerAddr);
        IVault vault = IVault(_vault);
        vault.deposit(lps);
        IERC20(_vault).safeTransfer(_recipient, vault.balanceOf(address(this)));
    }

    function zapAcross(address _from, uint amount, address _toRouter, address _recipient) external {
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);

        ISoulSwapPair pair = ISoulSwapPair(_from);
        _approveTokenIfNeeded(pair.token0(), _toRouter);
        _approveTokenIfNeeded(pair.token1(), _toRouter);

        IERC20(_from).safeTransfer(_from, amount);
        uint amt0;
        uint amt1;
        (amt0, amt1) = pair.burn(address(this));
        ISoulSwapRouter(_toRouter).addLiquidity(pair.token0(), pair.token1(), amt0, amt1, 0, 0, _recipient, block.timestamp);
    }

    function zapOut(address _from, uint amount, address routerAddr, address _recipient) external {
        // LP --> NATIVE through specified router
        // take the LP token
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, routerAddr);

        // get pairs for LP
        address token0 = ISoulSwapPair(_from).token0();
        address token1 = ISoulSwapPair(_from).token1();
        _approveTokenIfNeeded(token0, routerAddr);
        _approveTokenIfNeeded(token1, routerAddr);
        // check if either is already native token
        if (token0 == WNATIVE || token1 == WNATIVE) {
            // if so, we only need to swap one, figure out which and how much
            address token = token0 != WNATIVE ? token0 : token1;
            uint amtToken;
            uint amtETH;
            (amtToken, amtETH) = ISoulSwapRouter(routerAddr).removeLiquidityETH(token, amount, 0, 0, address(this), block.timestamp);
            // swap with msg.sender as recipient, so they already get the Native
            _swapTokenForNative(token, amtToken, _recipient, routerAddr);
            // send other half of Native
            TransferHelper.safeTransferETH(_recipient, amtETH);
        } else {
            // convert both for NATIVE with msg.sender as recipient
            uint amt0;
            uint amt1;
            (amt0, amt1) = ISoulSwapRouter(routerAddr).removeLiquidity(token0, token1, amount, 0, 0, address(this), block.timestamp);
            _swapTokenForNative(token0, amt0, _recipient, routerAddr);
            _swapTokenForNative(token1, amt1, _recipient, routerAddr);
        }
    }

    function zapOutToken(address _from, uint amount, address _to, address routerAddr, address _recipient) external {
        // from an LP token to an ERC20 through specified router
        IERC20(_from).safeTransferFrom(msg.sender, address(this), amount);
        _approveTokenIfNeeded(_from, routerAddr);

        address token0 = ISoulSwapPair(_from).token0();
        address token1 = ISoulSwapPair(_from).token1();
        _approveTokenIfNeeded(token0, routerAddr);
        _approveTokenIfNeeded(token1, routerAddr);
        uint amt0;
        uint amt1;
        (amt0, amt1) = ISoulSwapRouter(routerAddr).removeLiquidity(token0, token1, amount, 0, 0, address(this), block.timestamp);
        if (token0 != _to) {
            amt0 = _swap(token0, amt0, _to, address(this), routerAddr);
        }
        if (token1 != _to) {
            amt1 = _swap(token1, amt1, _to, address(this), routerAddr);
        }
        IERC20(_to).safeTransfer(_recipient, amt0.add(amt1));
    }

    /* ========== PRIVATE FUNCTIONS ========== */

    function _approveTokenIfNeeded(address token, address router) private {
        if (IERC20(token).allowance(address(this), router) == 0) {
            IERC20(token).safeApprove(router, type(uint).max);
        }
    }

    function _swapTokenToLP(address _from, uint amount, address _to, address recipient, address routerAddr) private returns (uint) {
                // get pairs for desired lp
        if (_from == ISoulSwapPair(_to).token0() || _from == ISoulSwapPair(_to).token1()) { // check if we already have one of the assets
            // if so, we're going to sell half of _from for the other token we need
            // figure out which token we need, and approve
            address other = _from == ISoulSwapPair(_to).token0() ? ISoulSwapPair(_to).token1() : ISoulSwapPair(_to).token0();
            _approveTokenIfNeeded(other, routerAddr);
            // calculate amount of _from to sell
            uint sellAmount = amount.div(2);
            // execute swap
            uint otherAmount = _swap(_from, sellAmount, other, address(this), routerAddr);
            uint liquidity;
            ( , , liquidity) = ISoulSwapRouter(routerAddr).addLiquidity(_from, other, amount.sub(sellAmount), otherAmount, 0, 0, recipient, block.timestamp);
            return liquidity;
        } else {
            // go through native token for highest liquidity
            uint nativeAmount = _swapTokenForNative(_from, amount, address(this), routerAddr);
            return _swapNativeToLP(_to, nativeAmount, recipient, routerAddr);
        }
    }

    function _swapNativeToLP(address _LP, uint amount, address recipient, address routerAddress) private returns (uint) {
            // LP
            ISoulSwapPair pair = ISoulSwapPair(_LP);
            address token0 = pair.token0();
            address token1 = pair.token1();
            uint liquidity;
            if (token0 == WNATIVE || token1 == WNATIVE) {
                address token = token0 == WNATIVE ? token1 : token0;
                ( , , liquidity) = _swapHalfNativeAndProvide(token, amount, routerAddress, recipient);
            } else {
                ( , , liquidity) = _swapNativeToEqualTokensAndProvide(token0, token1, amount, routerAddress, recipient);
            }
            return liquidity;
    }

    function _swapHalfNativeAndProvide(address token, uint amount, address routerAddress, address recipient) private returns (uint, uint, uint) {
            uint swapValue = amount.div(2);
            uint tokenAmount = _swapNativeForToken(token, swapValue, address(this), routerAddress);
            _approveTokenIfNeeded(token, routerAddress);
            if (useNativeRouter[routerAddress]) {
                IHyperswapRouter01 router = IHyperswapRouter01(routerAddress);
                return router.addLiquidityFTM{value : amount.sub(swapValue)}(token, tokenAmount, 0, 0, recipient, block.timestamp);
            }
            else {
                ISoulSwapRouter router = ISoulSwapRouter(routerAddress);
                return router.addLiquidityETH{value : amount.sub(swapValue)}(token, tokenAmount, 0, 0, recipient, block.timestamp);
            }
    }

    function _swapNativeToEqualTokensAndProvide(address token0, address token1, uint amount, address routerAddress, address recipient) private returns (uint, uint, uint) {
            uint swapValue = amount.div(2);
            uint token0Amount = _swapNativeForToken(token0, swapValue, address(this), routerAddress);
            uint token1Amount = _swapNativeForToken(token1, amount.sub(swapValue), address(this), routerAddress);
            _approveTokenIfNeeded(token0, routerAddress);
            _approveTokenIfNeeded(token1, routerAddress);
            ISoulSwapRouter router = ISoulSwapRouter(routerAddress);
            return router.addLiquidity(token0, token1, token0Amount, token1Amount, 0, 0, recipient, block.timestamp);
    }

    function _swapNativeForToken(address token, uint value, address recipient, address routerAddr) private returns (uint) {
        address[] memory path;
        ISoulSwapRouter router = ISoulSwapRouter(routerAddr);

        path = new address[](2);
        path[0] = WNATIVE;
        path[1] = token;

        uint[] memory amounts = router.swapExactETHForTokens{value : value}(0, path, recipient, block.timestamp);
        return amounts[amounts.length - 1];
    }

    function _swapTokenForNative(address token, uint amount, address recipient, address routerAddr) private returns (uint) {
        address[] memory path;
        ISoulSwapRouter router = ISoulSwapRouter(routerAddr);
        path = new address[](2);
        path[0] = token;
        path[1] = WNATIVE;

        uint[] memory amounts = router.swapExactTokensForETH(amount, 0, path, recipient, block.timestamp);
        return amounts[amounts.length - 1];
    }

    function _swap(address _from, uint amount, address _to, address recipient, address routerAddr) private returns (uint) {
        ISoulSwapRouter router = ISoulSwapRouter(routerAddr);

        address[] memory path;
        if (_from == WNATIVE || _to == WNATIVE) {
            path = new address[](2);
            path[0] = _from;
            path[1] = _to;
        } else {
            // Go through WNative
            path = new address[](3);
            path[0] = _from;
            path[1] = WNATIVE;
            path[2] = _to;
        }

        uint[] memory amounts = router.swapExactTokensForTokens(amount, 0, path, recipient, block.timestamp);
        return amounts[amounts.length - 1];
    }

    /* ========== RESTRICTED FUNCTIONS ========== */

    function withdraw(address token) external onlyOwner {
        if (token == address(0)) {
            payable(owner()).transfer(address(this).balance);
            return;
        }

        IERC20(token).transfer(owner(), IERC20(token).balanceOf(address(this)));
    }

    function toggleNativeRouter(address router) external onlyOwner {
        useNativeRouter[router] != true
            ? useNativeRouter[router] = true 
            : useNativeRouter[router] = false;
    }

    function setUseNativeRouter(address router) external onlyOwner {
        useNativeRouter[router] = true;
    }

    function setSoulSwapRouter(address router) external onlyOwner {
        SOUL_SWAP_ROUTER = router;
    }
}
