package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// BSC网络配置
const (
	BSC_RPC_URL = "https://1rpc.io/bnb"
	CHAIN_ID    = 56
	MIN_GAS_PRICE = 1000000000 // 1 Gwei 最低Gas价格
	GAS_LIMIT     = 200000     // 授权操作的Gas限制
)

// TokenManager2合约地址（Four.meme平台）
const TOKEN_MANAGER2_ADDRESS = "0x5c952063c7fc8610FFDB798152D69F0B9550762b"

// 最大授权数量 (2^256 - 1)
const MAX_UINT256 = "115792089237316195423570985008687907853269984665640564039457584007913129639935"

// 全局变量
var (
	ethClient   *ethclient.Client
	privateKey  *ecdsa.PrivateKey
	userAddress common.Address
)

func main() {
	fmt.Println("🔐 ERC20代币授权工具 v1.0")
	fmt.Println("目标平台: Four.meme (BSC)")
	fmt.Println(strings.Repeat("=", 50))

	// 获取参数
	tokenAddress := getTokenAddress()
	privateKeyHex := getPrivateKey()

	// 初始化连接
	err := initializeEthClient()
	if err != nil {
		log.Fatalf("❌ 连接BSC失败: %v", err)
	}
	defer ethClient.Close()

	// 初始化钱包
	err = initializeWallet(privateKeyHex)
	if err != nil {
		log.Fatalf("❌ 钱包初始化失败: %v", err)
	}

	fmt.Printf("📋 操作信息:\n")
	fmt.Printf("   钱包地址: %s\n", userAddress.Hex())
	fmt.Printf("   代币地址: %s\n", tokenAddress.Hex())
	fmt.Printf("   目标合约: %s\n", TOKEN_MANAGER2_ADDRESS)

	// 检查当前授权状态
	fmt.Println("\n🔍 检查当前授权状态...")
	currentAllowance := getCurrentAllowance(tokenAddress, userAddress, common.HexToAddress(TOKEN_MANAGER2_ADDRESS))
	maxAmount := new(big.Int)
	maxAmount.SetString(MAX_UINT256, 10)

	fmt.Printf("   当前授权: %s\n", currentAllowance.String())
	fmt.Printf("   最大数量: %s\n", maxAmount.String())

	// 判断是否需要授权
	if currentAllowance.Cmp(maxAmount) >= 0 {
		fmt.Println("✅ 已经是最大授权，无需重复授权!")
		return
	}

	// 执行授权
	fmt.Println("\n🚀 开始执行最大授权...")
	success := executeApprove(tokenAddress, maxAmount)
	if success {
		fmt.Println("✅ 授权成功完成!")
		fmt.Printf("🔗 授权合约: %s\n", TOKEN_MANAGER2_ADDRESS)
		fmt.Println("💡 现在可以无限制地在Four.meme平台交易此代币")
	} else {
		fmt.Println("❌ 授权失败!")
		os.Exit(1)
	}
}

// 获取代币地址
func getTokenAddress() common.Address {
	if len(os.Args) > 1 {
		tokenAddr := os.Args[1]
		if common.IsHexAddress(tokenAddr) {
			return common.HexToAddress(tokenAddr)
		} else {
			log.Fatalf("❌ 无效的代币地址: %s", tokenAddr)
		}
	}

	fmt.Print("请输入代币合约地址: ")
	var tokenAddr string
	fmt.Scanln(&tokenAddr)

	if !common.IsHexAddress(tokenAddr) {
		log.Fatalf("❌ 无效的代币地址: %s", tokenAddr)
	}

	return common.HexToAddress(tokenAddr)
}

// 获取私钥
func getPrivateKey() string {
	// 优先从环境变量获取
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	if privateKeyHex != "" {
		fmt.Println("📂 从环境变量读取私钥")
		return cleanPrivateKey(privateKeyHex)
	}

	// 交互式输入
	fmt.Print("请输入私钥 (不含0x): ")
	fmt.Scanln(&privateKeyHex)

	if privateKeyHex == "" {
		log.Fatal("❌ 私钥不能为空")
	}

	return cleanPrivateKey(privateKeyHex)
}

// 清理私钥格式
func cleanPrivateKey(privateKeyHex string) string {
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKeyHex = strings.TrimSpace(privateKeyHex)
	return privateKeyHex
}

// 初始化以太坊客户端
func initializeEthClient() error {
	fmt.Println("🌐 连接到BSC网络...")

	client, err := ethclient.Dial(BSC_RPC_URL)
	if err != nil {
		return fmt.Errorf("RPC连接失败: %v", err)
	}

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return fmt.Errorf("获取链ID失败: %v", err)
	}

	if chainID.Int64() != CHAIN_ID {
		client.Close()
		return fmt.Errorf("链ID不匹配: 期望 %d, 实际 %d", CHAIN_ID, chainID.Int64())
	}

	ethClient = client
	fmt.Printf("✅ 成功连接到BSC (Chain ID: %d)\n", chainID.Int64())
	return nil
}

// 初始化钱包
func initializeWallet(privateKeyHex string) error {
	fmt.Println("🔑 初始化钱包...")

	// 转换私钥
	key, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return fmt.Errorf("私钥格式错误: %v", err)
	}

	// 生成地址
	publicKey := key.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("转换公钥失败")
	}

	privateKey = key
	userAddress = crypto.PubkeyToAddress(*publicKeyECDSA)

	fmt.Printf("✅ 钱包初始化成功: %s\n", userAddress.Hex())
	return nil
}

// 获取当前授权余额
func getCurrentAllowance(tokenAddr, owner, spender common.Address) *big.Int {
	// ERC20 allowance方法的ABI
	allowanceABI := `[{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`

	// 解析ABI
	contractAbi, err := abi.JSON(strings.NewReader(allowanceABI))
	if err != nil {
		fmt.Printf("⚠️ 解析allowance ABI失败: %v\n", err)
		return big.NewInt(0)
	}

	// 编码函数调用
	data, err := contractAbi.Pack("allowance", owner, spender)
	if err != nil {
		fmt.Printf("⚠️ 编码allowance调用失败: %v\n", err)
		return big.NewInt(0)
	}

	// 调用合约
	result, err := ethClient.CallContract(context.Background(), ethereum.CallMsg{
		To:   &tokenAddr,
		Data: data,
	}, nil)
	if err != nil {
		fmt.Printf("⚠️ 查询授权余额失败: %v\n", err)
		return big.NewInt(0)
	}

	// 解码结果
	allowance := new(big.Int)
	allowance.SetBytes(result)

	return allowance
}

// 执行ERC20授权
func executeApprove(tokenAddr common.Address, amount *big.Int) bool {
	fmt.Printf("🔐 授权最大数量给 TokenManager2...\n")

	// 检查BNB余额
	balance, err := ethClient.BalanceAt(context.Background(), userAddress, nil)
	if err != nil {
		fmt.Printf("❌ 无法查询BNB余额: %v\n", err)
		return false
	}

	// 动态获取Gas价格
	gasPrice, err := getOptimalGasPrice()
	if err != nil {
		fmt.Printf("⚠️ 获取Gas价格失败，使用默认值: %v\n", err)
		gasPrice = big.NewInt(MIN_GAS_PRICE)
	}

	gasLimit := uint64(GAS_LIMIT)
	estimatedFee := new(big.Int).Mul(big.NewInt(int64(gasLimit)), gasPrice)

	if balance.Cmp(estimatedFee) < 0 {
		fmt.Printf("❌ BNB余额不足: 余额 %s, 需要 %s\n", formatBNB(balance), formatBNB(estimatedFee))
		return false
	}

	fmt.Printf("💰 BNB余额: %s\n", formatBNB(balance))
	fmt.Printf("⛽ Gas价格: %.2f Gwei (预估费用: %s)\n", 
		float64(gasPrice.Int64())/1e9, formatBNB(estimatedFee))

	// ERC20 approve方法的ABI
	approveABI := `[{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"}]`

	// 解析ABI
	contractAbi, err := abi.JSON(strings.NewReader(approveABI))
	if err != nil {
		fmt.Printf("❌ 解析approve ABI失败: %v\n", err)
		return false
	}

	// 编码函数调用
	spender := common.HexToAddress(TOKEN_MANAGER2_ADDRESS)
	data, err := contractAbi.Pack("approve", spender, amount)
	if err != nil {
		fmt.Printf("❌ 编码approve调用失败: %v\n", err)
		return false
	}

	// 获取nonce
	nonce, err := ethClient.PendingNonceAt(context.Background(), userAddress)
	if err != nil {
		fmt.Printf("❌ 获取nonce失败: %v\n", err)
		return false
	}

	// 构造交易
	tx := types.NewTransaction(
		nonce,
		tokenAddr,
		big.NewInt(0),
		gasLimit,
		gasPrice,
		data,
	)

	// 签名交易
	signer := types.NewEIP155Signer(big.NewInt(CHAIN_ID))
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		fmt.Printf("❌ 签名交易失败: %v\n", err)
		return false
	}

	// 发送交易
	err = ethClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Printf("❌ 发送授权交易失败: %v\n", err)
		return false
	}

	fmt.Printf("⏳ 授权交易哈希: %s\n", signedTx.Hash().Hex())
	fmt.Printf("🔗 BSCScan查看: https://bscscan.com/tx/%s\n", signedTx.Hash().Hex())

	// 等待确认
	receipt, err := waitForTransaction(signedTx.Hash())
	if err != nil {
		fmt.Printf("❌ 授权交易确认失败: %v\n", err)
		return false
	}

	return receipt.Status == 1
}

// 等待交易确认
func waitForTransaction(txHash common.Hash) (*types.Receipt, error) {
	fmt.Print("⏳ 等待交易确认")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return nil, fmt.Errorf("等待交易超时")
		case <-ticker.C:
			receipt, err := ethClient.TransactionReceipt(context.Background(), txHash)
			if err == nil {
				fmt.Println() // 换行
				if receipt.Status == 1 {
					fmt.Println("✅ 交易成功确认!")
					return receipt, nil
				} else {
					return receipt, fmt.Errorf("交易失败，状态: %d", receipt.Status)
				}
			}
			// 继续等待
			fmt.Print(".")
		}
	}
}

// 格式化BNB数量显示
func formatBNB(amount *big.Int) string {
	if amount == nil {
		return "0 BNB"
	}

	// 转换为BNB (除以10^18)
	bnb := new(big.Float)
	bnb.SetInt(amount)
	bnb = bnb.Quo(bnb, big.NewFloat(1e18))

	return fmt.Sprintf("%.6f BNB", bnb)
}

// 获取最优Gas价格
func getOptimalGasPrice() (*big.Int, error) {
	fmt.Println("🔍 获取最优Gas价格...")

	// 获取网络建议的Gas价格
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	suggestedGasPrice, err := ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取建议Gas价格失败: %v", err)
	}

	fmt.Printf("   网络建议: %.2f Gwei\n", float64(suggestedGasPrice.Int64())/1e9)

	// 确保不低于最低要求
	minGasPrice := big.NewInt(MIN_GAS_PRICE)
	if suggestedGasPrice.Cmp(minGasPrice) < 0 {
		fmt.Printf("   调整为最低: %.2f Gwei\n", float64(MIN_GAS_PRICE)/1e9)
		return minGasPrice, nil
	}

	// 在建议价格基础上乘以3倍，确保交易成功又不过度浪费
	bufferedGasPrice := new(big.Int)
	bufferedGasPrice.Mul(suggestedGasPrice, big.NewInt(3))

	fmt.Printf("   最终使用: %.2f Gwei (3x网络建议)\n", 
		float64(bufferedGasPrice.Int64())/1e9)

	return bufferedGasPrice, nil
}
