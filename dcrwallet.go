// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"decred.org/dcrwallet/v2/chain"
	"decred.org/dcrwallet/v2/errors"
	ldr "decred.org/dcrwallet/v2/internal/loader"
	"decred.org/dcrwallet/v2/internal/prompt"
	"decred.org/dcrwallet/v2/internal/rpc/rpcserver"
	"decred.org/dcrwallet/v2/internal/vsp"
	"decred.org/dcrwallet/v2/p2p"
	"decred.org/dcrwallet/v2/spv"
	"decred.org/dcrwallet/v2/ticketbuyer"
	"decred.org/dcrwallet/v2/version"
	"decred.org/dcrwallet/v2/wallet"
	"decred.org/dcrwallet/v2/walletseed"
	"github.com/decred/dcrd/addrmgr/v2"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/wire"
)

func init() {
	// Format nested errors without newlines (better for logs).
	errors.Separator = ":: "
}

var (
	cfg *config
)

func main() {
	if e := do(); e != nil {
		fmt.Println(e.Error())
	}
}

func do() error {
	seed, err := walletseed.DecodeUserInput("")
	if err != nil {
		return err
	}
	params := chaincfg.MainNetParams()
	root, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return err
	}
	purpose, err := root.Child(44 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return err
	}
	// Derive the coin type key as a child of the purpose key.
	coinTypeKey, err := purpose.Child(params.SLIP0044CoinType + hdkeychain.HardenedKeyStart)
	if err != nil {
		return err
	}
	acctPrivKey, err := coinTypeKey.Child(0 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return err
	}
	externalAddrKey, err := acctPrivKey.Child(0)
	if err != nil {
		return err
	}
	var addrPrivKey *hdkeychain.ExtendedKey
	var i uint32
	for i = 1; i < 100; i++ {
		apk, err := externalAddrKey.Child(i)
		if err != nil {
			return err
		}
		pkh := dcrutil.Hash160(apk.Neuter().SerializedPubKey())
		apkh, err := dcrutil.NewAddressPubKeyHash(pkh, params,
			dcrec.STEcdsaSecp256k1)
		if err != nil {
			return err
		}
		addrStr := apkh.Address()
		if addrStr == "DsZUKoAxdD44J6hyZsm2D5SCPBPVW39RKvA" {
			addrPrivKey = apk
			break
		}
	}

	mtx := wire.NewMsgTx()
	txHash, err := chainhash.NewHashFromStr("e92a36d64b987a487b2ce21b86a22af9304b9ab8a666256853778bd27c7c2c46")
	if err != nil {
		return err
	}
	amt, err := dcrutil.NewAmount(4.84233585)
	if err != nil {
		return err
	}
	prevOut := wire.NewOutPoint(txHash, 0, wire.TxTreeRegular)
	txIn := wire.NewTxIn(prevOut, int64(amt), nil)
	mtx.AddTxIn(txIn)

	addr, err := dcrutil.DecodeAddress("Dsa1DgVBuQG4qysANTMAZ3cEynjn269UvZh", params)
	if err != nil {
		return err
	}
	// Create a new script which pays to the provided address.
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	atomic, err := dcrutil.NewAmount(4.84218485)
	if err != nil {
		return err
	}
	txOut := wire.NewTxOut(int64(atomic), pkScript)
	mtx.AddTxOut(txOut)

	tx := wire.NewMsgTx()
	err = tx.Deserialize(hex.NewDecoder(strings.NewReader("01000000041fe40fb9fa3795d8cf50ae68970abadadf4b3272b07c64490c28cc7df36acfb90000000000ffffffff1fe48ac76a73c7398680989cf91e2c8d4f4b95a4b7daeb8b6a6024d334c9e5240000000000ffffffff1fe4bc828ce776aa6974a0c490c9d0ef2d1bc0d06f728069b552b1ced4567fd40000000000ffffffff1fe774cad26c31a8347b7926f5d00bae21544a77b8d4fe9b8db128f009118bd70000000000ffffffff0271d1dc1c0000000000001976a9145d515bd3f9723c85f95d577cea233f949e1b64b588ac8eec7e0000000000000017a914f5916158e3e2c4551c1796708db8367207ed13bb87000000000000000004230fbf07000000002546080000000000fd450147304402204b8e640ffcc9f20f522ef336209853ba718097ef76828b0227c1a112f11177d4022052bc1fa34cf39c4af35e88484f9292493fafcfeea67312323eb81c91f982386301483045022100ad9a3296cf800d1e8cda6bfae03b1bb585fe178335c1ebd2ef0aae3a354e9e1f022049364fc39540e55c1e498a6e6ee96ebce40a9a63c1621614b35ddcce7a9dc31201483045022100922e6e5ef1c9395ce03c5a890fbb6dd576e11252dd39f567637fafc57a2c0c1302202bae782a40e575af9f7ad45280debb3dfa5f5f89e79c905a13a8be19b8fd11ac014c69532102bc2a9206d10e5d5173583cbafebc78998745abeca13ed33151c93afbd850ca8e2103c995ce342de266d561d6ab4b06c7a14adb0f0b30002997f076f71c8f8ac93c98210330d6c9371b561d2b961a5987d336c0186a9c5dacd6ed4551420b5977e46a29b453ae230fbf07000000001057080000000000fd4501483045022100f6ef8b801392fa5c201de0508ab6132c6a12330292403883f60c03354535b24102201d4c7cd84cb986dd7060e9784ad825f30e06328bc3ca2e7e4b1617a171815e4501483045022100c837e3132f7b980c1f80ff760851f3462ac724466ddb447acd759cf9c60b09ed0220183a5134e8521d0f64aa91bffa23be4ab41717cf854d93d2d395c5ce13801e100147304402201866cd17e5bc98eb2dcfd8059f68397bec84e27895d4b4a73c1488f918c5722902203ea7da7f28c1251ab3be0b47be572d073ca8e57f84c133d999713dc0745fea22014c69532102bc2a9206d10e5d5173583cbafebc78998745abeca13ed33151c93afbd850ca8e2103c995ce342de266d561d6ab4b06c7a14adb0f0b30002997f076f71c8f8ac93c98210330d6c9371b561d2b961a5987d336c0186a9c5dacd6ed4551420b5977e46a29b453ae8272320600000000544d080000000000fd4501483045022100b1648e1ac0dbb4d6e052cb774e7b58210a890f92a29490de1ccf4be55b2394c902200a992c57c8bbd3fe115e688366b4254ab00484d4303f6ab764e2e3efebb5d6b50147304402205bb72e9dfd02156518bac03a8fca48db54e0b5421a887a516f7909ee9694d9cc0220175582ae5161a48cc4064d4bd1279242f95810fbda2352fb909ca896899360270148304502210094cb53b011b0cac2ab8ae6152ed4587a8b25d3741b7274958fbddb7f1944b2b2022040bedc81b750eb644c5662f27a9b59aa985c8f65c178b314f79e15af353a871e014c69532102bc2a9206d10e5d5173583cbafebc78998745abeca13ed33151c93afbd850ca8e2103c995ce342de266d561d6ab4b06c7a14adb0f0b30002997f076f71c8f8ac93c98210330d6c9371b561d2b961a5987d336c0186a9c5dacd6ed4551420b5977e46a29b453aec56cab0700000000d15c080000000000fd4401483045022100ddac557978a45a9e973a46358e4993e67a2e50f5327e5e623872f146ab5843c102200bbf9db2b1859a809c9183a3a819d4e7e772599e9f1e2b19a30e9b255f5fb47401473044022055538dbc1a69c1af0e8eb933bb4b9c227dcb1256930909dbd29a341a66b2383c02201ddfd34587935f9c9cf1cd3104607e41948d0feaeb09438bea21f15b9a9aea9a01473044022072452c10a7a54e084f75d47bb05e5be40ab041edd5fd95c3af928c483ad9942402207421d82022b8b1001dc6612811bf06803f2bb6304d89ddaeaaf6b2cafdf9dc2b014c69532102bc2a9206d10e5d5173583cbafebc78998745abeca13ed33151c93afbd850ca8e2103c995ce342de266d561d6ab4b06c7a14adb0f0b30002997f076f71c8f8ac93c98210330d6c9371b561d2b961a5987d336c0186a9c5dacd6ed4551420b5977e46a29b453ae")))
	if err != nil {
		return err
	}
	prevOutScript := tx.TxOut[0].PkScript

	var source sigDataSource
	source.key = func(addr dcrutil.Address) ([]byte, dcrec.SignatureType, bool, error) {
		serializedPriv, err := addrPrivKey.SerializedPrivKey()
		if err != nil {
			return nil, dcrec.STEcdsaSecp256k1, false, err
		}
		key := secp256k1.PrivKeyFromBytes(serializedPriv)
		return key.Serialize(), dcrec.STEcdsaSecp256k1, true, nil
	}
	source.script = func(addr dcrutil.Address) ([]byte, error) {
		return nil, fmt.Errorf("oops")
	}
	txIn = mtx.TxIn[0]
	script, err := txscript.SignTxOutput(params,
		mtx, 0, prevOutScript, txscript.SigHashAll, source, source, txIn.SignatureScript, true) // Yes treasury
	if err != nil {
		return err
	}
	txIn.SignatureScript = script

	// Return the serialized and hex-encoded transaction.
	sb := new(strings.Builder)
	err = mtx.Serialize(hex.NewEncoder(sb))
	if err != nil {
		return err
	}
	fmt.Println(sb.String())

	return nil
}

type sigDataSource struct {
	key    func(dcrutil.Address) ([]byte, dcrec.SignatureType, bool, error)
	script func(dcrutil.Address) ([]byte, error)
}

func (s sigDataSource) GetKey(a dcrutil.Address) ([]byte, dcrec.SignatureType, bool, error) {
	return s.key(a)
}
func (s sigDataSource) GetScript(a dcrutil.Address) ([]byte, error) { return s.script(a) }

// done returns whether the context's Done channel was closed due to
// cancellation or exceeded deadline.
func done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// run is the main startup and teardown logic performed by the main package.  It
// is responsible for parsing the config, starting RPC servers, loading and
// syncing the wallet (if necessary), and stopping all started services when the
// context is cancelled.
func run(ctx context.Context) error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig(ctx)
	if err != nil {
		return err
	}
	cfg = tcfg
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Show version at startup.
	log.Infof("Version %s (Go version %s %s/%s)", version.String(), runtime.Version(),
		runtime.GOOS, runtime.GOARCH)
	if cfg.NoFileLogging {
		log.Info("File logging disabled")
	}

	// Read IPC messages from the read end of a pipe created and passed by the
	// parent process, if any.  When this pipe is closed, shutdown is
	// initialized.
	if cfg.PipeRx != nil {
		go serviceControlPipeRx(uintptr(*cfg.PipeRx))
	}
	if cfg.PipeTx != nil {
		go serviceControlPipeTx(uintptr(*cfg.PipeTx))
	} else {
		go drainOutgoingPipeMessages()
	}

	// Run the pprof profiler if enabled.
	if len(cfg.Profile) > 0 {
		if done(ctx) {
			return ctx.Err()
		}

		profileRedirect := http.RedirectHandler("/debug/pprof", http.StatusSeeOther)
		http.Handle("/", profileRedirect)
		for _, listenAddr := range cfg.Profile {
			listenAddr := listenAddr // copy for closure
			go func() {
				log.Infof("Starting profile server on %s", listenAddr)
				err := http.ListenAndServe(listenAddr, nil)
				if err != nil {
					fatalf("Unable to run profiler: %v", err)
				}
			}()
		}
	}

	// Write mem profile if requested.
	if cfg.MemProfile != "" {
		if done(ctx) {
			return ctx.Err()
		}

		f, err := os.Create(cfg.MemProfile)
		if err != nil {
			log.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		timer := time.NewTimer(time.Minute * 5) // 5 minutes
		go func() {
			<-timer.C
			pprof.WriteHeapProfile(f)
			f.Close()
		}()
	}

	if done(ctx) {
		return ctx.Err()
	}

	// Create the loader which is used to load and unload the wallet.  If
	// --noinitialload is not set, this function is responsible for loading the
	// wallet.  Otherwise, loading is deferred so it can be performed over RPC.
	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	stakeOptions := &ldr.StakeOptions{
		VotingEnabled:       cfg.EnableVoting,
		VotingAddress:       cfg.TBOpts.votingAddress,
		PoolAddress:         cfg.poolAddress,
		PoolFees:            cfg.PoolFees,
		StakePoolColdExtKey: cfg.StakePoolColdExtKey,
	}
	loader := ldr.NewLoader(activeNet.Params, dbDir, stakeOptions,
		cfg.GapLimit, cfg.AllowHighFees, cfg.RelayFee.Amount,
		cfg.AccountGapLimit, cfg.DisableCoinTypeUpgrades, cfg.ManualTickets)
	loader.DialCSPPServer = cfg.dialCSPPServer

	// Stop any services started by the loader after the shutdown procedure is
	// initialized and this function returns.
	defer func() {
		// When panicing, do not cleanly unload the wallet (by closing
		// the db).  If a panic occured inside a bolt transaction, the
		// db mutex is still held and this causes a deadlock.
		if r := recover(); r != nil {
			panic(r)
		}
		err := loader.UnloadWallet()
		if err != nil && !errors.Is(err, errors.Invalid) {
			log.Errorf("Failed to close wallet: %v", err)
		} else if err == nil {
			log.Infof("Closed wallet")
		}
	}()

	// Open the wallet when --noinitialload was not set.
	var vspClient *vsp.Client
	passphrase := []byte{}
	if !cfg.NoInitialLoad {
		walletPass := []byte(cfg.WalletPass)
		if cfg.PromptPublicPass {
			walletPass, _ = passPrompt(ctx, "Enter public wallet passphrase", false)
		}

		if done(ctx) {
			return ctx.Err()
		}

		// Load the wallet.  It must have been created already or this will
		// return an appropriate error.
		var w *wallet.Wallet
		errc := make(chan error, 1)
		go func() {
			defer zero(walletPass)
			var err error
			w, err = loader.OpenExistingWallet(ctx, walletPass)
			if err != nil {
				log.Errorf("Failed to open wallet: %v", err)
				if errors.Is(err, errors.Passphrase) {
					// walletpass not provided, advice using --walletpass or --promptpublicpass
					if cfg.WalletPass == wallet.InsecurePubPassphrase {
						log.Info("Configure public passphrase with walletpass or promptpublicpass options.")
					}
				}
			}
			errc <- err
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			if err != nil {
				return err
			}
		}

		// TODO(jrick): I think that this prompt should be removed
		// entirely instead of enabling it when --noinitialload is
		// unset.  It can be replaced with an RPC request (either
		// providing the private passphrase as a parameter, or require
		// unlocking the wallet first) to trigger a full accounts
		// rescan.
		//
		// Until then, since --noinitialload users are expecting to use
		// the wallet only over RPC, disable this feature for them.
		if cfg.Pass != "" {
			passphrase = []byte(cfg.Pass)
			err = w.Unlock(ctx, passphrase, nil)
			if err != nil {
				log.Errorf("Incorrect passphrase in pass config setting.")
				return err
			}
		} else {
			passphrase = startPromptPass(ctx, w)
		}

		if cfg.EnableTicketBuyer && cfg.VSPOpts.URL != "" {
			changeAccountName := cfg.ChangeAccount
			if changeAccountName == "" && cfg.CSPPServer == "" {
				log.Warnf("Change account not set, using "+
					"purchase account %q", cfg.PurchaseAccount)
				changeAccountName = cfg.PurchaseAccount
			}
			changeAcct, err := w.AccountNumber(ctx, changeAccountName)
			if err != nil {
				log.Warnf("failed to get account number for "+
					"ticket change account %q: %v",
					changeAccountName, err)
				return err
			}
			purchaseAcct, err := w.AccountNumber(ctx, cfg.PurchaseAccount)
			if err != nil {
				log.Warnf("failed to get account number for "+
					"ticket purchase account %q: %v",
					cfg.PurchaseAccount, err)
				return err
			}
			vspCfg := vsp.Config{
				URL:    cfg.VSPOpts.URL,
				PubKey: cfg.VSPOpts.PubKey,
				Dialer: cfg.dial,
				Wallet: w,
				Policy: vsp.Policy{
					MaxFee:     cfg.VSPOpts.MaxFee.Amount,
					FeeAcct:    purchaseAcct,
					ChangeAcct: changeAcct,
				},
			}
			vspClient, err = ldr.VSP(vspCfg)
			if err != nil {
				log.Errorf("vsp: %v", err)
				return err
			}
		}

		var tb *ticketbuyer.TB
		if cfg.MixChange || cfg.EnableTicketBuyer {
			tb = ticketbuyer.New(w)
		}

		var lastFlag, lastLookup string
		lookup := func(flag, name string) (account uint32) {
			if tb != nil && err == nil {
				lastFlag = flag
				lastLookup = name
				account, err = w.AccountNumber(ctx, name)
			}
			return
		}
		var (
			purchaseAccount    uint32 // enableticketbuyer
			votingAccount      uint32 // enableticketbuyer
			mixedAccount       uint32 // (enableticketbuyer && csppserver) || mixchange
			changeAccount      uint32 // (enableticketbuyer && csppserver) || mixchange
			ticketSplitAccount uint32 // enableticketbuyer && csppserver

			votingAddr  = cfg.TBOpts.votingAddress
			poolFeeAddr = cfg.poolAddress
		)
		if cfg.EnableTicketBuyer {
			purchaseAccount = lookup("purchaseaccount", cfg.PurchaseAccount)
			if cfg.CSPPServer != "" {
				poolFeeAddr = nil
			}
			if cfg.CSPPServer != "" && cfg.TBOpts.VotingAccount == "" {
				err := errors.New("cannot run mixed ticketbuyer without --votingaccount")
				log.Error(err)
				return err
			}
			if cfg.TBOpts.VotingAccount != "" {
				votingAccount = lookup("ticketbuyer.votingaccount", cfg.TBOpts.VotingAccount)
				votingAddr = nil
			}
		}
		if (cfg.EnableTicketBuyer && cfg.CSPPServer != "") || cfg.MixChange {
			mixedAccount = lookup("mixedaccount", cfg.mixedAccount)
			changeAccount = lookup("changeaccount", cfg.ChangeAccount)
		}
		if cfg.EnableTicketBuyer && cfg.CSPPServer != "" {
			ticketSplitAccount = lookup("ticketsplitaccount", cfg.TicketSplitAccount)
		}
		if err != nil {
			log.Errorf("%s: account %q does not exist", lastFlag, lastLookup)
			return err
		}

		if tb != nil {
			// Start a ticket buyer.
			tb.AccessConfig(func(c *ticketbuyer.Config) {
				c.BuyTickets = cfg.EnableTicketBuyer
				c.Account = purchaseAccount
				c.Maintain = cfg.TBOpts.BalanceToMaintainAbsolute.Amount
				c.VotingAddr = votingAddr
				c.PoolFeeAddr = poolFeeAddr
				c.Limit = int(cfg.TBOpts.Limit)
				c.VotingAccount = votingAccount
				c.CSPPServer = cfg.CSPPServer
				c.DialCSPPServer = cfg.dialCSPPServer
				c.MixChange = cfg.MixChange
				c.MixedAccount = mixedAccount
				c.MixedAccountBranch = cfg.mixedBranch
				c.TicketSplitAccount = ticketSplitAccount
				c.ChangeAccount = changeAccount
				c.VSP = vspClient
			})
			log.Infof("Starting auto transaction creator")
			tbdone := make(chan struct{})
			go func() {
				err := tb.Run(ctx, passphrase)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Errorf("Transaction creator ended: %v", err)
				}
				tbdone <- struct{}{}
			}()
			defer func() { <-tbdone }()
		}
	}

	if done(ctx) {
		return ctx.Err()
	}

	// Create and start the RPC servers to serve wallet client connections.  If
	// any of the servers can not be started, it will be nil.  If none of them
	// can be started, this errors since at least one server must run for the
	// wallet to be useful.
	//
	// Servers will be associated with a loaded wallet if it has already been
	// loaded, or after it is loaded later on.
	gRPCServer, jsonRPCServer, err := startRPCServers(loader)
	if err != nil {
		log.Errorf("Unable to create RPC servers: %v", err)
		return err
	}
	if gRPCServer != nil {
		// Start wallet, voting and network gRPC services after a
		// wallet is loaded.
		loader.RunAfterLoad(func(w *wallet.Wallet) {
			rpcserver.StartWalletService(gRPCServer, w, cfg.dialCSPPServer)
			rpcserver.StartNetworkService(gRPCServer, w)
			rpcserver.StartVotingService(gRPCServer, w)
		})
		defer func() {
			log.Warn("Stopping gRPC server...")
			gRPCServer.Stop()
			log.Info("gRPC server shutdown")
		}()
	}
	if jsonRPCServer != nil {
		go func() {
			for range jsonRPCServer.RequestProcessShutdown() {
				requestShutdown()
			}
		}()
		defer func() {
			log.Warn("Stopping JSON-RPC server...")
			jsonRPCServer.Stop()
			log.Info("JSON-RPC server shutdown")
		}()
	}

	// When not running with --noinitialload, it is the main package's
	// responsibility to synchronize the wallet with the network through SPV or
	// the trusted dcrd server.  This blocks until cancelled.
	if !cfg.NoInitialLoad {
		if done(ctx) {
			return ctx.Err()
		}

		loader.RunAfterLoad(func(w *wallet.Wallet) {
			if cfg.VSPOpts.Sync {
				vspClient.ProcessManagedTickets(ctx, vspClient.Policy)
			}

			if cfg.SPV {
				spvLoop(ctx, w)
			} else {
				rpcSyncLoop(ctx, w)
			}
		})
	}

	// Wait until shutdown is signaled before returning and running deferred
	// shutdown tasks.
	<-ctx.Done()
	return ctx.Err()
}

func passPrompt(ctx context.Context, prefix string, confirm bool) (passphrase []byte, err error) {
	os.Stdout.Sync()
	c := make(chan struct{}, 1)
	go func() {
		passphrase, err = prompt.PassPrompt(bufio.NewReader(os.Stdin), prefix, confirm)
		c <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c:
		return passphrase, err
	}
}

// startPromptPass prompts the user for a password to unlock their wallet in
// the event that it was restored from seed or --promptpass flag is set.
func startPromptPass(ctx context.Context, w *wallet.Wallet) []byte {
	promptPass := cfg.PromptPass

	// Watching only wallets never require a password.
	if w.WatchingOnly() {
		return nil
	}

	// The wallet is totally desynced, so we need to resync accounts.
	// Prompt for the password. Then, set the flag it wallet so it
	// knows which address functions to call when resyncing.
	needSync, err := w.NeedsAccountsSync(ctx)
	if err != nil {
		log.Errorf("Error determining whether an accounts sync is necessary: %v", err)
	}
	if err == nil && needSync {
		fmt.Println("*** ATTENTION ***")
		fmt.Println("Since this is your first time running we need to sync accounts. Please enter")
		fmt.Println("the private wallet passphrase. This will complete syncing of the wallet")
		fmt.Println("accounts and then leave your wallet unlocked. You may relock wallet after by")
		fmt.Println("calling 'walletlock' through the RPC.")
		fmt.Println("*****************")
		promptPass = true
	}
	if cfg.EnableTicketBuyer {
		promptPass = true
	}

	if !promptPass {
		return nil
	}

	// We need to rescan accounts for the initial sync. Unlock the
	// wallet after prompting for the passphrase. The special case
	// of a --createtemp simnet wallet is handled by first
	// attempting to automatically open it with the default
	// passphrase. The wallet should also request to be unlocked
	// if stake mining is currently on, so users with this flag
	// are prompted here as well.
	for {
		if w.ChainParams().Net == wire.SimNet {
			err := w.Unlock(ctx, wallet.SimulationPassphrase, nil)
			if err == nil {
				// Unlock success with the default password.
				return wallet.SimulationPassphrase
			}
		}

		passphrase, err := passPrompt(ctx, "Enter private passphrase", false)
		if err != nil {
			return nil
		}

		err = w.Unlock(ctx, passphrase, nil)
		if err != nil {
			fmt.Println("Incorrect password entered. Please " +
				"try again.")
			continue
		}
		return passphrase
	}
}

func spvLoop(ctx context.Context, w *wallet.Wallet) {
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	amgrDir := filepath.Join(cfg.AppDataDir.Value, w.ChainParams().Name)
	amgr := addrmgr.New(amgrDir, cfg.lookup)
	lp := p2p.NewLocalPeer(w.ChainParams(), addr, amgr)
	syncer := spv.NewSyncer(w, lp)
	if len(cfg.SPVConnect) > 0 {
		syncer.SetPersistentPeers(cfg.SPVConnect)
	}
	w.SetNetworkBackend(syncer)
	for {
		err := syncer.Run(ctx)
		if done(ctx) {
			return
		}
		log.Errorf("SPV synchronization ended: %v", err)
	}
}

// rpcSyncLoop loops forever, attempting to create a connection to the
// consensus RPC server.  If this connection succeeds, the RPC client is used as
// the loaded wallet's network backend and used to keep the wallet synchronized
// to the network.  If/when the RPC connection is lost, the wallet is
// disassociated from the client and a new connection is attempmted.
func rpcSyncLoop(ctx context.Context, w *wallet.Wallet) {
	certs := readCAFile()
	dial := cfg.dial
	if cfg.NoDcrdProxy {
		dial = new(net.Dialer).DialContext
	}
	for {
		syncer := chain.NewSyncer(w, &chain.RPCOptions{
			Address:     cfg.RPCConnect,
			DefaultPort: activeNet.JSONRPCClientPort,
			User:        cfg.DcrdUsername,
			Pass:        cfg.DcrdPassword,
			Dial:        dial,
			CA:          certs,
			Insecure:    cfg.DisableClientTLS,
		})
		err := syncer.Run(ctx)
		if err != nil {
			syncLog.Errorf("Wallet synchronization stopped: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func readCAFile() []byte {
	// Read certificate file if TLS is not disabled.
	var certs []byte
	if !cfg.DisableClientTLS {
		var err error
		certs, err = ioutil.ReadFile(cfg.CAFile.Value)
		if err != nil {
			log.Warnf("Cannot open CA file: %v", err)
			// If there's an error reading the CA file, continue
			// with nil certs and without the client connection.
			certs = nil
		}
	} else {
		log.Info("Chain server RPC TLS is disabled")
	}

	return certs
}
