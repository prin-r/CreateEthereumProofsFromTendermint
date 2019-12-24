package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

var cdc = codec.New()

type proofInnerNode struct {
	Height  int8   `json:"height"`
	Size    int64  `json:"size"`
	Version int64  `json:"version"`
	Left    []byte `json:"left"`
	Right   []byte `json:"right"`
}

type Leave struct {
	Key       []byte `json:"key"`
	ValueHash []byte `json:"value"`
	Version   int64  `json:"version"`
}

type IAVLValueOp struct {
	key          []byte
	rootVerified bool
	rootHash     []byte
	treeEnd      bool

	Proof *struct {
		LeftPath   []proofInnerNode   `json:"left_path"`
		InnerNodes [][]proofInnerNode `json:"inner_nodes"`
		Leaves     []Leave            `json:"leaves"`
	} `json:"proof"`
}

type MultiStoreProofOp struct {
	// Encoded in ProofOp.Key
	key []byte

	// To encode in ProofOp.Data.
	Proof *struct {
		StoreInfos []struct {
			Name string
			Core struct {
				CommitID struct {
					Version int64
					Hash    []byte
				}
			}
		}
	} `json:"proof"`
}

func (mspo MultiStoreProofOp) getHashesDict() map[string][]byte {
	m := map[string][]byte{}
	for _, si := range mspo.Proof.StoreInfos {
		m[si.Name] = tmhash.Sum(tmhash.Sum(si.Core.CommitID.Hash))
	}
	return m
}

func (mspo MultiStoreProofOp) getSortedHashes(without string) [][]byte {
	m := mspo.getHashesDict()
	keys := []string{}
	for k := range m {
		if k != without {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	bs := [][]byte{}
	for _, k := range keys {
		bs = append(bs, m[k])
	}
	return bs
}

func (mspo MultiStoreProofOp) String() string {
	m := mspo.getHashesDict()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s := "\n"
	for _, k := range keys {
		s += fmt.Sprintf("%s : 0x%x\n", k, m[k])
	}
	return s
}

type Op struct {
	Type string `json:"type"`
	Key  string `json:"key"`
	Data string `json:"data"`
}

type Proof struct {
	Ops []Op `json:"ops"`
}

type LeafAndProof struct {
	Code      int    `json:"code"`
	Log       string `json:"log"`
	Info      string `json:"info"`
	Index     string `json:"index"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Proof     Proof  `json:"proof"`
	Height    string `json:"height"`
	Codespace string `json:"codespace"`
}

type Response struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      string `json:"id"`
	Result  struct {
		Lap LeafAndProof `json:"response"`
	} `json:"result"`
}

type IAVLMerklePath struct {
	IsDataOnRight  bool   `json:"isdataonright"`
	SubtreeHeight  string `json:"subtreeheight"`
	SubtreeSize    string `json:"subtreesize"`
	SubtreeVersion string `json:"subtreeversion"`
	SiblingHash    string `json:"siblinghash"`
}

type AppHashProof struct {
	Height    uint64          `json:"height"`
	RequestID string          `json:"key"`
	Data      string          `json:"value"`
	Version   string          `json:"version"`
	Paths     [][]interface{} `json:"Path"`
}

type AllProof struct {
	AppHashProof AppHashProof `json:"app_hash_proof"`
	BlockProof   BlockProof   `json:"block_proof"`
	Data         string       `json:"data"`
	Proof        string       `json:"proof"`
}

const s248 = "452312848583266388373324160190187140051835877600158453279131187530910662656"

func base64ToBytes(s string) []byte {
	b64, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b64
}

func concatPrefixes(ps []byte, isRight bool) *big.Int {
	c := big.NewInt(0)
	extraInfo := big.NewInt(int64(len(ps)))
	for i, p := range ps {
		c.Add(c, big.NewInt(int64(p)))
		if i != len(ps)-1 {
			c.Mul(c, big.NewInt(int64(256)))
		}
	}
	if isRight {
		extraInfo.Add(extraInfo, big.NewInt(int64(128)))
	}
	tp248, _ := new(big.Int).SetString(s248, 10)
	extraInfo.Mul(extraInfo, tp248)
	c.Add(c, extraInfo)
	return c
}

func (leave Leave) Prefix() *big.Int {
	buf := new(bytes.Buffer)

	err := amino.EncodeInt8(buf, 0)
	if err == nil {
		err = amino.EncodeVarint(buf, 1)
	}
	if err == nil {
		err = amino.EncodeVarint(buf, leave.Version)
	}

	return concatPrefixes(buf.Bytes(), false)
}

func (pin proofInnerNode) Prefix() *big.Int {
	buf := new(bytes.Buffer)

	err := amino.EncodeInt8(buf, pin.Height)
	if err == nil {
		err = amino.EncodeVarint(buf, pin.Size)
	}
	if err == nil {
		err = amino.EncodeVarint(buf, pin.Version)
	}

	if err != nil {
		panic(fmt.Sprintf("Failed to hash proofInnerNode: %v", err))
	}

	return concatPrefixes(buf.Bytes(), len(pin.Right) == 0)
}

func _getAppHashProof(reqId uint64) (LeafAndProof, error) {
	_resp, err := http.Get(
		fmt.Sprintf(
			`%s/abci_query?path="/store/zoracle/key"&data=0x01%016x&prove=true`,
			strings.Replace(nodeURI, "tcp", "http", 1),
			reqId,
		))
	if err != nil {
		return LeafAndProof{}, err
	}
	defer _resp.Body.Close()

	var resp Response
	json.NewDecoder(_resp.Body).Decode(&resp)

	return resp.Result.Lap, nil
}

func getMSHashPair(m [][]byte) []byte {
	h1 := tmhash.Sum(
		append(
			[]byte{1},
			append(
				tmhash.Sum(append([]byte{0}, append(append([]byte{3}, []byte("acc")...), append([]byte{32}, m[0]...)...)...)),
				tmhash.Sum(append([]byte{0}, append(append([]byte{12}, []byte("distribution")...), append([]byte{32}, m[1]...)...)...))...,
			)...,
		),
	)

	h2 := tmhash.Sum(
		append(
			[]byte{1},
			append(
				tmhash.Sum(append([]byte{0}, append(append([]byte{3}, []byte("gov")...), append([]byte{32}, m[2]...)...)...)),
				tmhash.Sum(append([]byte{0}, append(append([]byte{4}, []byte("main")...), append([]byte{32}, m[3]...)...)...))...,
			)...,
		),
	)

	h3 := tmhash.Sum(
		append(
			[]byte{1},
			append(
				tmhash.Sum(append([]byte{0}, append(append([]byte{6}, []byte("params")...), append([]byte{32}, m[4]...)...)...)),
				tmhash.Sum(append([]byte{0}, append(append([]byte{8}, []byte("slashing")...), append([]byte{32}, m[5]...)...)...))...,
			)...,
		),
	)

	h4 := tmhash.Sum(
		append(
			[]byte{1},
			append(
				tmhash.Sum(append([]byte{0}, append(append([]byte{7}, []byte("staking")...), append([]byte{32}, m[6]...)...)...)),
				tmhash.Sum(append([]byte{0}, append(append([]byte{6}, []byte("supply")...), append([]byte{32}, m[7]...)...)...))...,
			)...,
		),
	)

	h5 := tmhash.Sum(append([]byte{1}, append(h1, h2...)...))

	h6 := tmhash.Sum(append([]byte{1}, append(h3, h4...)...))

	h7 := tmhash.Sum(append([]byte{1}, append(h5, h6...)...))

	return h7
}

func generateProofForETH(lap LeafAndProof) (AppHashProof, string, error) {
	ahp := AppHashProof{}
	key := fmt.Sprintf("0x%x", base64ToBytes(lap.Key)[1:])
	value := fmt.Sprintf("0x%x", base64ToBytes(lap.Value))

	height, err := strconv.ParseUint(lap.Height, 10, 64)
	if err != nil {
		return AppHashProof{}, "", err
	}

	ahp.Height = height + 1
	ahp.RequestID = key
	ahp.Data = value
	ahp.Paths = []([]interface{}){}

	var opiavl IAVLValueOp
	err = cdc.UnmarshalBinaryLengthPrefixed(base64ToBytes(lap.Proof.Ops[0].Data), &opiavl)
	if err != nil {
		return AppHashProof{}, "", err
	}

	spew.Dump(opiavl)

	ahp.Version = fmt.Sprintf("%d", opiavl.Proof.Leaves[0].Version)

	for i := len(opiavl.Proof.LeftPath) - 1; i >= 0; i-- {
		p := opiavl.Proof.LeftPath[i]
		imp := IAVLMerklePath{}
		imp.SubtreeHeight = fmt.Sprintf("%d", p.Height)
		imp.SubtreeSize = fmt.Sprintf("%d", p.Size)
		imp.SubtreeVersion = fmt.Sprintf("%d", p.Version)
		if len(p.Right) == 0 {
			imp.SiblingHash = fmt.Sprintf("0x%x", p.Left)
			imp.IsDataOnRight = true
		} else {
			imp.SiblingHash = fmt.Sprintf("0x%x", p.Right)
			imp.IsDataOnRight = false
		}
		ahp.Paths = append(ahp.Paths, []interface{}{
			imp.IsDataOnRight,
			imp.SubtreeHeight,
			imp.SubtreeSize,
			imp.SubtreeVersion,
			imp.SiblingHash,
		})
	}

	var opms MultiStoreProofOp
	err = cdc.UnmarshalBinaryLengthPrefixed(base64ToBytes(lap.Proof.Ops[1].Data), &opms)
	if err != nil {
		return AppHashProof{}, "", err
	}

	spew.Dump(opms)

	h7 := getMSHashPair(opms.getSortedHashes("zoracle"))

	return ahp, fmt.Sprintf("0x%x", h7), nil
}

func EncodeTest() ([]byte, error) {
	var args abi.Arguments
	const sig = `[{"type": "bytes"}, {"type": "bytes"}, {"type": "uint256"}]`

	dec := json.NewDecoder(strings.NewReader(sig))
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}

	return args.Pack([]byte("123"), []byte("123"), big.NewInt(123))
}

func getAppProofData(
	_appHash string, //bytes32
	_encodedHeight string,
	_others []string, // bytes32[]
	_leftMsg string,
	_rightMsg string,
	_signatures string,
) ([]byte, error) {
	var args abi.Arguments
	dec := json.NewDecoder(strings.NewReader(`[{"type": "bytes32"},{"type": "bytes"},{"type": "bytes32[]"},{"type": "bytes"},{"type": "bytes"},{"type": "bytes"}]`))
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}

	others := []common.Hash{}
	for _, other := range _others {
		others = append(others, common.HexToHash(other))
	}

	return args.Pack(
		common.HexToHash(_appHash),
		common.FromHex(_encodedHeight),
		others,
		common.FromHex(_leftMsg),
		common.FromHex(_rightMsg),
		common.FromHex(_signatures),
	)
}

func getStoreProofData(
	_prefixes []string, //uint256[]
	_path []string, // bytes32[]
	_otherMSHashes string, // bytes32
	_key string,
	value string,
	_blockHeight string,
) ([]byte, error) {
	var args abi.Arguments
	dec := json.NewDecoder(strings.NewReader(`[{"type": "uint256[]"},{"type": "bytes32[]"},{"type": "bytes32"},{"type": "uint64"}]`))
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}

	prefixes := []*big.Int{}
	for _, prefix := range _prefixes {
		bn, _ := new(big.Int).SetString(prefix, 10)
		prefixes = append(prefixes, bn)
	}
	path := []common.Hash{}
	for _, edge := range _path {
		path = append(path, common.HexToHash(edge))
	}

	key, err := strconv.ParseUint(_key[2:], 16, 64)
	if err != nil {
		return nil, err
	}
	return args.Pack(
		prefixes,
		path,
		common.HexToHash(_otherMSHashes),
		key,
	)
}

func GetProof(reqId uint64, pk string) (AllProof, error) {
	lap, err := _getAppHashProof(reqId)
	if err != nil {
		return AllProof{}, err
	}

	ahp, osmh, err := generateProofForETH(lap)
	if err != nil {
		return AllProof{}, err
	}

	ap := AllProof{}
	ap.AppHashProof = ahp

	// params is height and privateKey
	bp, err := GetBlockProof(ahp.Height, pk)
	for i := 0; i < 50; i++ {
		bp, err = GetBlockProof(ahp.Height, pk)
		if err != nil {
			fmt.Println("=-=-=-=-=-=-=-=-=", err.Error())
			time.Sleep(time.Second)
		} else {
			break
		}
	}
	if err != nil {
		return AllProof{}, err
	}

	fmt.Println("………………………………………………………………………………………………………………")

	bp.OtherStoresMerkleHash = osmh

	ap.BlockProof = bp

	// args := abi.Arguments{}
	// dec := json.NewDecoder(strings.NewReader(`[{"type": "bytes"},{"type": "bytes"}]`))
	// if err := dec.Decode(&args); err != nil {
	// 	return AllProof{}, err
	// }

	// p3, _ := args.Pack(p1, p2)

	//ap.Data = ahp.Value
	//ap.Proof = fmt.Sprintf("0x%x", p3)

	return ap, nil
}
