package symmetric

import "math/big"

func XorDataWithKey(data []int, key *big.Int) []int {
	var xoredData []int
	for _, value := range data {
		v := new(big.Int)
		v.Xor(big.NewInt(int64(value)), key)
		xoredData = append(xoredData, int(v.Int64()))
	}
	return xoredData
}
