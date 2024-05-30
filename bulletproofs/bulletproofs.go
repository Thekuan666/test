package bulletproofs

import (
	"github.com/developerblockchain/zkrp/crypto/p256"
)

var ORDER = p256.CURVE.N
var SEEDH = "BulletproofsDoesNotNeedTrustedSetupH"
var MAX_RANGE_END int64 = 4294967296 // 2**32
var MAX_RANGE_END_EXPONENT = 32      // 2**32
