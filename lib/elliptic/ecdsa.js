var assert = require('assert');
var elliptic = require('../elliptic');

function ECDSA(options) {
  this.curve = options.curve;
  // Point on curve
  this.g = options.g;
  this.g.precompute(options.n.bitLength());
  // Order of the point
  this.n = options.n;
  // Co-factor
  this.h = options.h;
}
module.exports = ECDSA;

ECDSA.prototype.genKeyPair = function genKeyPair() {
  var priv = elliptic.rand(1, this.n);
  return {
    priv: priv,
    pub: this.g.mul(priv)
  };
};

ECDSA.prototype.sign = function sign(msg, key) {
  msg = new elliptic.bn(msg, 16);
  key = new elliptic.bn(key, 16);
  assert(msg.bitLength() < this.n.bitLength(),
         'Message is too big for this curve');

  var drbg = new elliptic.hmacDRBG(msg, key);
  do {
    var k = drbg.get(this.n);
    if (k.cmp(0) === 0)
      continue;

    var kp = this.g.mul(k);
    if (kp.isInfinity())
      continue;

    var r = kp.getX().mod(this.n);
    if (r.cmp(0) === 0)
      continue;

    var s = k.invm(this.n).mul(msg.add(r.mul(key))).mod(this.n);
    if (s.cmp(0) === 0)
      continue;

    return { r: r, s: s };
  } while (true);
};

ECDSA.prototype.validateKey = function validateKey(key) {
  assert(typeof key === 'object' && key.x && key.y);
  key = this.curve.point(key.x, key.y);

  if (key.isInfinity())
    return { result: false, reason: 'Invalid key' };
  if (!key.validate())
    return { result: false, reason: 'Key is not a point' };
  if (!key.mul(this.n).isInfinity())
    return { result: false, reason: 'Key*N != O' };

  return { result: true, reason: null };
};

ECDSA.prototype.verify = function verify(msg, signature, key) {
  msg = new elliptic.bn(msg, 16);
  assert(msg.bitLength() < this.n.bitLength(),
         'Message is too big for this curve');

  assert(typeof key === 'object' && key.x && key.y);
  key = this.curve.point(key.x, key.y);

  assert(typeof signature === 'object' && signature.r && signature.s);
  var r = new elliptic.bn(signature.r, 16);
  var s = new elliptic.bn(signature.s, 16);
  if (r.cmp(1) < 0 || r.cmp(this.n) >= 0)
    return false;
  if (s.cmp(1) < 0 || s.cmp(this.n) >= 0)
    return false;

  var sinv = s.invm(this.n);
  var u1 = sinv.mul(msg).mod(this.n);
  var u2 = sinv.mul(r).mod(this.n);

  var p = this.g.mul(u1).add(key.mul(u2));
  if (p.isInfinity())
    return false;

  return p.getX().mod(this.n).cmp(r) === 0;
};