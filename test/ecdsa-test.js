var assert = require('assert');
var elliptic = require('../');
var Signature = require('../lib/elliptic/ec/signature')
var BN = require('bn.js');
var hash = require('hash.js');

var entropy = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25
];

var msg = 'deadbeef';

describe('ECDSA', function() {
  function test(name) {
    describe('curve ' + name, function() {
      var curve;
      var ecdsa;

      beforeEach(function() {
        curve = elliptic.curves[name];
        assert(curve);

        ecdsa = new elliptic.ec(curve);
        keys = ecdsa.genKeyPair({
          entropy: entropy
        });
      });

      it('should generate proper key pair', function() {
        var keylen = 64;
        if (name === 'p384') {
          keylen = 96;
        } else if (name === 'p521') {
          keylen = 132
        }
        // Get keys out of pair
        assert(keys.getPublic().x && keys.getPublic().y);
        assert(keys.getPrivate().length > 0);
        assert.equal(keys.getPrivate('hex').length, keylen);
        assert(keys.getPublic('hex').length > 0);
        assert(keys.getPrivate('hex').length > 0);
        assert(keys.validate().result);
      });

      it('should sign and verify', function() {
        var signature = ecdsa.sign(msg, keys);
        assert(ecdsa.verify(msg, signature, keys), 'Normal verify');
      });

      it('should sign and verify using key\'s methods', function() {
        var signature = keys.sign(msg);
        assert(keys.verify(msg, signature), 'On-key verify');
      });

      it('should load private key from the hex value', function() {
        var copy = ecdsa.keyFromPrivate(keys.getPrivate('hex'), 'hex');
        var signature = ecdsa.sign(msg, copy);
        assert(ecdsa.verify(msg, signature, copy), 'hex-private verify');
      });

      it('should have `signature.s <= keys.ec.nh`', function() {
        // key.sign(msg, options)
        var sign = keys.sign('fefefe', { canonical: true });
        assert(sign.s.cmp(keys.ec.nh) <= 0);
      });

      it('should support `options.k`', function() {
        var sign = keys.sign(msg, {
          k: function(iter) {
            assert(iter >= 0);
            return new BN(1358);
          }
        });
        assert(ecdsa.verify(msg, sign, keys), 'custom-k verify');
      });

      it('should have another signature with pers', function () {
        var sign1 = keys.sign(msg);
        var sign2 = keys.sign(msg, { pers: '1234', persEnc: 'hex' });
        assert.notEqual(sign1.r.toArray().concat(sign1.s.toArray()),
                        sign2.r.toArray().concat(sign2.s.toArray()));
      });

      it('should load public key from compact hex value', function() {
        var pub = keys.getPublic(true, 'hex');
        var copy = ecdsa.keyFromPublic(pub, 'hex');
        assert.equal(copy.getPublic(true, 'hex'), pub);
      });

      it('should load public key from hex value', function() {
        var pub = keys.getPublic('hex');
        var copy = ecdsa.keyFromPublic(pub, 'hex');
        assert.equal(copy.getPublic('hex'), pub);
      });

      it('should support hex DER encoding of signatures', function() {
        var signature = ecdsa.sign(msg, keys);
        var dsign = signature.toDER('hex');
        assert(ecdsa.verify(msg, dsign, keys), 'hex-DER encoded verify');
      });

      it('should support DER encoding of signatures', function() {
        var signature = ecdsa.sign(msg, keys);
        var dsign = signature.toDER();
        assert(ecdsa.verify(msg, dsign, keys), 'DER encoded verify');
      });

      it('should not verify signature with wrong public key', function() {
        var signature = ecdsa.sign(msg, keys);

        var wrong = ecdsa.genKeyPair();
        assert(!ecdsa.verify(msg, signature, wrong), 'Wrong key verify');
      });

      it('should not verify signature with wrong private key', function() {
        var signature = ecdsa.sign(msg, keys);

        var wrong = ecdsa.keyFromPrivate(keys.getPrivate('hex') +
                                         keys.getPrivate('hex'));
        assert(!ecdsa.verify(msg, signature, wrong), 'Wrong key verify');
      });
    });
  }
  test('secp256k1');

  it('should deterministically generate private key', function() {
    var curve = elliptic.curves.secp256k1;
    assert(curve);

    var ecdsa = new elliptic.ec(curve);
    var keys = ecdsa.genKeyPair({
      pers: 'my.pers.string',
      entropy: hash.sha256().update('hello world').digest()
    });
    assert.equal(
      keys.getPrivate('hex'),
      '6160edb2b218b7f1394b9ca8eb65a72831032a1f2f3dc2d99291c2f7950ed887');
  });

  it('should recover the public key from a signature', function() {
    var ec = new elliptic.ec('secp256k1');
    var key = ec.genKeyPair();
    var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
    var signature = key.sign(msg);
    var recid = ec.getKeyRecoveryParam(msg, signature, key.getPublic());
    var r =  ec.recoverPubKey(msg, signature, recid);
    assert(key.getPublic().eq(r), 'the keys should match');
  });

  it('should fail to recover key when no quadratic residue available',
     function() {
    var ec = new elliptic.ec('secp256k1');

    var message =
        'f75c6b18a72fabc0f0b888c3da58e004f0af1fe14f7ca5d8c897fe164925d5e9';

    assert.throws(function() {
      ecdsa.recoverPubKey(message, {
        r: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        s: '8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3'
      }, 0);
    });
  });

  describe('Signature', function () {
    it('recoveryParam is 0', function () {
      var sig = new Signature({ r: '00', s: '00', recoveryParam: 0 });
      assert.equal(sig.recoveryParam, 0);
    });

    it('recoveryParam is 1', function () {
      var sig = new Signature({ r: '00', s: '00', recoveryParam: 1 });
      assert.equal(sig.recoveryParam, 1);
    });
  });
});
