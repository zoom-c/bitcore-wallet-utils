'use strict';

var _ = require('lodash');
var Uuid = require('uuid');
var chai = require('chai');
var sinon = require('sinon');
var should = chai.should();
var Bitcore = require('bitcore');
var WalletUtils = require('../lib/walletutils');

var aText = 'hola';
var aPubKey = '03bec86ad4a8a91fe7c11ec06af27246ec55094db3d86098b7d8b2f12afe47627f';
var aPrivKey = '09458c090a69a38368975fb68115df2f4b0ab7d1bc463fc60c67aa1730641d6c';
var aSignature = '3045022100d6186930e4cd9984e3168e15535e2297988555838ad10126d6c20d4ac0e74eb502201095a6319ea0a0de1f1e5fb50f7bf10b8069de10e0083e23dbbf8de9b8e02785';

var otherPubKey = '02555a2d45e309c00cc8c5090b6ec533c6880ab2d3bc970b3943def989b3373f16';

var helpers = {};

helpers.toSatoshi = function(btc) {
  if (_.isArray(btc)) {
    return _.map(btc, helpers.toSatoshi);
  } else {
    return helpers.strip(btc * 1e8);
  }
};

helpers.strip = function(number) {
  return (parseFloat(number.toPrecision(12)));
}

// // Amounts in satoshis 
helpers.generateUtxos = function(publicKeyRing, path, requiredSignatures, amounts) {
  var amounts = [].concat(amounts);
  var utxos = _.map(amounts, function(amount, i) {

    var address = WalletUtils.deriveAddress(publicKeyRing, path, requiredSignatures, 'testnet');

    var obj = {
      txid: Bitcore.crypto.Hash.sha256(new Buffer(i)).toString('hex'),
      vout: 100,
      satoshis: helpers.toSatoshi(amount),
      scriptPubKey: Bitcore.Script.buildMultisigOut(address.publicKeys, requiredSignatures).toScriptHashOut().toBuffer().toString('hex'),
      address: address.address,
      path: path,
      publicKeys: address.publicKeys
    };
    return obj;
  });
  return utxos;
};

describe('WalletUtils', function() {

  describe('#hashMessage', function() {
    it('should create a hash', function() {
      var res = WalletUtils.hashMessage(aText);
      res.toString('hex').should.equal('4102b8a140ec642feaa1c645345f714bc7132d4fd2f7f6202db8db305a96172f');
    });
  });

  describe('#signMessage', function() {
    it('should sign a message', function() {
      var sig = WalletUtils.signMessage(aText, aPrivKey);
      should.exist(sig);
      sig.should.equal(aSignature);
    });
    it('should fail to sign with wrong args', function() {
      (function() {
        WalletUtils.signMessage(aText, aPubKey);
      }).should.throw('Number');
    });
  });

  describe('#verifyMessage', function() {
    it('should fail to verify a malformed signature', function() {
      var res = WalletUtils.verifyMessage(aText, 'badsignature', otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should fail to verify a null signature', function() {
      var res = WalletUtils.verifyMessage(aText, null, otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should fail to verify with wrong pubkey', function() {
      var res = WalletUtils.verifyMessage(aText, aSignature, otherPubKey);
      should.exist(res);
      res.should.equal(false);
    });
    it('should verify', function() {
      var res = WalletUtils.verifyMessage(aText, aSignature, aPubKey);
      should.exist(res);
      res.should.equal(true);
    });
  });

  describe('#signMessage #verifyMessage round trip', function() {
    it('should sign and verify', function() {
      var aLongerText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
      var sig = WalletUtils.signMessage(aLongerText, aPrivKey);
      WalletUtils.verifyMessage(aLongerText, sig, aPubKey).should.equal(true);
    });
  });

  describe('#encryptMessage #decryptMessage round trip', function() {
    it('should encrypt and decrypt', function() {
      var pwd = "ezDRS2NRchMJLf1IWtjL5A==";
      var ct = WalletUtils.encryptMessage('hello world', pwd);
      var msg = WalletUtils.decryptMessage(ct, pwd);
      msg.should.equal('hello world');
    });
  });

  describe('#toSecret #fromSecret round trip', function() {
    it('should create secret and parse secret', function() {
      var i = 0;
      while (i++ < 100) {
        var walletId = Uuid.v4();
        var walletPrivKey = new Bitcore.PrivateKey();
        var network = i % 2 == 0 ? 'testnet' : 'livenet';
        var secret = WalletUtils.toSecret(walletId, walletPrivKey, network);
        var result = WalletUtils.fromSecret(secret);
        result.walletId.should.equal(walletId);
        result.walletPrivKey.toString().should.equal(walletPrivKey.toString());
        result.network.should.equal(network);
      };
    });
    it('should fail on invalid secret', function() {
      (function() {
        WalletUtils.fromSecret('invalidSecret');
      }).should.throw('Invalid secret');
    });

    it('should create secret and parse secret from string ', function() {
      var walletId = Uuid.v4();
      var walletPrivKey = new Bitcore.PrivateKey();
      var network = 'testnet';
      var secret = WalletUtils.toSecret(walletId, walletPrivKey.toString(), network);
      var result = WalletUtils.fromSecret(secret);
      result.walletId.should.equal(walletId);
      result.walletPrivKey.toString().should.equal(walletPrivKey.toString());
      result.network.should.equal(network);
    });
  });

  describe('#getNetworkFromXPubKey', function() {
    it('should check correctly', function() {
      var result;

      var xPrivKeyLivenet = (new Bitcore.HDPrivateKey('livenet')).toString();
      var xPubKeyLivenet = new Bitcore.HDPublicKey(xPrivKeyLivenet).toString();
      result = WalletUtils.getNetworkFromXPubKey(xPubKeyLivenet);
      result.should.be.equal('livenet');

      var xPrivKeyTestnet = (new Bitcore.HDPrivateKey('testnet')).toString();
      var xPubKeyTestnet = new Bitcore.HDPublicKey(xPrivKeyTestnet).toString();
      result = WalletUtils.getNetworkFromXPubKey(xPubKeyTestnet);
      result.should.be.equal('testnet');

    });
    it('should fail if argument is null or undefined', function() {
      var values = [
        null,
        123,
      ];
      _.each(values, function(value) {
        var valid = true;
        try {
          WalletUtils.getNetworkFromXPubKey(value);
        } catch (e) {
          valid = false;
        }
        valid.should.be.false;
      });
    });

  });

  describe('#privateKeyToAESKey', function() {
    it('should be ok', function() {
      var privKey = new Bitcore.PrivateKey(aPrivKey).toString();
      WalletUtils.privateKeyToAESKey(privKey).should.be.equal('2HvmUYBSD0gXLea6z0n7EQ==');
    });
    it('should fail if pk has invalid values', function() {
      var values = [
        null,
        123,
        '123',
      ];
      _.each(values, function(value) {
        var valid = true;
        try {
          WalletUtils.privateKeyToAESKey(value);
        } catch (e) {
          valid = false;
        }
        valid.should.be.false;
      });
    });
  });


  describe('#signTxp', function() {
    it('should sign correctly', function() {
      var hdPrivateKey = new Bitcore.HDPrivateKey('tprv8ZgxMBicQKsPdPLE72pfSo7CvzTsWddGHdwSuMNrcerr8yQZKdaPXiRtP9Ew8ueSe9M7jS6RJsp4DiAVS2xmyxcCC9kZV6X1FMsX7EQX2R5');
      var derivedPrivateKey = hdPrivateKey.derive(WalletUtils.PATHS.BASE_ADDRESS_DERIVATION);

      var toAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';
      var changeAddress = 'msj42CCGruhRsFrGATiUuh25dtxYtnpbTx';

      var publicKeyRing = [{
        xPubKey: new Bitcore.HDPublicKey(derivedPrivateKey)
      }];

      var path = 'm/1/0';
      var utxos = helpers.generateUtxos(publicKeyRing, path, 1, [1000, 2000]);
      var txp = {
        inputs: utxos,
        toAddress: toAddress,
        amount: 1200,
        changeAddress: {
          address: changeAddress
        },
        requiredSignatures: 1,
        outputOrder: [0, 1]
      };
      var signatures = WalletUtils.signTxp(txp, hdPrivateKey);
      signatures.length.should.be.equal(utxos.length);
    });
  });
});
