/*jslint node: true */
"use strict";
var fs = require('fs');
var crypto = require('crypto');
var util = require('util');
var constants = require('trustnote-common/constants.js');
var conf = require('trustnote-common/conf.js');
var objectHash = require('trustnote-common/object_hash.js');
var desktopApp = require('trustnote-common/desktop_app.js');
var db = require('trustnote-common/db.js');
var eventBus = require('trustnote-common/event_bus.js');
var ecdsaSig = require('trustnote-common/signature.js');
var Mnemonic = require('bitcore-mnemonic');
var Bitcore = require('bitcore-lib');
var readline = require('readline');

var async = require('async');
var appDataDir = desktopApp.getAppDataDir();
var KEYS_FILENAME = appDataDir + '/keys.json';
var UNITS_FILENAME = appDataDir + '/UnitUnsign.json';
var SIGNEDUNITS_FILENAME = appDataDir + '/UnitSigned.json';
var device = require('trustnote-common/device.js');

var wallet_id;
var xPrivKey;

function replaceConsoleLog(){
	var log_filename = conf.LOG_FILENAME || (appDataDir + '/log.txt');
	var writeStream = fs.createWriteStream(log_filename);
	console.log('---------------');
	console.log('From this point, output will be redirected to '+log_filename);
	console.log("To release the terminal, type Ctrl-Z, then 'bg'");
	console.log = function(){
		writeStream.write(Date().toString()+': ');
		writeStream.write(util.format.apply(null, arguments) + '\n');
	};
	console.warn = console.log;
	console.info = console.log;
}


function readKeys(onDone){
	console.log('-----------------------');
	if (conf.control_addresses)
		console.log("remote access allowed from devices: "+conf.control_addresses.join(', '));
	if (conf.payout_address)
		console.log("payouts allowed to address: "+conf.payout_address);
	console.log('-----------------------');
	fs.readFile(KEYS_FILENAME, 'utf8', function(err, data){
		var rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
			//terminal: true
		});
		if (err){
			console.log('failed to read keys, will exit');
			process.exit(0);
		}
		else{
			rl.question("Passphrase: ", function(passphrase){
				rl.close();
				if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
				if (process.stdout.clearLine)  process.stdout.clearLine();
				var keys = JSON.parse(data);
				var deviceTempPrivKey = Buffer(keys.temp_priv_key, 'base64');
				var devicePrevTempPrivKey = Buffer(keys.prev_temp_priv_key, 'base64');
				determineIfWalletExists(function(bWalletExists){
					if (bWalletExists)
						onDone(keys.mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey);
					else{
						console.log('no wallet exists, will exit');
						process.exit(0);
					}
				});
			});
		}
	});
}


function writeKeys(mnemonic_phrase, deviceTempPrivKey, devicePrevTempPrivKey, onDone){
	var keys = {
		mnemonic_phrase: mnemonic_phrase,
		temp_priv_key: deviceTempPrivKey.toString('base64'),
		prev_temp_priv_key: devicePrevTempPrivKey.toString('base64')
	};
	fs.writeFile(KEYS_FILENAME, JSON.stringify(keys, null, '\t'), 'utf8', function(err){
		if (err)
			throw Error("failed to write keys file");
		if (onDone)
			onDone();
	});
}


function readSingleWallet(handleWallet){
	db.query("SELECT wallet FROM wallets", function(rows){
		if (rows.length === 0)
			throw Error("no wallets");
		if (rows.length > 1)
			throw Error("more than 1 wallet");
		handleWallet(rows[0].wallet);
	});
}

function determineIfWalletExists(handleResult){
	db.query("SELECT wallet FROM wallets", function(rows){
		if (rows.length > 1)
			throw Error("more than 1 wallet");
		handleResult(rows.length > 0);
	});
}

var arrSigningDeviceAddresses = [];
var assocPrivatePayloads = {};
var signer = {
	readSigningPaths: function(conn, address, handleLengthsBySigningPaths){ // returns assoc array signing_path => length
		readFullSigningPaths(conn, address, arrSigningDeviceAddresses, function(assocTypesBySigningPaths){
			var assocLengthsBySigningPaths = {};
			for (var signing_path in assocTypesBySigningPaths){
				var type = assocTypesBySigningPaths[signing_path];
				if (type === 'key')
					assocLengthsBySigningPaths[signing_path] = constants.SIG_LENGTH;
				else if (type === 'merkle'){
					if (merkle_proof)
						assocLengthsBySigningPaths[signing_path] = merkle_proof.length;
				}
				else
					throw Error("unknown type "+type+" at "+signing_path);
			}
			handleLengthsBySigningPaths(assocLengthsBySigningPaths);
		});
	},
	readDefinition: function(conn, address, handleDefinition){
		conn.query(
			"SELECT definition FROM my_addresses WHERE address=? UNION SELECT definition FROM shared_addresses WHERE shared_address=?",
			[address, address],
			function(rows){
				if (rows.length !== 1)
					throw Error("definition not found");
				handleDefinition(null, JSON.parse(rows[0].definition));
			}
		);
	},
	sign: function(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature){
		var buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
		findAddress(address, signing_path, {
			ifError: function(err){
				throw Error(err);
			},
			ifUnknownAddress: function(err){
				throw Error("unknown address "+address+" at "+signing_path);
			},
			ifLocal: function(objAddress){
				signWithLocalPrivateKey(objAddress.wallet, objAddress.account, objAddress.is_change, objAddress.address_index, buf_to_sign, function(sig){
					handleSignature(null, sig);
				});
			},
			ifRemote: function(device_address){
				// we'll receive this event after the peer signs
				eventBus.once("signature-"+device_address+"-"+address+"-"+signing_path+"-"+buf_to_sign.toString("base64"), function(sig){
					handleSignature(null, sig);
					if (sig === '[refused]')
						eventBus.emit('refused_to_sign', device_address);
				});
				walletGeneral.sendOfferToSign(device_address, address, signing_path, objUnsignedUnit, assocPrivatePayloads);
				if (!bRequestedConfirmation){
					eventBus.emit("confirm_on_other_devices");
					bRequestedConfirmation = true;
				}
			},
			ifMerkle: function(bLocal){
				if (!bLocal)
					throw Error("merkle proof at path "+signing_path+" should be provided by another device");
				if (!merkle_proof)
					throw Error("merkle proof at path "+signing_path+" not provided");
				handleSignature(null, merkle_proof);
			}
		});
	}
};


function findAddress(address, signing_path, callbacks, fallback_remote_device_address){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress())
					return callbacks.ifRemote(row.device_address);
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
			}
			db.query(
				//	"SELECT address, device_address, member_signing_path FROM shared_address_signing_paths WHERE shared_address=? AND signing_path=?",
				// look for a prefix of the requested signing_path
				"SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
				WHERE shared_address=? AND signing_path=SUBSTR(?, 1, LENGTH(signing_path))",
				[address, signing_path],
				function(sa_rows){
					if (rows.length > 1)
						throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
					if (sa_rows.length === 0){
						if (fallback_remote_device_address)
							return callbacks.ifRemote(fallback_remote_device_address);
						return callbacks.ifUnknownAddress();
					}
					var objSharedAddress = sa_rows[0];
					var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
					var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
					if (objSharedAddress.address === '')
						return callbacks.ifMerkle(bLocal);
					findAddress(objSharedAddress.address, relative_signing_path, callbacks, bLocal ? null : objSharedAddress.device_address);
				}
			);
		}
	);
}

// returns assoc array signing_path => (key|merkle)
function readFullSigningPaths(conn, address, arrSigningDeviceAddresses, handleSigningPaths){

	var assocSigningPaths = {};

	function goDeeper(member_address, path_prefix, onDone){
		// first, look for wallet addresses
		var sql = "SELECT signing_path FROM my_addresses JOIN wallet_signing_paths USING(wallet) WHERE address=?";
		var arrParams = [member_address];
		if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
			sql += " AND device_address IN(?)";
			arrParams.push(arrSigningDeviceAddresses);
		}
		conn.query(sql, arrParams, function(rows){
			rows.forEach(function(row){
				assocSigningPaths[path_prefix + row.signing_path.substr(1)] = 'key';
			});
			if (rows.length > 0)
				return onDone();
			// next, look for shared addresses, and search from there recursively
			sql = "SELECT signing_path, address FROM shared_address_signing_paths WHERE shared_address=?";
			arrParams = [member_address];
			if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
				sql += " AND device_address IN(?)";
				arrParams.push(arrSigningDeviceAddresses);
			}
			conn.query(sql, arrParams, function(rows){
				if(rows.length > 0) {
					async.eachSeries(
						rows,
						function (row, cb) {
							if (row.address === '') { // merkle
								assocSigningPaths[path_prefix + row.signing_path.substr(1)] = 'merkle';
								return cb();
							}

							goDeeper(row.address, path_prefix + row.signing_path.substr(1), cb);
						},
						onDone
					);
				} else {
					assocSigningPaths[path_prefix] = 'key';
					onDone();
				}
			});
		});
	}

	goDeeper(address, 'r', function(){
		handleSigningPaths(assocSigningPaths); // order of signing paths is not significant
	});
}

function signWithLocalPrivateKey(wallet_id, account, is_change, address_index, text_to_sign, handleSig){
	var path = "m/44'/0'/" + account + "'/"+is_change+"/"+address_index;
	var privateKey = xPrivKey.derive(path).privateKey;
	var privKeyBuf = privateKey.bn.toBuffer({size:32}); // https://github.com/bitpay/bitcore-lib/issues/47
	handleSig(ecdsaSig.sign(text_to_sign, privKeyBuf));
}


setTimeout(function(){
	readKeys(function(mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey){
		var saveTempKeys = function(new_temp_key, new_prev_temp_key, onDone){
			writeKeys(mnemonic_phrase, new_temp_key, new_prev_temp_key, onDone);
		};
		var mnemonic = new Mnemonic(mnemonic_phrase);
		// global
		xPrivKey = mnemonic.toHDPrivateKey(passphrase);
		var devicePrivKey = xPrivKey.derive("m/1'").privateKey.bn.toBuffer({size:32});
		// read the id of the only wallet
		readSingleWallet(function(wallet){
			// global
			wallet_id = wallet;
			device.setDevicePrivateKey(devicePrivKey);
			let my_device_address = device.getMyDeviceAddress();
			db.query("SELECT 1 FROM extended_pubkeys WHERE device_address=?", [my_device_address], function(rows){
				if (rows.length > 1)
					throw Error("more than 1 extended_pubkey?");
				if (rows.length === 0)
					return setTimeout(function(){
						console.log('passphrase is incorrect');
						process.exit(0);
					}, 1000);
				require('trustnote-common/wallet.js'); // we don't need any of its functions but it listens for hub/* messages
				device.setTempKeys(deviceTempPrivKey, devicePrevTempPrivKey, saveTempKeys);
				device.setDeviceName(conf.deviceName);
				device.setDeviceHub(conf.hub);
				let my_device_pubkey = device.getMyDevicePubKey();
				console.log("====== my device address: "+my_device_address);
				console.log("====== my device pubkey: "+my_device_pubkey);
				if (conf.permanent_pairing_secret)
					console.log("====== my pairing code: "+my_device_pubkey+"@"+conf.hub+"#"+conf.permanent_pairing_secret);
				if (conf.bLight){
					var light_wallet = require('trustnote-common/light_wallet.js');
					light_wallet.setLightVendorHost(conf.hub);
				}
				eventBus.emit('headless_wallet_ready');
				setTimeout(replaceConsoleLog, 1000);
			});
		});
	});
}, 1000);

function ReadUnitsAndSign(onDone){
	console.log('-----------------------');
	console.log("Begin sigh ...");
	console.log('-----------------------');
	fs.readFile(UNITS_FILENAME, 'utf8', function(err, data){
		if (err){
			console.log('failed to read units, will exit');
			process.exit(0);
		}

		var objUnsignedUnit;
		var objUnit;
		var max_main;
		var max_change;
		try{
			objUnsignedUnit = JSON.parse(data);
			objUnit = objUnsignedUnit.objUnit
			max_main = objUnsignedUnit.max_main;
			max_change = objUnsignedUnit.max_change;
		}
		catch(e)
		{
			console.log('failed to parse units, will exit');
			process.exit(0);
		}

		console.log(max_main + "------" + max_change);
		catchupAddresses(max_main, max_change, function(){
			var assocSigningPaths = {};
			var conn;
			db.takeConnectionFromPool(function(new_conn){
				conn = new_conn;

				async.eachSeries(
					objUnit.authors,
					function(author, cb8){
						var from_address = author.address;
						signer.readSigningPaths(conn, from_address, function(assocLengthsBySigningPaths) {
							var arrSigningPaths = Object.keys(assocLengthsBySigningPaths);
							assocSigningPaths[from_address] = arrSigningPaths;
							cb8();
						});
					},
					function(err) {
						conn.release();
						if (err)
							throw Error("failed to get Signing Paths!");
						async.each(
							objUnit.authors,
							function (author, cb2) {
								var address = author.address;
								async.each( // different keys sign in parallel (if multisig)
									assocSigningPaths[address],
									function (path, cb3) {
										signer.sign(objUnit, assocPrivatePayloads, address, path, function (err, signature) {
											if (err)
												return cb3(err);
											// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
											if (signature === '[refused]')
												return cb3('one of the cosigners refused to sign');
											author.authentifiers[path] = signature;
											cb3();
										});
									},
									function (err) {
										cb2(err);
									}
								);
							},
							function (err) {
								if (err)
									return handleError(err);
								onDone(null, objUnit);
							}
						);
					}
				);
			});
		});

	});
}

function createSigner(){
	ReadUnitsAndSign(function(err, objSignedUnit){
		if (err)
			throw Error("failed to signed units!");
		writeUnits(objSignedUnit);
	});
}

function writeUnits(objUnit){
	fs.writeFile(SIGNEDUNITS_FILENAME, JSON.stringify(objUnit, null, '\t'), 'utf8', function(err){
		if (err)
			throw Error("failed to write signed units file!");
		console.log('Sign units succeed !!!');
		process.exit(0);
	});
}

function catchupAddresses(max_main, max_change, cb) {
	var wallet_defined_by_keys = require('trustnote-common/wallet_defined_by_keys.js');

	function addAddress(wallet, is_change, index, maxIndex, addAddressCallback) {
		wallet_defined_by_keys.issueAddress(wallet, is_change, index, function(addressInfo) {
			console.log("issua new " + is_change + " address, index：" + index + "," + addressInfo);
			index++;
			if (index <= maxIndex)
				addAddress(wallet, is_change, index, maxIndex, addAddressCallback);
			else
				addAddressCallback();
		});
	}

	function readMaxAddressIndex(wallet, is_change, handleMaxAddressIndex){
		db.query("SELECT MAX(address_index) AS max_index FROM my_addresses WHERE wallet=? AND is_change=?", [wallet, is_change], function(rows){
			var max_index = rows[0].max_index;
			handleMaxAddressIndex( (max_index === null) ? 0 : max_index );
		});
	}

	readSingleWallet(function(wallet){
		async.series([
				function(cb3) {
					readMaxAddressIndex(wallet, 0, function (next_main_index) {
						if (next_main_index < max_main)
							addAddress(wallet, 0, next_main_index, max_main, cb3);
						else
							cb3();
					});
				},
				function(cb3) {
					readMaxAddressIndex(wallet, 1, function (next_change_index) {
						if (next_change_index < max_change)
							addAddress(wallet, 1, next_change_index, max_change, cb3);
						else
							cb3();
					});
				},
			],function(err) {
				if (err)
					throw Error("issue address error");
				cb();
			}
		);
	});
}

eventBus.on('headless_wallet_ready', createSigner);
