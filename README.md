# import-dart-convert-import-dart-typed_data-import-package-crypto-crypto.dart-import-packag
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:tuple/tuple.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import "package:pointycastle/export.dart";

class AesHelper {
  static String encryptAESCryptoJS(String plainText, String passphrase) {
    try {
      Uint8List salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      List<int> inputList = utf8.encode(plainText);
      List<int> passwordInBytes = utf8.encode(passphrase);
      List<int> shaPassword = sha256.convert(passwordInBytes).bytes;
      var keyndIV = deriveKeyAndIV(shaPassword, salt);
      final key = encrypt.Key(keyndIV.item1);
      final iv = encrypt.IV(keyndIV.item2);
      final encrypter = encrypt.Encrypter(
          encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: "PKCS7"));
      final encrypted = encrypter.encryptBytes(inputList, iv: iv);
      Uint8List encryptedBytesWithSalt = Uint8List.fromList(encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (error) {
      throw error;
    }
  }

  static String decryptAESCryptoJS(String encrypted, String passphrase) {
    try {
      Uint8List salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      Uint8List encryptedBytesWithSalt = base64.decode(encrypted);
      List<int> passwordInBytes = utf8.encode(passphrase);
      List<int> shaPassword = sha256.convert(passwordInBytes).bytes;
      var keyndIV = deriveKeyAndIV(shaPassword, salt);
      final key = encrypt.Key(keyndIV.item1);
      final iv = encrypt.IV(keyndIV.item2);
      final encrypter = encrypt.Encrypter(
          encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: "PKCS7"));
      final decrypted =
          encrypter.decrypt64(base64.encode(encryptedBytesWithSalt), iv: iv);
      return decrypted;
    } catch (error) {
      throw error;
    }
  }

  static Tuple2<Uint8List, Uint8List> deriveKeyAndIV(
      Uint8List passphrase, Uint8List salt) {
    int iterationCount = 1000;
    int derivedKeyLength = 64;

    Pbkdf2Parameters params =
        new Pbkdf2Parameters(salt, iterationCount, derivedKeyLength);
    KeyDerivator keyDerivator =
        new PBKDF2KeyDerivator(new HMac(new SHA1Digest(), 64));
    keyDerivator.init(params);
    Uint8List concatenatedHashes = keyDerivator.process(passphrase);
    var keyBtyes = concatenatedHashes.sublist(0, 32);
    var ivBtyes = concatenatedHashes.sublist(32, 48);
    return new Tuple2(keyBtyes, ivBtyes);
  }
}


add package in pubspec.yaml file
  crypto: ^2.1.5
  tuple: ^1.0.3
  encrypt: ^4.0.0
  salt: ^0.1.2
  pointycastle: ^1.0.2
