//
//  SessionKey_Encrypt.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 03/06/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit
import CryptoSwift

class SessionKey_Encrypt: NSObject {

    func decryptServerEncryptedData(for response: Data, SharedSession Key:Data, completion: (_ salt: Data) -> ()) {
        let password: Array<UInt8> = Key.bytes
        do {
            let hashKeyData = Digest.sha256(password)
            print("Final SHA key is --> \(password.toBase64()!)")
            
            let newIV = response.subdata(in:  Range.init(0...15))
            let aes = try AES.init(key: hashKeyData, blockMode: CBC(iv: newIV.bytes))
            let sliceData = response.subdata(in:  Range.init(16...response.count-1))
            let ciphertext = try aes.decrypt(sliceData.bytes)
            let serverCompleteMsg = String(data: Data(ciphertext), encoding: .utf8)
            print("\n\nServer Completed decrypted message is --> \(serverCompleteMsg!)\n\n")

            if serverCompleteMsg == "Completed" {
                print("\n\nServer Sent Completed Message with Iv --> \(newIV.bytes)\n\n")
                completion(newIV)
            } else if serverCompleteMsg == "Finished" {
                print("\n\nServer Sent Finished Message --> \(serverCompleteMsg!)\n\n")
                completion(newIV)
            }
        } catch {
            print(error)
        }
        return
    }
    
    
    func decryptServerCommandResponseEncryptedData(for response: Data, SharedSession Key:Data, completion: (_ response: String) -> ()) {
        let password: Array<UInt8> = Key.bytes
        do {
            let hashKeyData = Digest.sha256(password)
            print("Final SHA key is --> \(password.toBase64()!)")
            
            let newIV = response.subdata(in:  Range.init(0...15))
            let aes = try AES.init(key: hashKeyData, blockMode: CBC(iv: newIV.bytes))
            let sliceData = response.subdata(in:  Range.init(16...response.count-1))
            let ciphertext = try aes.decrypt(sliceData.bytes)
            let serverCompleteMsg = String(data: Data(ciphertext), encoding: .utf8)
            print("\n\nServer command response decrypted --> \(serverCompleteMsg!)\n\n")
            completion(serverCompleteMsg!)

        } catch {
            print(error)
        }
        return
    }
    
    func sendClientEncryptedDataToServer(encrypt data: Data, SharedSession Key:Data, salt: Data, completion: (_ encryptData: Data) -> ()) {
        let password: Array<UInt8> =  Key.bytes
        do {
            let hashKeyData = Digest.sha256(password)
            let aes = try AES.init(key: hashKeyData, blockMode: CBC(iv: salt.bytes))
            let cipherEncryptData = try aes.encrypt(data.bytes)
            completion(Data(cipherEncryptData))
        } catch {
            print(error)
        }
        return
    }
    
    fileprivate func decryptClientEncryptedData(aes: AES, encryptedData: [UInt8]) {
        ///Decrypt
        do {
            let decipherEncryptData = try aes.decrypt(encryptedData)
            print("Testing : ->> " + String(bytes: decipherEncryptData, encoding: .utf8)!)
        } catch {
            print(error)
        }
    }
    
}
