//
//  Certificate.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 03/06/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit

class Certificate: NSObject {
    
    func getClientPrivateKeyFromCertificateData() -> Data {
        let bundle: Bundle = Bundle.main
        let mainbun = bundle.path(forResource: "app_private", ofType: "key")
        let key: NSData = NSData(contentsOfFile: mainbun!)!
        return key as Data
    }
    
    func getClientCertificateData() -> Data {
        let bundle: Bundle = Bundle.main
        let mainbun = bundle.path(forResource: "app_cert", ofType: "crt")
        let key: NSData = NSData(contentsOfFile: mainbun!)!
        return key as Data
    }
    
    func getClientb9PublicKeyCertificateData() -> Data {
        let bundle: Bundle = Bundle.main
        let mainbun = bundle.path(forResource: "public", ofType: "key")
        let key: NSData = NSData(contentsOfFile: mainbun!)!
        return key as Data
    }
    
    func getServerb9PublicKeyFromCertificateData() -> Data {
        let bundle: Bundle = Bundle.main
        let mainbun = bundle.path(forResource: "b9_cert", ofType: "der")
        let key: NSData = NSData(contentsOfFile: mainbun!)!
        return key as Data
    }
    
   
    
    func validateServerB9Certificate(for response: Data, completion: (_ b9certf: Data,_ publicKey: SecKey,_ publicKeyData: Data) -> ()) {
        var aBuffer: UnsafeMutablePointer<UInt8>!
        var aREsponse = response
        aREsponse.withUnsafeMutableBytes({
            [aCount = response.count] (bytes: UnsafeMutablePointer<UInt8>) -> Void in
            aBuffer = bytes
        })
        
        let Serverb9Certificate = NSData.init(bytes: &aBuffer[0], length: Int(941))
        
        guard let (secPublicKeyData, secPublicKey) = self.getDevicePublicKey(fromDeviceCertificate: Serverb9Certificate as NSData) else {
            return
        }
        if secPublicKeyData != nil && secPublicKey != nil {
            let aBase64 = (secPublicKeyData! as Data).base64EncodedString()
            printLog(Str: "Server's B9 certificate public key is :- \(aBase64)", From: true)
            printLog(Str: "Server's B9 certificate Sec key is :-  \(secPublicKey!)", From: true)

            printStepLog(Str: "Client Validate the Server B9 Certificateto.", From: false, Step: 3)
            
            completion(Serverb9Certificate as Data, secPublicKey!, secPublicKeyData! as Data)
        }
    }
    
    fileprivate func getDevicePublicKey(fromDeviceCertificate certificate: NSData) -> (NSData?, SecKey?)? {
        let certificateObj = SecCertificateCreateWithData(nil, certificate as CFData)
        if certificateObj == nil {
            return nil
        }
        var trustObj:SecTrust? = nil
        let policy = SecPolicyCreateBasicX509()
        if SecTrustCreateWithCertificates(certificateObj!, policy, &trustObj) != errSecSuccess {
            return nil
        }
        if trustObj == nil {
            return nil
        }
        guard let aCertURL = Bundle.main.url(forResource: "rootCA_cert_der", withExtension: "der"),
            let aCertData = NSData.init(contentsOf: aCertURL),
            let aCertDataObj = SecCertificateCreateWithData(nil, aCertData as CFData) else {
                return nil
        }
        let aCertificateList = [aCertDataObj]
        if SecTrustSetAnchorCertificates(trustObj!, aCertificateList as CFArray) != errSecSuccess {
            return nil
        }
        
        var aTrustResult = SecTrustResultType.invalid
        
        if SecTrustEvaluate(trustObj!, &aTrustResult) != errSecSuccess {
            return nil
        }
        
        let aPublicKey = SecTrustCopyPublicKey(trustObj!)
        if aPublicKey == nil {
            return nil
        }
        
        let aPublicKeyTag = Bundle.main.bundleIdentifier?.data(using: .utf8)
        var aPublicKeyData = NSData()
        
        let aQueryPublicTag:[String : Any] = [kSecClass as String               : kSecClassKey,
                                              kSecAttrApplicationTag as String  : aPublicKeyTag! as NSData,
                                              kSecAttrKeyType as String         : kSecAttrKeyTypeRSA]
        
        let aQueryPublicKey:[String : Any] = [kSecClass as String               : kSecClassKey,
                                              kSecAttrApplicationTag as String  : aPublicKeyTag! as NSData,
                                              kSecAttrKeyType as String         : kSecAttrKeyTypeRSA,
                                              kSecValueRef as String            : aPublicKey!,
                                              kSecReturnData as String          : true]
        
        var aResult: CFTypeRef?
        let aSanityCheck = SecItemAdd(aQueryPublicKey as CFDictionary, &aResult)
        
        if aSanityCheck == errSecSuccess, let aData = aResult as? NSData {
            aPublicKeyData = aData
            SecItemDelete(aQueryPublicTag as CFDictionary)
        } else {
            return nil
        }
        return (aPublicKeyData, aPublicKey)
    }
    
}

extension NSObject {
    
    func printLog(Str stri: String, From isServer: Bool) {
        print("***Log Start***\(isServer == true ? "<< ": ">> ")\(stri)\n****Log End***")
    }
    
    func printStepLog(Str stri: String, From isServer: Bool, Step no: Int) {
        print("\n************{ Step \(no) Start }*************\n************{ Log from \(isServer == true ? "Server": "Client") }*************\n : -> \(stri)" + "\n************{ Step \(no) End}*************\n");
    }

}
