//
//  TCPManager.swift
//  TLSPoc
//
//  Created by Thinq-Gasan (Jay) on 2020/02/05.
//  Copyright © 2020 gyana. All rights reserved.
//

import Foundation
import SystemConfiguration
import GMEllipticCurveCrypto
import SwiftyRSA
import CryptoSwift

class TcpSocketManager: NSObject, StreamDelegate {
    
    static let sharedInstance : TcpSocketManager = TcpSocketManager()

    var TlsLevelId: TLSLevel?
    
    var host:String?
    var port:Int?
    
    var inputStream: InputStream?
    var outputStream: OutputStream?
    var result:Int?
    var outputStreamOpened : Bool?
    var inputStreamOpened : Bool?
    var socketConnected : Bool?
    
    static var needToConnect : Bool?
    fileprivate var socketTimer: Timer!
    fileprivate var recvTimer: Timer!
    
    /// TLS variable details
    
    /// Server DER certificate SecKey
    fileprivate var b9secKey: SecKey?
    
    /// Server DER certificate PublicKeyData
    fileprivate var serverPublicKeyData: Data?
    
    var ServerPublicKeyData: Data = Data()
    var clientPrivateKey: NSData?
    var clientPublicKey: NSData?
    
    var sessionKey: String = UUID().uuidString
    var mySharedSecretKey: NSData?
    var salt: Data?
    
    func connect()->Bool {
        
        if(self.isSocketOpened()) {
            return true
        }
        
        outputStreamOpened = false
        inputStreamOpened = false
        socketConnected = false
        
        
        //Change you IP and Port
        Stream.getStreamsToHost(withName:"127.0.0.1", port : 8800, inputStream: &inputStream, outputStream: &outputStream)
        
        socketTimer = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(self.socketTimeout), userInfo: nil, repeats: false)
        
        if inputStream != nil && outputStream != nil {
            // Set delegate
            inputStream!.delegate = self
            outputStream!.delegate = self
            
            // Schedule
            inputStream!.schedule(in: .main, forMode: RunLoop.Mode.default)
            outputStream!.schedule(in: .main, forMode: RunLoop.Mode.default)
            
            // Enable SSL/TLS on the streams
            inputStream!.setProperty(kCFStreamSocketSecurityLevelNegotiatedSSL, forKey: Stream.PropertyKey.socketSecurityLevelKey)
            outputStream!.setProperty(kCFStreamSocketSecurityLevelNegotiatedSSL, forKey: Stream.PropertyKey.socketSecurityLevelKey)
            
            // Defin custom SSL/TLS settings
            let sslSettings : [NSString: Any] = [
                // Stream automatically sets up the socket, the streams and creates a trust object and evaulates it before you even get a chance to check the trust yourself. Only proper SSL certificates will work with this method. If you have a self signed certificate like I do, you need to disable the trust check here and evaulate the trust against your custom root CA yourself.
                NSString(format: kCFStreamSSLValidatesCertificateChain): kCFBooleanFalse!,
                //
                NSString(format: kCFStreamSSLPeerName): kCFNull!,
                // We are an SSL/TLS client, not a server
                // NSString(format: kCFStreamSSLCertificates): certs,
                NSString(format: kCFStreamSSLIsServer): kCFBooleanFalse!
            ]
            // Set the SSL/TLS settingson the streams
            inputStream!.setProperty(sslSettings, forKey: kCFStreamPropertySSLSettings as Stream.PropertyKey)
            outputStream!.setProperty(sslSettings, forKey: kCFStreamPropertySSLSettings as Stream.PropertyKey)
            // Open the streams
            
            inputStream!.open()
            outputStream!.open()
            
            printStepLog(Str: "Client connect to Server.", From: false, Step: 0)
            
            socketTimer.invalidate()
            
            outputStreamOpened = true
            inputStreamOpened = true
            
            return true
            
        }
        return false
    }
    
    @objc func socketTimeout() {
        print("Socket connect timeout")
        self.disconnect()
        
    }
    
    func send(data: String)-> Int  {
        if socketConnected==false {
            if (!self.connect()) {
                return -1
            }
        }
        var modifiedData : String = ""
        modifiedData = data.replacingOccurrences(of: "\r", with:"").replacingOccurrences(of: "\n", with:"")
        let outString = modifiedData + "\r\n"
        print("SEND: \(outString)")
        let bytesWritten = outputStream?.write(outString, maxLength:outString.count)
        if (bytesWritten != nil) {
            print("Successfully sent data")
            return bytesWritten!
        } else {
            return -1
        }
    }
    
    func sendData(data: Data)-> Int  {
        if socketConnected==false {
            if (!self.connect()) {
                return -1
            }
        }
        
        let bytesWritten = outputStream?.write(data: data)
        if (bytesWritten != nil) {
            return bytesWritten!
        } else {
            return -1
        }
        
    }
    
    func recv(buffersize: Int) -> Data? {
        let buffersize = 1024
        var buffer = [UInt8](repeating: 0, count: buffersize)
        var readData = Data()
        let bytesRead = inputStream?.read(&buffer, maxLength: buffersize)
        var dropCount = buffersize - bytesRead!
        print("dropCount: ", dropCount)
        if dropCount <= 0 {
            dropCount = 0
            print("dropCount Zero!! ")
        }
        let chunk = buffer.dropLast(dropCount)
        
        if(inputStream!.hasBytesAvailable) {
            readData = Data(chunk)
            while (true) {
                let len = inputStream?.read(&buffer, maxLength: buffer.count)
                
                if (len! > 0) && (len! < 1024) {
                    let streamedData = Data.init(bytes: buffer, count: len!)
                    readData += streamedData
                    //                    let streamString = String(bytes: streamedData, encoding: String.Encoding.utf8)!
                    //                    print("Server : " + streamString)
                    //                    if streamString.contains("\r\n") { break }
                } else {
                    print("Server : \(len!)")
                    if len! < 0 {
                        return readData
                    }
                }
            }
            return readData
        } else {
            return Data(chunk)
        }
    }
    
    func disconnect() {
        inputStream?.close()
        outputStream?.close()
        outputStreamOpened = false
        inputStreamOpened = false
        socketConnected = false
    }
    
    func GetneedtoConnect()-> Bool {
        return TcpSocketManager.needToConnect ?? false
    }
    
    func SetneedtoConnect(_ set : Bool) {
        TcpSocketManager.needToConnect = set
    }
    
    // This is where we get all our events (haven't finished writing this class)
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case Stream.Event.endEncountered:
            print("End Encountered")
            self.TlsLevelId = nil
            outputStreamOpened = false
            inputStreamOpened = false
            socketConnected = false
            break
        case Stream.Event.openCompleted:
            print("Open Completed")
            break
        case Stream.Event.hasSpaceAvailable:
            print("Has Space Available")
            break
        case Stream.Event.hasBytesAvailable:
            if let response = self.recv(buffersize: 1024), response.count > 0 {
                if self.TlsLevelId == .clientHello {
                    printStepLog(Str: "Server sent his B9 Certificateto Client.", From: true, Step: 2)
                    Certificate().validateServerB9Certificate(for: response) { (b9cft, b9secKey, pubKeyData)  in
                        /// Server DER certificate SecKey
                        self.b9secKey = b9secKey
                        /// Server DER certificate PublicKeyData
                        self.serverPublicKeyData = pubKeyData
                        self.TlsLevelId = .serverB9
                    }
                } else if self.TlsLevelId == .serverB9 {
                    self.verifyServerSignature(for: response) { (signature, ServerPublicKey) in
                        self.generateSharedSecKey(from: ServerPublicKey) { (cryPto) in
                            self.sendAppCertificateWithSessionKeyandSignature(for: cryPto, signature: signature, pubSecData: self.serverPublicKeyData!, completion: {
                                self.printStepLog(Str: "Client sent App Certification with Session key.", From: false, Step: 5)
                                self.TlsLevelId = .serverPublicKey
                            })
                        }
                    }
                } else if self.TlsLevelId == .serverPublicKey {
                    printStepLog(Str: "Server sent Completed message with Encryption.", From: true, Step: 6)
                    SessionKey_Encrypt().decryptServerEncryptedData(for: response, SharedSession: self.mySharedSecretKey! as Data) { (salt) in
                        self.salt = salt
                        printStepLog(Str: "Client read Completed message by Decrypting.", From: false, Step: 7)
                        SessionKey_Encrypt().sendClientEncryptedDataToServer(encrypt: "Completed".data(using: .utf8)!, SharedSession: self.mySharedSecretKey! as Data, salt: salt, completion: { (encryptedData) in
                            let result = self.sendData(data: encryptedData)
                            if (result == -1 ) {
                                print("write failed")
                            } else {
                                printStepLog(Str: "Client Sent Completed message by Encrypting.", From: false, Step: 8)
                                self.TlsLevelId = .Completed
                            }
                        })
                        
                    }
                } else if self.TlsLevelId == .Completed {
                    SessionKey_Encrypt().decryptServerEncryptedData(for: response, SharedSession: self.mySharedSecretKey! as Data) { (salt) in
                        SessionKey_Encrypt().sendClientEncryptedDataToServer(encrypt: "Finished".data(using: .utf8)!, SharedSession: self.mySharedSecretKey! as Data, salt: salt, completion: { (encryptedData) in
                            let result = self.sendData(data: encryptedData)
                            if (result == -1 ) {
                                print("write failed")
                            } else {
                                printStepLog(Str: "TLS finished.", From: true, Step: 9)
                                self.TlsLevelId = .Finished
                            }
                        })
                    }
                } else if self.TlsLevelId == .Finished {
                
                }
            } else {
                print("Response = 0 bytes no data")
            }
            break
        case Stream.Event.errorOccurred:
            print("Error Occured : \(eventCode) stream : \(aStream)")
            self.TlsLevelId = nil
            outputStreamOpened = false
            inputStreamOpened = false
            socketConnected = false
            
            break
        default:
            print("Default")
            break
        }
    }
    
    func generateSharedSecKey(from serverRes: Data, completion: @escaping (_ cryPto: GMEllipticCurveCrypto) -> ()) {
        self.ServerPublicKeyData = serverRes
        Key().generateSharedSecKeysUsing(ServerPublicKey: self.ServerPublicKeyData) { (response) in
            self.mySharedSecretKey = response.1
            self.clientPublicKey = response.0.publicKey as NSData?
            completion(response.0)
        }
    }
    
    func verifyServerSignature(for response: Data, completion: (_ signature: Data, _ publicKey: Data) -> ()) {
        var aBuffer: UnsafeMutablePointer<UInt8>!
        var aREsponse = response
        aREsponse.withUnsafeMutableBytes({
            [aCount = response.count] (bytes: UnsafeMutablePointer<UInt8>) -> Void in
            aBuffer = bytes
        })
        
        let ecdhPubKey = NSData.init(bytes: &aBuffer[0], length: Int(33))
        print("\nServer ECDH Publickey : \(ecdhPubKey)\n\n")
        
        let signatureData = NSData.init(bytes: &aBuffer[ecdhPubKey.count], length: Int(response.count-33))
        let ServerSignature: String = String(data: signatureData as Data, encoding: .utf8)!
        print("\nServer Digital Signature : \(ServerSignature)")
        
        let client_random = "Hello".data(using: .utf8) // _client
        let server_random = "Hello".data(using: .utf8) // _server
        
        var signatureDigest = (ecdhPubKey as Data)
        signatureDigest.append(client_random!)
        signatureDigest.append(server_random!)
        
        let eckeyDigested = Digest.sha256(signatureDigest.bytes)
        let clear = ClearMessage(data: Data(eckeyDigested))
        
        let pubKeySec = try! PublicKey(data: self.serverPublicKeyData!)
        let vsignature = try! Signature(base64Encoded: ServerSignature)
        let isSuccessful = try! clear.verify(with: pubKeySec, signature: vsignature, digestType: .sha256)
        
        if isSuccessful {
            print("Server's signature data verification success!")
            let privateSecKey = self.getClientPrivateKey()!
            let pubKeySec = try! PrivateKey(reference: privateSecKey)
            let clientSignature = try! clear.signed(with: pubKeySec, digestType: .sha256)
            print(clientSignature.data.base64EncodedString())
            completion(clientSignature.data, ecdhPubKey as Data)
        } else {
            print("Server's signature data verification failed!")
        }
    }
    
    func getClientPrivateKey() -> SecKey?  {
        let privateKeyData = Certificate().getClientPrivateKeyFromCertificateData()
        let privateKeyString = String(data: privateKeyData, encoding:  .utf8)!
        print(privateKeyString)
        let privtKey = privateKeyString.replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "").replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        let privKeyRSAData = Data(base64Encoded: privtKey, options: Data.Base64DecodingOptions.ignoreUnknownCharacters)
        
        return (try! PrivateKey(data: privKeyRSAData!)).reference
    }
    
    func sayHelloToServer() {
        let result = self.send(data: "Hello")
        if (result == -1 ) {
            print("write failed")
        } else {
            self.printStepLog(Str: "Client sent Hello to Server.", From: false, Step: 1)
            self.TlsLevelId = .clientHello
            // If user entred correct PIN code
        }
    }
    
    func isSocketOpened() -> Bool {
        if(outputStreamOpened == nil || inputStreamOpened == nil ){
            return false
        }
        socketConnected = outputStreamOpened! && inputStreamOpened!
        if(socketConnected!) {
            return true
        } else {
            return false
        }
    }
    
    func isConnectedToNetwork() -> Bool {
        var zeroAddress = sockaddr_in(sin_len: 0, sin_family: 0, sin_port: 0, sin_addr: in_addr(s_addr: 0), sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        zeroAddress.sin_len = UInt8(MemoryLayout.size(ofValue: zeroAddress))
        zeroAddress.sin_family = sa_family_t(AF_INET)
        let defaultRouteReachability = withUnsafePointer(to: &zeroAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {zeroSockAddress in
                SCNetworkReachabilityCreateWithAddress(nil, zeroSockAddress)
            }
        }
        var flags: SCNetworkReachabilityFlags = SCNetworkReachabilityFlags(rawValue: 0)
        if SCNetworkReachabilityGetFlags(defaultRouteReachability!, &flags) == false {
            return false
        }
        
        /* Only Working for WIFI
         let isReachable = flags == .reachable
         let needsConnection = flags == .connectionRequired
         
         return isReachable && !needsConnection
         */
        
        // Working for Cellular and WIFI
        let isReachable = (flags.rawValue & UInt32(kSCNetworkFlagsReachable)) != 0
        let needsConnection = (flags.rawValue & UInt32(kSCNetworkFlagsConnectionRequired)) != 0
        let ret = (isReachable && !needsConnection)
        
        return ret
    }
    
    func sendAppCertificateWithSessionKeyandSignature(for crypto: GMEllipticCurveCrypto, signature: Data, pubSecData: Data, completion: () -> ()) {
        let appCertificate: Data = Certificate().getClientCertificateData()
        let sharedKeyJSON = NSMutableData()
        sharedKeyJSON.append(appCertificate)
        sharedKeyJSON.append(crypto.publicKey)
        sharedKeyJSON.append(signature)
        
        let result = self.sendData(data: sharedKeyJSON as Data)
        if (result == -1 ) {
            print("write failed")
        } else {
            print("Success")
            completion()
        }
    }
    
}

extension OutputStream {
    func write(data: Data) -> Int {
        return data.withUnsafeBytes { write($0, maxLength: data.count) }
    }
}

