//
//  ViewController.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 14/05/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Do any additional setup after loading the view.
    }
    
    @IBAction func openConnectionAction(_ sender: Any) {
        if (!TcpSocketManager.sharedInstance.connect()) {
            print("Not connected")
        }
    }

    @IBAction func sendHelloAction(_ sender: Any) {
        if (TcpSocketManager.sharedInstance.isSocketOpened()) {
            TcpSocketManager.sharedInstance.sayHelloToServer()
        }
    }
    
    @IBAction func sendCommandRequest(_ sender: Any) {
        if TcpSocketManager.sharedInstance.TlsLevelId == .Finished {
            let jsonpasswd = """
            {
            "type": "request",
            "cmd": "TestCode",
            "code": "\(9755453)"
            }
            """
            print(jsonpasswd)
            
            
            SessionKey_Encrypt().sendClientEncryptedDataToServer(encrypt: jsonpasswd.data(using: .utf8)!, SharedSession: TcpSocketManager.sharedInstance.mySharedSecretKey! as Data, salt: TcpSocketManager.sharedInstance.salt!, completion: { (encryptedData) in
                let result = TcpSocketManager.sharedInstance.sendData(data: encryptedData)
                if (result == -1 ) {
                    print("write failed")
                } else {
                    printStepLog(Str: "TLS finished.", From: true, Step: 9)
                    let response : Data = TcpSocketManager.sharedInstance.recv(buffersize: 1024)!
                    
                    SessionKey_Encrypt().decryptServerCommandResponseEncryptedData(for: response, SharedSession: TcpSocketManager.sharedInstance.mySharedSecretKey! as Data) { (cmdresponse) in
                        printStepLog(Str: "Client read Completed message by Decrypting.", From: false, Step: 7)

                        if response.count > 0 {
                            if let result: SendPINCodeModel = TCPResponseParser.separateParameter(for: .SendPincode, response: cmdresponse.data(using: .utf8)!) as? SendPINCodeModel {
                                if result.result == "200" {
                                    print(result.data!)
                                }
                            }
                        }
                        
                    }
                }
            })
        }
    }
    
    
}
