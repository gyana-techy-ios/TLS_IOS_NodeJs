//
//  Key.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 03/06/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit
import GMEllipticCurveCrypto

class Key: NSObject {
    
    func generateSharedSecKeysUsing(ServerPublicKey Key: Data, completion: (_ result: (GMEllipticCurveCrypto, NSData)) -> ()) {
        var ServerPubKey: Data = Key
        let crypto = GMEllipticCurveCrypto.generateKeyPair(for: GMEllipticCurveSecp128r1)
        crypto?.compressedPublicKey = false        
        ServerPubKey = crypto?.compressPublicKey(ServerPubKey) ?? Data()
        let sharedSecretKey = crypto?.sharedSecret(forPublicKey: ServerPubKey)
        completion((crypto!, sharedSecretKey! as NSData))
    }
    
}
