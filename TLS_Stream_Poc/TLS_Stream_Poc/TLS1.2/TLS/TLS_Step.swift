//
//  TLS_Step.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 03/06/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit

/// TLS Step identifire
public enum TLSLevel {
    
    case clientHello
    case serverB9
    case serverSendDigitalSignature
    case clientVerifyDigitalSignature
    case clientSendDigitalSignature
    case serverPublicKey
    case clientAppCftSessionKey
    case serverCompletedEncrypt
    case clientCompletedEncrypt
    case Completed
    case Finished
    
}
