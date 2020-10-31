//
//  SendPINCodeModel.swift
//  TLS_Stream_Poc
//
//  Created by Gyana Prakash Gouda on 19/05/20.
//  Copyright © 2020 Gyana Prakash Gouda. All rights reserved.
//

import UIKit
import ObjectMapper

class SendPINCodeModel: Mappable {
    
    var type: String?
    var cmd: String?
    var data: String?
    var result: String?
   
    required init?(map: Map) {
        
    }
    
    // Mappable
    func mapping(map: Map) {
        type    <- map["type"]
        result  <- map["result"]
        cmd     <- map["cmd"]
        data  <- map["data"]
    }
    
}
