//
//  TCPResponseParser.swift
//  TLSPoc
//
//  Created by Gyana Prakash Gouda on 01/04/20.
//  Copyright © 2020 gyana. All rights reserved.
//

import UIKit
import ObjectMapper

class TCPResponseParser: NSObject {
    
    static func separateParameter(for method: TCPCommand, response: Data) -> AnyObject {
        switch method {
        case .SendPincode:
            return self.separatePrameterForCreatMap(response: response)
        }
    }
    
    private static func separatePrameterForCreatMap(response: Data) -> AnyObject {
        do {
            if let result = try JSONSerialization.jsonObject(with: response, options : .allowFragments) as? Dictionary<String,Any> {
                let sendPinResponse = Mapper<SendPINCodeModel>().map(JSON: result)
                return sendPinResponse!
            } else {
                return "Bad json" as AnyObject
            }
        } catch let error as NSError {
            return error as AnyObject
        }
    }
    
}
