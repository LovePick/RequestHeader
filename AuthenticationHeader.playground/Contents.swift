import UIKit
import CommonCrypto
import Foundation


let host:String = "http://sample.com"
let path:String = "/secureauth2/api/v1/users/"

let applicationKey:String = "1b700d2e7b7b4abfa1950c865e23e81a"
let applicationID:String = "01234567891011121314151617181920120212223242526272829"



let method:String = "POST"
let serverTime:NSInteger = NSInteger(Date().timeIntervalSince1970) //Server time
let body:[String:Any] = ["user_id":"jsmith", "type": "user_id"]



func createAuthorizationHeader(method:String, path:String, serverTime:NSInteger?, body:[String:Any]?)->String{
    
    let step1:String = createMethodString(method: method, dateTime: serverTime, appID: applicationID, path: path, body:body)
    
    
    let step2and3 = step1.hmacBase64(key: applicationKey)
    
    let step4 = "\(applicationID):\(step2and3)"
    
    let step5 = step4.toBase64()
    
    let step6 = "Basic \(step5)"
    
    return step6
    
}


func createMethodString(method:String, dateTime:NSInteger?, appID:String, path:String, body:[String:Any]?)->String{
    
    
    var str = "\(method)"
    if let intTime = dateTime{
        str = str + "\n\(intTime)"
    }
    
    str = str + "\n\(appID)\n\(path)"
    
    
    if let body = body{
        let jsonData = try? JSONSerialization.data(withJSONObject: body, options: [])
        let jsonString = String(data: jsonData!, encoding: .utf8)
        
        if let jsonString = jsonString{
            str = str + "\n\(jsonString)"
        }
        
    }
    
    
    return str
    
}


extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}

extension String{
    
    func hmacBase64(key: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, self, self.count, &digest)
        let data = Data(digest)
        return data.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
    }
    
    
    func hmacHex(key: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, self, self.count, &digest)
        let data = Data(digest)
        return data.hexEncodedString()
    }
    
    
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        
        return String(data: data, encoding: .utf8)
    }
    
    
    func toBase64() -> String {
        let loginData = self.data(using: String.Encoding.utf8)!
        return loginData.base64EncodedString()
    }
}



// Request

func myRequest(){
    
    let urlString = "\(host)\(path)"
    guard let url = URL(string: urlString) else {
        print("URL is not correct")
        return
    }
    
    let jsonData = try? JSONSerialization.data(withJSONObject: body)
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = method
    urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
    urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
    urlRequest.setValue("\(serverTime)", forHTTPHeaderField: "X-API-Request-Time")
    
    
    let authorization = createAuthorizationHeader(method: method, path: path, serverTime: serverTime, body: body)
    
    urlRequest.setValue(authorization, forHTTPHeaderField: "Authorization")
    
    // insert json data to the request
    urlRequest.httpBody = jsonData
    
    
    
    let session = URLSession.shared
    let task = session.dataTask(with: urlRequest) { (data:Data?, response:URLResponse?, error:Error?) in
        
        if let error = error{
            print(error.localizedDescription)
        }else{
            print("Do something")
        }
    }
    task.resume()
}

let msg:String = "12345"
let encode:String = msg.toBase64()
print(encode)
let decode:String? = encode.fromBase64()
print(decode!)








