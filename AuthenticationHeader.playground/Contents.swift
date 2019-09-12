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


enum CryptoAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    var HMACAlgorithm: CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:      result = kCCHmacAlgMD5
        case .SHA1:     result = kCCHmacAlgSHA1
        case .SHA224:   result = kCCHmacAlgSHA224
        case .SHA256:   result = kCCHmacAlgSHA256
        case .SHA384:   result = kCCHmacAlgSHA384
        case .SHA512:   result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    var digestLength: Int {
        var result: Int32 = 0
        switch self {
        case .MD5:      result = CC_MD5_DIGEST_LENGTH
        case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}


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



extension String {
    
    func hmac(algorithm: CryptoAlgorithm, key: String) -> String {

        let str = self.cString(using: String.Encoding.utf8)
        let strLen = Int(self.lengthOfBytes(using: String.Encoding.utf8))
        let digestLen = algorithm.digestLength
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        let keyStr = key.cString(using: String.Encoding.utf8)
        let keyLen = Int(key.lengthOfBytes(using: String.Encoding.utf8))
        
        CCHmac(algorithm.HMACAlgorithm, keyStr!, keyLen, str!, strLen, result)
        
        let digest = stringFromResult(result: result, length: digestLen)
        
        result.deallocate()
        
        return digest
        
    }
    
    private func stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash).lowercased()
    }

}

extension String {
    enum ExtendedEncoding {
        case hexadecimal
    }
    
    func data(using encoding:ExtendedEncoding) -> Data? {
        let hexStr = self.dropFirst(self.hasPrefix("0x") ? 2 : 0)
        
        guard hexStr.count % 2 == 0 else { return nil }
        
        var newData = Data(capacity: hexStr.count/2)
        
        var indexIsEven = true
        for i in hexStr.indices {
            if indexIsEven {
                let byteRange = i...hexStr.index(after: i)
                guard let byte = UInt8(hexStr[byteRange], radix: 16) else { return nil }
                newData.append(byte)
            }
            indexIsEven.toggle()
        }
        return newData
    }
}



extension String{
    
    func hmacBase64(key: String) -> String {
        
        let hexStr = self.hmac(algorithm: .SHA256, key: key)
        let data = hexStr.data(using: .utf8)!
        
        let str = String(data: data, encoding: .utf8)
        
        let base64 = str!.toBase64()
        
        
        return base64
        
        
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
        
        var loginData:Data? = self.data(using: .hexadecimal)//self.data(using: String.Encoding.utf8)!
        if loginData == nil {
            loginData = self.data(using: String.Encoding.utf8)!
        }
        
        return loginData!.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))//loginData.base64EncodedString()
    }
    
    
    func utf8DecodedString()-> String {
        let data = self.data(using: .utf8)
        if let message = String(data: data!, encoding: .nonLossyASCII){
            return message
        }
        return ""
    }
    
    func utf8EncodedString()-> String {
        let messageData = self.data(using: .nonLossyASCII)
        let text = String(data: messageData!, encoding: .utf8)
        return text!
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








