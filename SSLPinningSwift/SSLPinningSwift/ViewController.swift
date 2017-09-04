//
//  ViewController.swift
//  SSLPinningSwift
//
//  Created by MyCandy on 04/09/17.
//  Copyright © 2017 Silver Seahog. All rights reserved.
//

import UIKit
import Alamofire

class ViewController: UIViewController, URLSessionDelegate, URLSessionTaskDelegate {

    
    let githubCert = "github.com" // replace string with "corrupted" to test faulty certificate
    
    @IBOutlet weak var handlerBtn: UIButton!
    
    var urlSession: Foundation.URLSession!
    var serverTrustPolicy: ServerTrustPolicy!
    var serverTrustPolicies: [String: ServerTrustPolicy]!
    var afManager: SessionManager!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        handlerBtn.setTitle(githubCert, for: .normal)
        
        let pathToCert = Bundle.main.path(forResource: githubCert, ofType: "cer")
        let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
        self.configureAlamoFireSSLPinningWithCertificateData(localCertificate)
        self.urlSession = Foundation.URLSession(configuration: URLSessionConfiguration.default, delegate: self, delegateQueue: nil)

    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    
    // MARK: SSL Config
    
    func configureAlamoFireSSLPinningWithCertificateData(_ certificateData: Data) {
        self.serverTrustPolicy = ServerTrustPolicy.pinCertificates(certificates: [SecCertificateCreateWithData(nil, certificateData as CFData)!], validateCertificateChain: true, validateHost: true)
        
        self.serverTrustPolicies = [
            "https://github.com": self.serverTrustPolicy!
        ]
        
        self.afManager = SessionManager (
            configuration: URLSessionConfiguration.default,
            serverTrustPolicyManager: ServerTrustPolicyManager(policies: self.serverTrustPolicies)
        )
    }
    
    func configureURLSession() {
        self.urlSession = Foundation.URLSession(configuration: URLSessionConfiguration.default, delegate: self, delegateQueue: nil)
    }
    
    // MARK: URL session delegate
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let serverTrust = challenge.protectionSpace.serverTrust
        let certificate = SecTrustGetCertificateAtIndex(serverTrust!, 0)
        
        // Set SSL policies for domain name check
        let policies = NSMutableArray();
        policies.add(SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString)))
        SecTrustSetPolicies(serverTrust!, policies);
        
        // Evaluate server certificate
        var result: SecTrustResultType = SecTrustResultType(rawValue: 0)!
        SecTrustEvaluate(serverTrust!, &result)
        let isServerTrusted:Bool = result == SecTrustResultType.unspecified || result == SecTrustResultType.proceed

        // Get local and remote cert data
        let remoteCertificateData:Data = SecCertificateCopyData(certificate!) as Data
        let pathToCert = Bundle.main.path(forResource: githubCert, ofType: "cer")
        let localCertificate:Data = try! Data(contentsOf: URL(fileURLWithPath: pathToCert!))
        
        if (isServerTrusted && (remoteCertificateData == localCertificate)) {
            let credential:URLCredential = URLCredential(trust: serverTrust!)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }


    // MARK: Button actions
    
    @IBAction func alamoFireRequestHandler(_ sender: UIButton) {
        self.afManager.request(githubCert).responseString {
            response in
            print("Response:", response)
            guard let data = response.data, response.error == nil else {
                print(response.error.debugDescription)
                    return
            }
                print(String(data: data, encoding: String.Encoding.utf8)!)
            }
            
        }
    
}

