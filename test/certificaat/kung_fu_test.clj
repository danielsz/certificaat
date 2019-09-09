(ns certificaat.kung-fu-test
  (:require [certificaat.kung-fu :as kung-fu]
            [certificaat.util.configuration :as config]
            [certificaat.acme4j.account :as account]
            [certificaat.acme4j.session :as session]
            [certificaat.acme4j.keypair :as keypair]
            [certificaat.acme4j.challenge :as challenge]
            [certificaat.acme4j.authorization]
            [certificaat.acme4j.order :as order]
            [certificaat.acme4j.certificate :as certificate]
            [certificaat.domain :as d :refer [marshal valid?]]
            [certificaat.utils :refer [load-url]]
            [certificaat.plugins.server :as server]
            [clj-http.client :as client]
            [clojure.test :refer [deftest is use-fixtures testing]])
  (:import [java.io FileWriter]
           [java.time Instant]
           [java.util Date]))

(def options {:config-dir (str (or (System/getenv "XDG_CONFIG_HOME") (str (System/getProperty "user.home") "/.config/")) "certificaat/")
              :keypair-filename "account.key"
              :key-type :rsa
              :key-size 2048
              :acme-uri "acme://letsencrypt.org/staging" ; in production, use acme://letsencrypt.org
              :domain "zebulun.tuppu.net"
              :organisation "ChangeMe corporation"
              :contact "mailto:admin@change.me"
              :challenges #{"http-01"}
              :san #{"foo.tuppu.net"}
              :hooks [:before-challenge :after-request] ; hooks to inject before challenges and after certificate request 
              :plugins {:webroot {:enabled false
                                  :path "/tmp"}
                        :httpd {:enabled true
                                :port 3010}
                        :diffie-hellman {:enabled false
                                         :modulus 2048
                                         :filename "dhparam.pem"
                                         :group14 true}
                        :email {:enabled false
                                :smtp {:host "smtp.changeme.org"
                                       :user "changeme"
                                       :pass "changeme"
                                       :port 587}
                                :sendmail false}}})

(defn setup [f]
  (config/setup options)
  (f)
  (config/delete-domain-config-dir! options))

(use-fixtures :once setup)

(deftest session-kung-fu
  (let [session (kung-fu/session options)
        metadata (.getMetadata session)]
    (is (= org.shredzone.acme4j.Session (type session)))
    (is (= org.shredzone.acme4j.Metadata (type metadata)))
    (is (= java.net.URI (type (.getTermsOfService metadata))))
    (is (= java.net.URL (type (.getWebsite metadata))))
    (is (= false (.isExternalAccountRequired metadata)))))

(deftest session
  (let [session (session/create (:acme-uri options))
        metadata (.getMetadata session)]
    (is (= org.shredzone.acme4j.Session (type session)))
    (is (= org.shredzone.acme4j.Metadata (type metadata)))
    (is (= java.net.URI (type (.getTermsOfService metadata))))
    (is (= java.net.URL (type (.getWebsite metadata))))
    (is (false? (.isExternalAccountRequired metadata)))))

(deftest account-creation
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        contact (:contact options)
        account (account/create session keypair contact :with-login false)]
    (is (= org.shredzone.acme4j.Account (type account)))
    (is (= java.net.URL (type (.getLocation account))))))

(deftest account-location
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)]
    (marshal account (str (:config-dir options) "/account.url"))
    (is (= org.shredzone.acme4j.Account (type account)))
    (is (= java.net.URL (type (.getLocation account))))))

(deftest login-at-account-creation
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        contact (:contact options)
        login (account/create session keypair contact :with-login true)]    
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        account-location (.getLocation account)
        login (.login session account-location keypair)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login-constructor
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        login (org.shredzone.acme4j.Login. (.getLocation account) keypair session)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login-method
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (account/login (str (:config-dir options) "/account.url") keypair session)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest order
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
        order-builder (doto (.newOrder account)
                        (.domains domains))]
    (is (= org.shredzone.acme4j.OrderBuilder (type order-builder)))
    (is (= org.shredzone.acme4j.Order (type (.create order-builder))))))

(deftest resource-binding-order
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/restore session keypair)
        login (.login session (.getLocation account) keypair)
        domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
        order (order/create account domains)
        order-url (.getLocation order)
        url-path (str (:config-dir options) (:domain options) "/order.url")]
    (marshal order url-path)
    (is (= (type order) (type (.bindOrder login order-url)))) ; same object
    (is (not= order (.bindOrder login order-url))) ; different instance
    (is (= (.getLocation order) (.getLocation (.bindOrder login order-url)))) ; same url
    (is (= (type order) (type (order/restore login url-path))))
    (is (= org.shredzone.acme4j.Order (type (.bindOrder login (load-url url-path)))))))

(deftest authorization
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         login (account/login (str (:config-dir options) "/account.url") keypair session)
         order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [status (.getStatus auth)]]
      (is (= org.shredzone.acme4j.Authorization (type auth)))
      (is (some #{status} [org.shredzone.acme4j.Status/PENDING org.shredzone.acme4j.Status/VALID])))))

(deftest resource-binding-authorization
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         account-location (.getLocation account)
         login (.login session account-location keypair)
         domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
         order (order/create account domains)]
    (doseq [auth (.getAuthorizations order)
            :let [auth-url (.getLocation auth)]]
      (is (= org.shredzone.acme4j.Authorization (type (.bindAuthorization login auth-url))))
      (is (= (.getLocation auth) (.getLocation (.bindAuthorization login auth-url)))))))

(deftest challenges
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
         order (order/create account domains)]
    (doseq [auth (.getAuthorizations order)
            :let [challenges (.getChallenges auth)]]
      (is (some #{org.shredzone.acme4j.challenge.Http01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.Dns01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.TlsAlpn01Challenge} (map type challenges))))))

(deftest challenge-http-01
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
         order (order/create account domains)]
    (doseq [auth (.getAuthorizations order)
            :let [challenge (.findChallenge auth org.shredzone.acme4j.challenge.Http01Challenge/TYPE)
                  domain (.getDomain (.getIdentifier auth))]]
      (is (some? (.getAuthorization challenge)))
      (is (some? (.getToken challenge)))
      (is (some? domain))
      (is (java.net.URL. (str "http://" domain "/.well-known/acme-challenge/" (.getToken challenge)))))))


(deftest process-challenge-http-01
  (testing "sudo socat tcp-listen:80,reuseaddr,fork tcp:localhost:3010"
    (let  [session (kung-fu/session options)
           keypair (keypair/read (:config-dir options) (:keypair-filename options))
           account (account/restore session keypair)
           domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
           order (order/create account domains)
           authorizations (.getAuthorizations order)
           domains+challenges (for [authorization authorizations]
                               [(.getDomain (.getIdentifier authorization))
                                (.findChallenge authorization org.shredzone.acme4j.challenge.Http01Challenge/TYPE)])
           challenges (map last domains+challenges)
           server (server/listen challenges options)]
      (doseq [[domain challenge] domains+challenges
              :let [resp (client/get (str "http://127.0.0.1/.well-known/acme-challenge/" (.getToken challenge)))]]
        (is (= (.getAuthorization challenge) (:body resp))))
      (server/stop-server server))))

(deftest trigger-challenge-http-01
  (testing "sudo socat tcp-listen:80,reuseaddr,fork tcp:localhost:3010"
    (let  [session (kung-fu/session options)
           keypair (keypair/read (:config-dir options) (:keypair-filename options))
           account (account/read session keypair)
           domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
           order (order/create account domains)
           authorizations (.getAuthorizations order)
           challenges (for [authorization authorizations]
                        (challenge/find authorization (first (:challenges options))))         
           server (server/listen challenges options)]
      (doseq [challenge challenges]
        (challenge/accept challenge))
      (doseq [authorization authorizations]
        (.update authorization)
        (is (= true (valid? authorization))))
      (server/stop-server server))))

(deftest finalize-order
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])
        order (order/create account domains)
        domain-keypair (keypair/read (str (:config-dir options) (:domain options)) "/domain.key")
        csrb (certificate/prepare domain-keypair (:domain options) (:organisation options))
        csr (.getEncoded csrb)]
    (certificate/persist-certificate-request csrb (str (:config-dir options) (:domain options) "/cert.csr")) 
    (.execute order csr)
    (.update order)
    (is (= true (valid? order)))))

(deftest certificate
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        login (.login session (.getLocation account) keypair)
        url-path (str (:config-dir options) (:domain options) "/order.url")        
        order (.bindOrder login (load-url url-path))
        csrb (certificate/load-certificate-request (str (:config-dir options) (:domain options) "/cert.csr"))
        csr (.getEncoded csrb)
        _ (.execute order csr)
        cert (.getCertificate order)
        X509Certificate (.getCertificate cert)
        chain (.getCertificateChain cert)]
    (is (= org.shredzone.acme4j.Certificate (type cert)))
    (certificate/persist cert (str (:config-dir options) (:domain options) "/domain-chain.crt"))
    (.checkValidity X509Certificate)
    (d/marshal cert (str (:config-dir options) (:domain options) "/cert.url"))
    (is (pos? (.compareTo (.getNotAfter X509Certificate) (Date/from (Instant/now)))))))
