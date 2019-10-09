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
            [certificaat.domain :as d :refer [valid?]]
            [certificaat.plugins.server :as server]
            [clj-http.client :as client]
            [clojure.core.async :refer [<!!]]
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
              :challenge-type "http-01"
              :san #{"www.teamsocial.me"}
              :hooks [:before-challenge :after-request] ; hooks to inject before challenges and after certificate request 
              :plugins {:webroot {:enabled false
                                  :path "/tmp"}
                        :httpd {:enabled true
                                :port 3010}
                        :diffie-hellman {:enabled false
                                         :modulus 2048
                                         :filename "dhparam.pem"
                                         :group14 true}
                        :copy-to-path {:enabled true
                                       :path "/tmp"}
                        :email {:enabled false
                                :smtp {:host "smtp.changeme.org"
                                       :user "changeme"
                                       :pass "changeme"
                                       :port 587}
                                :sendmail false}}})

(defn setup [f]
  (config/setup options)
  (kung-fu/account options)
  (kung-fu/order options)
  (f)
  (config/delete-domain-config-dir! options))

(use-fixtures :once setup)

(deftest session-kung-fu
  (let [session (session/create (:acme-uri options))
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
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        contact (:contact options)
        account (account/create session keypair contact :with-login false)]
    (is (= org.shredzone.acme4j.Account (type account)))
    (is (= java.net.URL (type (.getLocation account))))))

(deftest account-location
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)]
    (is (= org.shredzone.acme4j.Account (type account)))
    (is (= java.net.URL (type (.getLocation account))))))

(deftest login-at-account-creation
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        contact (:contact options)
        login (account/create session keypair contact :with-login true)]    
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        account-location (.getLocation account)
        login (.login session account-location keypair)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login-constructor
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        login (org.shredzone.acme4j.Login. (.getLocation account) keypair session)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest login-method
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (kung-fu/login keypair session options)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest wildcard-domain-validation
  (let [options-with-wildcard-domain (assoc options :domain "*.tuppu.net")
        options-with-wildcard-san (assoc options :san #{"*.tuppu.net"})]
    (is (thrown? Exception (d/validate ::d/config options-with-wildcard-domain)))
    (is (thrown? Exception (d/validate ::d/config options-with-wildcard-san)))
    (is (d/validate ::d/config options))))

(deftest authorization
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (kung-fu/login keypair session options)
        order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [status (.getStatus auth)]]
      (is (= org.shredzone.acme4j.Authorization (type auth)))
      (is (some #{status} [org.shredzone.acme4j.Status/PENDING org.shredzone.acme4j.Status/VALID])))))

(deftest challenges
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (kung-fu/login keypair session options)
        order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [challenges (.getChallenges auth)]]
      (is (some #{org.shredzone.acme4j.challenge.Http01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.Dns01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.TlsAlpn01Challenge} (map type challenges))))))

(deftest challenge-http-01
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (kung-fu/login keypair session options)
        order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [challenge (.findChallenge auth org.shredzone.acme4j.challenge.Http01Challenge/TYPE)
                  domain (.getDomain (.getIdentifier auth))]]
      (is (some? (.getAuthorization challenge)))
      (is (some? (.getToken challenge)))
      (is (some? domain))
      (is (java.net.URL. (str "http://" domain "/.well-known/acme-challenge/" (.getToken challenge)))))))

(deftest process-challenge-http-01
  (testing "sudo socat tcp-listen:80,reuseaddr,fork tcp:localhost:3010"
    (let [session (session/create (:acme-uri options))
          keypair (keypair/read (:config-dir options) (:keypair-filename options))
          login (kung-fu/login keypair session options)
          order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))
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
    (let  [session (session/create (:acme-uri options))
           keypair (keypair/read (:config-dir options) (:keypair-filename options))
           login (kung-fu/login keypair session options)
           order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))
           authorizations (.getAuthorizations order)
           challenges (for [authorization authorizations]
                        (challenge/find authorization (:challenge-type options)))
           server (server/listen challenges options)]
      (doseq [challenge challenges]
        (println "Channel returned:" (<!! (challenge/accept challenge))))
      (doseq [authorization authorizations]
        (.update authorization)
        (is (= true (valid? authorization))))
      (server/stop-server server))))

(deftest finalize-order
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        login (kung-fu/login keypair session options)
        order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))
        domains (if (:san options) (conj (:san options) (:domain options)) [(:domain options)])        
        domain-keypair (keypair/read (str (:config-dir options) (:domain options)) "/domain.key")
        csrb (certificate/prepare domain-keypair domains (:organisation options))
        csr (.getEncoded csrb)]
    (certificate/persist-certificate-request csrb (str (:config-dir options) (:domain options) "/cert.csr")) 
    (when (<!! (order/ready-to-finalize? order)) (.execute order csr))
    (.update order)
    (is (= true (valid? order)))))

(deftest certificate
  (let [session (session/create (:acme-uri options))
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        login (.login session (.getLocation account) keypair)
        order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))
        csrb (certificate/load-certificate-request (str (:config-dir options) (:domain options) "/cert.csr"))
        csr (.getEncoded csrb)
        cert (.getCertificate order)
        X509Certificate (.getCertificate cert)
        chain (.getCertificateChain cert)]
    (is (= org.shredzone.acme4j.Certificate (type cert)))
    (certificate/persist cert (str (:config-dir options) (:domain options) "/cert-chain.crt"))
    (.checkValidity X509Certificate)
    (is (pos? (.compareTo (.getNotAfter X509Certificate) (Date/from (Instant/now)))))))
