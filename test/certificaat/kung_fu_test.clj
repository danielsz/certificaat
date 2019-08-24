(ns certificaat.kung-fu-test
  (:require [certificaat.kung-fu :as kung-fu]
            [certificaat.util.configuration :as config]
            [certificaat.acme4j.account :as account]
            [certificaat.acme4j.session :as session]
            [certificaat.acme4j.keypair :as keypair]
            [clojure.test :refer [deftest is use-fixtures]]))

(def options {:config-dir (str (or (System/getenv "XDG_CONFIG_HOME") (str (System/getProperty "user.home") "/.config/")) "certificaat/")
               :keypair-filename "account.key"
               :key-type :rsa
               :key-size 2048
               :acme-uri "acme://letsencrypt.org/staging" ; in production, use acme://letsencrypt.org
               :domain "change.me"
               :san #{}
               :organisation "ChangeMe corporation"
               :contact "mailto:admin@change.me"
               :challenges #{"http-01"}
               :hooks [:before-challenge :after-request] ; hooks to inject before challenges and after certificate request 
               :plugins {:webroot {:enabled false
                                   :path "/tmp"}
                         :httpd {:enabled false}
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
    (is (= java.net.URL (type (.getWebsite metadata))))))

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
        account-location (.getLocation account)
        login (org.shredzone.acme4j.Login. account-location keypair session)]
    (is (= org.shredzone.acme4j.Login (type login)))
    (is (= org.shredzone.acme4j.Account (type (.getAccount login))))))

(deftest order
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        order-builder (doto (.newOrder account)
                        (.domains ["example.org" "www.example.org" "m.example.org"]))]
    (is (= org.shredzone.acme4j.OrderBuilder (type order-builder)))
    (is (= org.shredzone.acme4j.Order (type (.create order-builder))))))

(deftest resource-binding-order
  (let [session (kung-fu/session options)
        keypair (keypair/read (:config-dir options) (:keypair-filename options))
        account (account/read session keypair)
        account-location (.getLocation account)
        login (.login session account-location keypair)
        order-builder (doto (.newOrder account)
                        (.domains ["example.org" "www.example.org" "m.example.org"]))
        order (.create order-builder)
        order-url (.getLocation order)]
    (is (= (type order) (type (.bindOrder login order-url)))) ; same object
    (is (not= order (.bindOrder login order-url))) ; different instance
    (is (= (.getLocation order) (.getLocation (.bindOrder login order-url)))) ; same url
    ))

(deftest authorization
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         order-builder (doto (.newOrder account)
                         (.domains ["example.org" "www.example.org" "m.example.org"]))
         order (.create order-builder)]
    (doseq [auth (.getAuthorizations order)]
      (is (= org.shredzone.acme4j.Authorization (type auth)))
      (is (= org.shredzone.acme4j.Status/PENDING (.getStatus auth))))))

(deftest resource-binding-authorization
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         account-location (.getLocation account)
         login (.login session account-location keypair)
         order-builder (doto (.newOrder account)
                         (.domains ["example.org" "www.example.org" "m.example.org"]))
         order (.create order-builder)]
    (doseq [auth (.getAuthorizations order)
            :let [auth-url (.getLocation auth)]]
      (is (= org.shredzone.acme4j.Authorization (type (.bindAuthorization login auth-url))))
      (is (= (.getLocation auth) (.getLocation (.bindAuthorization login auth-url)))))))

(deftest challenges
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         order-builder (doto (.newOrder account)
                         (.domains ["example.org" "www.example.org" "m.example.org"]))
         order (.create order-builder)]
    (doseq [auth (.getAuthorizations order)
            :let [challenges (.getChallenges foo)]]
      (is (some #{org.shredzone.acme4j.challenge.Http01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.Dns01Challenge} (map type challenges)))
      (is (some #{org.shredzone.acme4j.challenge.TlsAlpn01Challenge} (map type challenges))))))

(deftest challenge-http-01
  (let  [session (kung-fu/session options)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         account (account/read session keypair)
         order-builder (doto (.newOrder account)
                         (.domains ["example.org" "www.example.org" "m.example.org"]))
         order (.create order-builder)]
    (doseq [auth (.getAuthorizations order)
            :let [challenge (.findChallenge auth org.shredzone.acme4j.challenge.Http01Challenge/TYPE)
                  domain (.getDomain (.getIdentifier auth))]]
      (is (some? (.getAuthorization challenge)))
      (is (some? (.getToken challenge)))
      (is (some? domain))
      (is (java.net.URL. (str "http://" domain "/.well-known/acme-challenge/" (.getToken challenge)))))))
