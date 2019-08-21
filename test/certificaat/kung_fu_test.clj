(ns certificaat.kung-fu-test
  (:require [certificaat.kung-fu :as kung-fu]
            [certificaat.acme4j.account :as account]
            [certificaat.acme4j.session :as session]
            [certificaat.acme4j.keypair :as keypair]
            [clojure.test :refer [deftest is]]))

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


(deftest session-kung-fu
  (let [session (kung-fu/session options)
        metadata (.getMetadata session)]
    (is (= org.shredzone.acme4j.Session (type session)))
    (is (= org.shredzone.acme4j.Metadata (type metadata)))
    (is (= java.net.URI (type (.getTermsOfService metadata))))
    (is (= java.net.URL (type (.getWebsite metadata))))))

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
