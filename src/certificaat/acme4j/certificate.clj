(ns certificaat.acme4j.certificate
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.registration :as registration]
            [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Certificate]
           [org.shredzone.acme4j.util CSRBuilder CertificateUtils]
           [org.shredzone.acme4j.util KeyPairUtils]
           [java.security.cert CertificateExpiredException CertificateNotYetValidException]
           [java.io FileWriter FileReader]))

(defn prepare [keypair domain organization & additional-domains]
  (let [builder (CSRBuilder.)]
    (.addDomain builder domain)
    (when additional-domains
      (doseq [domain additional-domains]
        (.addDomain builder domain)))
    (doto builder
      (.setOrganization organization)
      (.sign keypair))))

(defn persist-certificate-request [path csrb]
  (let [fw (FileWriter. path)]
    (.write csrb fw)))

(defn load-certificate-request [path]
  (let [input (io/input-stream path)]
    (CertificateUtils/readCSR input)))

(defn persist [cert path]
  (let [fw (FileWriter. path)]
    (.writeCertificate cert fw)))

(defn restore [login path]
  (.bindCertificate login (load-url path)))

(defn revoke [cert]
  (.revoke cert))

(defn match?
  "Utility function to determine if a private key matches a certificate"
  [cert key]
  (= (.getModulus (.getPublicKey cert)) (.getModulus (.getPrivate key))))

(defn info
  ([{config-dir :config-dir domain :domain}]
   (let [path (str config-dir domain "/")
         cert-file (str path "domain-chain.crt")
         key-file (str path "domain.key")]
    (info cert-file key-file)))
  ([cert-file key-file]
   (let [cert (CertificateUtils/readCSR (io/input-stream cert-file))
         issuer (.getIssuerX500Principal cert)
         subject (.getSubjectX500Principal cert)
         info {:issuer (.getName issuer)
               :subject (.getName subject)
               :san (map str (seq (.getSubjectAlternativeNames cert)))
               :valid-until (.getNotAfter cert)
               :path cert-file}]
     (if (.exists (io/file key-file))
       (let [key (KeyPairUtils/readKeyPair (FileReader. key-file))]
         (if (match? cert key)
           (assoc info :private-key key-file)
           info))
       info))))


(extend-type Certificate
  Certificaat
  (valid? [this] (let [cert (.download this)]
                   (log/info "Certificate expires after" (.getNotAfter cert))
                   (try (.checkValidity cert)
                        true
                        (catch CertificateExpiredException e false)
                        (catch CertificateNotYetValidException e false))))
  (marshal [this path]
    (spit path (.getLocation this))))
